"""Background PostgreSQL logical WAL (`pgoutput` + `test_decoding`) poller and slot monitor."""

from __future__ import annotations

import json
import re
import struct
import sys
import threading
import time
from typing import Any

from .cdc import CDCChangeEvent, CDCIngestor
from .drivers.postgres_driver import PostgresDriver
from .ledger import UndoLedger, new_tx_id
from .models import EngineType, MutationOp


def _parse_tuple_kv(text: str) -> dict[str, Any]:
    """Parse `col[type]:val col2[type]:'str''val'` emitted by Postgres `test_decoding`."""
    out: dict[str, Any] = {}
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        # Read column[type]:
        bracket = text.find("[", i)
        if bracket == -1:
            break
        col_name = text[i:bracket].strip('"')
        close_br = text.find("]:", bracket)
        if close_br == -1:
            break
        col_type = text[bracket + 1 : close_br].lower()
        i = close_br + 2

        if i < n and text[i] == "'":
            i += 1
            buf: list[str] = []
            while i < n:
                if text[i] == "'":
                    if i + 1 < n and text[i + 1] == "'":
                        buf.append("'")
                        i += 2
                        continue
                    i += 1
                    break
                buf.append(text[i])
                i += 1
            raw_val = "".join(buf)
            if col_type in ("bytea",) and raw_val.startswith("\\x"):
                out[col_name] = bytes.fromhex(raw_val[2:])
            else:
                out[col_name] = raw_val
        else:
            end = i
            while end < n and not text[end].isspace():
                end += 1
            token = text[i:end]
            i = end
            if token == "null":
                out[col_name] = None
            elif token == "unchanged-toast-datum":
                continue
            elif col_type in ("integer", "bigint", "smallint", "int4", "int8", "int2"):
                out[col_name] = int(token)
            elif col_type in ("double precision", "real", "numeric", "float8", "float4"):
                out[col_name] = float(token)
            elif col_type == "boolean":
                out[col_name] = token == "true"
            else:
                out[col_name] = token
    return out


def parse_test_decoding_line(data: str) -> dict[str, Any] | None:
    """Parse one `pg_logical_slot_get_changes` `data` string."""
    s = data.strip()
    if s.startswith("BEGIN "):
        return {"kind": "begin", "xid": s.split()[1]}
    if s.startswith("COMMIT "):
        return {"kind": "commit", "xid": s.split()[1]}
    m_msg = re.match(
        r"^message:\s+transactional:\s+\d+\s+prefix:\s+([^,]+),\s+sz:\s+\d+\s+content:(.*)$",
        s,
        re.S,
    )
    if m_msg:
        prefix, content = m_msg.groups()
        return {"kind": "message", "prefix": prefix.strip(), "content": content}

    m_tbl = re.match(
        r"^table\s+([^.]+)\.([^:]+):\s+(INSERT|UPDATE|DELETE):\s*(.*)$", s, re.S
    )
    if not m_tbl:
        return None
    schema, table, op_word, rest = m_tbl.groups()
    schema = schema.strip('"')
    table = table.strip('"')

    if op_word == "INSERT":
        return {
            "kind": "dml",
            "op": "c",
            "schema": schema,
            "table": table,
            "before": None,
            "after": _parse_tuple_kv(rest),
        }
    if op_word == "DELETE":
        if rest.startswith("old-key: "):
            rest = rest[len("old-key: ") :]
        return {
            "kind": "dml",
            "op": "d",
            "schema": schema,
            "table": table,
            "before": _parse_tuple_kv(rest),
            "after": None,
        }
    if op_word == "UPDATE":
        if " new-tuple: " in rest:
            old_part, new_part = rest.split(" new-tuple: ", 1)
            if old_part.startswith("old-key: "):
                old_part = old_part[len("old-key: ") :]
            before = _parse_tuple_kv(old_part)
            after = _parse_tuple_kv(new_part)
        else:
            before = {}
            after = _parse_tuple_kv(rest)
        return {
            "kind": "dml",
            "op": "u",
            "schema": schema,
            "table": table,
            "before": before,
            "after": after,
        }
    return None


def _read_cstr(buf: bytes, off: int) -> tuple[str, int]:
    nul = buf.find(b"\x00", off)
    if nul == -1:
        return buf[off:].decode("utf-8", errors="replace"), len(buf)
    return buf[off:nul].decode("utf-8", errors="replace"), nul + 1


def _cast_pgoutput_text(raw: str, type_oid: int) -> Any:
    if type_oid in (20, 21, 23):
        return int(raw)
    if type_oid in (700, 701, 1700):
        return float(raw)
    if type_oid == 16:
        return raw.lower() in ("t", "true", "1")
    if type_oid == 17 and raw.startswith("\\x"):
        return bytes.fromhex(raw[2:])
    return raw


def _decode_pgoutput_tuple(
    buf: bytes, off: int, cols: list[tuple[str, int]]
) -> tuple[dict[str, Any], int]:
    ncols = struct.unpack_from("!H", buf, off)[0]
    off += 2
    out: dict[str, Any] = {}
    for idx in range(ncols):
        col_name, type_oid = cols[idx] if idx < len(cols) else (f"col_{idx}", 25)
        kind = chr(buf[off])
        off += 1
        if kind == "n":
            out[col_name] = None
        elif kind == "u":
            continue
        elif kind == "t":
            ln = struct.unpack_from("!i", buf, off)[0]
            off += 4
            raw = buf[off : off + ln].decode("utf-8", errors="replace")
            off += ln
            out[col_name] = _cast_pgoutput_text(raw, type_oid)
        elif kind == "b":
            ln = struct.unpack_from("!i", buf, off)[0]
            off += 4
            out[col_name] = buf[off : off + ln]
            off += ln
    return out, off


def parse_pgoutput_message(
    data: bytes, relations: dict[int, dict[str, Any]]
) -> dict[str, Any] | None:
    """Parse a single raw `pgoutput` protocol v1 binary message."""
    if not data:
        return None
    mtype = chr(data[0])
    if mtype == "B":
        xid = struct.unpack_from("!I", data, 17)[0]
        return {"kind": "begin", "xid": str(xid)}
    if mtype == "C":
        return {"kind": "commit"}
    if mtype == "M":
        prefix, off = _read_cstr(data, 10)
        ln = struct.unpack_from("!I", data, off)[0]
        off += 4
        content = data[off : off + ln].decode("utf-8", errors="replace")
        return {"kind": "message", "prefix": prefix, "content": content}
    if mtype == "R":
        rel_id = struct.unpack_from("!I", data, 1)[0]
        schema, off = _read_cstr(data, 5)
        table, off = _read_cstr(data, off)
        off += 1  # replica identity
        ncols = struct.unpack_from("!H", data, off)[0]
        off += 2
        cols: list[tuple[str, int]] = []
        for _ in range(ncols):
            off += 1  # flags
            col_name, off = _read_cstr(data, off)
            type_oid, _type_mod = struct.unpack_from("!Ii", data, off)
            off += 8
            cols.append((col_name, type_oid))
        relations[rel_id] = {"schema": schema, "table": table, "cols": cols}
        return {"kind": "relation", "rel_id": rel_id}
    if mtype == "I":
        rel_id = struct.unpack_from("!I", data, 1)[0]
        rel = relations.get(rel_id)
        if rel is None:
            return None
        after, _ = _decode_pgoutput_tuple(data, 6, rel["cols"])
        return {
            "kind": "dml",
            "op": "c",
            "schema": rel["schema"],
            "table": rel["table"],
            "before": None,
            "after": after,
        }
    if mtype == "U":
        rel_id = struct.unpack_from("!I", data, 1)[0]
        rel = relations.get(rel_id)
        if rel is None:
            return None
        off = 5
        tag = chr(data[off])
        if tag in ("K", "O"):
            before, off = _decode_pgoutput_tuple(data, off + 1, rel["cols"])
            tag = chr(data[off])
        else:
            before = {}
        after = {}
        if tag == "N":
            after, _ = _decode_pgoutput_tuple(data, off + 1, rel["cols"])
        return {
            "kind": "dml",
            "op": "u",
            "schema": rel["schema"],
            "table": rel["table"],
            "before": before,
            "after": after,
        }
    if mtype == "D":
        rel_id = struct.unpack_from("!I", data, 1)[0]
        rel = relations.get(rel_id)
        if rel is None:
            return None
        before, _ = _decode_pgoutput_tuple(data, 6, rel["cols"])
        return {
            "kind": "dml",
            "op": "d",
            "schema": rel["schema"],
            "table": rel["table"],
            "before": before,
            "after": None,
        }
    return None


class PostgresWALPoller:
    """Polls a Postgres logical replication slot (`pgoutput` default, `test_decoding` fallback)."""

    def __init__(
        self,
        driver: PostgresDriver,
        ledger: UndoLedger,
        *,
        slot_name: str = "reverse_proxy_slot",
        plugin: str = "pgoutput",
        publication_name: str = "_reverse_proxy_pub",
        poll_interval_sec: float = 0.25,
        max_wal_retention_mb: int | None = 1024,
    ) -> None:
        self.driver = driver
        self.ledger = ledger
        self.slot_name = slot_name
        self.plugin = plugin
        self.publication_name = publication_name
        self.poll_interval_sec = poll_interval_sec
        self.max_wal_retention_mb = max_wal_retention_mb
        self._pk_cache: dict[tuple[str, str], list[str]] = {}
        self._pgoutput_relations: dict[int, dict[str, Any]] = {}
        self._xid_tx_map: dict[str, str] = {}
        self._xid_skip: set[str] = set()
        self._xid_skip_tables: dict[str, set[tuple[str, str]]] = {}
        self._xid_events: dict[str, list[dict[str, Any]]] = {}
        self._poll_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._warned_unlimited = False
        self._warned_retention = False

    def ensure_slot(self) -> None:
        res = self.driver._client.execute(
            "SELECT plugin FROM pg_catalog.pg_replication_slots WHERE slot_name = $1;",
            [self.slot_name],
        )
        if res.rows:
            self.plugin = str(res.rows[0][0])
        else:
            self.driver._client.execute(
                "SELECT pg_catalog.pg_create_logical_replication_slot($1, $2);",
                [self.slot_name, self.plugin],
            )
        if self.plugin == "pgoutput":
            pub_check = self.driver._client.execute(
                "SELECT 1 FROM pg_catalog.pg_publication WHERE pubname = $1;",
                [self.publication_name],
            )
            if not pub_check.rows:
                pub_q = self.driver.quote_ident(self.publication_name)
                try:
                    self.driver._client.query(f"CREATE PUBLICATION {pub_q} FOR ALL TABLES;")
                except Exception:
                    pass
        self.check_slot_safety(emit_warnings=True)

    def get_slot_health(self) -> dict[str, Any]:
        """Inspect replication slot retention, wal_status, and server `max_slot_wal_keep_size`."""
        res = self.driver._client.execute(
            """
            SELECT slot_name, plugin, active, wal_status, safe_wal_size,
                   COALESCE(pg_catalog.pg_wal_lsn_diff(pg_catalog.pg_current_wal_lsn(), restart_lsn)::bigint, 0) AS retained_bytes
            FROM pg_catalog.pg_replication_slots
            WHERE slot_name = $1;
            """,
            [self.slot_name],
        )
        max_keep_res = self.driver._client.execute("SHOW max_slot_wal_keep_size;", ())
        max_keep = str(max_keep_res.rows[0][0]) if max_keep_res.rows else "-1"
        if not res.rows:
            return {
                "slot_name": self.slot_name,
                "exists": False,
                "plugin": self.plugin,
                "max_slot_wal_keep_size": max_keep,
            }
        sname, plugin, active, wal_status, safe_wal_size, retained_bytes = res.rows[0]
        return {
            "slot_name": str(sname),
            "exists": True,
            "plugin": str(plugin),
            "active": bool(active),
            "wal_status": str(wal_status) if wal_status is not None else "unknown",
            "safe_wal_size_bytes": int(safe_wal_size) if safe_wal_size is not None else None,
            "retained_bytes": int(retained_bytes or 0),
            "max_slot_wal_keep_size": max_keep,
        }

    def check_slot_safety(self, *, emit_warnings: bool = True) -> dict[str, Any]:
        health = self.get_slot_health()
        if emit_warnings:
            if health.get("max_slot_wal_keep_size") == "-1" and not self._warned_unlimited:
                self._warned_unlimited = True
                print(
                    "[reverse-proxy] warning: PostgreSQL max_slot_wal_keep_size=-1 (unlimited); "
                    "set max_slot_wal_keep_size (e.g. 1024MB) in postgresql.conf so a stopped poller cannot fill WAL disk.",
                    file=sys.stderr,
                    flush=True,
                )
            retained = int(health.get("retained_bytes") or 0)
            if (
                self.max_wal_retention_mb is not None
                and retained > self.max_wal_retention_mb * 1024 * 1024
                and not self._warned_retention
            ):
                self._warned_retention = True
                print(
                    f"[reverse-proxy] warning: WAL slot '{self.slot_name}' retaining "
                    f"{retained / (1024 * 1024):.1f} MB (threshold={self.max_wal_retention_mb} MB).",
                    file=sys.stderr,
                    flush=True,
                )
        return health

    def _get_pk_columns(self, schema: str, table: str) -> list[str]:
        key = (schema, table)
        if key not in self._pk_cache:
            try:
                t_schema = self.driver.inspect_table(table, schema)
                self._pk_cache[key] = (
                    [] if t_schema.using_rowid_fallback else list(t_schema.pk_columns)
                )
            except Exception:
                self._pk_cache[key] = []
        return self._pk_cache[key]

    def poll_once(self) -> int:
        """Fetch and process pending WAL changes once. Returns number of committed txs processed."""
        with self._poll_lock:
            return self._poll_once_locked()

    def _poll_once_locked(self) -> int:
        committed_count = 0
        rec_tables_cache: dict[str, set[tuple[str, str]]] = {}
        use_pgoutput = self.plugin == "pgoutput"
        while True:
            if use_pgoutput:
                res = self.driver._client.execute(
                    "SELECT lsn::text, xid::text, pg_catalog.encode(data, 'hex') "
                    "FROM pg_catalog.pg_logical_slot_get_binary_changes("
                    "$1, NULL, 50000, 'proto_version', '1', 'publication_names', $2, 'messages', 'true');",
                    [self.slot_name, self.publication_name],
                )
            else:
                res = self.driver._client.execute(
                    "SELECT lsn::text, xid::text, data FROM pg_catalog.pg_logical_slot_get_changes($1, NULL, 50000);",
                    [self.slot_name],
                )
            for _lsn, xid_raw, data in res.rows:
                xid = str(xid_raw)
                if use_pgoutput:
                    raw_bytes = bytes.fromhex(str(data))
                    if not raw_bytes:
                        continue
                    mtype = chr(raw_bytes[0])
                    if mtype in ("I", "U", "D"):
                        if xid in self._xid_skip:
                            continue
                        rel_id = struct.unpack_from("!I", raw_bytes, 1)[0]
                        rel = self._pgoutput_relations.get(rel_id)
                        if rel is not None:
                            if rel["schema"] == "_reverse_quarantine":
                                continue
                            t_pair = (rel["schema"], rel["table"])
                            if t_pair in self._xid_skip_tables.get(xid, ()):
                                continue
                            corr_id = self._xid_tx_map.get(xid)
                            if corr_id:
                                tbls = rec_tables_cache.get(corr_id)
                                if tbls is None:
                                    rec = self.ledger.get_record(corr_id)
                                    if rec is not None:
                                        tbls = {(op.schema or "public", op.table) for op in rec.ops}
                                        rec_tables_cache[corr_id] = tbls
                                if tbls and t_pair in tbls:
                                    continue
                    parsed = parse_pgoutput_message(raw_bytes, self._pgoutput_relations)
                else:
                    raw_data = str(data)
                    if raw_data.startswith("table "):
                        if xid in self._xid_skip:
                            continue
                        corr_id = self._xid_tx_map.get(xid)
                        if corr_id:
                            tbls = rec_tables_cache.get(corr_id)
                            if tbls is None:
                                rec = self.ledger.get_record(corr_id)
                                tbls = (
                                    {(op.schema or "public", op.table) for op in rec.ops}
                                    if rec is not None
                                    else set()
                                )
                                rec_tables_cache[corr_id] = tbls
                            if tbls:
                                colon_idx = raw_data.find(": ", 6)
                                if colon_idx != -1:
                                    schema_tbl = raw_data[6:colon_idx]
                                    dot_idx = schema_tbl.find(".")
                                    if dot_idx != -1:
                                        t_key = (schema_tbl[:dot_idx], schema_tbl[dot_idx + 1 :])
                                        if t_key in tbls:
                                            continue
                    parsed = parse_test_decoding_line(raw_data)

                if parsed is None:
                    continue
                kind = parsed["kind"]
                if kind == "begin":
                    self._xid_events.setdefault(xid, [])
                elif kind == "message" and parsed["prefix"] == "reverse_proxy":
                    try:
                        meta = json.loads(parsed["content"])
                        if meta.get("is_reverse"):
                            self._xid_skip.add(xid)
                        elif "tx_id" in meta:
                            self._xid_tx_map[xid] = str(meta["tx_id"])
                            if meta.get("table"):
                                self._xid_skip_tables.setdefault(xid, set()).add(
                                    (str(meta.get("schema") or "public"), str(meta["table"]))
                                )
                    except Exception:
                        pass
                elif kind == "dml":
                    if (
                        parsed["schema"] == "_reverse_quarantine"
                        or xid in self._xid_skip
                        or (parsed["schema"], parsed["table"]) in self._xid_skip_tables.get(xid, ())
                    ):
                        continue
                    self._xid_events.setdefault(xid, []).append(parsed)
                elif kind == "commit":
                    events = self._xid_events.pop(xid, [])
                    corr_tx_id = self._xid_tx_map.pop(xid, None)
                    self._xid_skip_tables.pop(xid, None)
                    if xid in self._xid_skip:
                        self._xid_skip.discard(xid)
                        continue
                    if events:
                        self._flush_xid(xid, corr_tx_id, events)
                        committed_count += 1
            if len(res.rows) < 50000:
                break
        return committed_count

    def _flush_xid(
        self, xid: str, corr_tx_id: str | None, events: list[dict[str, Any]]
    ) -> None:
        existing_rec = self.ledger.get_record(corr_tx_id) if corr_tx_id else None
        existing_tables = (
            {(op.schema or "public", op.table) for op in existing_rec.ops}
            if existing_rec is not None
            else set()
        )

        tx_id = corr_tx_id or new_tx_id()
        cdc = CDCIngestor(self.ledger, EngineType.POSTGRES)
        cdc.begin_marker(tx_id, session_id="wal_poller", raw_sql=f"/* WAL xid={xid} */")

        added_any = False
        for ev in events:
            tbl_key = (ev["schema"], ev["table"])
            if existing_rec is not None and tbl_key in existing_tables:
                # Primary mutation already captured by SQL proxy with exact query text
                continue
            pks = self._get_pk_columns(ev["schema"], ev["table"])
            if not pks:
                sample = ev["after"] or ev["before"] or {}
                pks = ["id"] if "id" in sample else list(sample.keys())
            cdc.ingest_event(
                CDCChangeEvent(
                    op=ev["op"],
                    table=ev["table"],
                    schema=ev["schema"],
                    pk_columns=pks,
                    before=ev["before"],
                    after=ev["after"],
                    tx_id=tx_id,
                    raw_sql=f"/* WAL trigger/side-effect on {ev['schema']}.{ev['table']} */",
                )
            )
            added_any = True

        if not added_any:
            return

        if existing_rec is not None:
            # Build MutationOps from the extra trigger events and append to existing UndoRecord!
            temp_events = cdc._pending.pop(tx_id, [])
            extra_ops: list[MutationOp] = []
            op_map = {"c": "INSERT", "u": "UPDATE", "d": "DELETE"}
            for ev in temp_events:
                op_type = op_map.get(ev.op, ev.op.upper())
                if (
                    extra_ops
                    and extra_ops[-1].op_type == op_type
                    and extra_ops[-1].table == ev.table
                    and extra_ops[-1].schema == ev.schema
                ):
                    target = extra_ops[-1]
                else:
                    target = MutationOp(
                        op_type=op_type,
                        table=ev.table,
                        schema=ev.schema,
                        pk_columns=list(ev.pk_columns),
                        column_types={},
                    )
                    extra_ops.append(target)
                if op_type == "INSERT" and ev.after is not None:
                    target.after_rows.append(dict(ev.after))
                elif op_type == "DELETE" and ev.before is not None:
                    target.before_rows.append(dict(ev.before))
                elif op_type == "UPDATE" and ev.before is not None and ev.after is not None:
                    target.before_rows.append(dict(ev.before))
                    target.after_rows.append(dict(ev.after))
            if extra_ops:
                self.ledger.append_ops(tx_id, extra_ops, warning="Captured trigger/WAL side effects.")
        else:
            cdc.commit_tx(tx_id)

    def start(self) -> None:
        self.ensure_slot()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception:
                pass
            self._stop_event.wait(self.poll_interval_sec)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
