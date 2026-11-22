"""Persistent SQLite-backed Undo Ledger with zlib compression and spill-to-disk support."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import EngineType, MutationOp, ReversibilityStatus, UndoRecord


def _encode_value(val: Any) -> Any:
    if isinstance(val, (bytes, bytearray, memoryview)):
        return {
            "__proxy_type__": "bytes_b64",
            "value": base64.b64encode(bytes(val)).decode("ascii"),
        }
    return val


def _decode_value(val: Any) -> Any:
    if isinstance(val, dict) and val.get("__proxy_type__") == "bytes_b64":
        return base64.b64decode(val["value"])
    return val


def _encode_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: _encode_value(v) for k, v in row.items()} for row in rows]


def _decode_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: _decode_value(v) for k, v in row.items()} for row in rows]


def _count_rows_affected(ops: list[MutationOp]) -> int:
    return sum(
        max(
            len(op.before_rows),
            len(op.after_rows),
            op.side_rowcount,
            1 if op.op_type.startswith(("QUARANTINE_", "ALTER_")) else 0,
        )
        for op in ops
    )


def new_tx_id() -> str:
    return f"tx_{uuid.uuid4().hex[:10]}"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class UndoLedger:
    """Thread-safe persistent append-only ledger with zlib compression and spill-to-disk."""

    def __init__(
        self,
        db_path: str = ":memory:",
        *,
        compress_threshold_bytes: int = 512,
        spill_threshold_bytes: int = 4 * 1024 * 1024,
        spill_dir: str | None = None,
    ) -> None:
        self.db_path = db_path
        self.compress_threshold_bytes = compress_threshold_bytes
        self.spill_threshold_bytes = spill_threshold_bytes
        if spill_dir is not None:
            self.spill_dir: str | None = spill_dir
        elif db_path != ":memory:":
            self.spill_dir = f"{db_path}.spill"
        else:
            self.spill_dir = None

        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            if self.db_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS undo_records (
                    seq_no INTEGER PRIMARY KEY AUTOINCREMENT,
                    tx_id TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL,
                    engine TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    raw_sql TEXT NOT NULL,
                    status TEXT NOT NULL,
                    ops_json TEXT NOT NULL DEFAULT '[]',
                    warnings_json TEXT NOT NULL,
                    reversed_at TEXT,
                    reversed_by_tx_id TEXT,
                    ops_encoding TEXT NOT NULL DEFAULT 'json',
                    ops_blob BLOB,
                    spill_path TEXT,
                    spill_sha256 TEXT,
                    rows_affected INTEGER NOT NULL DEFAULT 0,
                    actor TEXT NOT NULL DEFAULT 'anonymous',
                    durability TEXT NOT NULL DEFAULT 'durable'
                );
                """
            )
            # Migrate older ledger schemas cleanly
            existing_cols = {
                r[1] for r in self._conn.execute("PRAGMA table_info(undo_records);").fetchall()
            }
            migrations = {
                "ops_encoding": "ALTER TABLE undo_records ADD COLUMN ops_encoding TEXT NOT NULL DEFAULT 'json';",
                "ops_blob": "ALTER TABLE undo_records ADD COLUMN ops_blob BLOB;",
                "spill_path": "ALTER TABLE undo_records ADD COLUMN spill_path TEXT;",
                "spill_sha256": "ALTER TABLE undo_records ADD COLUMN spill_sha256 TEXT;",
                "rows_affected": "ALTER TABLE undo_records ADD COLUMN rows_affected INTEGER NOT NULL DEFAULT 0;",
                "actor": "ALTER TABLE undo_records ADD COLUMN actor TEXT NOT NULL DEFAULT 'anonymous';",
                "durability": "ALTER TABLE undo_records ADD COLUMN durability TEXT NOT NULL DEFAULT 'durable';",
            }
            for col, ddl in migrations.items():
                if col not in existing_cols:
                    self._conn.execute(ddl)

            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_undo_created ON undo_records(seq_no DESC);"
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS purge_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    purged_at TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT 'anonymous',
                    mode TEXT NOT NULL,
                    target TEXT,
                    records_erased INTEGER NOT NULL DEFAULT 0,
                    quarantines_dropped INTEGER NOT NULL DEFAULT 0,
                    details_json TEXT NOT NULL DEFAULT '[]'
                );
                """
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _serialize_ops(
        self, tx_id: str, ops: list[MutationOp]
    ) -> tuple[str, str, bytes | None, str | None, str | None]:
        ops_payload = [
            {
                "op_type": op.op_type,
                "table": op.table,
                "schema": op.schema,
                "pk_columns": op.pk_columns,
                "column_types": op.column_types,
                "before_rows": _encode_rows(op.before_rows),
                "after_rows": _encode_rows(op.after_rows),
                "quarantine_name": op.quarantine_name,
                "using_rowid_fallback": op.using_rowid_fallback,
                "rowid_column": op.rowid_column,
                "extra_ddl": op.extra_ddl,
                **({"rbr_fde_b64": op.rbr_fde_b64} if op.rbr_fde_b64 else {}),
                **({"rbr_undo_events": op.rbr_undo_events} if op.rbr_undo_events else {}),
                **({"side_table_before": op.side_table_before} if op.side_table_before else {}),
                **({"side_table_after": op.side_table_after} if op.side_table_after else {}),
                **({"side_rowcount": op.side_rowcount} if op.side_rowcount else {}),
                **({"phase_timings": op.phase_timings} if op.phase_timings else {}),
            }
            for op in ops
        ]
        json_str = json.dumps(ops_payload, separators=(",", ":"))
        raw_bytes = json_str.encode("utf-8")

        if len(raw_bytes) < self.compress_threshold_bytes:
            return "json", json_str, None, None, None

        compressed = zlib.compress(raw_bytes, level=6)
        if self.spill_dir is not None and len(compressed) >= self.spill_threshold_bytes:
            os.makedirs(self.spill_dir, exist_ok=True)
            spill_file = os.path.join(self.spill_dir, f"{tx_id}.undo.zlib")
            tmp_file = f"{spill_file}.{os.getpid()}.tmp"
            digest = hashlib.sha256(compressed).hexdigest()
            with open(tmp_file, "wb") as fh:
                fh.write(compressed)
                fh.flush()
            os.replace(tmp_file, spill_file)
            return "spill_zlib_json", "[]", None, spill_file, digest

        return "zlib_json", "[]", compressed, None, None

    def _deserialize_ops(self, row: sqlite3.Row) -> list[MutationOp]:
        keys = set(row.keys())
        encoding = row["ops_encoding"] if "ops_encoding" in keys else "json"
        if encoding == "json":
            ops_raw = json.loads(row["ops_json"])
        elif encoding == "zlib_json":
            ops_raw = json.loads(zlib.decompress(bytes(row["ops_blob"])).decode("utf-8"))
        elif encoding == "spill_zlib_json":
            spill_path = row["spill_path"]
            if not spill_path or not os.path.exists(spill_path):
                raise ValueError(f"Undo spill file missing for tx '{row['tx_id']}': '{spill_path}'.")
            with open(spill_path, "rb") as fh:
                compressed = fh.read()
            expected_sha = row["spill_sha256"] if "spill_sha256" in keys else None
            if expected_sha:
                actual_sha = hashlib.sha256(compressed).hexdigest()
                if actual_sha != expected_sha:
                    raise ValueError(
                        f"Undo spill file corrupted (SHA-256 mismatch) for tx '{row['tx_id']}' at '{spill_path}'."
                    )
            ops_raw = json.loads(zlib.decompress(compressed).decode("utf-8"))
        else:
            raise ValueError(f"Unsupported undo ledger encoding: {encoding}")

        return [
            MutationOp(
                op_type=item["op_type"],
                table=item["table"],
                schema=item["schema"],
                pk_columns=item["pk_columns"],
                column_types=item["column_types"],
                before_rows=_decode_rows(item["before_rows"]),
                after_rows=_decode_rows(item["after_rows"]),
                quarantine_name=item.get("quarantine_name"),
                using_rowid_fallback=item.get("using_rowid_fallback", False),
                rowid_column=item.get("rowid_column"),
                extra_ddl=item.get("extra_ddl", []),
                rbr_fde_b64=item.get("rbr_fde_b64"),
                rbr_undo_events=item.get("rbr_undo_events", []),
                side_table_before=item.get("side_table_before"),
                side_table_after=item.get("side_table_after"),
                side_rowcount=item.get("side_rowcount", 0),
                phase_timings=dict(item.get("phase_timings") or {}),
            )
            for item in ops_raw
        ]

    def record_transaction(
        self,
        *,
        tx_id: str,
        engine: EngineType,
        session_id: str,
        raw_sql: str,
        status: ReversibilityStatus,
        ops: list[MutationOp],
        warnings: list[str] | None = None,
        actor: str = "anonymous",
    ) -> UndoRecord:
        created_at = utc_now_iso()
        warnings = list(warnings or [])
        rows_affected = _count_rows_affected(ops)
        durability = "capture_pending" if any(op.side_table_before for op in ops) else "durable"
        encoding, ops_json, ops_blob, spill_path, spill_sha256 = self._serialize_ops(tx_id, ops)

        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO undo_records (
                    tx_id, created_at, engine, session_id, raw_sql,
                    status, ops_json, warnings_json,
                    ops_encoding, ops_blob, spill_path, spill_sha256, rows_affected, actor, durability
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tx_id,
                    created_at,
                    engine.value,
                    session_id,
                    raw_sql,
                    status.value,
                    ops_json,
                    json.dumps(warnings),
                    encoding,
                    ops_blob,
                    spill_path,
                    spill_sha256,
                    rows_affected,
                    actor,
                    durability,
                ),
            )
            self._conn.commit()
            seq_no = cur.lastrowid or 0

        return UndoRecord(
            tx_id=tx_id,
            seq_no=seq_no,
            created_at=created_at,
            engine=engine,
            session_id=session_id,
            raw_sql=raw_sql,
            status=status,
            ops=ops,
            warnings=warnings,
            rows_affected=rows_affected,
            actor=actor,
            durability=durability,
        )

    def _row_to_record(self, row: sqlite3.Row, *, include_ops: bool = True) -> UndoRecord:
        ops = self._deserialize_ops(row) if include_ops else []
        keys = set(row.keys())
        rows_affected = (
            row["rows_affected"]
            if "rows_affected" in keys and row["rows_affected"]
            else _count_rows_affected(ops)
        )
        actor = row["actor"] if "actor" in keys and row["actor"] else "anonymous"
        durability = row["durability"] if "durability" in keys and row["durability"] else "durable"
        return UndoRecord(
            tx_id=row["tx_id"],
            seq_no=row["seq_no"],
            created_at=row["created_at"],
            engine=EngineType(row["engine"]),
            session_id=row["session_id"],
            raw_sql=row["raw_sql"],
            status=ReversibilityStatus(row["status"]),
            ops=ops,
            warnings=json.loads(row["warnings_json"]),
            reversed_at=row["reversed_at"],
            reversed_by_tx_id=row["reversed_by_tx_id"],
            rows_affected=rows_affected,
            actor=actor,
            durability=durability,
        )

    def get_record(self, tx_id: str) -> UndoRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM undo_records WHERE tx_id = ?",
                (tx_id,),
            ).fetchone()
            return self._row_to_record(row, include_ops=True) if row else None

    def list_records(self, limit: int = 25) -> list[UndoRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM undo_records ORDER BY seq_no DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._row_to_record(r, include_ops=True) for r in rows]

    def list_quarantine_records(self, limit: int = 10000) -> list[UndoRecord]:
        """List only QUARANTINE-status records without decompressing unrelated bulk DML ops."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM undo_records WHERE status = ? ORDER BY seq_no DESC LIMIT ?",
                (ReversibilityStatus.QUARANTINE.value, limit),
            ).fetchall()
            return [self._row_to_record(r, include_ops=True) for r in rows]

    def list_summaries(self, limit: int = 25) -> list[UndoRecord]:
        """List lightweight UndoRecord summaries without decompressing row blobs."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT seq_no, tx_id, created_at, engine, session_id, raw_sql,
                       status, warnings_json, reversed_at, reversed_by_tx_id, rows_affected, actor, durability
                FROM undo_records
                ORDER BY seq_no DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [self._row_to_record(r, include_ops=False) for r in rows]

    def mark_unavailable(self, tx_id: str, reason: str) -> None:
        """Mark a transaction's undo payload as unavailable (e.g. unspilled side table lost on crash)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT warnings_json FROM undo_records WHERE tx_id = ?", (tx_id,)
            ).fetchone()
            warnings = json.loads(row["warnings_json"]) if row else []
            if reason and reason not in warnings:
                warnings.append(reason)
            self._conn.execute(
                """
                UPDATE undo_records
                SET durability = 'unavailable', warnings_json = ?
                WHERE tx_id = ?
                """,
                (json.dumps(warnings), tx_id),
            )
            self._conn.commit()

    def mark_reversed(self, tx_id: str, reversed_by_tx_id: str) -> None:
        reversed_at = utc_now_iso()
        with self._lock:
            self._conn.execute(
                """
                UPDATE undo_records
                SET status = ?, reversed_at = ?, reversed_by_tx_id = ?
                WHERE tx_id = ?
                """,
                (ReversibilityStatus.REVERSED.value, reversed_at, reversed_by_tx_id, tx_id),
            )
            self._conn.commit()

    def append_ops(
        self,
        tx_id: str,
        extra_ops: list[MutationOp],
        *,
        warning: str | None = None,
        attach_rbr: dict[tuple[str, str], tuple[str, list[str]]] | None = None,
    ) -> UndoRecord | None:
        """Append additional MutationOps (e.g. trigger side effects from WAL/binlog) to an existing record."""
        with self._lock:
            rec = self.get_record(tx_id)
            if rec is None:
                return None
            combined_ops = list(rec.ops)
            if attach_rbr:
                for op in combined_ops:
                    hit = attach_rbr.get((op.schema or "", op.table))
                    if hit is None:
                        for (sch, tbl), val in attach_rbr.items():
                            if tbl == op.table and (not op.schema or op.schema == sch):
                                hit = val
                                break
                    if hit is not None:
                        fde_b64, ev_b64s = hit
                        op.rbr_fde_b64 = op.rbr_fde_b64 or fde_b64
                        op.rbr_undo_events.extend(ev_b64s)
            combined_ops.extend(extra_ops)
            combined_warnings = list(rec.warnings)
            if warning and warning not in combined_warnings:
                combined_warnings.append(warning)
            rows_affected = _count_rows_affected(combined_ops)
            encoding, ops_json, ops_blob, spill_path, spill_sha256 = self._serialize_ops(
                tx_id, combined_ops
            )
            self._conn.execute(
                """
                UPDATE undo_records
                SET ops_json = ?, ops_encoding = ?, ops_blob = ?, spill_path = ?, spill_sha256 = ?,
                    rows_affected = ?, warnings_json = ?
                WHERE tx_id = ?
                """,
                (
                    ops_json,
                    encoding,
                    ops_blob,
                    spill_path,
                    spill_sha256,
                    rows_affected,
                    json.dumps(combined_warnings),
                    tx_id,
                ),
            )
            self._conn.commit()
            rec.ops = combined_ops
            rec.warnings = combined_warnings
            rec.rows_affected = rows_affected
            return rec

    @staticmethod
    def _unlink_spill(spill_path: str | None) -> None:
        if spill_path:
            try:
                if os.path.exists(spill_path):
                    os.unlink(spill_path)
            except OSError:
                pass

    def _collect_quarantines(self, row: sqlite3.Row) -> list[tuple[str, str | None]]:
        out: list[tuple[str, str | None]] = []
        try:
            ops = self._deserialize_ops(row)
        except Exception:
            return out
        for op in ops:
            if op.quarantine_name:
                out.append((op.quarantine_name, op.schema))
            if op.side_table_before:
                out.append((op.side_table_before, op.schema))
            if op.side_table_after:
                out.append((op.side_table_after, op.schema))
        return out

    def purge_tx(self, tx_id: str) -> tuple[bool, list[tuple[str, str | None]]]:
        """Permanently erase a single transaction record and its spill file (erasure / GDPR)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM undo_records WHERE tx_id = ?", (tx_id,)
            ).fetchone()
            if row is None:
                return False, []
            quarantines = self._collect_quarantines(row)
            spill_path = row["spill_path"] if "spill_path" in row.keys() else None
            self._conn.execute("DELETE FROM undo_records WHERE tx_id = ?", (tx_id,))
            self._conn.commit()
        self._unlink_spill(spill_path)
        return True, quarantines

    def purge_table(self, table_name: str) -> tuple[int, list[tuple[str, str | None]]]:
        """Permanently erase all undo records touching `table_name` and their spill files."""
        target = table_name.lower()
        to_delete: list[tuple[str, str | None, list[tuple[str, str | None]]]] = []
        with self._lock:
            rows = self._conn.execute("SELECT * FROM undo_records ORDER BY seq_no ASC").fetchall()
            for row in rows:
                matched = False
                quarantines: list[tuple[str, str | None]] = []
                try:
                    ops = self._deserialize_ops(row)
                    for op in ops:
                        if op.table.lower() == target:
                            matched = True
                        if op.quarantine_name:
                            quarantines.append((op.quarantine_name, op.schema))
                        if op.side_table_before:
                            quarantines.append((op.side_table_before, op.schema))
                        if op.side_table_after:
                            quarantines.append((op.side_table_after, op.schema))
                except Exception:
                    if target in str(row["raw_sql"]).lower():
                        matched = True
                if matched:
                    spill_path = row["spill_path"] if "spill_path" in row.keys() else None
                    to_delete.append((row["tx_id"], spill_path, quarantines))
            all_q: list[tuple[str, str | None]] = []
            for tx_id, _, qs in to_delete:
                self._conn.execute("DELETE FROM undo_records WHERE tx_id = ?", (tx_id,))
                all_q.extend(qs)
            if to_delete:
                self._conn.commit()
        for _, spill_path, _ in to_delete:
            self._unlink_spill(spill_path)
        return len(to_delete), all_q

    def purge_older_than(self, days: float) -> tuple[int, list[tuple[str, str | None]]]:
        """Erase undo records and spill files older than `days` days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM undo_records WHERE created_at < ?", (cutoff,)
            ).fetchall()
            all_q: list[tuple[str, str | None]] = []
            spills: list[str | None] = []
            for row in rows:
                all_q.extend(self._collect_quarantines(row))
                spills.append(row["spill_path"] if "spill_path" in row.keys() else None)
            if rows:
                self._conn.execute("DELETE FROM undo_records WHERE created_at < ?", (cutoff,))
                self._conn.commit()
        for sp in spills:
            self._unlink_spill(sp)
        return len(rows), all_q

    def materialize_side_ops(self, tx_id: str, new_ops: list[MutationOp]) -> None:
        """Persist materialized side-table rows into the durable ledger/spill file."""
        rows_affected = _count_rows_affected(new_ops)
        encoding, ops_json, ops_blob, spill_path, spill_sha256 = self._serialize_ops(
            tx_id, new_ops
        )
        with self._lock:
            self._conn.execute(
                """
                UPDATE undo_records
                SET ops_json = ?, ops_encoding = ?, ops_blob = ?, spill_path = ?, spill_sha256 = ?,
                    rows_affected = ?, durability = 'durable'
                WHERE tx_id = ?
                """,
                (
                    ops_json,
                    encoding,
                    ops_blob,
                    spill_path,
                    spill_sha256,
                    rows_affected,
                    tx_id,
                ),
            )
            self._conn.commit()

    def record_purge_event(
        self,
        *,
        actor: str,
        mode: str,
        target: str | None,
        records_erased: int,
        quarantines_dropped: int,
        details: list[str] | None = None,
    ) -> None:
        """Record who purged what and when into the append-only purge audit log."""
        purged_at = utc_now_iso()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO purge_audit_log (
                    purged_at, actor, mode, target, records_erased, quarantines_dropped, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    purged_at,
                    actor or "anonymous",
                    mode,
                    target,
                    records_erased,
                    quarantines_dropped,
                    json.dumps(list(details or [])),
                ),
            )
            self._conn.commit()

    def list_purge_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM purge_audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                {
                    "id": row["id"],
                    "purged_at": row["purged_at"],
                    "actor": row["actor"],
                    "mode": row["mode"],
                    "target": row["target"],
                    "records_erased": row["records_erased"],
                    "quarantines_dropped": row["quarantines_dropped"],
                    "details": json.loads(row["details_json"]),
                }
                for row in rows
            ]
