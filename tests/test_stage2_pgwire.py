"""Stage 2 tests: pgwire v3 Server, pgwire Client (Simple + Extended Query + Auth), and PostgresDriver."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import re
import sqlite3
import struct
import threading
import unittest
from typing import Any

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import PgError, PgWireClient, PostgresDriver, SQLiteDriver
from reverse_proxy.frontends import PgWireServer
from reverse_proxy.protocols.pgwire_codec import (
    OID_INT4,
    OID_TEXT,
    PG_PROTOCOL_V3,
    SSL_REQUEST_CODE,
    PgColumnDesc,
    decode_pg_text_value,
    encode_auth_md5,
    encode_auth_ok,
    encode_auth_sasl,
    encode_auth_sasl_continue,
    encode_auth_sasl_final,
    encode_backend_key_data,
    encode_bind_complete,
    encode_close_complete,
    encode_command_complete,
    encode_data_row,
    encode_error_response,
    encode_no_data,
    encode_parameter_description,
    encode_parameter_status,
    encode_parse_complete,
    encode_ready_for_query,
    encode_row_description,
    infer_pg_oid,
    parse_bind_payload,
    parse_close_or_describe_payload,
    parse_parse_payload,
    parse_startup_params,
    pg_placeholders_to_sqlite,
)


def _extract_tx_id(notices: list[str]) -> str:
    for n in notices:
        m = re.search(r"tx_id=(tx_[0-9a-f]+)", n)
        if m:
            return m.group(1)
    raise AssertionError(f"No tx_id found in notices: {notices}")


class _ThreadedPgWireServer:
    """Runs an asyncio PgWireServer in a background thread for synchronous socket tests."""

    def __init__(self, engine: ReverseProxyEngine) -> None:
        self.engine = engine
        self.loop = asyncio.new_event_loop()
        self.server = PgWireServer(engine, host="127.0.0.1", port=0)
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.start())
        self._ready.set()
        try:
            self.loop.run_forever()
        finally:
            self.loop.run_until_complete(self.server.stop())
            self.loop.close()

    @property
    def port(self) -> int:
        return self.server.bound_port

    def start(self) -> None:
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(timeout=5.0)


class _SimulatedPostgresBackend:
    """
    Lightweight pgwire v3 backend simulating PostgreSQL catalog & SQL behaviors
    (SCRAM-SHA-256/MD5 auth, pg_catalog, to_regclass, FOR UPDATE, IS NOT DISTINCT FROM,
    CREATE SCHEMA / SET SCHEMA) over TCP so PostgresDriver can be exercised end-to-end.
    """

    def __init__(self, auth_mode: str = "trust", password: str = "secret") -> None:
        self.auth_mode = auth_mode
        self.password = password
        self.db = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
        self.schemas: set[str] = {"public"}
        # Track table schemas: table_name -> schema_name
        self.table_schemas: dict[str, str] = {}
        # Track primary keys in order: (schema, table) -> list[str]
        self.table_pks: dict[tuple[str, str], list[str]] = {}

        self.loop = asyncio.new_event_loop()
        self._server: asyncio.AbstractServer | None = None
        self._port = 0
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> None:
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(timeout=5.0)
        self.db.close()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._start_srv())
        self._ready.set()
        try:
            self.loop.run_forever()
        finally:
            if self._server is not None:
                self._server.close()
                self.loop.run_until_complete(self._server.wait_closed())
            self.loop.close()

    async def _start_srv(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self._port = self._server.sockets[0].getsockname()[1]

    def _exec_pg_sql(self, sql: str, params: list[Any]) -> tuple[list[str], list[tuple[Any, ...]], str]:
        s = sql.strip().rstrip(";").strip()
        upper = s.upper()

        # 1. to_regclass($1)::text
        if "TO_REGCLASS(" in upper:
            target = str(params[0])
            if "." in target:
                sch, tbl = target.split(".", 1)
            else:
                sch, tbl = "public", target
            sch = sch.strip('"')
            tbl = tbl.strip('"')
            exists = self.table_schemas.get(tbl) == sch
            return ["to_regclass"], [(f"{sch}.{tbl}" if exists else None,)], "SELECT 1"

        # 2. pg_attribute column query
        if "PG_CATALOG.PG_ATTRIBUTE" in upper and "FORMAT_TYPE" in upper:
            sch, tbl = str(params[0]), str(params[1])
            if self.table_schemas.get(tbl) != sch:
                return ["attname", "format_type"], [], "SELECT 0"
            rows = self.db.execute(f'PRAGMA table_info("{tbl}");').fetchall()
            out = [(r[1], r[2] or "text") for r in rows]
            return ["attname", "format_type"], out, f"SELECT {len(out)}"

        # 3. pg_index PK query
        if "PG_CATALOG.PG_INDEX" in upper and "INDISPRIMARY" in upper:
            sch, tbl = str(params[0]), str(params[1])
            if self.table_schemas.get(tbl) != sch:
                return ["attname"], [], "SELECT 0"
            pks = self.table_pks.get((sch, tbl), [])
            return ["attname"], [(pk,) for pk in pks], f"SELECT {len(pks)}"

        # 3b. pg_indexes / pg_depend queries
        if "PG_CATALOG.PG_INDEXES" in upper:
            return ["indexname"], [], "SELECT 0"
        if "PG_CATALOG.PG_DEPEND" in upper:
            return ["relname"], [], "SELECT 0"

        # 4. CREATE SCHEMA IF NOT EXISTS
        m_cs = re.match(r'^CREATE\s+SCHEMA\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([A-Za-z_0-9]+)"?$', s, re.I)
        if m_cs:
            self.schemas.add(m_cs.group(1))
            return [], [], "CREATE SCHEMA"

        # 5. ALTER TABLE schema.tbl SET SCHEMA new_schema
        m_ss = re.match(
            r'^ALTER\s+TABLE\s+"?([A-Za-z_0-9]+)"?\."?([A-Za-z_0-9]+)"?\s+SET\s+SCHEMA\s+"?([A-Za-z_0-9]+)"?$',
            s,
            re.I,
        )
        if m_ss:
            old_sch, tbl, new_sch = m_ss.groups()
            if self.table_schemas.get(tbl) != old_sch:
                raise RuntimeError(f'table "{old_sch}.{tbl}" does not exist')
            self.table_schemas[tbl] = new_sch
            self.table_pks[(new_sch, tbl)] = self.table_pks.pop((old_sch, tbl), [])
            return [], [], "ALTER TABLE"

        # 6. ALTER TABLE schema.tbl RENAME TO new_tbl
        m_rn = re.match(
            r'^ALTER\s+TABLE\s+"?([A-Za-z_0-9]+)"?\."?([A-Za-z_0-9]+)"?\s+RENAME\s+TO\s+"?([A-Za-z_0-9]+)"?$',
            s,
            re.I,
        )
        if m_rn:
            sch, old_tbl, new_tbl = m_rn.groups()
            self.db.execute(f'ALTER TABLE "{old_tbl}" RENAME TO "{new_tbl}";')
            self.table_schemas.pop(old_tbl, None)
            self.table_schemas[new_tbl] = sch
            self.table_pks[(sch, new_tbl)] = self.table_pks.pop((sch, old_tbl), [])
            return [], [], "ALTER TABLE"

        # 7. DROP TABLE schema.tbl
        m_dt = re.match(r'^DROP\s+TABLE\s+"?([A-Za-z_0-9]+)"?\."?([A-Za-z_0-9]+)"?$', s, re.I)
        if m_dt:
            sch, tbl = m_dt.groups()
            self.db.execute(f'DROP TABLE "{tbl}";')
            self.table_schemas.pop(tbl, None)
            self.table_pks.pop((sch, tbl), None)
            return [], [], "DROP TABLE"

        # 8. Track CREATE TABLE schema & PKs
        m_ct = re.match(r'^CREATE\s+TABLE\s+(?:"?([A-Za-z_0-9]+)"?\.)?"?([A-Za-z_0-9]+)"?', s, re.I)
        if m_ct:
            sch = m_ct.group(1) or "public"
            tbl = m_ct.group(2)
            # Strip schema prefix for SQLite execution
            sqlite_sql = re.sub(rf'"?{re.escape(sch)}"?\."?{re.escape(tbl)}"?', f'"{tbl}"', s, count=1)
            self.db.execute(sqlite_sql)
            self.table_schemas[tbl] = sch
            info = self.db.execute(f'PRAGMA table_info("{tbl}");').fetchall()
            pks = [r[1] for r in sorted((r for r in info if r[5] > 0), key=lambda x: x[5])]
            self.table_pks[(sch, tbl)] = pks
            return [], [], "CREATE TABLE"

        # Rewrite Postgres idioms to SQLite equivalents for backend simulation
        translated = pg_placeholders_to_sqlite(s)
        translated = re.sub(r'\bIS\s+NOT\s+DISTINCT\s+FROM\b', 'IS', translated, flags=re.I)
        translated = re.sub(r'\s+FOR\s+UPDATE$', '', translated, flags=re.I)
        # Strip explicit "public." / "_reverse_quarantine." prefixes on table refs
        for sch in self.schemas:
            translated = re.sub(rf'"{re.escape(sch)}"\.', '', translated)
            translated = re.sub(rf'\b{re.escape(sch)}\.', '', translated)

        cur = self.db.execute(translated, params)
        if cur.description:
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            tag = f"SELECT {len(rows)}"
            if upper.startswith("INSERT"):
                tag = f"INSERT 0 {len(rows)}"
            elif upper.startswith("UPDATE"):
                tag = f"UPDATE {len(rows)}"
            elif upper.startswith("DELETE"):
                tag = f"DELETE {len(rows)}"
            return cols, rows, tag

        rc = cur.rowcount if cur.rowcount >= 0 else 0
        if upper.startswith("BEGIN"):
            return [], [], "BEGIN"
        if upper.startswith("COMMIT"):
            return [], [], "COMMIT"
        if upper.startswith("ROLLBACK"):
            return [], [], "ROLLBACK"
        return [], [], f"OK {rc}"

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        prepared: dict[str, str] = {}
        portals: dict[str, tuple[str, list[Any]]] = {}
        try:
            raw_len = await reader.readexactly(4)
            length = struct.unpack("!I", raw_len)[0]
            body = await reader.readexactly(length - 4)
            code = struct.unpack("!I", body[:4])[0]
            if code == SSL_REQUEST_CODE:
                writer.write(b"N")
                await writer.drain()
                raw_len = await reader.readexactly(4)
                length = struct.unpack("!I", raw_len)[0]
                body = await reader.readexactly(length - 4)
                code = struct.unpack("!I", body[:4])[0]
            if code != PG_PROTOCOL_V3:
                return
            params = parse_startup_params(body[4:])
            user = params.get("user", "postgres")

            # Auth handshake
            if self.auth_mode == "md5":
                salt = b"\x01\x02\x03\x04"
                writer.write(encode_auth_md5(salt))
                await writer.drain()
                h = await reader.readexactly(5)
                plen = struct.unpack("!I", h[1:5])[0] - 4
                pmsg = (await reader.readexactly(plen)).rstrip(b"\x00").decode("utf-8")
                inner = hashlib.md5((self.password + user).encode("utf-8")).hexdigest()
                expected = "md5" + hashlib.md5(inner.encode("ascii") + salt).hexdigest()
                if pmsg != expected:
                    writer.write(encode_error_response("password authentication failed", sqlstate="28P01"))
                    await writer.drain()
                    return
            elif self.auth_mode == "scram":
                writer.write(encode_auth_sasl(["SCRAM-SHA-256"]))
                await writer.drain()
                h = await reader.readexactly(5)
                plen = struct.unpack("!I", h[1:5])[0] - 4
                pmsg = await reader.readexactly(plen)
                nul = pmsg.find(b"\x00")
                init_len = struct.unpack_from("!i", pmsg, nul + 1)[0]
                client_first = pmsg[nul + 5 : nul + 5 + init_len].decode("utf-8")
                client_first_bare = client_first[3:]
                c_nonce = dict(x.split("=", 1) for x in client_first_bare.split(","))["r"]
                s_nonce = c_nonce + "srv999"
                salt = b"saltsalt"
                iters = 4096
                srv_first = f"r={s_nonce},s={base64.b64encode(salt).decode('ascii')},i={iters}"
                writer.write(encode_auth_sasl_continue(srv_first.encode("utf-8")))
                await writer.drain()

                h = await reader.readexactly(5)
                plen = struct.unpack("!I", h[1:5])[0] - 4
                client_final = (await reader.readexactly(plen)).decode("utf-8")
                cf_parts = dict(x.split("=", 1) for x in client_final.split(","))
                salted_pw = hashlib.pbkdf2_hmac("sha256", self.password.encode("utf-8"), salt, iters)
                client_key = hmac.new(salted_pw, b"Client Key", hashlib.sha256).digest()
                stored_key = hashlib.sha256(client_key).digest()
                auth_msg = f"{client_first_bare},{srv_first},c=biws,r={s_nonce}".encode("utf-8")
                c_sig = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
                expected_proof = bytes(a ^ b for a, b in zip(client_key, c_sig))
                if base64.b64decode(cf_parts["p"]) != expected_proof:
                    writer.write(encode_error_response("SCRAM auth failed", sqlstate="28P01"))
                    await writer.drain()
                    return
                srv_key = hmac.new(salted_pw, b"Server Key", hashlib.sha256).digest()
                srv_sig = hmac.new(srv_key, auth_msg, hashlib.sha256).digest()
                writer.write(
                    encode_auth_sasl_final(f"v={base64.b64encode(srv_sig).decode('ascii')}".encode("utf-8"))
                )
                await writer.drain()

            writer.write(encode_auth_ok())
            writer.write(encode_parameter_status("server_version", "16.0"))
            writer.write(encode_backend_key_data(1, 1))
            writer.write(encode_ready_for_query("I"))
            await writer.drain()

            while True:
                try:
                    header = await reader.readexactly(5)
                except asyncio.IncompleteReadError:
                    break
                mtype = chr(header[0])
                mlen = struct.unpack("!I", header[1:5])[0] - 4
                payload = await reader.readexactly(mlen) if mlen > 0 else b""
                if mtype == "X":
                    break
                if mtype == "Q":
                    sql = payload.rstrip(b"\x00").decode("utf-8")
                    try:
                        cols, rows, tag = self._exec_pg_sql(sql, [])
                        if cols:
                            descs = [PgColumnDesc(c, type_oid=infer_pg_oid(rows, i)) for i, c in enumerate(cols)]
                            writer.write(encode_row_description(descs))
                            for r in rows:
                                writer.write(encode_data_row(r))
                        writer.write(encode_command_complete(tag))
                    except Exception as exc:
                        writer.write(encode_error_response(str(exc)))
                    writer.write(encode_ready_for_query("I"))
                    await writer.drain()
                elif mtype == "P":
                    sname, q, _ = parse_parse_payload(payload)
                    prepared[sname] = q
                    writer.write(encode_parse_complete())
                elif mtype == "B":
                    pname, sname, _, pvals, _ = parse_bind_payload(payload)
                    decoded = [decode_pg_text_value(v, OID_TEXT) for v in pvals]
                    portals[pname] = (prepared[sname], decoded)
                    writer.write(encode_bind_complete())
                elif mtype == "D":
                    ttype, name = parse_close_or_describe_payload(payload)
                    if ttype == "S":
                        writer.write(encode_parameter_description([]))
                        writer.write(encode_no_data())
                    else:
                        sql, p = portals[name]
                        try:
                            cols, rows, tag = self._exec_pg_sql(sql, p)
                            portals[name] = ("__CACHED__", [(cols, rows, tag)])
                            if cols:
                                descs = [PgColumnDesc(c, type_oid=infer_pg_oid(rows, i)) for i, c in enumerate(cols)]
                                writer.write(encode_row_description(descs))
                            else:
                                writer.write(encode_no_data())
                        except Exception as exc:
                            writer.write(encode_error_response(str(exc)))
                elif mtype == "E":
                    sql_or_flag, data = portals[""]
                    if sql_or_flag == "__CACHED__":
                        cols, rows, tag = data[0]
                    else:
                        cols, rows, tag = self._exec_pg_sql(sql_or_flag, data)
                    for r in rows:
                        writer.write(encode_data_row(r))
                    writer.write(encode_command_complete(tag))
                elif mtype == "C":
                    writer.write(encode_close_complete())
                elif mtype == "S":
                    writer.write(encode_ready_for_query("I"))
                    await writer.drain()
        except (asyncio.IncompleteReadError, EOFError, ConnectionResetError):
            pass
        finally:
            writer.close()


class TestStage2PgWireFrontend(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SQLiteDriver(":memory:")
        self.ledger = UndoLedger(":memory:")
        self.engine = ReverseProxyEngine(self.driver, self.ledger)
        self.srv = _ThreadedPgWireServer(self.engine)
        self.srv.start()
        self.client = PgWireClient(host="127.0.0.1", port=self.srv.port, user="alice", database="app")

    def tearDown(self) -> None:
        self.client.close()
        self.srv.stop()
        self.driver.close()
        self.ledger.close()

    def test_simple_query_over_pgwire_and_proxy_reverse(self) -> None:
        self.client.query("CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner TEXT, balance INTEGER);")
        ins = self.client.query("INSERT INTO accounts (id, owner, balance) VALUES (1, 'Alice', 100), (2, 'Bob', 50);")[0]
        tx_ins = _extract_tx_id(ins.notices)

        upd = self.client.query("UPDATE accounts SET balance = balance - 30 WHERE id = 1;")[0]
        tx_upd = _extract_tx_id(upd.notices)

        sel = self.client.query("SELECT id, owner, balance FROM accounts ORDER BY id;")[0]
        self.assertEqual(sel.columns, ["id", "owner", "balance"])
        self.assertEqual(sel.rows, [(1, "Alice", 70), (2, "Bob", 50)])

        # Reverse UPDATE right over the Postgres wire!
        rev = self.client.query(f"PROXY REVERSE {tx_upd};")[0]
        self.assertEqual(rev.command_tag, "PROXY REVERSE OK")
        self.assertEqual(
            self.client.query("SELECT balance FROM accounts WHERE id = 1;")[0].rows,
            [(100,)],
        )

        # PROXY HISTORY over pgwire
        hist = self.client.query("PROXY HISTORY LIMIT 5;")[0]
        self.assertEqual(hist.columns[0], "tx_id")
        self.assertEqual(len(hist.rows), 2)

        # Reverse INSERT too
        self.client.query(f"PROXY REVERSE {tx_ins};")
        self.assertEqual(self.client.query("SELECT COUNT(*) FROM accounts;")[0].rows, [(0,)])

    def test_extended_query_protocol_parameterized_mutations_and_reverse(self) -> None:
        self.client.query("CREATE TABLE items (id INTEGER PRIMARY KEY, title TEXT, qty INTEGER);")

        ins = self.client.execute(
            "INSERT INTO items (id, title, qty) VALUES ($1, $2, $3);",
            [10, "Keyboard", 5],
        )
        tx_ins = _extract_tx_id(ins.notices)

        upd = self.client.execute(
            "UPDATE items SET qty = $1 WHERE id = $2;",
            [12, 10],
        )
        tx_upd = _extract_tx_id(upd.notices)

        sel = self.client.execute("SELECT id, title, qty FROM items WHERE id = $1;", [10])
        self.assertEqual(sel.rows, [(10, "Keyboard", 12)])

        # Reverse parameterized UPDATE
        self.client.query(f"PROXY REVERSE {tx_upd};")
        self.assertEqual(
            self.client.execute("SELECT qty FROM items WHERE id = $1;", [10]).rows,
            [(5,)],
        )

        # Reverse parameterized INSERT
        self.client.query(f"PROXY REVERSE {tx_ins};")
        self.assertEqual(self.client.query("SELECT COUNT(*) FROM items;")[0].rows, [(0,)])

    def test_explicit_transaction_tx_status_and_rollback_over_pgwire(self) -> None:
        self.client.query("CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT);")
        self.assertEqual(self.client.tx_status, "I")

        self.client.query("BEGIN;")
        self.assertEqual(self.client.tx_status, "T")
        self.client.query("INSERT INTO logs (id, msg) VALUES (1, 'ephemeral');")
        self.client.query("ROLLBACK;")
        self.assertEqual(self.client.tx_status, "I")
        self.assertEqual(self.client.query("SELECT COUNT(*) FROM logs;")[0].rows, [(0,)])
        self.assertEqual(len(self.client.query("PROXY HISTORY;")[0].rows), 0)


class TestStage2PostgresDriver(unittest.TestCase):
    def test_pgwire_client_md5_and_scram_sha256_auth(self) -> None:
        for mode in ("md5", "scram"):
            backend = _SimulatedPostgresBackend(auth_mode=mode, password="s3cr3t-password")
            backend.start()
            try:
                client = PgWireClient(
                    host="127.0.0.1",
                    port=backend.port,
                    user="postgres",
                    password="s3cr3t-password",
                )
                self.assertEqual(client.query("SELECT 1 AS ok;")[0].rows, [(1,)])
                client.close()

                with self.assertRaises(PgError):
                    PgWireClient(
                        host="127.0.0.1",
                        port=backend.port,
                        user="postgres",
                        password="wrong-password",
                    )
            finally:
                backend.stop()

    def test_postgres_driver_end_to_end_dml_quarantine_and_drift(self) -> None:
        backend = _SimulatedPostgresBackend(auth_mode="scram", password="pgpass")
        backend.start()
        driver = PostgresDriver(
            host="127.0.0.1",
            port=backend.port,
            user="postgres",
            password="pgpass",
            database="postgres",
        )
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)

        try:
            engine.execute(
                "CREATE TABLE public.orders (id INTEGER PRIMARY KEY, item TEXT, amount INTEGER);"
            )
            tx_ins = engine.execute_one(
                "INSERT INTO public.orders (id, item, amount) VALUES (1, 'Laptop', 1200), (2, 'Mouse', 40);"
            ).tx_id
            tx_upd = engine.execute_one(
                "UPDATE public.orders SET amount = 999 WHERE id = 1;"
            ).tx_id
            tx_del = engine.execute_one(
                "DELETE FROM public.orders WHERE id = 2;"
            ).tx_id

            # Reverse DELETE
            self.assertTrue(engine.reverse(tx_del).success)
            self.assertEqual(
                engine.execute_one("SELECT id, item, amount FROM public.orders ORDER BY id;").rows,
                [(1, "Laptop", 999), (2, "Mouse", 40)],
            )

            # Create drift on row 1, verify safe reverse blocks, then FORCE
            engine.execute_one("UPDATE public.orders SET amount = 1500 WHERE id = 1;")
            blocked = engine.reverse(tx_upd)
            self.assertFalse(blocked.success)
            self.assertEqual(blocked.conflicts[0].column, "amount")
            self.assertTrue(engine.reverse(tx_upd, force=True).success)
            self.assertEqual(
                engine.execute_one("SELECT amount FROM public.orders WHERE id = 1;").rows,
                [(1200,)],
            )

            # Quarantined DROP TABLE + restore back into `public` schema
            tx_drop = engine.execute_one("DROP TABLE public.orders;").tx_id
            self.assertFalse(driver._table_exists("orders", "public"))
            self.assertTrue(engine.reverse(tx_drop).success)
            self.assertTrue(driver._table_exists("orders", "public"))
            self.assertEqual(
                engine.execute_one("SELECT COUNT(*) FROM public.orders;").rows,
                [(2,)],
            )

            # Reverse original INSERT (force=True since row 1 was touched & row 2 was re-inserted)
            self.assertTrue(engine.reverse(tx_ins, force=True).success)
            self.assertEqual(
                engine.execute_one("SELECT COUNT(*) FROM public.orders;").rows,
                [(0,)],
            )
        finally:
            driver.close()
            ledger.close()
            backend.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
