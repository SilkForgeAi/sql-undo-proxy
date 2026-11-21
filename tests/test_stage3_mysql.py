"""Stage 3 tests: MySQL wire frontend, MySQLWireClient, and MySQLDriver."""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
import threading
import unittest
from typing import Any

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import MySQLDriver, MySQLWireClient, SQLiteDriver
from reverse_proxy.frontends import MySQLServer
from reverse_proxy.protocols.mysql_codec import (
    CLIENT_DEPRECATE_EOF,
    COM_INIT_DB,
    COM_PING,
    COM_QUERY,
    COM_QUIT,
    SERVER_STATUS_AUTOCOMMIT,
    MySQLColumnDef,
    encode_column_definition_41,
    encode_eof_packet,
    encode_err_packet,
    encode_handshake_v10,
    encode_lenenc_int,
    encode_ok_packet,
    encode_text_row,
    frame_mysql_packet,
    infer_mysql_field_type,
    parse_handshake_response_41,
)


def _extract_tx_id(info: str) -> str:
    m = re.search(r"tx_id=(tx_[0-9a-f]+)", info)
    if not m:
        raise AssertionError(f"No tx_id found in OK info: {info!r}")
    return m.group(1)


class _ThreadedMySQLServer:
    def __init__(self, engine: ReverseProxyEngine) -> None:
        self.engine = engine
        self.loop = asyncio.new_event_loop()
        self.server = MySQLServer(engine, host="127.0.0.1", port=0)
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


class _SimulatedMySQLBackend:
    """Lightweight MySQL 8 wire backend simulating INFORMATION_SCHEMA, RENAME TABLE, `<=>`, and LAST_INSERT_ID."""

    def __init__(self, default_db: str = "app") -> None:
        self.default_db = default_db
        self.db = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
        self.databases: set[str] = {default_db}
        # table_name -> db_name
        self.table_dbs: dict[str, str] = {}
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

    def _exec_mysql_sql(self, sql: str) -> tuple[list[str], list[tuple[Any, ...]], int, int]:
        s = sql.strip().rstrip(";").strip()
        upper = s.upper()

        if upper == "SELECT DATABASE()":
            return ["DATABASE()"], [(self.default_db,)], 0, 0

        # INFORMATION_SCHEMA.TABLES
        if "INFORMATION_SCHEMA.TABLES" in upper:
            m = re.search(r"TABLE_SCHEMA\s*=\s*'([^']+)'\s+AND\s+TABLE_NAME\s*=\s*'([^']+)'", s, re.I)
            assert m is not None
            db_name, tbl_name = m.groups()
            rows = [(1,)] if self.table_dbs.get(tbl_name) == db_name else []
            return ["1"], rows, 0, 0

        # INFORMATION_SCHEMA.COLUMNS
        if "INFORMATION_SCHEMA.COLUMNS" in upper:
            m = re.search(r"TABLE_SCHEMA\s*=\s*'([^']+)'\s+AND\s+TABLE_NAME\s*=\s*'([^']+)'", s, re.I)
            assert m is not None
            db_name, tbl_name = m.groups()
            if self.table_dbs.get(tbl_name) != db_name:
                return ["COLUMN_NAME", "DATA_TYPE"], [], 0, 0
            info = self.db.execute(f'PRAGMA table_info("{tbl_name}");').fetchall()
            return ["COLUMN_NAME", "DATA_TYPE"], [(r[1], r[2] or "varchar") for r in info], 0, 0

        # INFORMATION_SCHEMA.KEY_COLUMN_USAGE
        if "INFORMATION_SCHEMA.KEY_COLUMN_USAGE" in upper:
            m = re.search(r"TABLE_SCHEMA\s*=\s*'([^']+)'\s+AND\s+TABLE_NAME\s*=\s*'([^']+)'", s, re.I)
            assert m is not None
            db_name, tbl_name = m.groups()
            if self.table_dbs.get(tbl_name) != db_name:
                return ["COLUMN_NAME"], [], 0, 0
            pks = self.table_pks.get((db_name, tbl_name), [])
            return ["COLUMN_NAME"], [(pk,) for pk in pks], 0, 0

        # CREATE DATABASE
        m_cd = re.match(r'^CREATE\s+DATABASE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([A-Za-z_0-9]+)`?$', s, re.I)
        if m_cd:
            self.databases.add(m_cd.group(1))
            return [], [], 0, 0

        # RENAME TABLE db1.t1 TO db2.t2
        m_rt = re.match(
            r'^RENAME\s+TABLE\s+`?([A-Za-z_0-9]+)`?\.`?([A-Za-z_0-9]+)`?\s+TO\s+`?([A-Za-z_0-9]+)`?\.`?([A-Za-z_0-9]+)`?$',
            s,
            re.I,
        )
        if m_rt:
            db1, t1, db2, t2 = m_rt.groups()
            if self.table_dbs.get(t1) != db1:
                raise RuntimeError(f"Unknown table '{db1}.{t1}'")
            self.db.execute(f'ALTER TABLE "{t1}" RENAME TO "{t2}";')
            self.table_dbs.pop(t1, None)
            self.table_dbs[t2] = db2
            self.table_pks[(db2, t2)] = self.table_pks.pop((db1, t1), [])
            return [], [], 0, 0

        # CREATE TABLE
        m_ct = re.match(r'^CREATE\s+TABLE\s+(?:`?([A-Za-z_0-9]+)`?\.)?`?([A-Za-z_0-9]+)`?', s, re.I)
        if m_ct:
            db_name = m_ct.group(1) or self.default_db
            tbl_name = m_ct.group(2)
            translated = s.replace("`", '"')
            translated = re.sub(r'\bAUTO_INCREMENT\b', 'AUTOINCREMENT', translated, flags=re.I)
            translated = re.sub(rf'"{re.escape(db_name)}"\.', '', translated)
            self.db.execute(translated)
            self.table_dbs[tbl_name] = db_name
            info = self.db.execute(f'PRAGMA table_info("{tbl_name}");').fetchall()
            pks = [r[1] for r in sorted((r for r in info if r[5] > 0), key=lambda x: x[5])]
            self.table_pks[(db_name, tbl_name)] = pks
            return [], [], 0, 0

        # DROP TABLE
        m_dt = re.match(r'^DROP\s+TABLE\s+(?:`?([A-Za-z_0-9]+)`?\.)?`?([A-Za-z_0-9]+)`?$', s, re.I)
        if m_dt:
            db_name = m_dt.group(1) or self.default_db
            tbl_name = m_dt.group(2)
            self.db.execute(f'DROP TABLE "{tbl_name}";')
            self.table_dbs.pop(tbl_name, None)
            self.table_pks.pop((db_name, tbl_name), None)
            return [], [], 0, 0

        # Translate MySQL idioms -> SQLite for simulation
        translated = s.replace("`", '"')
        translated = translated.replace("<=>", " IS ")
        translated = re.sub(r'\s+FOR\s+UPDATE$', '', translated, flags=re.I)
        for db_name in self.databases:
            translated = re.sub(rf'"{re.escape(db_name)}"\.', '', translated)
            translated = re.sub(rf'\b{re.escape(db_name)}\.', '', translated)
        # Handle ON DUPLICATE KEY UPDATE -> ON CONFLICT DO UPDATE (single PK simulation)
        if "ON DUPLICATE KEY UPDATE" in translated.upper():
            m_odku = re.search(r'\bON\s+DUPLICATE\s+KEY\s+UPDATE\s+(.*)$', translated, re.I | re.S)
            if m_odku:
                prefix = translated[: m_odku.start()].rstrip()
                upd_part = re.sub(r'VALUES\(("[^"]+"|[A-Za-z_0-9]+)\)', r'excluded.\1', m_odku.group(1), flags=re.I)
                # Find table name
                m_ins = re.match(r'^INSERT\s+INTO\s+"?([A-Za-z_0-9]+)"?', prefix, re.I)
                pks = self.table_pks.get((self.default_db, m_ins.group(1)), ["id"]) if m_ins else ["id"]
                pk_str = ", ".join(f'"{p}"' for p in pks)
                translated = f"{prefix} ON CONFLICT ({pk_str}) DO UPDATE SET {upd_part}"

        # Track whether INSERT omitted explicit PK for simulated multi-row LAST_INSERT_ID
        is_insert = upper.startswith("INSERT")
        prev_max_rowid = 0
        if is_insert:
            m_ins = re.match(r'^INSERT\s+INTO\s+"?([A-Za-z_0-9]+)"?', translated, re.I)
            if m_ins:
                tbl = m_ins.group(1)
                row = self.db.execute(f'SELECT COALESCE(MAX(rowid), 0) FROM "{tbl}";').fetchone()
                prev_max_rowid = row[0] if row else 0

        cur = self.db.execute(translated)
        if cur.description:
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()
            return cols, rows, len(rows), 0

        affected = cur.rowcount if cur.rowcount >= 0 else 0
        last_id = 0
        if is_insert and affected > 0:
            # MySQL LAST_INSERT_ID() returns the FIRST generated ID of a multi-row insert
            last_id = prev_max_rowid + 1 if affected > 1 else (cur.lastrowid or 0)
        return [], [], affected, last_id

    async def _read_packet(self, reader: asyncio.StreamReader) -> tuple[int, bytes]:
        header = await reader.readexactly(4)
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        seq_id = header[3]
        payload = await reader.readexactly(length) if length > 0 else b""
        return seq_id, payload

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            hs = encode_handshake_v10(conn_id=1, scramble=os.urandom(20))
            writer.write(frame_mysql_packet(hs, seq_id=0))
            await writer.drain()

            seq, resp = await self._read_packet(reader)
            hs_resp = parse_handshake_response_41(resp)
            deprecate_eof = bool(hs_resp["client_flags"] & CLIENT_DEPRECATE_EOF)
            writer.write(frame_mysql_packet(encode_ok_packet(), seq_id=seq + 1))
            await writer.drain()

            while True:
                try:
                    seq, payload = await self._read_packet(reader)
                except asyncio.IncompleteReadError:
                    break
                cmd = payload[0]
                nseq = seq + 1
                if cmd == COM_QUIT:
                    break
                if cmd in (COM_PING, COM_INIT_DB):
                    writer.write(frame_mysql_packet(encode_ok_packet(), seq_id=nseq))
                    await writer.drain()
                    continue
                if cmd == COM_QUERY:
                    sql = payload[1:].decode("utf-8")
                    try:
                        cols, rows, affected, last_id = self._exec_mysql_sql(sql)
                    except Exception as exc:
                        writer.write(frame_mysql_packet(encode_err_packet(str(exc)), seq_id=nseq))
                        await writer.drain()
                        continue
                    if not cols:
                        writer.write(
                            frame_mysql_packet(
                                encode_ok_packet(affected_rows=affected, last_insert_id=last_id),
                                seq_id=nseq,
                            )
                        )
                        await writer.drain()
                        continue
                    writer.write(frame_mysql_packet(encode_lenenc_int(len(cols)), seq_id=nseq))
                    nseq += 1
                    for idx, name in enumerate(cols):
                        cd = MySQLColumnDef(name=name, field_type=infer_mysql_field_type(rows, idx))
                        writer.write(frame_mysql_packet(encode_column_definition_41(cd), seq_id=nseq))
                        nseq += 1
                    if not deprecate_eof:
                        writer.write(frame_mysql_packet(encode_eof_packet(), seq_id=nseq))
                        nseq += 1
                    for r in rows:
                        writer.write(frame_mysql_packet(encode_text_row(r), seq_id=nseq))
                        nseq += 1
                    if deprecate_eof:
                        writer.write(frame_mysql_packet(encode_ok_packet(header_byte=0xFE), seq_id=nseq))
                    else:
                        writer.write(frame_mysql_packet(encode_eof_packet(), seq_id=nseq))
                    await writer.drain()
        except (asyncio.IncompleteReadError, EOFError, ConnectionResetError):
            pass
        finally:
            writer.close()


class TestStage3MySQLFrontend(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SQLiteDriver(":memory:")
        self.ledger = UndoLedger(":memory:")
        self.engine = ReverseProxyEngine(self.driver, self.ledger)
        self.srv = _ThreadedMySQLServer(self.engine)
        self.srv.start()
        self.client = MySQLWireClient(host="127.0.0.1", port=self.srv.port, user="root", database="app")

    def tearDown(self) -> None:
        self.client.close()
        self.srv.stop()
        self.driver.close()
        self.ledger.close()

    def test_mysql_frontend_dml_tx_status_and_proxy_reverse(self) -> None:
        self.client.ping()
        self.client.query("CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT, price REAL);")

        ins = self.client.query(
            "INSERT INTO products (id, sku, price) VALUES (1, 'SKU-A', 19.5), (2, 'SKU-B', 30.0);"
        )
        self.assertEqual(ins.affected_rows, 2)
        tx_ins = _extract_tx_id(ins.info)

        upd = self.client.query("UPDATE products SET price = 99.0 WHERE id = 1;")
        tx_upd = _extract_tx_id(upd.info)

        sel = self.client.query("SELECT id, sku, price FROM products ORDER BY id;")
        self.assertEqual(sel.columns, ["id", "sku", "price"])
        self.assertEqual(sel.rows, [(1, "SKU-A", 99.0), (2, "SKU-B", 30.0)])

        # Reverse UPDATE over MySQL wire
        rev = self.client.query(f"PROXY REVERSE {tx_upd};")
        self.assertEqual(rev.columns[0], "step_no")
        self.assertEqual(self.client.query("SELECT price FROM products WHERE id = 1;").rows, [(19.5,)])

        # Explicit transaction tracking over MySQL wire
        self.client.query("BEGIN;")
        self.assertTrue(self.client.server_status & 0x0001)
        self.client.query("DELETE FROM products WHERE id = 2;")
        self.client.query("ROLLBACK;")
        self.assertFalse(self.client.server_status & 0x0001)
        self.assertEqual(self.client.query("SELECT COUNT(*) FROM products;").rows, [(2,)])

        # Reverse initial INSERT
        self.client.query(f"PROXY REVERSE {tx_ins};")
        self.assertEqual(self.client.query("SELECT COUNT(*) FROM products;").rows, [(0,)])


class TestStage3MySQLDriver(unittest.TestCase):
    def test_mysql_driver_autoincrement_explicit_pk_update_delete_quarantine_drift(self) -> None:
        backend = _SimulatedMySQLBackend(default_db="app")
        backend.start()
        driver = MySQLDriver(host="127.0.0.1", port=backend.port, user="root", database="app")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)

        try:
            engine.execute(
                "CREATE TABLE `app`.`users` (id INTEGER PRIMARY KEY AUTO_INCREMENT, name TEXT, email TEXT);"
            )
            # Multi-row auto-increment INSERT (no RETURNING in MySQL)
            tx_auto = engine.execute_one(
                "INSERT INTO `users` (`name`, `email`) VALUES ('Alice', 'a@x.io'), ('Bob', NULL);"
            ).tx_id
            self.assertEqual(
                engine.execute_one("SELECT id, name, email FROM `users` ORDER BY id;").rows,
                [(1, "Alice", "a@x.io"), (2, "Bob", None)],
            )

            # Explicit PK INSERT
            tx_exp = engine.execute_one(
                "INSERT INTO `users` (`id`, `name`, `email`) VALUES (10, 'Carol', 'c@x.io');"
            ).tx_id

            # UPDATE + NULL-safe drift detection
            tx_upd = engine.execute_one(
                "UPDATE `users` SET `email` = 'bob@x.io' WHERE `id` = 2;"
            ).tx_id
            self.assertEqual(
                engine.execute_one("SELECT email FROM `users` WHERE id = 2;").rows,
                [("bob@x.io",)],
            )

            # Reverse UPDATE cleanly
            self.assertTrue(engine.reverse(tx_upd).success)
            self.assertEqual(
                engine.execute_one("SELECT email FROM `users` WHERE id = 2;").rows,
                [(None,)],
            )

            # DELETE + reverse
            tx_del = engine.execute_one("DELETE FROM `users` WHERE `id` = 10;").tx_id
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM `users`;").rows, [(2,)])
            self.assertTrue(engine.reverse(tx_del).success)
            self.assertEqual(
                engine.execute_one("SELECT id, name FROM `users` WHERE id = 10;").rows,
                [(10, "Carol")],
            )

            # Drift block + FORCE override
            engine.execute_one("UPDATE `users` SET `name` = 'Carol-Edited' WHERE `id` = 10;")
            blocked = engine.reverse(tx_exp)
            self.assertFalse(blocked.success)
            self.assertEqual(blocked.conflicts[0].column, "name")
            self.assertTrue(engine.reverse(tx_exp, force=True).success)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM `users`;").rows, [(2,)])

            # DROP TABLE quarantine + restore
            tx_drop = engine.execute_one("DROP TABLE `users`;").tx_id
            self.assertFalse(driver._table_exists("users", "app"))
            self.assertTrue(engine.reverse(tx_drop).success)
            self.assertTrue(driver._table_exists("users", "app"))
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM `users`;").rows, [(2,)])

            # Reverse auto-increment multi-row INSERT
            self.assertTrue(engine.reverse(tx_auto).success)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM `users`;").rows, [(0,)])
        finally:
            driver.close()
            ledger.close()
            backend.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
