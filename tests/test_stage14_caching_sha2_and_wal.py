"""Stage 14 tests: MySQL caching_sha2_password auth, WAL test_decoding parser, and ledger append_ops."""

from __future__ import annotations

import asyncio
import threading
import unittest

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import MySQLError, MySQLWireClient, SQLiteDriver
from reverse_proxy.frontends import MySQLServer
from reverse_proxy.models import MutationOp
from reverse_proxy.protocols.mysql_codec import (
    caching_sha2_password_scramble,
    encode_handshake_response_41,
    parse_handshake_response_41,
)
from reverse_proxy.wal_poller import parse_test_decoding_line


class TestStage14CachingSha2AndWAL(unittest.TestCase):
    def test_caching_sha2_password_scramble_and_mysql_server_auth(self) -> None:
        nonce = b"12345678901234567890"
        tok = caching_sha2_password_scramble("pw", nonce)
        self.assertEqual(len(tok), 32)

        resp_pkt = encode_handshake_response_41(
            username="alice",
            auth_response=tok,
            database="app",
            auth_plugin="caching_sha2_password",
        )
        parsed = parse_handshake_response_41(resp_pkt)
        self.assertEqual(parsed["auth_plugin"], "caching_sha2_password")
        self.assertEqual(parsed["auth_response"], tok)

        # Verify MySQLServer accepts caching_sha2_password responses when auth_users is set
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        srv = MySQLServer(engine, port=0, auth_users={"alice": "secret-sha2"})
        loop = asyncio.new_event_loop()
        ready = threading.Event()

        def run_loop() -> None:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(srv.start())
            ready.set()
            try:
                loop.run_forever()
            finally:
                loop.run_until_complete(srv.stop())
                loop.close()

        t = threading.Thread(target=run_loop, daemon=True)
        t.start()
        ready.wait(timeout=5)
        try:
            c = MySQLWireClient(
                host="127.0.0.1", port=srv.bound_port, user="alice", password="secret-sha2"
            )
            self.assertEqual(c.query("SELECT 7;").rows, [(7,)])
            c.close()

            with self.assertRaises(MySQLError):
                MySQLWireClient(
                    host="127.0.0.1", port=srv.bound_port, user="alice", password="bad"
                )
        finally:
            loop.call_soon_threadsafe(loop.stop)
            t.join(timeout=5)
            driver.close()
            ledger.close()

    def test_parse_test_decoding_lines_and_append_ops(self) -> None:
        b = parse_test_decoding_line("BEGIN 908")
        self.assertEqual(b, {"kind": "begin", "xid": "908"})

        m = parse_test_decoding_line(
            'message: transactional: 1 prefix: reverse_proxy, sz: 18 content:{"tx_id":"tx_123"}'
        )
        self.assertEqual(m["kind"], "message")
        self.assertEqual(m["prefix"], "reverse_proxy")

        ins = parse_test_decoding_line(
            "table public.wal_t: INSERT: id[integer]:1 name[text]:'O''Brien' active[boolean]:true note[text]:null"
        )
        self.assertEqual(ins["op"], "c")
        self.assertEqual(ins["after"], {"id": 1, "name": "O'Brien", "active": True, "note": None})

        upd = parse_test_decoding_line(
            "table public.wal_t: UPDATE: old-key: id[integer]:1 name[text]:'Alice' new-tuple: id[integer]:1 name[text]:'Bob'"
        )
        self.assertEqual(upd["op"], "u")
        self.assertEqual(upd["before"], {"id": 1, "name": "Alice"})
        self.assertEqual(upd["after"], {"id": 1, "name": "Bob"})

        # Test ledger.append_ops merging trigger op onto primary record
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        try:
            engine.execute("CREATE TABLE a (id INTEGER PRIMARY KEY, x INTEGER);")
            engine.execute("CREATE TABLE b (id INTEGER PRIMARY KEY, msg TEXT);")
            tx = engine.execute_one("INSERT INTO a (id, x) VALUES (1, 10);").tx_id
            driver._conn.execute("INSERT INTO b (id, msg) VALUES (9, 'from_trigger');")
            ledger.append_ops(
                tx,
                [
                    MutationOp(
                        op_type="INSERT",
                        table="b",
                        schema=None,
                        pk_columns=["id"],
                        column_types={"id": "INTEGER", "msg": "TEXT"},
                        after_rows=[{"id": 9, "msg": "from_trigger"}],
                    )
                ],
                warning="Captured trigger side effect.",
            )
            self.assertTrue(engine.reverse(tx).success)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM a;").rows[0][0], 0)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM b;").rows[0][0], 0)
        finally:
            driver.close()
            ledger.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
