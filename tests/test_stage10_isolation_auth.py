"""Stage 10 tests: Per-session backend connection isolation, proxy auth, and actor attribution."""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import threading
import unittest
import urllib.request

from reverse_proxy import ControlPlaneServer, ReverseProxyEngine, UndoLedger
from reverse_proxy.cli import _parse_auth_users, build_parser
from reverse_proxy.drivers import (
    MySQLError,
    MySQLWireClient,
    PgError,
    PgWireClient,
    SQLiteDriver,
)
from reverse_proxy.frontends import MySQLServer, PgWireServer


def _extract_tx_id(text: str) -> str:
    m = re.search(r"tx_id=(tx_[0-9a-f]+)", text)
    if not m:
        raise AssertionError(f"No tx_id found in {text!r}")
    return m.group(1)


class _DualProtocolServer:
    def __init__(
        self,
        engine: ReverseProxyEngine,
        auth_users: dict[str, str] | None = None,
    ) -> None:
        self.engine = engine
        self.pg = PgWireServer(engine, port=0, auth_users=auth_users)
        self.mysql = MySQLServer(engine, port=0, auth_users=auth_users)
        self.loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.pg.start())
        self.loop.run_until_complete(self.mysql.start())
        self._ready.set()
        try:
            self.loop.run_forever()
        finally:
            self.loop.run_until_complete(self.pg.stop())
            self.loop.run_until_complete(self.mysql.stop())
            self.loop.close()

    def start(self) -> None:
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(timeout=5.0)


class TestStage10IsolationAndAuth(unittest.TestCase):
    def test_concurrent_sessions_with_driver_factory_do_not_collide(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_a = os.path.join(tmp, "sess_a.db")
            db_b = os.path.join(tmp, "sess_b.db")
            db_ctrl = os.path.join(tmp, "ctrl.db")
            ledger_path = os.path.join(tmp, "ledger.db")

            # Use distinct backing DBs per factory call to simulate independent backend connections
            # (e.g. Postgres/MySQL connections) without SQLite's single-file writer lock blocking.
            db_paths = [db_ctrl, db_a, db_b]
            for p in db_paths:
                init_drv = SQLiteDriver(p)
                init_drv._conn.execute(
                    "CREATE TABLE ledger_items (id INTEGER PRIMARY KEY, owner TEXT);"
                )
                init_drv.close()

            created_drivers: list[SQLiteDriver] = []
            idx_counter = {"i": 0}

            def make_driver() -> SQLiteDriver:
                p = db_paths[min(idx_counter["i"], len(db_paths) - 1)]
                idx_counter["i"] += 1
                d = SQLiteDriver(p)
                created_drivers.append(d)
                return d

            ledger = UndoLedger(ledger_path)
            engine = ReverseProxyEngine(make_driver, ledger)
            srv = _DualProtocolServer(engine)
            srv.start()

            try:
                pg_alice = PgWireClient(host="127.0.0.1", port=srv.pg.bound_port, user="alice")
                my_bob = MySQLWireClient(host="127.0.0.1", port=srv.mysql.bound_port, user="bob")

                # Alice opens an explicit transaction and inserts id=1 (NOT committed yet)
                pg_alice.query("BEGIN;")
                pg_alice.query("INSERT INTO ledger_items (id, owner) VALUES (1, 'alice');")

                # Bob opens his own transaction concurrently on his isolated driver and rolls back
                my_bob.query("BEGIN;")
                my_bob.query("INSERT INTO ledger_items (id, owner) VALUES (2, 'bob-temp');")
                my_bob.query("ROLLBACK;")

                # Bob commits id=3 while Alice's tx is still open
                res_bob = my_bob.query("INSERT INTO ledger_items (id, owner) VALUES (3, 'bob');")
                tx_bob = _extract_tx_id(res_bob.info)

                # Verify distinct per-session drivers & locks were allocated
                sessions = list(engine._sessions.values())
                self.assertEqual(len(sessions), 2)
                self.assertIsNot(sessions[0].driver, sessions[1].driver)
                self.assertIsNot(sessions[0].lock, sessions[1].lock)

                # Alice now commits her tx -> her id=1 was NOT rolled back or committed prematurely!
                commit_res = pg_alice.query("COMMIT;")[0]
                tx_alice = _extract_tx_id(" ".join(commit_res.notices))

                self.assertEqual(
                    pg_alice.query("SELECT id, owner FROM ledger_items ORDER BY id;")[0].rows,
                    [(1, "alice")],
                )
                self.assertEqual(
                    my_bob.query("SELECT id, owner FROM ledger_items ORDER BY id;").rows,
                    [(3, "bob")],
                )

                # Verify actor attribution in ledger
                self.assertEqual(ledger.get_record(tx_alice).actor, "alice")
                self.assertEqual(ledger.get_record(tx_bob).actor, "bob")

                pg_alice.close()
                my_bob.close()
            finally:
                srv.stop()
                engine.close()
                ledger.close()

    def test_proxy_auth_md5_and_mysql_native_password_plus_actor_ui(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        auth_users = {"alice": "pg-secret", "bob": "my-secret"}
        srv = _DualProtocolServer(engine, auth_users=auth_users)
        ui = ControlPlaneServer(engine, host="127.0.0.1", port=0, auth_users=auth_users)
        srv.start()
        ui.start()

        try:
            # Invalid credentials rejected on both wire protocols
            with self.assertRaises(PgError):
                PgWireClient(
                    host="127.0.0.1",
                    port=srv.pg.bound_port,
                    user="alice",
                    password="wrong",
                )
            with self.assertRaises(MySQLError):
                MySQLWireClient(
                    host="127.0.0.1",
                    port=srv.mysql.bound_port,
                    user="bob",
                    password="wrong",
                )

            # Valid auth succeeds and attributes records to alice / bob
            pg = PgWireClient(
                host="127.0.0.1",
                port=srv.pg.bound_port,
                user="alice",
                password="pg-secret",
            )
            my = MySQLWireClient(
                host="127.0.0.1",
                port=srv.mysql.bound_port,
                user="bob",
                password="my-secret",
            )
            pg.query("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);")
            pg.query("INSERT INTO notes (id, body) VALUES (1, 'from-alice');")
            my.query("INSERT INTO notes (id, body) VALUES (2, 'from-bob');")

            hist_sql = pg.query("PROXY HISTORY LIMIT 5;")[0]
            self.assertEqual(hist_sql.columns[:2], ["tx_id", "actor"])
            actors = [row[1] for row in hist_sql.rows]
            self.assertEqual(actors, ["bob", "alice"])

            # Unauthenticated Web UI request is rejected with 401 when auth_users is configured
            with self.assertRaises(urllib.error.HTTPError) as ctx_err:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{ui.bound_port}/api/history", timeout=5
                )
            self.assertEqual(ctx_err.exception.code, 401)

            import base64 as _b64

            basic_hdr = "Basic " + _b64.b64encode(b"alice:pg-secret").decode("ascii")
            req_hist = urllib.request.Request(
                f"http://127.0.0.1:{ui.bound_port}/api/history",
                headers={"Authorization": basic_hdr},
            )
            with urllib.request.urlopen(req_hist, timeout=5) as resp:
                api_hist = json.loads(resp.read().decode("utf-8"))
            self.assertEqual([r["actor"] for r in api_hist["records"]], ["bob", "alice"])

            pg.close()
            my.close()
        finally:
            ui.stop()
            srv.stop()
            driver.close()
            ledger.close()

    def test_cli_auth_user_flag(self) -> None:
        args = build_parser().parse_args(
            ["--auth-user", "alice:s1", "--auth-user", "bob:s2:extra"]
        )
        parsed = _parse_auth_users(args.auth_user)
        self.assertEqual(parsed, {"alice": "s1", "bob": "s2:extra"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
