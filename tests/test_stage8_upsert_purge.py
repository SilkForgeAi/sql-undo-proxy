"""Stage 8 tests: Exact UPSERT pre-image capture (SQLite, Postgres, MySQL) and PROXY PURGE."""

from __future__ import annotations

import json
import unittest
import urllib.request

from reverse_proxy import ControlPlaneServer, ReverseProxyEngine, ReversibilityStatus, UndoLedger
from reverse_proxy.drivers import MySQLDriver, PostgresDriver, SQLiteDriver
from test_stage6_symmetry_truncate import _ExtendedMySQLBackend, _ExtendedPostgresBackend


class TestStage8UpsertAndPurge(unittest.TestCase):
    def test_sqlite_mixed_upsert_reverts_existing_and_deletes_new(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        try:
            engine.execute(
                "CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner TEXT, balance INTEGER);"
            )
            engine.execute_one(
                "INSERT INTO accounts (id, owner, balance) VALUES (1, 'Alice', 100);"
            )

            ups = engine.execute_one(
                "INSERT INTO accounts (id, owner, balance) VALUES (1, 'Alice', 999), (2, 'Bob', 50) "
                "ON CONFLICT (id) DO UPDATE SET balance = excluded.balance;"
            )
            self.assertEqual(ups.reversibility, ReversibilityStatus.EXACT)
            self.assertEqual(
                engine.execute_one("SELECT id, owner, balance FROM accounts ORDER BY id;").rows,
                [(1, "Alice", 999), (2, "Bob", 50)],
            )

            rev = engine.reverse(ups.tx_id)
            self.assertTrue(rev.success, msg=rev.error)
            self.assertEqual(
                engine.execute_one("SELECT id, owner, balance FROM accounts ORDER BY id;").rows,
                [(1, "Alice", 100)],
            )
        finally:
            driver.close()
            ledger.close()

    def test_postgres_mixed_upsert_over_pgwire(self) -> None:
        backend = _ExtendedPostgresBackend(auth_mode="trust")
        backend.start()
        driver = PostgresDriver(host="127.0.0.1", port=backend.port)
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        try:
            engine.execute(
                "CREATE TABLE public.accounts (id INTEGER PRIMARY KEY, owner TEXT, balance INTEGER);"
            )
            engine.execute_one(
                "INSERT INTO public.accounts (id, owner, balance) VALUES (1, 'Alice', 100);"
            )

            ups = engine.execute_one(
                "INSERT INTO public.accounts (id, owner, balance) VALUES (1, 'Alice', 888), (2, 'Bob', 75) "
                "ON CONFLICT (id) DO UPDATE SET balance = excluded.balance;"
            )
            self.assertEqual(ups.reversibility, ReversibilityStatus.EXACT)
            self.assertTrue(engine.reverse(ups.tx_id).success)
            self.assertEqual(
                engine.execute_one("SELECT id, owner, balance FROM public.accounts ORDER BY id;").rows,
                [(1, "Alice", 100)],
            )
        finally:
            driver.close()
            ledger.close()
            backend.stop()

    def test_mysql_mixed_upsert_over_mysql_wire(self) -> None:
        backend = _ExtendedMySQLBackend(default_db="app")
        backend.start()
        driver = MySQLDriver(host="127.0.0.1", port=backend.port, database="app")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        try:
            engine.execute(
                "CREATE TABLE `app`.`accounts` (id INTEGER PRIMARY KEY, owner TEXT, balance INTEGER);"
            )
            engine.execute_one(
                "INSERT INTO `accounts` (id, owner, balance) VALUES (1, 'Alice', 100);"
            )

            ups = engine.execute_one(
                "INSERT INTO `accounts` (id, owner, balance) VALUES (1, 'Alice', 777), (2, 'Bob', 25) "
                "ON DUPLICATE KEY UPDATE balance = VALUES(balance);"
            )
            self.assertEqual(ups.reversibility, ReversibilityStatus.EXACT)
            self.assertEqual(
                engine.execute_one("SELECT id, owner, balance FROM `accounts` ORDER BY id;").rows,
                [(1, "Alice", 777), (2, "Bob", 25)],
            )

            rev = engine.reverse(ups.tx_id)
            self.assertTrue(rev.success, msg=rev.error)
            self.assertEqual(
                engine.execute_one("SELECT id, owner, balance FROM `accounts` ORDER BY id;").rows,
                [(1, "Alice", 100)],
            )
        finally:
            driver.close()
            ledger.close()
            backend.stop()

    def test_proxy_purge_and_web_api_purge(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        ui = ControlPlaneServer(engine, host="127.0.0.1", port=0)
        ui.start()
        try:
            engine.execute("CREATE TABLE t1 (id INTEGER PRIMARY KEY); CREATE TABLE t2 (id INTEGER PRIMARY KEY);")
            drop1 = engine.execute_one("DROP TABLE t1;")
            drop2 = engine.execute_one("DROP TABLE t2;")

            q1 = f"_reverse_quarantine__{drop1.tx_id}__t1"
            q2 = f"_reverse_quarantine__{drop2.tx_id}__t2"
            self.assertTrue(driver._table_exists(q1))
            self.assertTrue(driver._table_exists(q2))

            req = urllib.request.Request(
                f"http://127.0.0.1:{ui.bound_port}/api/purge",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["count"], 2)
            self.assertFalse(driver._table_exists(q1))
            self.assertFalse(driver._table_exists(q2))

            # Second PROXY PURGE is a clean 0-row no-op
            p2 = engine.execute_one("PROXY PURGE;")
            self.assertEqual(p2.rowcount, 0)
        finally:
            ui.stop()
            driver.close()
            ledger.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
