"""Stage 6 tests: Reversible TRUNCATE TABLE, multi-engine blast radius, batch drift prefetch, and diff pagination."""

from __future__ import annotations

import json
import re
import unittest
import urllib.request

from reverse_proxy import (
    BlastRadiusExceededError,
    ControlPlaneServer,
    ReverseProxyEngine,
    ReversibilityStatus,
    UndoLedger,
)
from reverse_proxy.drivers import MySQLDriver, PostgresDriver, SQLiteDriver
from test_stage2_pgwire import _SimulatedPostgresBackend
from test_stage3_mysql import _SimulatedMySQLBackend


class _ExtendedPostgresBackend(_SimulatedPostgresBackend):
    """Adds `CREATE TABLE ... (LIKE ... INCLUDING ALL)` for TRUNCATE simulation."""

    def _exec_pg_sql(self, sql: str, params: list) -> tuple[list[str], list[tuple], str]:
        s = sql.strip().rstrip(";").strip()
        m = re.match(
            r'^CREATE\s+TABLE\s+"?([A-Za-z_0-9]+)"?\."?([A-Za-z_0-9]+)"?\s*\(\s*LIKE\s+"?([A-Za-z_0-9]+)"?\."?([A-Za-z_0-9]+)"?\s+INCLUDING\s+ALL\s*\)$',
            s,
            re.I,
        )
        if m:
            dst_sch, dst_tbl, src_sch, src_tbl = m.groups()
            self.db.execute(f'CREATE TABLE "{dst_tbl}" AS SELECT * FROM "{src_tbl}" WHERE 0;')
            self.table_schemas[dst_tbl] = dst_sch
            self.table_pks[(dst_sch, dst_tbl)] = list(self.table_pks.get((src_sch, src_tbl), []))
            return [], [], "CREATE TABLE"
        return super()._exec_pg_sql(sql, params)


class _ExtendedMySQLBackend(_SimulatedMySQLBackend):
    """Adds `CREATE TABLE ... LIKE ...` and multi-pair `RENAME TABLE a TO b, c TO d`."""

    def _exec_mysql_sql(self, sql: str) -> tuple[list[str], list[tuple], int, int]:
        s = sql.strip().rstrip(";").strip()
        m_like = re.match(
            r'^CREATE\s+TABLE\s+`?([A-Za-z_0-9]+)`?\.`?([A-Za-z_0-9]+)`?\s+LIKE\s+`?([A-Za-z_0-9]+)`?\.`?([A-Za-z_0-9]+)`?$',
            s,
            re.I,
        )
        if m_like:
            dst_db, dst_tbl, src_db, src_tbl = m_like.groups()
            self.db.execute(f'CREATE TABLE "{dst_tbl}" AS SELECT * FROM "{src_tbl}" WHERE 0;')
            self.table_dbs[dst_tbl] = dst_db
            self.table_pks[(dst_db, dst_tbl)] = list(self.table_pks.get((src_db, src_tbl), []))
            return [], [], 0, 0

        if s.upper().startswith("RENAME TABLE") and "," in s:
            pairs_raw = s[len("RENAME TABLE") :].strip().split(",")
            for pair in pairs_raw:
                super()._exec_mysql_sql("RENAME TABLE " + pair.strip())
            return [], [], 0, 0

        return super()._exec_mysql_sql(sql)


class TestStage6SymmetryAndTruncate(unittest.TestCase):
    def test_sqlite_truncate_quarantine_drift_and_force_restore(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)

        try:
            engine.execute(
                """
                CREATE TABLE widgets (id INTEGER PRIMARY KEY, sku TEXT UNIQUE, qty INTEGER);
                CREATE INDEX idx_widgets_qty ON widgets(qty);
                INSERT INTO widgets (id, sku, qty) VALUES (1, 'W1', 10), (2, 'W2', 20);
                """
            )
            trunc = engine.execute_one("TRUNCATE TABLE widgets;")
            self.assertEqual(trunc.reversibility, ReversibilityStatus.QUARANTINE)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM widgets;").rows[0][0], 0)

            # Table & UNIQUE constraint still active on recreated empty table
            engine.execute_one("INSERT INTO widgets (id, sku, qty) VALUES (99, 'W99', 1);")
            # Drift check blocks unsafe reverse because row 99 was inserted after TRUNCATE
            blocked = engine.reverse(trunc.tx_id)
            self.assertFalse(blocked.success)
            self.assertIn("new row(s) inserted since TRUNCATE", blocked.conflicts[0].reason)

            # FORCE drops post-truncate row and restores original snapshot
            forced = engine.reverse(trunc.tx_id, force=True)
            self.assertTrue(forced.success, msg=forced.error)
            self.assertEqual(
                engine.execute_one("SELECT id, sku, qty FROM widgets ORDER BY id;").rows,
                [(1, "W1", 10), (2, "W2", 20)],
            )
        finally:
            driver.close()
            ledger.close()

    def test_postgres_driver_truncate_blast_radius_and_batch_drift(self) -> None:
        backend = _ExtendedPostgresBackend(auth_mode="trust")
        backend.start()
        driver = PostgresDriver(host="127.0.0.1", port=backend.port, max_capture_rows=3)
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)

        try:
            engine.execute(
                "CREATE TABLE public.items (org_id INTEGER, item_id INTEGER, label TEXT, PRIMARY KEY (org_id, item_id));"
            )
            engine.execute_one(
                "INSERT INTO public.items (org_id, item_id, label) VALUES "
                "(1, 1, 'a'), (1, 2, 'b'), (1, 3, 'c'), (1, 4, 'd');"
            )

            # Blast radius stops 4-row DELETE when limit=3
            with self.assertRaises(BlastRadiusExceededError):
                engine.execute_one("DELETE FROM public.items;")
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM public.items;").rows[0][0], 4)

            # Batch composite-PK UPDATE & REVERSE
            driver.max_capture_rows = 100
            upd = engine.execute_one("UPDATE public.items SET label = 'z' WHERE org_id = 1;")
            self.assertTrue(engine.reverse(upd.tx_id).success)
            self.assertEqual(
                engine.execute_one("SELECT label FROM public.items ORDER BY item_id;").rows,
                [("a",), ("b",), ("c",), ("d",)],
            )

            # TRUNCATE TABLE + RESTORE
            trunc = engine.execute_one("TRUNCATE TABLE public.items;")
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM public.items;").rows[0][0], 0)
            self.assertTrue(engine.reverse(trunc.tx_id).success)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM public.items;").rows[0][0], 4)
        finally:
            driver.close()
            ledger.close()
            backend.stop()

    def test_mysql_driver_truncate_blast_radius_and_batch_drift(self) -> None:
        backend = _ExtendedMySQLBackend(default_db="app")
        backend.start()
        driver = MySQLDriver(host="127.0.0.1", port=backend.port, database="app", max_capture_rows=3)
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)

        try:
            engine.execute(
                "CREATE TABLE `app`.`metrics` (k1 INTEGER, k2 INTEGER, val INTEGER, PRIMARY KEY (k1, k2));"
            )
            engine.execute_one(
                "INSERT INTO `metrics` (k1, k2, val) VALUES (1, 10, 100), (1, 20, 200), (2, 10, 300), (2, 20, 400);"
            )

            # Blast radius blocks 4-row UPDATE when limit=3
            with self.assertRaises(BlastRadiusExceededError):
                engine.execute_one("UPDATE `metrics` SET val = 0;")
            self.assertEqual(engine.execute_one("SELECT SUM(val) FROM `metrics`;").rows[0][0], 1000)

            # Batch composite-PK DELETE & REVERSE
            driver.max_capture_rows = 100
            d = engine.execute_one("DELETE FROM `metrics` WHERE k1 = 1;")
            self.assertTrue(engine.reverse(d.tx_id).success)
            self.assertEqual(engine.execute_one("SELECT SUM(val) FROM `metrics`;").rows[0][0], 1000)

            # TRUNCATE TABLE + RESTORE
            trunc = engine.execute_one("TRUNCATE TABLE `metrics`;")
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM `metrics`;").rows[0][0], 0)
            self.assertTrue(engine.reverse(trunc.tx_id).success)
            self.assertEqual(engine.execute_one("SELECT SUM(val) FROM `metrics`;").rows[0][0], 1000)
        finally:
            driver.close()
            ledger.close()
            backend.stop()

    def test_web_ui_diff_pagination(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        ui = ControlPlaneServer(engine, host="127.0.0.1", port=0)
        ui.start()
        try:
            engine.execute("CREATE TABLE nums (id INTEGER PRIMARY KEY);")
            vals = ", ".join(f"({i})" for i in range(1, 51))
            ins = engine.execute_one(f"INSERT INTO nums (id) VALUES {vals};")
            url = f"http://127.0.0.1:{ui.bound_port}/api/diff/{ins.tx_id}?offset=10&limit=5"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["offset"], 10)
            self.assertEqual(data["limit"], 5)
            self.assertEqual(data["ops"][0]["total_after_rows"], 50)
            self.assertEqual(len(data["ops"][0]["after_rows"]), 5)
            self.assertEqual(data["ops"][0]["after_rows"][0]["id"], 11)
        finally:
            ui.stop()
            driver.close()
            ledger.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
