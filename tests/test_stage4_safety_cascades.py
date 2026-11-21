"""Stage 4 tests: Blast radius guardrails, WHERE-clause policy, and recursive ON DELETE CASCADE capture."""

from __future__ import annotations

import os
import tempfile
import unittest

from reverse_proxy import BlastRadiusExceededError, ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import SQLiteDriver


class TestStage4SafetyAndCascades(unittest.TestCase):
    def test_blast_radius_guard_stops_large_delete_and_update_before_mutating(self) -> None:
        driver = SQLiteDriver(":memory:", max_capture_rows=5)
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)

        try:
            engine.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, kind TEXT);")
            values = ", ".join(f"({i}, 'click')" for i in range(1, 11))
            engine.execute_one(f"INSERT INTO events (id, kind) VALUES {values};")

            # Deleting 10 rows exceeds max_capture_rows=5 -> aborts BEFORE deleting anything
            with self.assertRaises(BlastRadiusExceededError) as ctx:
                engine.execute_one("DELETE FROM events;")
            self.assertEqual(ctx.exception.limit, 5)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM events;").rows[0][0], 10)

            # Updating 10 rows also aborts safely
            with self.assertRaises(BlastRadiusExceededError):
                engine.execute_one("UPDATE events SET kind = 'view';")
            self.assertEqual(
                engine.execute_one("SELECT COUNT(*) FROM events WHERE kind = 'click';").rows[0][0],
                10,
            )

            # Targeted DELETE of 3 rows succeeds and reverses cleanly
            d = engine.execute_one("DELETE FROM events WHERE id <= 3;")
            self.assertEqual(d.rowcount, 3)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM events;").rows[0][0], 7)
            self.assertTrue(engine.reverse(d.tx_id).success)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM events;").rows[0][0], 10)
        finally:
            driver.close()
            ledger.close()

    def test_require_where_policy_blocks_unscoped_delete_and_update(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(
            driver,
            ledger,
            require_where_on_delete=True,
            require_where_on_update=True,
        )
        try:
            engine.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);")
            engine.execute_one("INSERT INTO users (id, name) VALUES (1, 'Alice');")

            with self.assertRaisesRegex(ValueError, "WHERE"):
                engine.execute_one("DELETE FROM users;")
            with self.assertRaisesRegex(ValueError, "WHERE"):
                engine.execute_one("UPDATE users SET name = 'Nobody';")

            self.assertEqual(engine.execute_one("SELECT name FROM users WHERE id = 1;").rows, [("Alice",)])
        finally:
            driver.close()
            ledger.close()

    def test_recursive_three_level_on_delete_cascade_capture_and_restore(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)

        try:
            engine.execute(
                """
                CREATE TABLE orgs (id INTEGER PRIMARY KEY, name TEXT);
                CREATE TABLE projects (
                    id INTEGER PRIMARY KEY,
                    org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
                    title TEXT
                );
                CREATE TABLE tasks (
                    id INTEGER PRIMARY KEY,
                    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
                    summary TEXT
                );
                INSERT INTO orgs (id, name) VALUES (1, 'Acme'), (2, 'Beta');
                INSERT INTO projects (id, org_id, title) VALUES (10, 1, 'Apollo'), (20, 2, 'Zephyr');
                INSERT INTO tasks (id, project_id, summary) VALUES
                    (100, 10, 'Launch'),
                    (101, 10, 'Monitor'),
                    (200, 20, 'KeepMe');
                """
            )

            del_res = engine.execute_one("DELETE FROM orgs WHERE id = 1;")
            self.assertEqual(del_res.rowcount, 1)
            self.assertTrue(any("CASCADE" in w for w in del_res.warnings))

            # Cascade wiped Acme's project and both tasks, leaving Beta intact
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM orgs;").rows[0][0], 1)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM projects;").rows[0][0], 1)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM tasks;").rows[0][0], 1)

            # Reversing restores orgs -> projects -> tasks in FK dependency order!
            rev = engine.reverse(del_res.tx_id)
            self.assertTrue(rev.success, msg=rev.error)
            self.assertEqual(engine.execute_one("SELECT id, name FROM orgs ORDER BY id;").rows, [(1, "Acme"), (2, "Beta")])
            self.assertEqual(engine.execute_one("SELECT id, title FROM projects ORDER BY id;").rows, [(10, "Apollo"), (20, "Zephyr")])
            self.assertEqual(
                engine.execute_one("SELECT id, summary FROM tasks ORDER BY id;").rows,
                [(100, "Launch"), (101, "Monitor"), (200, "KeepMe")],
            )
        finally:
            driver.close()
            ledger.close()

    def test_compressed_and_spilled_undo_ledger_reverse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app_db = os.path.join(tmp, "app.db")
            ledger_db = os.path.join(tmp, "ledger.db")
            # Force spill-to-disk above 200 bytes compressed
            driver = SQLiteDriver(app_db)
            ledger = UndoLedger(
                ledger_db,
                compress_threshold_bytes=50,
                spill_threshold_bytes=200,
            )
            engine = ReverseProxyEngine(driver, ledger)
            try:
                engine.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, payload TEXT);")
                vals = ", ".join(f"({i}, 'payload-data-{i:04d}-xxxx')" for i in range(1, 51))
                ins = engine.execute_one(f"INSERT INTO items (id, payload) VALUES {vals};")
                spill_file = os.path.join(f"{ledger_db}.spill", f"{ins.tx_id}.undo.zlib")
                self.assertTrue(os.path.exists(spill_file))

                # Summary read works without inflating ops
                summaries = engine.history(limit=5)
                self.assertEqual(summaries[0].rows_affected, 50)
                self.assertEqual(summaries[0].ops, [])

                # Reverse loads from spill file and deletes all 50 rows cleanly
                rev = engine.reverse(ins.tx_id)
                self.assertTrue(rev.success, msg=rev.error)
                self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM items;").rows[0][0], 0)
            finally:
                driver.close()
                ledger.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
