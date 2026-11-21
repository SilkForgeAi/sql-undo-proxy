"""Stage 7 tests: Causal Dependency Graph and Cascading Cross-Transaction Reversal."""

from __future__ import annotations

import json
import unittest
import urllib.request

from reverse_proxy import ControlPlaneServer, ReverseProxyEngine, ReversibilityStatus, UndoLedger
from reverse_proxy.drivers import SQLiteDriver


class TestStage7CausalGraph(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SQLiteDriver(":memory:")
        self.ledger = UndoLedger(":memory:")
        self.engine = ReverseProxyEngine(self.driver, self.ledger)

    def tearDown(self) -> None:
        self.driver.close()
        self.ledger.close()

    def test_same_row_multi_transaction_chain_cascade(self) -> None:
        self.engine.execute(
            "CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner TEXT, balance INTEGER);"
        )
        t1 = self.engine.execute_one(
            "INSERT INTO accounts (id, owner, balance) VALUES (1, 'Alice', 100);"
        ).tx_id
        t_other = self.engine.execute_one(
            "INSERT INTO accounts (id, owner, balance) VALUES (2, 'Unrelated', 999);"
        ).tx_id
        t2 = self.engine.execute_one(
            "UPDATE accounts SET balance = 200 WHERE id = 1;"
        ).tx_id
        t3 = self.engine.execute_one(
            "UPDATE accounts SET owner = 'Alice-Updated', balance = 350 WHERE id = 1;"
        ).tx_id

        # Normal reverse of t1 fails due to drift from t2/t3
        self.assertFalse(self.engine.reverse(t1).success)

        # Dependency plan identifies [t3, t2, t1] and excludes t_other!
        plan = self.engine.analyze_dependencies(t1)
        self.assertEqual(plan.ordered_tx_ids, [t3, t2, t1])
        self.assertNotIn(t_other, plan.ordered_tx_ids)

        # Dry run previews all 3 steps without mutating
        dry = self.engine.reverse(t1, dry_run=True, cascade=True)
        self.assertTrue(dry.success)
        self.assertEqual(dry.cascaded_tx_ids, [t3, t2, t1])
        self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM accounts;").rows[0][0], 2)

        # Execute PROXY REVERSE <t1> CASCADE via SQL
        res = self.engine.execute_one(f"PROXY REVERSE {t1} CASCADE;")
        self.assertEqual(res.command_tag, "PROXY REVERSE OK")

        # Alice is gone, Unrelated Bob/2 stays untouched!
        self.assertEqual(
            self.engine.execute_one("SELECT id, owner, balance FROM accounts;").rows,
            [(2, "Unrelated", 999)],
        )
        self.assertEqual(self.ledger.get_record(t1).status, ReversibilityStatus.REVERSED)
        self.assertEqual(self.ledger.get_record(t2).status, ReversibilityStatus.REVERSED)
        self.assertEqual(self.ledger.get_record(t3).status, ReversibilityStatus.REVERSED)
        self.assertEqual(self.ledger.get_record(t_other).status, ReversibilityStatus.EXACT)

    def test_cross_table_fk_dependency_chain_cascade(self) -> None:
        self.engine.execute(
            """
            CREATE TABLE orgs (id INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY,
                org_id INTEGER REFERENCES orgs(id),
                title TEXT
            );
            CREATE TABLE tasks (
                id INTEGER PRIMARY KEY,
                project_id INTEGER REFERENCES projects(id),
                summary TEXT
            );
            """
        )
        t1 = self.engine.execute_one("INSERT INTO orgs (id, name) VALUES (1, 'Acme');").tx_id
        t_keep = self.engine.execute_one("INSERT INTO orgs (id, name) VALUES (2, 'KeepCo');").tx_id
        t2 = self.engine.execute_one(
            "INSERT INTO projects (id, org_id, title) VALUES (10, 1, 'Apollo');"
        ).tx_id
        t3 = self.engine.execute_one(
            "INSERT INTO tasks (id, project_id, summary) VALUES (100, 10, 'Ship');"
        ).tx_id

        # Single reverse on t1 fails FK constraint because projects(10) references orgs(1)
        single = self.engine.reverse(t1)
        self.assertFalse(single.success)

        # Causal cascade unwinds tasks -> projects -> orgs cleanly!
        plan = self.engine.analyze_dependencies(t1)
        self.assertEqual(plan.ordered_tx_ids, [t3, t2, t1])

        res = self.engine.reverse(t1, cascade=True)
        self.assertTrue(res.success, msg=res.error)
        self.assertEqual(res.cascaded_tx_ids, [t3, t2, t1])
        self.assertEqual(self.engine.execute_one("SELECT id, name FROM orgs;").rows, [(2, "KeepCo")])
        self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM projects;").rows[0][0], 0)
        self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM tasks;").rows[0][0], 0)
        self.assertEqual(self.ledger.get_record(t_keep).status, ReversibilityStatus.EXACT)

    def test_ddl_shadow_and_web_ui_dependencies_endpoint(self) -> None:
        ui = ControlPlaneServer(self.engine, host="127.0.0.1", port=0)
        ui.start()
        try:
            self.engine.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);")
            t1 = self.engine.execute_one("INSERT INTO notes (id, body) VALUES (1, 'hello');").tx_id
            t2 = self.engine.execute_one("DROP TABLE notes;").tx_id

            with urllib.request.urlopen(
                f"http://127.0.0.1:{ui.bound_port}/api/dependencies/{t1}", timeout=5
            ) as resp:
                dep_json = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(dep_json["ordered_tx_ids"], [t2, t1])
            self.assertEqual(dep_json["reasons"][0]["kind"], "ddl_shadow")

            req = urllib.request.Request(
                f"http://127.0.0.1:{ui.bound_port}/api/reverse/{t1}",
                data=json.dumps({"cascade": True}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                rev_json = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(rev_json["success"])
            self.assertEqual(rev_json["cascaded_tx_ids"], [t2, t1])
            # Table is restored (t2 undone) and row 1 is deleted (t1 undone)!
            self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM notes;").rows[0][0], 0)
        finally:
            ui.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
