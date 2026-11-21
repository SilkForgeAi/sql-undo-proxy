"""Stage 13 tests: Multi-table UPDATE ... FROM / JOIN and cross-engine FK causal introspection."""

from __future__ import annotations

import unittest

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import SQLiteDriver
from reverse_proxy.parser import parse_statement


class TestStage13MultiTableAndFK(unittest.TestCase):
    def test_parser_extracts_from_join_clauses(self) -> None:
        pg = parse_statement(
            "UPDATE sc_tasks SET title = sc_projects.name FROM sc_projects WHERE sc_tasks.project_id = sc_projects.id;"
        )
        self.assertEqual(pg.table, "sc_tasks")
        self.assertEqual(pg.from_join_clause, "sc_projects")
        self.assertEqual(pg.where_clause, "sc_tasks.project_id = sc_projects.id")

        my = parse_statement(
            "UPDATE my_tasks t JOIN my_projects p ON t.project_id = p.id SET t.title = p.name WHERE p.id = 1;"
        )
        self.assertEqual(my.table, "my_tasks")
        self.assertEqual(my.alias, "t")
        self.assertEqual(my.from_join_clause, "JOIN my_projects p ON t.project_id = p.id")
        self.assertEqual(my.where_clause, "p.id = 1")

        del_my = parse_statement(
            "DELETE t FROM my_tasks t JOIN my_projects p ON t.project_id = p.id WHERE p.id = 1;"
        )
        self.assertEqual(del_my.table, "my_tasks")
        self.assertEqual(del_my.alias, "t")
        self.assertEqual(del_my.from_join_clause, "JOIN my_projects p ON t.project_id = p.id")
        self.assertEqual(del_my.where_clause, "p.id = 1")

        mrg = parse_statement(
            "MERGE INTO targets t USING sources s ON t.id = s.id WHEN MATCHED THEN UPDATE SET val = s.val;"
        )
        self.assertEqual(mrg.table, "targets")
        self.assertEqual(mrg.alias, "t")
        self.assertEqual(mrg.merge_using, "sources s")
        self.assertEqual(mrg.merge_on, "t.id = s.id")

    def test_sqlite_replace_into_reverts_existing_and_deletes_new(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        try:
            engine.execute(
                "CREATE TABLE kv (k INTEGER PRIMARY KEY, v TEXT); INSERT INTO kv VALUES (1, 'old');"
            )
            rep = engine.execute_one("REPLACE INTO kv (k, v) VALUES (1, 'new'), (2, 'added');")
            self.assertEqual(
                engine.execute_one("SELECT k, v FROM kv ORDER BY k;").rows,
                [(1, "new"), (2, "added")],
            )
            self.assertTrue(engine.reverse(rep.tx_id).success)
            self.assertEqual(
                engine.execute_one("SELECT k, v FROM kv ORDER BY k;").rows,
                [(1, "old")],
            )
        finally:
            driver.close()
            ledger.close()

    def test_sqlite_update_from_join_and_reverse(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        try:
            engine.execute(
                """
                CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT);
                CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER, title TEXT);
                INSERT INTO projects (id, name) VALUES (1, 'Apollo'), (2, 'Zeus');
                INSERT INTO tasks (id, project_id, title) VALUES (10, 1, 'old-title'), (20, 2, 'keep-title');
                """
            )
            upd = engine.execute_one(
                "UPDATE tasks SET title = projects.name FROM projects WHERE tasks.project_id = projects.id AND projects.id = 1;"
            )
            self.assertEqual(
                engine.execute_one("SELECT title FROM tasks ORDER BY id;").rows,
                [("Apollo",), ("keep-title",)],
            )
            self.assertTrue(engine.reverse(upd.tx_id).success)
            self.assertEqual(
                engine.execute_one("SELECT title FROM tasks ORDER BY id;").rows,
                [("old-title",), ("keep-title",)],
            )
        finally:
            driver.close()
            ledger.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
