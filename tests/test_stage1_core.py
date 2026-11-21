"""Stage 1 tests: Parser, UndoLedger, SQLiteDriver, and ReverseProxyEngine."""

from __future__ import annotations

import os
import tempfile
import unittest

from reverse_proxy import (
    EngineType,
    ReverseProxyEngine,
    ReversibilityStatus,
    StatementKind,
    UndoLedger,
)
from reverse_proxy.drivers import SQLiteDriver
from reverse_proxy.parser import parse_statement, split_statements


class TestParser(unittest.TestCase):
    def test_split_statements_ignores_semicolons_in_strings_and_comments(self) -> None:
        sql = """
        -- comment with ; semicolon
        INSERT INTO notes (body) VALUES ('hello; world');
        /* multi-line ;
           comment */
        UPDATE notes SET body = "semi;colon" WHERE id = 1;
        """
        stmts = split_statements(sql)
        self.assertEqual(len(stmts), 2)
        self.assertEqual(parse_statement(stmts[0]).kind, StatementKind.INSERT)
        self.assertEqual(parse_statement(stmts[1]).kind, StatementKind.UPDATE)

    def test_split_statements_ignores_semicolons_in_dollar_quotes(self) -> None:
        sql = """
        CREATE FUNCTION fn_test() RETURNS TRIGGER AS $$
        BEGIN
            INSERT INTO log VALUES ('a;b');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        SELECT 1;
        """
        stmts = split_statements(sql)
        self.assertEqual(len(stmts), 2)
        self.assertTrue(stmts[0].startswith("CREATE FUNCTION"))
        self.assertEqual(stmts[1], "SELECT 1")

    def test_update_where_ignores_nested_subquery_where(self) -> None:
        sql = "UPDATE users u SET active = 0 WHERE u.id IN (SELECT user_id FROM bans WHERE active = 1) ORDER BY u.id LIMIT 10"
        parsed = parse_statement(sql)
        self.assertEqual(parsed.kind, StatementKind.UPDATE)
        self.assertEqual(parsed.table, "users")
        self.assertEqual(parsed.alias, "u")
        self.assertEqual(
            parsed.where_clause,
            "u.id IN (SELECT user_id FROM bans WHERE active = 1)",
        )

    def test_proxy_commands(self) -> None:
        p1 = parse_statement("PROXY HISTORY LIMIT 10")
        self.assertEqual(p1.kind, StatementKind.PROXY_HISTORY)
        self.assertEqual(p1.proxy_limit, 10)

        p2 = parse_statement("PROXY REVERSE abc123 DRY RUN")
        self.assertEqual(p2.kind, StatementKind.PROXY_REVERSE)
        self.assertEqual(p2.proxy_tx_id, "abc123")
        self.assertTrue(p2.proxy_dry_run)
        self.assertFalse(p2.proxy_force)

        p3 = parse_statement("PROXY REVERSE 7556959a3f2b FORCE")
        self.assertEqual(p3.kind, StatementKind.PROXY_REVERSE)
        self.assertEqual(p3.proxy_tx_id, "7556959a3f2b")
        self.assertTrue(p3.proxy_force)


class TestStage1Engine(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SQLiteDriver(":memory:")
        self.ledger = UndoLedger(":memory:")
        self.engine = ReverseProxyEngine(self.driver, self.ledger)

        self.engine.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                balance REAL DEFAULT 0.0,
                avatar BLOB
            );
            CREATE TABLE memberships (
                org_id INTEGER,
                user_id INTEGER,
                role TEXT,
                PRIMARY KEY (org_id, user_id)
            );
            CREATE TABLE audit_logs (
                msg TEXT
            );
            """
        )

    def tearDown(self) -> None:
        self.driver.close()
        self.ledger.close()

    def test_insert_and_reverse_including_blobs_and_nulls(self) -> None:
        res = self.engine.execute_one(
            "INSERT INTO users (id, name, email, balance, avatar) VALUES "
            "(1, 'Alice', NULL, 42.5, X'DEADBEEF'), "
            "(2, 'Bob', 'bob@example.com', 10.0, NULL)"
        )
        self.assertIsNotNone(res.tx_id)
        self.assertEqual(res.rowcount, 2)
        self.assertEqual(res.reversibility, ReversibilityStatus.EXACT)

        rows = self.engine.execute_one("SELECT id, name, email, avatar FROM users ORDER BY id").rows
        self.assertEqual(rows, [(1, "Alice", None, b"\xde\xad\xbe\xef"), (2, "Bob", "bob@example.com", None)])

        # Dry run first: shouldn't delete rows
        dry = self.engine.reverse(res.tx_id, dry_run=True)
        self.assertTrue(dry.success)
        self.assertEqual(dry.reversed_rows, 2)
        self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM users").rows[0][0], 2)

        # Actual reverse via SQL command
        rev_res = self.engine.execute_one(f"PROXY REVERSE {res.tx_id}")
        self.assertEqual(rev_res.command_tag, "PROXY REVERSE OK")
        self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM users").rows[0][0], 0)

        rec = self.ledger.get_record(res.tx_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.status, ReversibilityStatus.REVERSED)

    def test_insert_with_user_returning_clause(self) -> None:
        res = self.engine.execute_one(
            "INSERT INTO users (id, name, email) VALUES (10, 'Carol', 'c@x.io') RETURNING id, upper(name)"
        )
        self.assertEqual(res.columns, ["id", "upper(name)"])
        self.assertEqual(res.rows, [(10, "CAROL")])
        self.assertIsNotNone(res.tx_id)

        rev = self.engine.reverse(res.tx_id)
        self.assertTrue(rev.success)
        self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM users").rows[0][0], 0)

    def test_update_and_reverse_with_alias_and_nulls(self) -> None:
        self.engine.execute_one(
            "INSERT INTO users (id, name, email, balance) VALUES (1, 'Alice', 'a@x.io', 100.0), (2, 'Bob', NULL, 50.0)"
        )
        upd = self.engine.execute_one(
            "UPDATE users AS u SET email = NULL, balance = balance + 25 WHERE u.id = 1"
        )
        self.assertEqual(upd.rowcount, 1)
        self.assertEqual(
            self.engine.execute_one("SELECT email, balance FROM users WHERE id = 1").rows,
            [(None, 125.0)],
        )

        rev = self.engine.reverse(upd.tx_id)
        self.assertTrue(rev.success)
        self.assertEqual(
            self.engine.execute_one("SELECT email, balance FROM users WHERE id = 1").rows,
            [("a@x.io", 100.0)],
        )

    def test_delete_and_reverse_composite_pk_and_rowid_table(self) -> None:
        # Composite PK
        self.engine.execute_one(
            "INSERT INTO memberships (org_id, user_id, role) VALUES (1, 10, 'admin'), (1, 20, 'member')"
        )
        d1 = self.engine.execute_one("DELETE FROM memberships WHERE org_id = 1")
        self.assertEqual(d1.rowcount, 2)
        self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM memberships").rows[0][0], 0)

        rev1 = self.engine.reverse(d1.tx_id)
        self.assertTrue(rev1.success)
        self.assertEqual(
            self.engine.execute_one("SELECT org_id, user_id, role FROM memberships ORDER BY user_id").rows,
            [(1, 10, "admin"), (1, 20, "member")],
        )

        # Rowid fallback table (no explicit PK)
        self.engine.execute_one("INSERT INTO audit_logs (msg) VALUES ('boot'), ('login')")
        d2 = self.engine.execute_one("DELETE FROM audit_logs WHERE msg = 'boot'")
        self.assertTrue(any("rowid fallback" in w for w in d2.warnings))
        self.assertEqual(self.engine.execute_one("SELECT msg FROM audit_logs").rows, [("login",)])

        rev2 = self.engine.reverse(d2.tx_id)
        self.assertTrue(rev2.success)
        self.assertEqual(
            self.engine.execute_one("SELECT rowid, msg FROM audit_logs ORDER BY rowid").rows,
            [(1, "boot"), (2, "login")],
        )

    def test_drop_table_quarantine_and_restore(self) -> None:
        self.engine.execute_one("INSERT INTO users (id, name) VALUES (1, 'Alice')")
        drop_res = self.engine.execute_one("DROP TABLE users")
        self.assertEqual(drop_res.reversibility, ReversibilityStatus.QUARANTINE)

        # Querying users should fail now
        with self.assertRaises(Exception):
            self.engine.execute_one("SELECT * FROM users")

        # Reverse restores the table AND its data
        rev = self.engine.reverse(drop_res.tx_id)
        self.assertTrue(rev.success)
        self.assertEqual(self.engine.execute_one("SELECT id, name FROM users").rows, [(1, "Alice")])

        # DROP TABLE IF EXISTS on missing table is clean no-op
        noop = self.engine.execute_one("DROP TABLE IF EXISTS does_not_exist")
        self.assertIsNone(noop.tx_id)

    def test_explicit_transactions_rollback_savepoint_and_atomic_commit(self) -> None:
        # 1. Rolled-back transaction creates zero undo records
        before_count = len(self.engine.history())
        self.engine.execute(
            """
            BEGIN;
            INSERT INTO users (id, name) VALUES (99, 'Temp');
            ROLLBACK;
            """
        )
        self.assertEqual(len(self.engine.history()), before_count)
        self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM users").rows[0][0], 0)

        # 2. Savepoint rollback discards only ops after savepoint
        results = self.engine.execute(
            """
            BEGIN;
            INSERT INTO users (id, name, balance) VALUES (1, 'Alice', 100);
            SAVEPOINT sp1;
            UPDATE users SET balance = 999 WHERE id = 1;
            ROLLBACK TO SAVEPOINT sp1;
            INSERT INTO users (id, name, balance) VALUES (2, 'Bob', 200);
            COMMIT;
            """
        )
        commit_res = results[-1]
        self.assertIsNotNone(commit_res.tx_id)
        self.assertEqual(
            self.engine.execute_one("SELECT id, name, balance FROM users ORDER BY id").rows,
            [(1, "Alice", 100.0), (2, "Bob", 200.0)],
        )

        # Reversing the committed transaction undoes BOTH inserts cleanly
        rev = self.engine.reverse(commit_res.tx_id)
        self.assertTrue(rev.success)
        self.assertEqual(self.engine.execute_one("SELECT COUNT(*) FROM users").rows[0][0], 0)

    def test_drift_detection_blocks_unsafe_reverse_and_force_overrides(self) -> None:
        self.engine.execute_one("INSERT INTO users (id, name, balance) VALUES (1, 'Alice', 100.0)")
        tx1 = self.engine.execute_one("UPDATE users SET balance = 200.0 WHERE id = 1").tx_id
        # Concurrent/subsequent edit creates drift
        self.engine.execute_one("UPDATE users SET balance = 350.0 WHERE id = 1")

        # Safe reverse aborts with conflict
        blocked = self.engine.reverse(tx1)
        self.assertFalse(blocked.success)
        self.assertEqual(len(blocked.conflicts), 1)
        self.assertEqual(blocked.conflicts[0].column, "balance")
        self.assertEqual(blocked.conflicts[0].expected_after, 200.0)
        self.assertEqual(blocked.conflicts[0].actual_current, 350.0)
        # Value remains 350.0
        self.assertEqual(self.engine.execute_one("SELECT balance FROM users WHERE id = 1").rows[0][0], 350.0)

        # PROXY REVERSE SQL surface reports conflict cleanly
        sql_conflict = self.engine.execute_one(f"PROXY REVERSE {tx1}")
        self.assertEqual(sql_conflict.command_tag, "PROXY REVERSE CONFLICT")

        # FORCE overrides drift
        forced = self.engine.execute_one(f"PROXY REVERSE {tx1} FORCE")
        self.assertEqual(forced.command_tag, "PROXY REVERSE OK")
        self.assertEqual(self.engine.execute_one("SELECT balance FROM users WHERE id = 1").rows[0][0], 100.0)

    def test_proxy_history_and_diff_and_disk_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "app.db")
            ledger_path = os.path.join(tmpdir, "ledger.db")

            d1 = SQLiteDriver(db_path)
            l1 = UndoLedger(ledger_path)
            e1 = ReverseProxyEngine(d1, l1)
            e1.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT);")
            ins = e1.execute_one("INSERT INTO items (id, label) VALUES (1, 'widget')")
            upd = e1.execute_one("UPDATE items SET label = 'gadget' WHERE id = 1")
            hist = e1.execute_one("PROXY HISTORY LIMIT 5")
            self.assertEqual(hist.rowcount, 2)
            diff = e1.execute_one(f"PROXY DIFF {upd.tx_id}")
            self.assertEqual(diff.rowcount, 1)
            d1.close()
            l1.close()

            # Reopen in a fresh process/instance and reverse!
            d2 = SQLiteDriver(db_path)
            l2 = UndoLedger(ledger_path)
            e2 = ReverseProxyEngine(d2, l2)
            rev = e2.reverse(upd.tx_id)
            self.assertTrue(rev.success)
            self.assertEqual(e2.execute_one("SELECT label FROM items WHERE id = 1").rows, [("widget",)])
            rev2 = e2.reverse(ins.tx_id)
            self.assertTrue(rev2.success)
            self.assertEqual(e2.execute_one("SELECT COUNT(*) FROM items").rows[0][0], 0)
            d2.close()
            l2.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
