"""Stage 16 tests: Reversible ALTER TABLE & RENAME TABLE migrations across SQLite + parser."""

from __future__ import annotations

import unittest

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import SQLiteDriver
from reverse_proxy.models import ReversibilityStatus, StatementKind
from reverse_proxy.parser import parse_statement


class TestStage16ReversibleDDL(unittest.TestCase):
    def test_parser_alter_and_rename_classification(self) -> None:
        p_add = parse_statement("ALTER TABLE public.users ADD COLUMN bio TEXT DEFAULT 'hi';")
        self.assertEqual(p_add.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(p_add.schema, "public")
        self.assertEqual(p_add.table, "users")
        self.assertEqual(p_add.alter_actions, [{"action": "ADD_COLUMN", "column": "bio", "if_not_exists": False}])

        p_drop = parse_statement('ALTER TABLE "users" DROP COLUMN IF EXISTS "email";')
        self.assertEqual(p_drop.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(p_drop.table, "users")
        self.assertEqual(p_drop.alter_actions, [{"action": "DROP_COLUMN", "column": "email", "if_exists": True}])

        p_ren_col = parse_statement("ALTER TABLE users RENAME COLUMN bio TO summary;")
        self.assertEqual(p_ren_col.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(p_ren_col.alter_actions, [{"action": "RENAME_COLUMN", "old_name": "bio", "new_name": "summary"}])

        p_ren_tbl = parse_statement("RENAME TABLE app.users TO app.members;")
        self.assertEqual(p_ren_tbl.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(p_ren_tbl.schema, "app")
        self.assertEqual(p_ren_tbl.table, "users")
        self.assertEqual(p_ren_tbl.alter_actions, [{"action": "RENAME_TABLE", "new_schema": "app", "new_table": "members"}])

        p_multi = parse_statement("ALTER TABLE users ADD COLUMN c1 INT, DROP COLUMN old_c;")
        self.assertEqual(p_multi.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(len(p_multi.alter_actions), 2)

        # Unsupported constraint alter falls back cleanly to OTHER_DDL
        p_con = parse_statement("ALTER TABLE users ADD CONSTRAINT uq_name UNIQUE (name);")
        self.assertEqual(p_con.kind, StatementKind.OTHER_DDL)

        p_type = parse_statement("ALTER TABLE users ALTER COLUMN age TYPE TEXT;")
        self.assertEqual(p_type.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(p_type.alter_actions, [{"action": "ALTER_COLUMN_TYPE", "column": "age"}])

        p_def = parse_statement("ALTER TABLE users ALTER COLUMN tier SET DEFAULT 'pro';")
        self.assertEqual(p_def.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(p_def.alter_actions, [{"action": "ALTER_COLUMN_DEFAULT", "column": "tier"}])

        p_nn = parse_statement("ALTER TABLE users ALTER COLUMN name DROP NOT NULL;")
        self.assertEqual(p_nn.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(p_nn.alter_actions, [{"action": "ALTER_COLUMN_NOT_NULL", "column": "name"}])

        p_mod = parse_statement("ALTER TABLE users MODIFY COLUMN bio VARCHAR(200) NOT NULL;")
        self.assertEqual(p_mod.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(p_mod.alter_actions, [{"action": "MODIFY_COLUMN", "column": "bio"}])

        p_chg = parse_statement("ALTER TABLE users CHANGE COLUMN bio summary VARCHAR(255);")
        self.assertEqual(p_chg.kind, StatementKind.ALTER_TABLE)
        self.assertEqual(p_chg.alter_actions, [{"action": "CHANGE_COLUMN", "old_name": "bio", "new_name": "summary"}])

        p_drop_multi = parse_statement("DROP TABLE IF EXISTS public.t1, t2 CASCADE;")
        self.assertEqual(p_drop_multi.kind, StatementKind.DROP_TABLE)
        self.assertEqual(p_drop_multi.drop_targets, [("public", "t1"), (None, "t2")])
        self.assertTrue(p_drop_multi.if_exists)

        p_trunc_multi = parse_statement("TRUNCATE TABLE t1, t2;")
        self.assertEqual(p_trunc_multi.kind, StatementKind.TRUNCATE_TABLE)
        self.assertEqual(p_trunc_multi.drop_targets, [(None, "t1"), (None, "t2")])

        p_cidx = parse_statement("CREATE UNIQUE INDEX idx_users_name ON app.users (name);")
        self.assertEqual(p_cidx.kind, StatementKind.CREATE_INDEX)
        self.assertEqual(p_cidx.index_name, "idx_users_name")
        self.assertEqual(p_cidx.table, "users")

        p_didx = parse_statement("DROP INDEX IF EXISTS idx_users_name ON app.users;")
        self.assertEqual(p_didx.kind, StatementKind.DROP_INDEX)
        self.assertEqual(p_didx.index_name, "idx_users_name")
        self.assertTrue(p_didx.if_exists)

    def test_sqlite_reversible_alter_add_drop_rename_and_purge(self) -> None:
        drv = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        eng = ReverseProxyEngine(drv, ledger)
        try:
            eng.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, tier TEXT NOT NULL DEFAULT 'free');")
            eng.execute("INSERT INTO users (id, name, tier) VALUES (1, 'Alice', 'pro'), (2, 'Bob', 'enterprise');")

            # 1. ADD COLUMN -> PROXY REVERSE drops added column
            r_add = eng.execute_one("ALTER TABLE users ADD COLUMN score INTEGER DEFAULT 10;")
            self.assertEqual(r_add.reversibility, ReversibilityStatus.EXACT)
            self.assertEqual(
                eng.execute_one("SELECT score FROM users WHERE id = 1;").rows,
                [(10,)],
            )
            rev_add = eng.execute_one("PROXY REVERSE LAST;")
            self.assertEqual(rev_add.command_tag, "PROXY REVERSE OK")
            self.assertNotIn("score", drv.inspect_table("users").columns)

            # 2. DROP COLUMN -> quarantines values -> PROXY REVERSE restores column + values!
            r_drop = eng.execute_one("ALTER TABLE users DROP COLUMN tier;")
            self.assertEqual(r_drop.reversibility, ReversibilityStatus.QUARANTINE)
            self.assertNotIn("tier", drv.inspect_table("users").columns)

            rev_drop = eng.execute_one("PROXY REVERSE LAST;")
            self.assertEqual(rev_drop.command_tag, "PROXY REVERSE OK")
            self.assertIn("tier", drv.inspect_table("users").columns)
            self.assertEqual(
                eng.execute_one("SELECT id, name, tier FROM users ORDER BY id;").rows,
                [(1, "Alice", "pro"), (2, "Bob", "enterprise")],
            )

            # 4. RENAME COLUMN -> PROXY REVERSE renames back
            eng.execute_one("ALTER TABLE users RENAME COLUMN tier TO plan;")
            self.assertIn("plan", drv.inspect_table("users").columns)
            eng.execute_one("PROXY REVERSE LAST;")
            self.assertIn("tier", drv.inspect_table("users").columns)
            self.assertNotIn("plan", drv.inspect_table("users").columns)

            # 5. RENAME TABLE -> PROXY REVERSE renames back
            eng.execute_one("ALTER TABLE users RENAME TO accounts;")
            self.assertTrue(drv._table_exists("accounts"))
            self.assertFalse(drv._table_exists("users"))
            eng.execute_one("PROXY REVERSE LAST;")
            self.assertTrue(drv._table_exists("users"))
            self.assertFalse(drv._table_exists("accounts"))

            # 6. CREATE INDEX -> PROXY REVERSE drops it; DROP INDEX -> PROXY REVERSE recreates it
            eng.execute_one("CREATE INDEX idx_users_name ON users (name);")
            self.assertIsNotNone(drv._sqlite_index_def("idx_users_name")[0])
            eng.execute_one("PROXY REVERSE LAST;")
            self.assertIsNone(drv._sqlite_index_def("idx_users_name")[0])

            eng.execute_one("CREATE UNIQUE INDEX idx_users_name ON users (name);")
            eng.execute_one("DROP INDEX idx_users_name;")
            self.assertIsNone(drv._sqlite_index_def("idx_users_name")[0])
            eng.execute_one("PROXY REVERSE LAST;")
            self.assertIsNotNone(drv._sqlite_index_def("idx_users_name")[0])
            eng.execute_one("DROP INDEX idx_users_name;")

            # 7. DROP COLUMN on NOT NULL column without DEFAULT emits explicit SQLite warning & restores data
            eng.execute("CREATE TABLE users2 (id INTEGER PRIMARY KEY, code TEXT NOT NULL);")
            eng.execute("INSERT INTO users2 VALUES (1, 'A1');")
            eng.execute_one("ALTER TABLE users2 DROP COLUMN code;")
            rev_nn = eng.reverse("LAST")
            self.assertTrue(rev_nn.success, msg=rev_nn.error)
            self.assertTrue(any("omitted NOT NULL" in w for w in rev_nn.warnings))
            self.assertEqual(eng.execute_one("SELECT id, code FROM users2;").rows, [(1, "A1")])

            # 8. PROXY PURGE drops un-reversed column quarantine tables
            eng.execute_one("ALTER TABLE users2 DROP COLUMN code;")
            purge_res = eng.execute_one("PROXY PURGE;")
            self.assertGreaterEqual(len(purge_res.rows), 1)
            blocked = eng.reverse("LAST")
            self.assertFalse(blocked.success)
            self.assertIn("no longer exists", blocked.conflicts[0].reason)
        finally:
            eng.close()
            ledger.close()


if __name__ == "__main__":
    unittest.main()
