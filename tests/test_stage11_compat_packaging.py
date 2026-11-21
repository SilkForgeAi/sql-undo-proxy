"""Stage 11 tests: Real-client startup/introspection probe compatibility and packaging files."""

from __future__ import annotations

import os
import unittest

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import MySQLWireClient, PgWireClient, SQLiteDriver
from test_stage10_isolation_auth import _DualProtocolServer


class TestStage11CompatAndPackaging(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SQLiteDriver(":memory:")
        self.ledger = UndoLedger(":memory:")
        self.engine = ReverseProxyEngine(self.driver, self.ledger)
        self.srv = _DualProtocolServer(self.engine)
        self.srv.start()

    def tearDown(self) -> None:
        self.srv.stop()
        self.driver.close()
        self.ledger.close()

    def test_postgres_client_startup_and_introspection_probes(self) -> None:
        pg = PgWireClient(host="127.0.0.1", port=self.srv.pg.bound_port, user="psql_user")
        try:
            self.assertEqual(pg.query("SET extra_float_digits = 3;")[0].command_tag, "SET")
            self.assertEqual(pg.query("SET application_name = 'DBeaver';")[0].command_tag, "SET")
            self.assertEqual(
                pg.query("SHOW standard_conforming_strings;")[0].rows, [("on",)]
            )
            self.assertEqual(
                pg.query("SHOW transaction isolation level;")[0].rows, [("read committed",)]
            )
            self.assertIn("PostgreSQL", pg.query("SELECT version();")[0].rows[0][0])
            self.assertEqual(pg.query("SELECT current_database();")[0].rows, [("app",)])
            self.assertEqual(pg.query("SELECT current_schema();")[0].rows, [("public",)])
        finally:
            pg.close()

    def test_mysql_client_startup_and_introspection_probes(self) -> None:
        my = MySQLWireClient(host="127.0.0.1", port=self.srv.mysql.bound_port, user="mysql_cli")
        try:
            my.query("SET NAMES utf8mb4;")
            my.query("USE app;")
            self.assertIn(
                "sql-reverse-proxy",
                my.query("SELECT @@version_comment LIMIT 1;").rows[0][0],
            )
            self.assertEqual(my.query("SELECT @@max_allowed_packet;").rows, [(67108864,)])
            self.assertEqual(
                my.query("SELECT @@transaction_isolation;").rows, [("REPEATABLE-READ",)]
            )
            self.assertEqual(my.query("SELECT DATABASE();").rows, [("app",)])

            my.query("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);")
            self.assertEqual(my.query("SHOW TABLES;").rows, [("users",)])
            desc = my.query("DESCRIBE users;")
            self.assertEqual([r[0] for r in desc.rows], ["id", "email"])
            self.assertEqual(desc.rows[0][3], "PRI")
            self.assertEqual(my.query("SHOW VARIABLES LIKE 'char%';").rows, [])
        finally:
            my.close()

    def test_packaging_and_docker_files_present(self) -> None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for rel in ("pyproject.toml", "Dockerfile", "docker-compose.yml"):
            self.assertTrue(os.path.exists(os.path.join(root, rel)), msg=f"Missing {rel}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
