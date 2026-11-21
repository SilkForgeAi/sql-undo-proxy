"""Stage 5 tests: Control Plane Web UI, REST API, and CLI argument parser."""

from __future__ import annotations

import json
import unittest
import urllib.request
from typing import Any

from reverse_proxy import ControlPlaneServer, ReverseProxyEngine, UndoLedger
from reverse_proxy.cli import build_parser
from reverse_proxy.drivers import SQLiteDriver


class TestStage5WebUIAndCLI(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SQLiteDriver(":memory:")
        self.ledger = UndoLedger(":memory:")
        self.engine = ReverseProxyEngine(self.driver, self.ledger)
        self.ui = ControlPlaneServer(
            self.engine, host="127.0.0.1", port=0, pg_port=5433, mysql_port=3307
        )
        self.ui.start()
        self.base_url = f"http://127.0.0.1:{self.ui.bound_port}"

    def tearDown(self) -> None:
        self.ui.stop()
        self.driver.close()
        self.ledger.close()

    def _get(self, path: str) -> Any:
        with urllib.request.urlopen(self.base_url + path, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            ctype = resp.headers.get("Content-Type", "")
            return json.loads(body) if "application/json" in ctype else body

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def test_web_ui_html_and_full_reverse_lifecycle(self) -> None:
        html = self._get("/")
        self.assertIn("Universal SQL Reverse Proxy", html)

        status = self._get("/api/status")
        self.assertEqual(status["engine"], "sqlite")
        self.assertEqual(status["pg_port"], 5433)
        self.assertEqual(status["mysql_port"], 3307)

        # Execute DDL + DML through HTTP console API
        self._post("/api/query", {"sql": "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);"})
        ins = self._post(
            "/api/query",
            {"sql": "INSERT INTO users (id, name, role) VALUES (1, 'Alice', 'user');"},
        )
        tx_ins = ins["tx_id"]
        self.assertIsNotNone(tx_ins)

        upd = self._post(
            "/api/query",
            {"sql": "UPDATE users SET role = 'admin' WHERE id = 1;"},
        )
        tx_upd = upd["tx_id"]

        hist = self._get("/api/history?limit=10")
        self.assertEqual(len(hist["records"]), 2)

        diff = self._get(f"/api/diff/{tx_upd}")
        self.assertEqual(diff["ops"][0]["before_rows"][0]["role"], "user")
        self.assertEqual(diff["ops"][0]["after_rows"][0]["role"], "admin")

        # Dry run via API
        dry = self._post(f"/api/reverse/{tx_upd}", {"dry_run": True})
        self.assertTrue(dry["success"])
        self.assertTrue(dry["dry_run"])
        self.assertEqual(dry["reversed_rows"], 1)

        # Reverse UPDATE via API ("The Reverse Button")
        rev = self._post(f"/api/reverse/{tx_upd}", {"dry_run": False})
        self.assertTrue(rev["success"])

        sel = self._post("/api/query", {"sql": "SELECT role FROM users WHERE id = 1;"})
        self.assertEqual(sel["rows"], [["user"]])

        # Create drift & verify API reports conflict until force=True
        self._post("/api/query", {"sql": "UPDATE users SET role = 'owner' WHERE id = 1;"})
        conflict_res = self._post(f"/api/reverse/{tx_ins}", {"dry_run": False})
        self.assertFalse(conflict_res["success"])
        self.assertEqual(len(conflict_res["conflicts"]), 1)

        forced_res = self._post(f"/api/reverse/{tx_ins}", {"dry_run": False, "force": True})
        self.assertTrue(forced_res["success"])
        check = self._post("/api/query", {"sql": "SELECT COUNT(*) FROM users;"})
        self.assertEqual(check["rows"], [[0]])

    def test_cli_parser_defaults_and_flags(self) -> None:
        args = build_parser().parse_args(
            ["--engine", "postgres", "--backend-port", "5432", "--require-where-delete"]
        )
        self.assertEqual(args.engine, "postgres")
        self.assertEqual(args.backend_port, 5432)
        self.assertTrue(args.require_where_delete)


if __name__ == "__main__":
    unittest.main(verbosity=2)
