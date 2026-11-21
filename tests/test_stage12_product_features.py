"""Stage 12 tests: Schema-drift resilience, CDC HTTP webhooks, audit export, TOML config, and TLS."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from typing import Any

from reverse_proxy import ControlPlaneServer, ReverseProxyEngine, UndoLedger
from reverse_proxy.cli import build_parser, load_config_into_args
from reverse_proxy.drivers import PgWireClient, SQLiteDriver
from reverse_proxy.frontends import PgWireServer


class TestStage12ProductFeatures(unittest.TestCase):
    def test_schema_drift_add_and_drop_column_resilience(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        try:
            engine.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT);")
            tx_ins = engine.execute_one(
                "INSERT INTO users (id, name, email) VALUES (1, 'Alice', 'a@x.io');"
            ).tx_id
            tx_upd = engine.execute_one(
                "UPDATE users SET name = 'Alicia' WHERE id = 1;"
            ).tx_id

            # Adding a column later should NOT break reversing tx_upd!
            engine.execute_one("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'member';")
            self.assertTrue(engine.reverse(tx_upd).success)
            self.assertEqual(
                engine.execute_one("SELECT name, role FROM users WHERE id = 1;").rows,
                [("Alice", "member")],
            )

            # Dropping a column later triggers a clear schema-change conflict on safe reverse,
            # while FORCE adapts and reverses using remaining columns!
            tx_del = engine.execute_one("DELETE FROM users WHERE id = 1;").tx_id
            engine.execute_one("ALTER TABLE users DROP COLUMN email;")

            blocked = engine.reverse(tx_del)
            self.assertFalse(blocked.success)
            self.assertIn("Schema changed", blocked.conflicts[0].reason)

            forced = engine.reverse(tx_del, force=True)
            self.assertTrue(forced.success, msg=forced.error)
            self.assertEqual(
                engine.execute_one("SELECT id, name, role FROM users WHERE id = 1;").rows,
                [(1, "Alice", "member")],
            )

            # Reversing tx_ins (force=True since email was dropped & role was added) deletes row 1
            self.assertTrue(engine.reverse(tx_ins, force=True).success)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM users;").rows[0][0], 0)
        finally:
            driver.close()
            ledger.close()

    def test_cdc_webhooks_search_filter_and_audit_export(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        ui = ControlPlaneServer(engine, host="127.0.0.1", port=0)
        ui.start()
        base = f"http://127.0.0.1:{ui.bound_port}"

        def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
            req = urllib.request.Request(
                base + path,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            engine.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT);")
            engine.execute_one("INSERT INTO items (id, label) VALUES (1, 'seed');", actor="alice")
            driver._conn.execute("UPDATE items SET label = 'cdc_edited' WHERE id = 1;")

            # Stream CDC event + commit over HTTP
            post(
                "/api/cdc/event",
                {
                    "payload": {
                        "op": "u",
                        "source": {"table": "items"},
                        "pk_columns": ["id"],
                        "before": {"id": 1, "label": "seed"},
                        "after": {"id": 1, "label": "cdc_edited"},
                        "transaction": {"id": "tx_http_cdc_1"},
                    }
                },
            )
            c_res = post("/api/cdc/commit/tx_http_cdc_1", {})
            self.assertTrue(c_res["committed"])
            self.assertEqual(c_res["ops_count"], 1)

            # Search/filter history endpoint
            with urllib.request.urlopen(base + "/api/history?actor=alice", timeout=5) as r:
                alice_hist = json.loads(r.read().decode("utf-8"))
            self.assertEqual(len(alice_hist["records"]), 1)
            self.assertEqual(alice_hist["records"][0]["actor"], "alice")

            # Export CSV & JSON
            with urllib.request.urlopen(base + "/api/export?format=csv", timeout=5) as r:
                csv_text = r.read().decode("utf-8")
            self.assertIn("tx_http_cdc_1", csv_text)
            self.assertIn("tx_id,seq_no,created_at", csv_text)

            # Reverse CDC tx over API
            rev = post("/api/reverse/tx_http_cdc_1", {"dry_run": False})
            self.assertTrue(rev["success"])
            self.assertEqual(
                engine.execute_one("SELECT label FROM items WHERE id = 1;").rows,
                [("seed",)],
            )
        finally:
            ui.stop()
            driver.close()
            ledger.close()

    def test_toml_config_loader(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = os.path.join(tmp, "proxy.toml")
            with open(cfg_path, "w", encoding="utf-8") as fh:
                fh.write(
                    """
                    [backend]
                    engine = "postgres"
                    host = "db.internal"
                    port = 5439
                    user = "svc"
                    password = "pw"
                    database = "prod"

                    [proxy]
                    listen_host = "0.0.0.0"
                    pg_port = 15433
                    require_where_delete = true

                    [auth.users]
                    alice = "s1"
                    """
                )
            args = build_parser().parse_args(["--config", cfg_path])
            loaded = load_config_into_args(args)
            self.assertEqual(loaded.engine, "postgres")
            self.assertEqual(loaded.backend_host, "db.internal")
            self.assertEqual(loaded.backend_port, 5439)
            self.assertEqual(loaded.listen_host, "0.0.0.0")
            self.assertEqual(loaded.pg_port, 15433)
            self.assertTrue(loaded.require_where_delete)
            self.assertIn("alice:s1", loaded.auth_user)

    @unittest.skipUnless(shutil.which("openssl"), "openssl required for ephemeral TLS cert test")
    def test_tls_pgwire_and_https_web_ui(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cert_path = os.path.join(tmp, "cert.pem")
            key_path = os.path.join(tmp, "key.pem")
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    key_path,
                    "-out",
                    cert_path,
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=127.0.0.1",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            srv_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

            cli_ctx = ssl.create_default_context()
            cli_ctx.check_hostname = False
            cli_ctx.verify_mode = ssl.CERT_NONE

            driver = SQLiteDriver(":memory:")
            ledger = UndoLedger(":memory:")
            engine = ReverseProxyEngine(driver, ledger)

            pg_srv = PgWireServer(engine, host="127.0.0.1", port=0, ssl_context=srv_ctx)
            ui = ControlPlaneServer(engine, host="127.0.0.1", port=0, ssl_context=srv_ctx)
            loop = asyncio.new_event_loop()
            ready = threading.Event()

            def run_loop() -> None:
                asyncio.set_event_loop(loop)
                loop.run_until_complete(pg_srv.start())
                ready.set()
                try:
                    loop.run_forever()
                finally:
                    loop.run_until_complete(pg_srv.stop())
                    loop.close()

            t = threading.Thread(target=run_loop, daemon=True)
            t.start()
            ready.wait(timeout=5)
            ui.start()

            try:
                pg = PgWireClient(
                    host="127.0.0.1",
                    port=pg_srv.bound_port,
                    user="tls_user",
                    ssl_mode="require",
                    ssl_context=cli_ctx,
                )
                self.assertEqual(pg.query("SELECT 42 AS answer;")[0].rows, [(42,)])
                pg.close()

                with urllib.request.urlopen(
                    f"https://127.0.0.1:{ui.bound_port}/api/status",
                    context=cli_ctx,
                    timeout=5,
                ) as resp:
                    st = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(st["tls"])
            finally:
                ui.stop()
                loop.call_soon_threadsafe(loop.stop)
                t.join(timeout=5)
                driver.close()
                ledger.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
