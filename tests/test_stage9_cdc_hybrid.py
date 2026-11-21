"""Stage 9 tests: Hybrid CDC / WAL ingestion closing trigger & stored-procedure blind spots."""

from __future__ import annotations

import unittest

from reverse_proxy import (
    CDCChangeEvent,
    CDCIngestor,
    EngineType,
    ReverseProxyEngine,
    ReversibilityStatus,
    UndoLedger,
)
from reverse_proxy.drivers import SQLiteDriver


class TestStage9CDCHybrid(unittest.TestCase):
    def test_cdc_ingestor_captures_trigger_side_effects_and_reverses_atomically(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        cdc = CDCIngestor(ledger, EngineType.SQLITE)

        try:
            # Database has a trigger: updating `accounts` automatically updates `ledger_totals`
            # and inserts a row into `audit_trail`.
            engine.execute(
                """
                CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER);
                CREATE TABLE ledger_totals (id INTEGER PRIMARY KEY, total INTEGER);
                CREATE TABLE audit_trail (id INTEGER PRIMARY KEY, account_id INTEGER, delta INTEGER);
                INSERT INTO accounts (id, balance) VALUES (1, 100);
                INSERT INTO ledger_totals (id, total) VALUES (1, 100);
                """
            )
            # Simulate DB state after `UPDATE accounts SET balance = 250 WHERE id = 1;`
            # where an internal trigger also bumped `ledger_totals` and wrote `audit_trail`:
            driver._conn.execute("UPDATE accounts SET balance = 250 WHERE id = 1;")
            driver._conn.execute("UPDATE ledger_totals SET total = 250 WHERE id = 1;")
            driver._conn.execute("INSERT INTO audit_trail (id, account_id, delta) VALUES (10, 1, 150);")

            # CDC / WAL stream delivers all three correlated changes under one tx_id
            tx_id = "tx_wal_0001"
            cdc.begin_marker(
                tx_id,
                session_id="pg_app_1",
                raw_sql="UPDATE accounts SET balance = 250 WHERE id = 1",
            )
            cdc.ingest_debezium_envelope(
                {
                    "payload": {
                        "op": "u",
                        "source": {"table": "accounts"},
                        "pk_columns": ["id"],
                        "before": {"id": 1, "balance": 100},
                        "after": {"id": 1, "balance": 250},
                        "transaction": {"id": tx_id},
                    }
                }
            )
            cdc.ingest_debezium_envelope(
                {
                    "payload": {
                        "op": "u",
                        "source": {"table": "ledger_totals"},
                        "pk_columns": ["id"],
                        "before": {"id": 1, "total": 100},
                        "after": {"id": 1, "total": 250},
                        "transaction": {"id": tx_id},
                    }
                }
            )
            cdc.ingest_debezium_envelope(
                {
                    "payload": {
                        "op": "c",
                        "source": {"table": "audit_trail"},
                        "pk_columns": ["id"],
                        "before": None,
                        "after": {"id": 10, "account_id": 1, "delta": 150},
                        "transaction": {"id": tx_id},
                    }
                }
            )
            rec = cdc.commit_tx(tx_id)
            self.assertIsNotNone(rec)
            self.assertEqual(rec.status, ReversibilityStatus.EXACT)
            self.assertEqual(len(rec.ops), 3)

            # Reversing via the normal engine reverses ALL 3 tables in reverse order!
            rev = engine.reverse(tx_id)
            self.assertTrue(rev.success, msg=rev.error)
            self.assertEqual(
                engine.execute_one("SELECT balance FROM accounts WHERE id = 1;").rows,
                [(100,)],
            )
            self.assertEqual(
                engine.execute_one("SELECT total FROM ledger_totals WHERE id = 1;").rows,
                [(100,)],
            )
            self.assertEqual(
                engine.execute_one("SELECT COUNT(*) FROM audit_trail;").rows[0][0],
                0,
            )
        finally:
            driver.close()
            ledger.close()

    def test_cdc_rollback_discards_and_causal_graph_links_cdc_records(self) -> None:
        driver = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        cdc = CDCIngestor(ledger, EngineType.SQLITE)
        try:
            engine.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, qty INTEGER);")
            driver._conn.execute("INSERT INTO items (id, qty) VALUES (1, 10);")

            cdc.ingest_event(
                CDCChangeEvent(
                    op="c",
                    table="items",
                    pk_columns=["id"],
                    after={"id": 1, "qty": 10},
                    tx_id="tx_cdc_1",
                )
            )
            cdc.commit_tx("tx_cdc_1")

            # Rolled-back CDC tx produces nothing
            cdc.ingest_event(
                CDCChangeEvent(
                    op="d",
                    table="items",
                    pk_columns=["id"],
                    before={"id": 1, "qty": 10},
                    tx_id="tx_cdc_aborted",
                )
            )
            cdc.rollback_tx("tx_cdc_aborted")
            self.assertIsNone(ledger.get_record("tx_cdc_aborted"))

            # Subsequent SQL update through the proxy links causally to the CDC insert!
            tx_sql_upd = engine.execute_one("UPDATE items SET qty = 25 WHERE id = 1;").tx_id
            plan = engine.analyze_dependencies("tx_cdc_1")
            self.assertEqual(plan.ordered_tx_ids, [tx_sql_upd, "tx_cdc_1"])

            res = engine.reverse("tx_cdc_1", cascade=True)
            self.assertTrue(res.success, msg=res.error)
            self.assertEqual(engine.execute_one("SELECT COUNT(*) FROM items;").rows[0][0], 0)
        finally:
            driver.close()
            ledger.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
