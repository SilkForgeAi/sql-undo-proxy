"""Stage 20 tests: Adversarial failure boundaries, crash-truncated side tables, concurrent direct writers, and CDC lag."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from typing import Any

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import PostgresDriver, SQLiteDriver
from reverse_proxy.models import (
    EngineType,
    MutationOp,
    ReversibilityStatus,
    UndoRecord,
)
from test_stage19_sidetable_spill import _RecordingPgWireClient, _SideTableSQLiteDriver


class TestStage20AdversarialSafety(unittest.TestCase):
    def test_1_crash_truncated_side_table_transitions_durability_and_fails_closed(self) -> None:
        """Priority 1: Unclean crash losing an unspilled _side_* table must report `unavailable` and fail closed."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "app.db")
            ledger_path = os.path.join(tmp, "ledger.db")
            setup = _SideTableSQLiteDriver(db_path, side_table_threshold=2)
            setup._conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, amount INTEGER);")
            setup._conn.executemany(
                "INSERT INTO orders VALUES (?, ?);", [(1, 100), (2, 200), (3, 300), (4, 400)]
            )
            setup._conn.commit()
            setup.close()

            ledger = UndoLedger(ledger_path, compress_threshold_bytes=64, spill_threshold_bytes=128)
            eng = ReverseProxyEngine(
                lambda: _SideTableSQLiteDriver(db_path, side_table_threshold=2),
                ledger,
                side_spill_delay_seconds=30.0,
            )
            try:
                upd = eng.execute_one("UPDATE orders SET amount = amount + 50;")
                tx_upd = upd.tx_id
                assert tx_upd is not None

                # Immediately after commit (before spill): durability is explicitly `capture_pending`
                hist1 = eng.execute_one("PROXY HISTORY 5;")
                self.assertEqual(hist1.columns[-1], "durability")
                row_upd = next(r for r in hist1.rows if r[0] == tx_upd)
                self.assertEqual(row_upd[7], "capture_pending")

                # Simulate an unclean database crash that drops/truncates unspilled _side_* tables before background spill
                rec_pending = ledger.get_record(tx_upd)
                assert rec_pending is not None
                sb = rec_pending.ops[0].side_table_before
                sa = rec_pending.ops[0].side_table_after
                raw_conn = sqlite3.connect(db_path)
                raw_conn.execute(f'DROP TABLE IF EXISTS "{sb}";')
                raw_conn.execute(f'DROP TABLE IF EXISTS "{sa}";')
                raw_conn.commit()
                raw_conn.close()

                # Attempt PROXY REVERSE on the crash-damaged unspilled record -> must FAIL CLOSED (never succeed with 0 rows!)
                rev_res = eng.reverse(tx_upd)
                self.assertFalse(rev_res.success)
                self.assertIn("unspilled side-table snapshot", rev_res.error or "")

                # Ledger durability state is now permanently updated to `unavailable`
                hist2 = eng.execute_one("PROXY HISTORY 5;")
                row_after = next(r for r in hist2.rows if r[0] == tx_upd)
                self.assertEqual(row_after[7], "unavailable")

                # Subsequent reverse attempt immediately refuses with unavailable durability error
                rev_again = eng.reverse(tx_upd)
                self.assertFalse(rev_again.success)
                self.assertIn("unavailable", rev_again.error or "")

                # Also verify PostgresDriver fails closed when an UNLOGGED _side_* table is empty after crash recovery
                class _EmptySideTablePgClient(_RecordingPgWireClient):
                    def execute(self, sql: str, params: Any = ()) -> Any:
                        if "SELECT 1 FROM" in sql.upper() and "_SIDE_B_" in sql.upper():
                            from reverse_proxy.drivers.pgwire_client import PgWireResult
                            return [PgWireResult(columns=["?column?"], rows=[], command_tag="SELECT 0")]
                        return super().execute(sql, params)

                pg_cli = _EmptySideTablePgClient(160004)
                pg_drv = PostgresDriver(client=pg_cli, side_table_threshold=100)
                rec_pg_crash = UndoRecord(
                    tx_id="tx_pg_unlogged_truncated",
                    seq_no=1,
                    created_at="2026-11-21T00:00:00Z",
                    engine=EngineType.POSTGRES,
                    session_id="s1",
                    raw_sql="DELETE FROM items;",
                    status=ReversibilityStatus.EXACT,
                    ops=[
                        MutationOp(
                            op_type="DELETE",
                            table="items",
                            schema="public",
                            pk_columns=["id"],
                            column_types={"id": "integer", "score": "double precision"},
                            side_table_before="_side_b_items_crash",
                            side_rowcount=500,
                        )
                    ],
                )
                pg_rev = pg_drv.apply_reverse(rec_pg_crash)
                self.assertFalse(pg_rev.success)
                self.assertIn("Empty/truncated unspilled side-table snapshot", pg_rev.error or "")
            finally:
                eng.close()
                ledger.close()

    def test_2_direct_writer_races_overlapping_updates_key_reuse_absent_row_and_schema_drift(self) -> None:
        """Priority 2: Surgical undo preserves unrelated direct writes and refuses on overlapping edits, key reuse, absent rows, or dropped columns."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "app.db")
            ledger_path = os.path.join(tmp, "ledger.db")
            drv = SQLiteDriver(db_path)
            ledger = UndoLedger(ledger_path)
            eng = ReverseProxyEngine(drv, ledger)
            direct_app = sqlite3.connect(db_path)
            try:
                eng.execute_one(
                    "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, tier TEXT);"
                )
                eng.execute_one(
                    "INSERT INTO customers VALUES (1, 'Alice', 'pro'), (2, 'Bob', 'free'), (3, 'Carol', 'pro');"
                )

                # A. Agent accidentally deletes pro customers (id=1, 3) while direct app connection inserts id=4 & updates id=2
                tx_del = eng.execute_one("DELETE FROM customers WHERE tier = 'pro';").tx_id
                assert tx_del is not None
                direct_app.execute("INSERT INTO customers VALUES (4, 'Dave', 'enterprise');")
                direct_app.execute("UPDATE customers SET tier = 'plus' WHERE id = 2;")
                direct_app.commit()

                # Surgical undo restores Alice (1) and Carol (3) WITHOUT rewinding Bob (2) or Dave (4)!
                rev_ok = eng.execute_one(f"PROXY REVERSE {tx_del};")
                self.assertEqual(rev_ok.command_tag, "PROXY REVERSE OK")
                rows = eng.execute_one("SELECT id, name, tier FROM customers ORDER BY id;").rows
                self.assertEqual(
                    rows,
                    [
                        (1, "Alice", "pro"),
                        (2, "Bob", "plus"),
                        (3, "Carol", "pro"),
                        (4, "Dave", "enterprise"),
                    ],
                )

                # B. Key reuse after DELETE: agent deletes id=3, direct app re-inserts id=3 with different data -> refuses!
                tx_del2 = eng.execute_one("DELETE FROM customers WHERE id = 3;").tx_id
                assert tx_del2 is not None
                direct_app.execute("INSERT INTO customers VALUES (3, 'charlie_reused_pk', 'vip');")
                direct_app.commit()
                rev_pk_reuse = eng.execute_one(f"PROXY REVERSE {tx_del2};")
                self.assertEqual(rev_pk_reuse.command_tag, "PROXY REVERSE CONFLICT")
                self.assertIn("same primary key was inserted since DELETE", rev_pk_reuse.rows[0][5])
                # Restore id=3 via FORCE
                self.assertEqual(
                    eng.execute_one(f"PROXY REVERSE {tx_del2} FORCE;").command_tag,
                    "PROXY REVERSE OK",
                )

                # C. Absent-row conflict after UPDATE: agent updates id=1, direct app deletes id=1 -> refuses!
                tx_upd1 = eng.execute_one("UPDATE customers SET tier = 'max' WHERE id = 1;").tx_id
                assert tx_upd1 is not None
                direct_app.execute("DELETE FROM customers WHERE id = 1;")
                direct_app.commit()
                rev_absent = eng.execute_one(f"PROXY REVERSE {tx_upd1};")
                self.assertEqual(rev_absent.command_tag, "PROXY REVERSE CONFLICT")
                self.assertIn("deleted since UPDATE", rev_absent.rows[0][5])

                # D. Overlapping column modification after UPDATE: agent updates id=2, direct app modifies id=2 -> refuses!
                tx_upd2 = eng.execute_one("UPDATE customers SET tier = 'gold' WHERE id = 2;").tx_id
                assert tx_upd2 is not None
                direct_app.execute("UPDATE customers SET tier = 'platinum' WHERE id = 2;")
                direct_app.commit()
                rev_overlap = eng.execute_one(f"PROXY REVERSE {tx_upd2};")
                self.assertEqual(rev_overlap.command_tag, "PROXY REVERSE CONFLICT")
                self.assertIn("modified since UPDATE", rev_overlap.rows[0][5])
            finally:
                direct_app.close()
                eng.close()
                ledger.close()

    def test_3_ledger_write_failure_surfaces_explicitly_without_silent_success(self) -> None:
        """Priority 3: If the undo ledger write fails after DB execution, the proxy must raise an explicit error rather than silently returning OK."""
        drv = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        eng = ReverseProxyEngine(drv, ledger)
        try:
            eng.execute_one("CREATE TABLE items (id INTEGER PRIMARY KEY, v TEXT);")
            orig_record = ledger.record_transaction

            def _failing_record(**kwargs: Any) -> UndoRecord:
                raise sqlite3.OperationalError("simulated disk full on undo_ledger.db")

            ledger.record_transaction = _failing_record  # type: ignore[method-assign]
            with self.assertRaises(sqlite3.OperationalError):
                eng.execute_one("INSERT INTO items VALUES (1, 'unrecorded');")
            ledger.record_transaction = orig_record  # type: ignore[method-assign]
        finally:
            eng.close()
            ledger.close()

    def test_4_explicit_tx_savepoints_partial_rollback_and_session_disconnect(self) -> None:
        """Priority 4: Multi-statement BEGIN + SAVEPOINT + ROLLBACK TO SAVEPOINT + COMMIT records only surviving mutations; abrupt disconnect discards uncommitted ops."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "app.db")
            ledger = UndoLedger(":memory:")
            eng = ReverseProxyEngine(lambda: SQLiteDriver(db_path), ledger)
            try:
                eng.execute_one("CREATE TABLE ledger_test (id INTEGER PRIMARY KEY, note TEXT);", session_id="s1")

                # Session 1: BEGIN -> INSERT 1 -> SAVEPOINT sp1 -> INSERT 2 -> ROLLBACK TO sp1 -> INSERT 3 -> COMMIT
                eng.execute_one("BEGIN;", session_id="s1")
                eng.execute_one("INSERT INTO ledger_test VALUES (1, 'kept_one');", session_id="s1")
                eng.execute_one("SAVEPOINT sp1;", session_id="s1")
                eng.execute_one("INSERT INTO ledger_test VALUES (2, 'rolled_back_two');", session_id="s1")
                eng.execute_one("ROLLBACK TO SAVEPOINT sp1;", session_id="s1")
                eng.execute_one("INSERT INTO ledger_test VALUES (3, 'kept_three');", session_id="s1")
                c_res = eng.execute_one("COMMIT;", session_id="s1")
                assert c_res.tx_id is not None

                rec = ledger.get_record(c_res.tx_id)
                assert rec is not None
                captured_ids = sorted(op.after_rows[0]["id"] for op in rec.ops)
                self.assertEqual(captured_ids, [1, 3])

                # Session 2: Opens BEGIN, mutates, then disconnects abruptly without COMMIT
                eng.execute_one("BEGIN;", session_id="s_drop")
                eng.execute_one("INSERT INTO ledger_test VALUES (99, 'uncommitted_drop');", session_id="s_drop")
                eng.close_session("s_drop")

                # Verify id=99 was never committed and never written to the undo ledger
                rows = eng.execute_one("SELECT id FROM ledger_test ORDER BY id;", session_id="s1").rows
                self.assertEqual(rows, [(1,), (3,)])
                self.assertEqual(len(eng.history(limit=10)), 1)

                # Reversing c_res.tx_id cleanly removes both id=1 and id=3
                rev = eng.reverse(c_res.tx_id)
                self.assertTrue(rev.success)
                self.assertEqual(
                    eng.execute_one("SELECT COUNT(*) FROM ledger_test;", session_id="s1").rows[0][0],
                    0,
                )
            finally:
                eng.close()
                ledger.close()

    def test_6_delayed_cdc_stream_flushes_before_reverse_executes(self) -> None:
        """Priority 6: When WAL/binlog poller has delayed in-flight trigger events, reverse() flushes them via wal_sync_fn before building the reverse plan."""
        drv = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        eng = ReverseProxyEngine(drv, ledger)
        try:
            eng.execute_one("CREATE TABLE payments (id INTEGER PRIMARY KEY, amount INTEGER);")
            eng.execute_one("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, payment_id INTEGER, msg TEXT);")

            ins = eng.execute_one("INSERT INTO payments VALUES (10, 500);")
            tx_id = ins.tx_id
            assert tx_id is not None

            # Simulate a database trigger side effect that wrote to `audit_log`, still sitting in the WAL/binlog buffer
            drv._conn.execute("INSERT INTO audit_log VALUES (1, 10, 'trigger_fired');")
            drv._conn.commit()
            flushed = False

            def _delayed_wal_sync() -> None:
                nonlocal flushed
                if not flushed:
                    flushed = True
                    ledger.append_ops(
                        tx_id,
                        [
                            MutationOp(
                                op_type="INSERT",
                                table="audit_log",
                                schema="main",
                                pk_columns=["id"],
                                column_types={"id": "INTEGER", "payment_id": "INTEGER", "msg": "TEXT"},
                                after_rows=[{"id": 1, "payment_id": 10, "msg": "trigger_fired"}],
                            )
                        ],
                        warning="Captured delayed trigger side effect.",
                    )

            eng.wal_sync_fn = _delayed_wal_sync

            # Calling reverse(tx_id) must invoke wal_sync_fn FIRST, attach the delayed audit_log op, and reverse BOTH tables atomically!
            rev = eng.reverse(tx_id)
            self.assertTrue(rev.success)
            self.assertTrue(flushed)
            self.assertEqual(eng.execute_one("SELECT COUNT(*) FROM payments;").rows[0][0], 0)
            self.assertEqual(eng.execute_one("SELECT COUNT(*) FROM audit_log;").rows[0][0], 0)
        finally:
            eng.close()
            ledger.close()


if __name__ == "__main__":
    unittest.main()
