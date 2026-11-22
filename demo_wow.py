#!/usr/bin/env python3
"""Self-contained end-to-end demonstration of SQL Undo Proxy.

Demonstrates:
  1. An AI agent deletes customer rows via the proxy.
  2. An unrelated application concurrently inserts and updates other rows.
  3. The operator inspects PROXY HISTORY and PROXY DIFF.
  4. PROXY REVERSE restores the deleted rows while preserving concurrent writes.
  5. A conflicting concurrent edit triggers PROXY REVERSE CONFLICT safely.
  6. Quarantined DROP TABLE is restored in milliseconds.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile

from reverse_proxy.drivers.sqlite_driver import SQLiteDriver
from reverse_proxy.engine import ReverseProxyEngine
from reverse_proxy.ledger import UndoLedger


def _banner(title: str) -> None:
    print(f"\n{'=' * 74}")
    print(f"  {title}")
    print(f"{'=' * 74}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sql_undo_demo_") as tmp:
        db_path = os.path.join(tmp, "app.db")
        ledger_path = os.path.join(tmp, "undo_ledger.db")

        driver = SQLiteDriver(db_path, max_capture_rows=10000)
        ledger = UndoLedger(ledger_path)
        engine = ReverseProxyEngine(
            driver,
            ledger,
            require_where_on_delete=True,
            require_where_on_update=True,
        )

        # Seed schema & initial customer data
        engine.execute_one(
            "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, tier TEXT);"
        )
        engine.execute_one("INSERT INTO customers VALUES (1, 'Alice', 'pro');")
        engine.execute_one("INSERT INTO customers VALUES (2, 'Bob', 'free');")
        engine.execute_one("INSERT INTO customers VALUES (3, 'Carol', 'pro');")

        _banner("1. AI Agent accidentally deletes all 'pro' customers")
        delete_res = engine.execute_one("DELETE FROM customers WHERE tier = 'pro';", actor="ai_agent")
        assert delete_res.tx_id is not None
        bad_tx_id = delete_res.tx_id
        print(f"Executed: DELETE FROM customers WHERE tier = 'pro';")
        print(f"Captured: tx_id={bad_tx_id} rows_affected={delete_res.rowcount}")

        _banner("2. Meanwhile, live application inserts & updates unrelated rows")
        app_conn = sqlite3.connect(db_path)
        app_conn.execute("INSERT INTO customers VALUES (4, 'Dave', 'enterprise');")
        app_conn.execute("UPDATE customers SET tier = 'plus' WHERE id = 2;")
        app_conn.commit()
        print("Live app rows before undo:", engine.execute_one("SELECT id, name, tier FROM customers ORDER BY id;").rows)

        _banner("3. Operator inspects PROXY HISTORY and PROXY DIFF")
        hist = engine.execute_one("PROXY HISTORY LIMIT 3;")
        for row in hist.rows:
            print(f"  tx_id={row[0]} actor={row[1]} status={row[3]} rows={row[4]} durability={row[7]} sql={row[6]}")
        diff = engine.execute_one(f"PROXY DIFF {bad_tx_id};")
        for row in diff.rows:
            print(f"  op={row[0]} table={row[1]} pk={row[2]} before={row[3]} after={row[4]}")

        _banner("4. Surgical PROXY REVERSE restores deleted rows without touching Dave or Bob")
        rev = engine.execute_one(f"PROXY REVERSE {bad_tx_id};")
        print("Reverse result:", rev.command_tag, rev.rows[0])
        rows_after = engine.execute_one("SELECT id, name, tier FROM customers ORDER BY id;").rows
        print("Live app rows after undo:", rows_after)
        assert rows_after == [
            (1, "Alice", "pro"),
            (2, "Bob", "plus"),
            (3, "Carol", "pro"),
            (4, "Dave", "enterprise"),
        ]

        _banner("5. Drift Protection: Conflicting concurrent edit refuses safely")
        upd_res = engine.execute_one("UPDATE customers SET tier = 'gold' WHERE id = 1;", actor="ai_agent")
        assert upd_res.tx_id is not None
        upd_tx = upd_res.tx_id
        # Out-of-band application modifies Alice's row after the proxy transaction
        app_conn.execute("UPDATE customers SET tier = 'custom_vip' WHERE id = 1;")
        app_conn.commit()
        conflict_rev = engine.execute_one(f"PROXY REVERSE {upd_tx};")
        print("Conflict response:", conflict_rev.command_tag, conflict_rev.rows[0])
        assert conflict_rev.command_tag == "PROXY REVERSE CONFLICT"

        _banner("6. Quarantined DROP TABLE restored in milliseconds")
        drop_res = engine.execute_one("DROP TABLE customers;", actor="ai_agent")
        assert drop_res.tx_id is not None
        drop_tx = drop_res.tx_id
        print(f"Quarantined DROP TABLE -> tx_id={drop_tx}")
        engine.execute_one(f"PROXY REVERSE {drop_tx};")
        restored_count = engine.execute_one("SELECT COUNT(*) FROM customers;").rows[0][0]
        print(f"Restored customers table with {restored_count} rows intact!")
        assert restored_count == 4

        app_conn.close()
        ledger.close()
        driver.close()
        print("\nAll 6 end-to-end demo checks passed.")


if __name__ == "__main__":
    main()
