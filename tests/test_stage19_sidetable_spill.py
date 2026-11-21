"""Stage 19 tests: Side-table capture, async spill worker lifecycle, cleanup, PG18 RETURNING OLD/NEW SQL, and MySQL BEGIN/UPDATE/ROLLBACK."""

from __future__ import annotations

import dataclasses
import os
import tempfile
import unittest
from typing import Any, Sequence

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import MySQLDriver, MySQLWireClient, PostgresDriver, SQLiteDriver
from reverse_proxy.drivers.mysql_client import MySQLResult
from reverse_proxy.drivers.pgwire_client import PgWireResult
from reverse_proxy.models import (
    MutationOp,
    ParsedStatement,
    QueryResult,
    ReversePlanStep,
    StatementKind,
    TableSchema,
)
from test_stage3_mysql import _SimulatedMySQLBackend
from test_stage10_isolation_auth import _DualProtocolServer


class _SideTableSQLiteDriver(SQLiteDriver):
    """Test driver extending SQLiteDriver with DB-side snapshot tables & async spill materialization."""

    def __init__(self, db_path: str, *, side_table_threshold: int = 3) -> None:
        super().__init__(db_path)
        self.side_table_threshold = side_table_threshold

    def _side_tables_present(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '_side_%' ORDER BY name;"
        ).fetchall()
        return [str(r[0]) for r in rows]

    def drop_side_tables(self, items: Sequence[tuple[str, str | None]]) -> None:
        for tname, _ in items:
            if tname:
                self._conn.execute(f'DROP TABLE IF EXISTS "{tname}";')
        self._conn.commit()

    def purge_quarantine_table(self, quarantine_name: str, schema: str | None = None) -> bool:
        exists = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?;", (quarantine_name,)
        ).fetchone()
        if exists:
            self._conn.execute(f'DROP TABLE IF EXISTS "{quarantine_name}";')
            self._conn.commit()
            return True
        return super().purge_quarantine_table(quarantine_name, schema)

    def materialize_side_op(self, op: MutationOp) -> tuple[MutationOp, list[str]]:
        drop_names: list[str] = []
        before_rows = list(op.before_rows)
        after_rows = list(op.after_rows)
        if op.side_table_before:
            cur = self._conn.execute(f'SELECT * FROM "{op.side_table_before}";')
            cols = [d[0] for d in cur.description]
            before_rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            drop_names.append(op.side_table_before)
        if op.side_table_after:
            cur = self._conn.execute(f'SELECT * FROM "{op.side_table_after}";')
            cols = [d[0] for d in cur.description]
            after_rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            drop_names.append(op.side_table_after)
        return (
            MutationOp(
                op_type=op.op_type,
                table=op.table,
                schema=op.schema,
                pk_columns=list(op.pk_columns),
                column_types=dict(op.column_types),
                before_rows=before_rows,
                after_rows=after_rows,
            ),
            drop_names,
        )

    def execute_and_capture(
        self,
        stmt: ParsedStatement,
        tx_id: str,
        *,
        in_client_tx: bool = False,
        params: Sequence[Any] = (),
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        if (
            stmt.kind in (StatementKind.UPDATE, StatementKind.DELETE)
            and stmt.table
            and not in_client_tx
        ):
            t_schema = self.inspect_table(stmt.table)
            where_sql = f" WHERE {stmt.where_clause}" if stmt.where_clause else ""
            cnt = int(
                self._conn.execute(
                    f'SELECT COUNT(*) FROM "{stmt.table}"{where_sql};', list(params)
                ).fetchone()[0]
            )
            if cnt > self.side_table_threshold and t_schema.pk_columns:
                sb = f"_side_b_{stmt.table}_{tx_id[-8:]}"
                sa = f"_side_a_{stmt.table}_{tx_id[-8:]}"
                self._conn.execute(
                    f'CREATE TABLE "{sb}" AS SELECT * FROM "{stmt.table}"{where_sql};',
                    list(params),
                )
                cur = self._conn.execute(stmt.raw_sql, list(params))
                if stmt.kind == StatementKind.UPDATE:
                    self._conn.execute(
                        f'CREATE TABLE "{sa}" AS SELECT * FROM "{stmt.table}"{where_sql};',
                        list(params),
                    )
                self._conn.commit()
                op = MutationOp(
                    op_type="UPDATE" if stmt.kind == StatementKind.UPDATE else "DELETE",
                    table=stmt.table,
                    schema="main",
                    pk_columns=t_schema.pk_columns,
                    column_types=t_schema.column_types,
                    side_table_before=sb,
                    side_table_after=(sa if stmt.kind == StatementKind.UPDATE else None),
                    side_rowcount=cur.rowcount,
                )
                tag = f"{op.op_type} {cur.rowcount}"
                return QueryResult(rowcount=cur.rowcount, command_tag=tag), [op], []
        return super().execute_and_capture(stmt, tx_id, in_client_tx=in_client_tx, params=params)

    def build_reverse_plan(self, record, *, force: bool = False, lock_rows: bool = False):
        steps: list[ReversePlanStep] = []
        for op in reversed(record.ops):
            if op.op_type == "UPDATE" and op.side_table_before and not op.before_rows:
                t_schema = self.inspect_table(op.table)
                non_pk = [c for c in t_schema.columns if c not in op.pk_columns]
                sets = ", ".join(f'"{c}" = b."{c}"' for c in non_pk)
                pk_eq = " AND ".join(f'"{op.table}"."{pk}" = b."{pk}"' for pk in op.pk_columns)
                steps.append(
                    ReversePlanStep(
                        description=f"SQL side-table restore {op.table}",
                        sql=f'UPDATE "{op.table}" SET {sets} FROM "{op.side_table_before}" AS b WHERE {pk_eq};',
                    )
                )
                continue
            if op.op_type == "DELETE" and op.side_table_before and not op.before_rows:
                t_schema = self.inspect_table(op.table)
                cols = ", ".join(f'"{c}"' for c in t_schema.columns)
                steps.append(
                    ReversePlanStep(
                        description=f"SQL side-table reinsert {op.table}",
                        sql=f'INSERT INTO "{op.table}" ({cols}) SELECT {cols} FROM "{op.side_table_before}";',
                    )
                )
                continue
            sub_rec = dataclasses.replace(record, ops=[op])
            s_part, c_part = super().build_reverse_plan(sub_rec, force=force)
            steps.extend(s_part)
            if c_part and not force:
                return steps, c_part
        return steps, []


class _RecordingPgWireClient:
    """Minimal recording stub for verifying PG 16 vs PG 18 side-table SQL generation."""

    def __init__(self, version_num: int) -> None:
        self.version_num = version_num
        self.executed: list[str] = []
        self.dropped: list[str] = []

    def query(self, sql: str) -> list[PgWireResult]:
        return self.execute(sql, ())

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        self.executed.append(sql)
        upper = sql.upper().strip()
        if "SHOW SERVER_VERSION_NUM" in upper:
            return PgWireResult(columns=["server_version_num"], rows=[(str(self.version_num),)], command_tag="SHOW")
        if "PG_CATALOG.PG_ATTRIBUTE" in upper and "FORMAT_TYPE" in upper:
            return PgWireResult(
                columns=["attname", "format_type"],
                rows=[("id", "integer"), ("score", "double precision")],
                command_tag="SELECT 2",
            )
        if "PG_CATALOG.PG_INDEX" in upper:
            return PgWireResult(columns=["attname"], rows=[("id",)], command_tag="SELECT 1")
        if "SELECT TO_REGCLASS" in upper:
            return PgWireResult(columns=["to_regclass"], rows=[("public.items",)], command_tag="SELECT 1")
        if "SELECT COUNT(*)" in upper:
            return PgWireResult(columns=["count"], rows=[(1000,)], command_tag="SELECT 1")
        if "SELECT 1 FROM" in upper and "LIMIT" in upper:
            return PgWireResult(columns=["?column?"], rows=[(1,)] * 101, command_tag="SELECT 101")
        if upper.startswith("DROP TABLE"):
            self.dropped.append(sql)
            return [PgWireResult(command_tag="DROP TABLE")]
        if "RETURNING OLD." in upper or "INSERT INTO" in upper or upper.startswith("WITH _"):
            res = PgWireResult(command_tag="INSERT 0 1000")
            return res if (upper.startswith("WITH ") or upper.startswith("INSERT ")) else [res]
        if upper.startswith("SELECT "):
            return [PgWireResult(columns=[], rows=[], command_tag="SELECT 0")]
        return [PgWireResult(command_tag="OK")]

    def copy_from_stdin(self, copy_sql: str, chunks: Any) -> PgWireResult:
        self.executed.append(copy_sql)
        _ = b"".join(chunks)
        return PgWireResult(command_tag="COPY 1000")

    def close(self) -> None:
        pass


class _RecordingMySQLClient:
    """Minimal recording stub for verifying MySQL side-table capture & drop SQL."""

    def __init__(self) -> None:
        self.executed: list[str] = []
        self.dropped: list[str] = []

    def query(self, sql: str) -> MySQLResult:
        return self.execute(sql, ())

    def execute(self, sql: str, params: Sequence[Any] = ()) -> MySQLResult:
        self.executed.append(sql)
        upper = sql.upper().strip()
        if "SELECT VERSION()" in upper:
            return MySQLResult(columns=["v"], rows=[("8.0.36",)])
        if "SELECT DATABASE()" in upper:
            return MySQLResult(columns=["db"], rows=[("app",)])
        if upper.startswith("SHOW COLUMNS FROM"):
            return MySQLResult(
                columns=["Field", "Type", "Null", "Key", "Default", "Extra"],
                rows=[("id", "int", "NO", "PRI", None, ""), ("score", "double", "YES", "", None, "")],
            )
        if "INFORMATION_SCHEMA.KEY_COLUMN_USAGE" in upper:
            return MySQLResult(
                columns=["COLUMN_NAME"],
                rows=[("id",)],
            )
        if "INFORMATION_SCHEMA.COLUMNS" in upper:
            return MySQLResult(
                columns=["COLUMN_NAME", "DATA_TYPE"],
                rows=[("id", "int"), ("score", "double")],
            )
        if "INFORMATION_SCHEMA.TABLES" in upper:
            return MySQLResult(columns=["c"], rows=[(1,)])
        if "SELECT COUNT(*)" in upper:
            return MySQLResult(columns=["c"], rows=[(1000,)])
        if "SELECT 1 FROM" in upper and "LIMIT" in upper:
            return MySQLResult(columns=["1"], rows=[(1,)] * 101)
        if upper.startswith("DROP TABLE"):
            self.dropped.append(sql)
            return MySQLResult()
        if upper.startswith("UPDATE"):
            return MySQLResult(affected_rows=1000)
        return MySQLResult()

    def close(self) -> None:
        pass


class TestStage19SideTableSpillAndRollback(unittest.TestCase):
    def test_side_table_direct_reverse_before_spill_and_zero_orphans_after_flush(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "app.db")
            ledger_path = os.path.join(tmp, "ledger.db")
            setup = _SideTableSQLiteDriver(db_path, side_table_threshold=3)
            setup.execute_and_capture(
                ParsedStatement(kind=StatementKind.OTHER_DDL, raw_sql="CREATE TABLE scores (id INTEGER PRIMARY KEY, val INTEGER);"),
                "tx_setup",
            )
            setup.close()

            ledger = UndoLedger(ledger_path, compress_threshold_bytes=64, spill_threshold_bytes=128)
            eng = ReverseProxyEngine(
                lambda: _SideTableSQLiteDriver(db_path, side_table_threshold=3),
                ledger,
                side_spill_delay_seconds=5.0,
            )
            try:
                eng.execute_one(
                    "INSERT INTO scores VALUES (1, 10), (2, 20), (3, 30), (4, 40), (5, 50), (6, 60);"
                )
                upd = eng.execute_one("UPDATE scores SET val = val + 100;")
                self.assertEqual(upd.rowcount, 6)
                tx_upd = upd.tx_id
                assert tx_upd is not None

                # Within spill delay window: side tables exist & PROXY REVERSE executes directly from _side_* without waiting!
                rec_unspilled = ledger.get_record(tx_upd)
                self.assertIsNotNone(rec_unspilled)
                self.assertIsNotNone(rec_unspilled.ops[0].side_table_before)
                self.assertEqual(len(eng.driver._side_tables_present()), 2)  # type: ignore[attr-defined]

                rev_u = eng.execute_one(f"PROXY REVERSE {tx_upd};")
                self.assertEqual(rev_u.command_tag, "PROXY REVERSE OK")
                self.assertIn("SQL side-table restore", rev_u.rows[0][1])
                self.assertEqual(
                    eng.execute_one("SELECT SUM(val) FROM scores;").rows[0][0],
                    210,
                )

                # Flushing spills materializes compressed disk spill & drops ALL _side_* tables cleanly
                eng.flush_spills(timeout=10.0)
                self.assertEqual(eng.driver._side_tables_present(), [])  # type: ignore[attr-defined]
                rec_spilled = ledger.get_record(tx_upd)
                self.assertIsNotNone(rec_spilled)
                self.assertIsNone(rec_spilled.ops[0].side_table_before)
                self.assertEqual(len(rec_spilled.ops[0].before_rows), 6)

                # Second bulk mutation: DELETE -> spill synchronously via PROXY DIFF -> reverse from materialized spill!
                del_res = eng.execute_one("DELETE FROM scores;")
                self.assertEqual(del_res.rowcount, 6)
                tx_del = del_res.tx_id
                assert tx_del is not None
                diff_res = eng.execute_one(f"PROXY DIFF {tx_del};")
                self.assertEqual(diff_res.command_tag, "PROXY DIFF")
                self.assertEqual(eng.driver._side_tables_present(), [])  # type: ignore[attr-defined]

                rev_d = eng.execute_one(f"PROXY REVERSE {tx_del};")
                self.assertEqual(rev_d.command_tag, "PROXY REVERSE OK")
                self.assertEqual(eng.execute_one("SELECT COUNT(*) FROM scores;").rows[0][0], 6)

                # Third bulk mutation purged BEFORE spill must also drop its _side_* tables immediately!
                upd2 = eng.execute_one("UPDATE scores SET val = val + 1;")
                assert upd2.tx_id is not None
                self.assertEqual(len(eng.driver._side_tables_present()), 2)  # type: ignore[attr-defined]
                p_tx = eng.execute_one(f"PROXY PURGE TX {upd2.tx_id};", actor="cleanup_bot")
                self.assertEqual(p_tx.rows[0][1], 1)
                self.assertEqual(eng.driver._side_tables_present(), [])  # type: ignore[attr-defined]
            finally:
                eng.close()
                ledger.close()

    def test_postgres_16_vs_18_side_table_sql_generation(self) -> None:
        pg16 = _RecordingPgWireClient(160004)
        d16 = PostgresDriver(client=pg16, side_table_threshold=100)
        stmt = ParsedStatement(kind=StatementKind.UPDATE, raw_sql="UPDATE items SET score = score + 1;", table="items")
        res16, ops16, _ = d16.execute_and_capture(stmt, "tx_16", in_client_tx=False)
        self.assertEqual(res16.rowcount, 1000)
        self.assertIsNotNone(ops16[0].side_table_before)
        self.assertTrue(any("FOR UPDATE;" in s for s in pg16.executed))
        self.assertTrue(any("WITH _u AS (UPDATE items SET score = score + 1 RETURNING *)" in s for s in pg16.executed))

        pg18 = _RecordingPgWireClient(180007)
        d18 = PostgresDriver(client=pg18, side_table_threshold=100)
        res18, ops18, _ = d18.execute_and_capture(stmt, "tx_18", in_client_tx=False)
        self.assertEqual(res18.rowcount, 1000)
        self.assertIsNotNone(ops18[0].side_table_before)
        self.assertFalse(any("SELECT" in s and "FOR UPDATE;" in s for s in pg18.executed))
        self.assertTrue(
            any('RETURNING OLD."id" AS _o0, OLD."score" AS _o1, NEW."id" AS _n0, NEW."score" AS _n1' in s for s in pg18.executed)
        )
        for key in ("blast_radius_check_s", "side_table_create_s", "snapshot_capture_s", "dml_exec_s", "commit_s"):
            self.assertIn(key, ops16[0].phase_timings)
            self.assertIn(key, ops18[0].phase_timings)
        d18.drop_side_tables([(ops18[0].side_table_before, "public"), (ops18[0].side_table_after or "", "public")])
        self.assertEqual(len(pg18.dropped), 2)

    def test_post_spill_temp_table_restore_path_postgres_and_mysql(self) -> None:
        from reverse_proxy.models import EngineType, ReversibilityStatus, UndoRecord

        before_rows = [{"id": i, "score": float(i)} for i in range(1, 151)]
        after_rows = [{"id": i, "score": float(i + 10)} for i in range(1, 151)]
        spilled_op = MutationOp(
            op_type="UPDATE",
            table="items",
            schema="public",
            pk_columns=["id"],
            column_types={"id": "integer", "score": "double precision"},
            before_rows=before_rows,
            after_rows=after_rows,
        )
        rec_pg = UndoRecord(
            tx_id="tx_spilled_pg",
            seq_no=1,
            created_at="2026-11-21T00:00:00Z",
            engine=EngineType.POSTGRES,
            session_id="s1",
            raw_sql="UPDATE items SET score = score + 10;",
            status=ReversibilityStatus.EXACT,
            ops=[spilled_op],
        )
        pg_cli = _RecordingPgWireClient(180007)
        d_pg = PostgresDriver(client=pg_cli, side_table_threshold=100)
        rev_pg = d_pg.apply_reverse(rec_pg, dry_run=False, force=False)
        self.assertTrue(rev_pg.success)
        self.assertEqual(rev_pg.restore_path, "spilled_temp_table")
        self.assertTrue(any("CREATE TEMP TABLE" in s and "ON COMMIT DROP" in s for s in pg_cli.executed))
        self.assertTrue(any("COPY " in s and "FROM STDIN" in s for s in pg_cli.executed))

        spilled_my_op = dataclasses.replace(spilled_op, schema="app")
        rec_my = dataclasses.replace(rec_pg, tx_id="tx_spilled_my", engine=EngineType.MYSQL, ops=[spilled_my_op])
        my_cli = _RecordingMySQLClient()
        d_my = MySQLDriver(client=my_cli, database="app", side_table_threshold=100)
        rev_my = d_my.apply_reverse(rec_my, dry_run=False, force=False)
        self.assertTrue(rev_my.success)
        self.assertEqual(rev_my.restore_path, "spilled_temp_table")
        self.assertTrue(any("CREATE TABLE `_reverse_quarantine`.`_rev_b_items_" in s for s in my_cli.executed))
        self.assertEqual(len(my_cli.dropped), 2)

    def test_mysql_side_table_capture_and_drop(self) -> None:
        my_cli = _RecordingMySQLClient()
        drv = MySQLDriver(client=my_cli, database="app", side_table_threshold=100)
        stmt = ParsedStatement(kind=StatementKind.UPDATE, raw_sql="UPDATE items SET score = score + 1;", table="items")
        res, ops, _ = drv.execute_and_capture(stmt, "tx_my", in_client_tx=False)
        self.assertEqual(res.rowcount, 1000)
        self.assertIsNotNone(ops[0].side_table_before)
        self.assertIsNotNone(ops[0].side_table_after)
        self.assertTrue(any("PRIMARY KEY (`id`)" in s and "ENGINE=InnoDB" in s for s in my_cli.executed))
        drv.drop_side_tables([(ops[0].side_table_before, "app"), (ops[0].side_table_after or "", "app")])
        self.assertEqual(len(my_cli.dropped), 2)

    def test_mysql_begin_update_rollback_writes_zero_undo_records(self) -> None:
        backend = _SimulatedMySQLBackend(default_db="app")
        backend.start()
        driver = MySQLDriver(host="127.0.0.1", port=backend.port, user="root", database="app")
        ledger = UndoLedger(":memory:")
        engine = ReverseProxyEngine(driver, ledger)
        srv = _DualProtocolServer(engine)
        srv.start()
        cli = MySQLWireClient(host="127.0.0.1", port=srv.mysql.bound_port, user="root", password="", database="app")
        try:
            cli.query("CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER);")
            tx_ins = cli.query("INSERT INTO accounts (id, balance) VALUES (1, 500), (2, 800);")
            self.assertEqual(tx_ins.affected_rows, 2)
            hist_before = cli.query("PROXY HISTORY 10;").rows

            cli.query("BEGIN;")
            self.assertTrue(cli.server_status & 0x0001)
            cli.query("UPDATE accounts SET balance = balance - 250 WHERE id = 1;")
            self.assertEqual(cli.query("SELECT balance FROM accounts WHERE id = 1;").rows, [(250,)])
            cli.query("ROLLBACK;")
            self.assertFalse(cli.server_status & 0x0001)

            self.assertEqual(cli.query("SELECT balance FROM accounts ORDER BY id;").rows, [(500,), (800,)])
            hist_after = cli.query("PROXY HISTORY 10;").rows
            self.assertEqual(len(hist_after), len(hist_before))
        finally:
            cli.close()
            srv.stop()
            engine.close()
            ledger.close()
            backend.stop()


if __name__ == "__main__":
    unittest.main()
