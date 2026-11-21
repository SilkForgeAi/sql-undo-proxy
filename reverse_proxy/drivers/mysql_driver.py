"""MySQL EngineDriver implementation (handles pre-image capture without RETURNING, `<=>` drift checks, and quarantine DB renames)."""

from __future__ import annotations

import dataclasses
import json
import re
import time
import uuid
from collections.abc import Sequence
from contextlib import contextmanager
from typing import Any, Iterator

from ..models import (
    BlastRadiusExceededError,
    DriftConflict,
    EngineType,
    ForeignKeyEdge,
    MutationOp,
    ParsedStatement,
    QueryResult,
    ReversePlanStep,
    ReverseResult,
    StatementKind,
    TableSchema,
    UndoRecord,
)
from ..parser import extract_insert_value_dicts, tokenize, unquote_ident
from .base import EngineDriver
from .mysql_client import MySQLError, MySQLResult, MySQLWireClient

QUARANTINE_DB = "_reverse_quarantine"


class MySQLDriver(EngineDriver):
    """EngineDriver for MySQL 5.7/8.0+ using pure-Python wire transport."""

    engine_type = EngineType.MYSQL

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 3306,
        user: str = "root",
        password: str = "",
        database: str = "app",
        max_capture_rows: int | None = None,
        client: MySQLWireClient | None = None,
        binlog_marker_enabled: bool = False,
        side_table_threshold: int = 500,
    ) -> None:
        self._owns_client = client is None
        self.max_capture_rows = max_capture_rows
        self.binlog_marker_enabled = binlog_marker_enabled
        self.side_table_threshold = side_table_threshold
        self._marker_table_ready = False
        self._is_real_mysql: bool | None = None
        self._last_commit_s: float = 0.0
        self._conn_params = {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "database": database,
        }
        self._client = client or MySQLWireClient(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
        )
        self._default_db = database

    def _ensure_marker_table(self) -> None:
        if self._marker_table_ready:
            return
        try:
            qdb = self.quote_ident(QUARANTINE_DB)
            self._client.query(f"CREATE DATABASE IF NOT EXISTS {qdb};")
            self._client.query(
                f"CREATE TABLE IF NOT EXISTS {qdb}.`_proxy_wal_marker` ("
                f"`id` TINYINT PRIMARY KEY, `payload` VARCHAR(255) NOT NULL"
                f") ENGINE=InnoDB;"
            )
            self._marker_table_ready = True
        except Exception:
            pass

    def _maybe_emit_binlog_marker(
        self,
        *,
        tx_id: str | None = None,
        is_reverse: bool = False,
        db: str | None = None,
        table: str | None = None,
    ) -> None:
        if not self.binlog_marker_enabled:
            return
        if is_reverse:
            meta: dict[str, Any] = {"is_reverse": True}
        else:
            meta = {"tx_id": tx_id}
            if table and not self._table_has_triggers(table, db or self._default_db):
                meta["skip_binlog_dml"] = True
        payload = json.dumps(meta)
        try:
            qdb = self.quote_ident(QUARANTINE_DB)
            self._client.execute(
                f"INSERT INTO {qdb}.`_proxy_wal_marker` (`id`, `payload`) VALUES (1, ?) "
                f"ON DUPLICATE KEY UPDATE `payload` = VALUES(`payload`);",
                [payload],
            )
        except Exception:
            pass

    def _table_has_triggers(self, table: str, db: str) -> bool:
        try:
            res = self._client.execute(
                "SELECT 1 FROM INFORMATION_SCHEMA.TRIGGERS "
                "WHERE EVENT_OBJECT_SCHEMA = ? AND EVENT_OBJECT_TABLE = ? LIMIT 1;",
                [db, table],
            )
            return bool(res.rows)
        except Exception:
            return False

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def quote_ident(self, name: str) -> str:
        return "`" + name.replace("`", "``") + "`"

    def _current_db(self) -> str:
        res = self._client.query("SELECT DATABASE();")
        if res.rows and res.rows[0][0]:
            return str(res.rows[0][0])
        return self._default_db

    def _qualify(self, table: str, schema: str | None = None) -> str:
        db = schema or self._current_db()
        if db:
            return f"{self.quote_ident(db)}.{self.quote_ident(table)}"
        return self.quote_ident(table)

    def _table_exists(self, table: str, schema: str | None = None) -> bool:
        db = schema or self._current_db()
        res = self._client.execute(
            "SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? LIMIT 1;",
            [db, table],
        )
        return bool(res.rows)

    def inspect_table(self, table: str, schema: str | None = None) -> TableSchema:
        db = schema or self._current_db()
        col_res = self._client.execute(
            """
            SELECT COLUMN_NAME, DATA_TYPE
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
            ORDER BY ORDINAL_POSITION;
            """,
            [db, table],
        )
        if not col_res.rows:
            raise ValueError(f"Table '{db}.{table}' does not exist or has no columns.")

        columns = [str(r[0]) for r in col_res.rows]
        column_types = {str(r[0]): str(r[1]) for r in col_res.rows}

        pk_res = self._client.execute(
            """
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'
            ORDER BY ORDINAL_POSITION;
            """,
            [db, table],
        )
        pk_columns = [str(r[0]) for r in pk_res.rows]
        if not pk_columns:
            # No explicit PK: match on full column tuple
            pk_columns = list(columns)

        return TableSchema(
            table=table,
            schema=db,
            columns=columns,
            pk_columns=pk_columns,
            column_types=column_types,
            using_rowid_fallback=False,
        )

    def inspect_foreign_keys(self) -> list[ForeignKeyEdge]:
        db = self._current_db()
        sql = """
            SELECT
                kcu.TABLE_NAME,
                kcu.COLUMN_NAME,
                kcu.REFERENCED_TABLE_NAME,
                kcu.REFERENCED_COLUMN_NAME,
                rc.DELETE_RULE,
                kcu.CONSTRAINT_NAME
            FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE kcu
            JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS rc
              ON rc.CONSTRAINT_SCHEMA = kcu.TABLE_SCHEMA
             AND rc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME
            WHERE kcu.TABLE_SCHEMA = ?
              AND kcu.REFERENCED_TABLE_NAME IS NOT NULL
            ORDER BY kcu.CONSTRAINT_NAME, kcu.ORDINAL_POSITION;
        """
        try:
            res = self._client.execute(sql, [db])
        except Exception:
            return []
        if not res.rows:
            return []
        grouped: dict[str, list[tuple[Any, ...]]] = {}
        for row in res.rows:
            grouped.setdefault(str(row[5]), []).append(row)
        edges: list[ForeignKeyEdge] = []
        for rows in grouped.values():
            edges.append(
                ForeignKeyEdge(
                    child_table=str(rows[0][0]),
                    child_columns=[str(r[1]) for r in rows],
                    parent_table=str(rows[0][2]),
                    parent_columns=[str(r[3]) for r in rows],
                    on_delete=str(rows[0][4] or "NO ACTION").upper(),
                    schema=db,
                )
            )
        return edges

    @contextmanager
    def _ensure_tx(self, in_client_tx: bool) -> Iterator[None]:
        if in_client_tx:
            self._last_commit_s = 0.0
            yield
            return
        self._client.query("BEGIN;")
        try:
            yield
        except Exception:
            try:
                self._client.query("ROLLBACK;")
            except Exception:
                pass
            raise
        else:
            t_c0 = time.perf_counter()
            self._client.query("COMMIT;")
            self._last_commit_s = time.perf_counter() - t_c0

    def begin_tx(self) -> None:
        self._client.query("BEGIN;")

    def commit_tx(self) -> None:
        self._client.query("COMMIT;")

    def rollback_tx(self) -> None:
        self._client.query("ROLLBACK;")

    def savepoint(self, name: str) -> None:
        self._client.query(f"SAVEPOINT {self.quote_ident(name)};")

    def rollback_to_savepoint(self, name: str) -> None:
        self._client.query(f"ROLLBACK TO SAVEPOINT {self.quote_ident(name)};")

    def release_savepoint(self, name: str) -> None:
        self._client.query(f"RELEASE SAVEPOINT {self.quote_ident(name)};")

    def execute_read(self, sql: str, params: Sequence[Any] = ()) -> QueryResult:
        res = self._client.execute(sql, params)
        return QueryResult(
            columns=res.columns,
            rows=res.rows,
            rowcount=len(res.rows) if res.columns else res.affected_rows,
            command_tag="SELECT",
        )

    @staticmethod
    def _res_to_dicts(res: MySQLResult) -> list[dict[str, Any]]:
        if not res.columns:
            return []
        return [dict(zip(res.columns, r)) for r in res.rows]

    def execute_and_capture(
        self,
        stmt: ParsedStatement,
        tx_id: str,
        *,
        in_client_tx: bool,
        params: Sequence[Any] = (),
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        warnings = list(stmt.warnings)

        if stmt.kind == StatementKind.DROP_TABLE:
            return self._execute_quarantine_drop(
                stmt, tx_id, in_client_tx=in_client_tx, warnings=warnings
            )

        if stmt.kind == StatementKind.TRUNCATE_TABLE:
            return self._execute_quarantine_truncate(
                stmt, tx_id, in_client_tx=in_client_tx, warnings=warnings
            )

        if stmt.kind == StatementKind.ALTER_TABLE:
            return self._execute_alter_table(
                stmt, tx_id, in_client_tx=in_client_tx, warnings=warnings
            )

        if stmt.kind in (StatementKind.CREATE_INDEX, StatementKind.DROP_INDEX):
            return self._execute_index_ddl(
                stmt, in_client_tx=in_client_tx, warnings=warnings
            )

        if stmt.kind in (StatementKind.OTHER_DDL, StatementKind.OTHER):
            with self._ensure_tx(in_client_tx):
                res = self._client.execute(stmt.raw_sql, params)
            return (
                QueryResult(
                    rowcount=res.affected_rows,
                    command_tag=stmt.kind.value.upper(),
                    warnings=warnings,
                ),
                [],
                warnings,
            )

        if not stmt.table:
            raise ValueError(f"Could not determine target table for statement: {stmt.raw_sql}")

        if self.binlog_marker_enabled and not in_client_tx and not self._marker_table_ready:
            self._ensure_marker_table()

        if stmt.kind == StatementKind.INSERT:
            return self._execute_insert(
                stmt, tx_id=tx_id, in_client_tx=in_client_tx, params=params, warnings=warnings
            )
        if stmt.kind == StatementKind.UPDATE:
            return self._execute_update(
                stmt, tx_id=tx_id, in_client_tx=in_client_tx, params=params, warnings=warnings
            )
        if stmt.kind == StatementKind.DELETE:
            return self._execute_delete(
                stmt, tx_id=tx_id, in_client_tx=in_client_tx, params=params, warnings=warnings
            )

        raise ValueError(f"Unsupported mutating statement kind: {stmt.kind}")

    def _execute_quarantine_drop(
        self,
        stmt: ParsedStatement,
        tx_id: str,
        *,
        in_client_tx: bool,
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        targets = stmt.drop_targets or ([(stmt.schema, stmt.table)] if stmt.table else [])
        if not targets:
            raise ValueError(f"Could not determine target table for DROP TABLE: {stmt.raw_sql}")
        default_db = self._current_db()
        existing: list[tuple[str, str, TableSchema, str]] = []
        for t_sch, t_tbl in targets:
            db = t_sch or default_db
            if not self._table_exists(t_tbl, db):
                if stmt.if_exists:
                    continue
                raise MySQLError(f"Unknown table '{db}.{t_tbl}'", code=1051, sqlstate="42S02")
            t_schema = self.inspect_table(t_tbl, db)
            existing.append((db, t_tbl, t_schema, f"{t_tbl}__{tx_id}"))

        if not existing:
            return (
                QueryResult(rowcount=0, command_tag="DROP TABLE", warnings=warnings),
                [],
                warnings,
            )

        self._client.query(f"CREATE DATABASE IF NOT EXISTS {self.quote_ident(QUARANTINE_DB)};")
        renames = ", ".join(
            f"{self._qualify(t_tbl, db)} TO {self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(q_name)}"
            for db, t_tbl, _ts, q_name in existing
        )
        self._client.query(f"RENAME TABLE {renames};")

        ops = [
            MutationOp(
                op_type="QUARANTINE_DROP",
                table=t_tbl,
                schema=db,
                pk_columns=t_schema.pk_columns,
                column_types=t_schema.column_types,
                quarantine_name=q_name,
            )
            for db, t_tbl, t_schema, q_name in existing
        ]
        return (
            QueryResult(rowcount=0, command_tag="DROP TABLE", warnings=warnings),
            ops,
            warnings,
        )

    def _execute_quarantine_truncate(
        self,
        stmt: ParsedStatement,
        tx_id: str,
        *,
        in_client_tx: bool,
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        db = stmt.schema or self._current_db()
        if not self._table_exists(stmt.table, db):
            raise MySQLError(f"Table '{db}.{stmt.table}' doesn't exist", code=1146, sqlstate="42S02")

        t_schema = self.inspect_table(stmt.table, db)
        quarantine_name = f"{stmt.table}__{tx_id}"
        tmp_new_name = f"__proxy_trunc_new__{tx_id}__{stmt.table}"
        orig_qual = self._qualify(stmt.table, db)
        tmp_qual = self._qualify(tmp_new_name, db)
        q_qual = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(quarantine_name)}"

        self._client.query(f"CREATE DATABASE IF NOT EXISTS {self.quote_ident(QUARANTINE_DB)};")
        self._client.query(f"CREATE TABLE {tmp_qual} LIKE {orig_qual};")
        self._client.query(f"RENAME TABLE {orig_qual} TO {q_qual}, {tmp_qual} TO {orig_qual};")

        op = MutationOp(
            op_type="QUARANTINE_TRUNCATE",
            table=stmt.table,
            schema=db,
            pk_columns=t_schema.pk_columns,
            column_types=t_schema.column_types,
            quarantine_name=quarantine_name,
        )
        return (
            QueryResult(rowcount=0, command_tag="TRUNCATE TABLE", warnings=warnings),
            [op],
            warnings,
        )

    def _mysql_col_def(self, db: str, table: str, col: str) -> dict[str, Any] | None:
        res = self._client.execute(
            """
            SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND LOWER(COLUMN_NAME) = LOWER(?)
            LIMIT 1;
            """,
            [db, table, col],
        )
        if not res.rows:
            return None
        name, col_type, is_nullable, col_default = res.rows[0]
        def _dec(v: Any) -> str:
            return v.decode("utf-8", errors="replace") if isinstance(v, (bytes, bytearray)) else str(v)

        name_s = _dec(name)
        col_type_s = _dec(col_type)
        is_null_s = _dec(is_nullable)
        col_default_s = _dec(col_default) if col_default is not None else None
        exact_def: str | None = None
        try:
            ddl_res = self._client.query(f"SHOW CREATE TABLE {self._qualify(table, db)};")
            if ddl_res.rows:
                create_raw = ddl_res.rows[0][1]
                create_sql = _dec(create_raw)
                prefix = f"`{name_s}` "
                for line in create_sql.splitlines():
                    stripped = line.strip().rstrip(",")
                    if stripped.lower().startswith(prefix.lower()):
                        exact_def = stripped[len(prefix) :].strip()
                        break
        except Exception:
            pass
        return {
            "column": name_s,
            "col_type": col_type_s,
            "not_null": is_null_s.upper() == "NO",
            "col_default": col_default_s,
            "mysql_col_def": exact_def,
        }

    def _execute_alter_table(
        self,
        stmt: ParsedStatement,
        tx_id: str,
        *,
        in_client_tx: bool,
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        ops: list[MutationOp] = []
        cur_db = stmt.schema or self._current_db()
        cur_table = stmt.table
        table_exists = self._table_exists(cur_table, cur_db)
        t_schema = self.inspect_table(cur_table, cur_db) if table_exists else None

        pre_snapshots: list[tuple[dict[str, Any], dict[str, Any], str, list[str]]] = []
        effective_actions: list[dict[str, Any]] = []

        for act in stmt.alter_actions:
            kind = act["action"]
            if kind == "ADD_COLUMN":
                col = act["column"]
                if act.get("if_not_exists") and t_schema and col.lower() in {c.lower() for c in t_schema.columns}:
                    continue
                effective_actions.append(act)
            elif kind in ("DROP_COLUMN", "MODIFY_COLUMN", "CHANGE_COLUMN"):
                col = act["old_name"] if kind == "CHANGE_COLUMN" else act["column"]
                col_meta = self._mysql_col_def(cur_db, cur_table, col) if table_exists else None
                if col_meta is None:
                    if kind == "DROP_COLUMN" and act.get("if_exists"):
                        continue
                else:
                    assert t_schema is not None
                    join_pks = [pk for pk in t_schema.pk_columns if pk.lower() != col_meta["column"].lower()]
                    tag = "col" if kind == "DROP_COLUMN" else "mod"
                    q_name = f"{cur_table}__{tag}_{col_meta['column']}__{tx_id}"
                    qdb = self.quote_ident(QUARANTINE_DB)
                    self._client.query(f"CREATE DATABASE IF NOT EXISTS {qdb};")
                    key_cols_sql = ", ".join(self.quote_ident(pk) for pk in join_pks)
                    sel_cols = f"{key_cols_sql}, {self.quote_ident(col_meta['column'])}" if key_cols_sql else self.quote_ident(col_meta["column"])
                    src = self._qualify(cur_table, cur_db)
                    q_tbl = f"{qdb}.{self.quote_ident(q_name)}"
                    self._client.query(f"CREATE TABLE {q_tbl} AS SELECT {sel_cols} FROM {src};")
                    if key_cols_sql:
                        try:
                            self._client.query(
                                f"ALTER TABLE {q_tbl} ADD INDEX _proxy_q_idx ({key_cols_sql});"
                            )
                        except Exception:
                            pass
                    if kind == "CHANGE_COLUMN":
                        col_meta = {**col_meta, "old_name": col_meta["column"], "new_name": act["new_name"]}
                    else:
                        col_meta = {**col_meta, "old_name": col_meta["column"], "new_name": col_meta["column"]}
                    pre_snapshots.append((act, col_meta, q_name, join_pks))
                    effective_actions.append(act)
            elif kind == "ALTER_COLUMN_DEFAULT":
                col = act["column"]
                col_meta = self._mysql_col_def(cur_db, cur_table, col) if table_exists else None
                if col_meta is not None:
                    pre_snapshots.append((act, col_meta, "", []))
                    effective_actions.append(act)
            elif kind in ("RENAME_COLUMN", "RENAME_TABLE"):
                effective_actions.append(act)

        res = self._client.query(stmt.raw_sql)

        snap_iter = iter(pre_snapshots)
        for act in effective_actions:
            kind = act["action"]
            assert t_schema is not None
            if kind == "ADD_COLUMN":
                ops.append(
                    MutationOp(
                        op_type="ALTER_ADD_COLUMN",
                        table=cur_table,
                        schema=cur_db,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                        extra_ddl=[json.dumps({"column": act["column"]})],
                    )
                )
            elif kind in ("DROP_COLUMN", "MODIFY_COLUMN", "CHANGE_COLUMN"):
                _act, col_meta, q_name, join_pks = next(snap_iter)
                op_kind = "QUARANTINE_DROP_COLUMN" if kind == "DROP_COLUMN" else "QUARANTINE_ALTER_COLUMN"
                ops.append(
                    MutationOp(
                        op_type=op_kind,
                        table=cur_table,
                        schema=cur_db,
                        pk_columns=join_pks,
                        column_types=t_schema.column_types,
                        quarantine_name=q_name,
                        extra_ddl=[json.dumps(col_meta)],
                    )
                )
            elif kind == "ALTER_COLUMN_DEFAULT":
                _act, col_meta, _, _ = next(snap_iter)
                ops.append(
                    MutationOp(
                        op_type="ALTER_COLUMN_ATTR",
                        table=cur_table,
                        schema=cur_db,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                        extra_ddl=[json.dumps({**col_meta, "attr_kind": kind})],
                    )
                )
            elif kind == "RENAME_COLUMN":
                ops.append(
                    MutationOp(
                        op_type="ALTER_RENAME_COLUMN",
                        table=cur_table,
                        schema=cur_db,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                        extra_ddl=[json.dumps({"old_name": act["old_name"], "new_name": act["new_name"]})],
                    )
                )
            elif kind == "RENAME_TABLE":
                new_tbl = act["new_table"]
                new_db = act.get("new_schema") or cur_db
                ops.append(
                    MutationOp(
                        op_type="ALTER_RENAME_TABLE",
                        table=cur_table,
                        schema=cur_db,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                        extra_ddl=[
                            json.dumps(
                                {
                                    "old_schema": cur_db,
                                    "old_table": cur_table,
                                    "new_schema": new_db,
                                    "new_table": new_tbl,
                                }
                            )
                        ],
                    )
                )
                cur_table = new_tbl
                cur_db = new_db

        return (
            QueryResult(rowcount=res.affected_rows, command_tag="ALTER TABLE", warnings=warnings),
            ops,
            warnings,
        )

    def _mysql_index_def(self, db: str, table: str | None, index_name: str) -> tuple[str | None, str | None]:
        def _dec(v: Any) -> str:
            return v.decode("utf-8", errors="replace") if isinstance(v, (bytes, bytearray)) else str(v)

        if table:
            res = self._client.execute(
                """
                SELECT TABLE_NAME, NON_UNIQUE, COLUMN_NAME, SUB_PART, INDEX_TYPE
                FROM INFORMATION_SCHEMA.STATISTICS
                WHERE TABLE_SCHEMA = ? AND LOWER(TABLE_NAME) = LOWER(?) AND LOWER(INDEX_NAME) = LOWER(?)
                ORDER BY SEQ_IN_INDEX;
                """,
                [db, table, index_name],
            )
        else:
            res = self._client.execute(
                """
                SELECT TABLE_NAME, NON_UNIQUE, COLUMN_NAME, SUB_PART, INDEX_TYPE
                FROM INFORMATION_SCHEMA.STATISTICS
                WHERE TABLE_SCHEMA = ? AND LOWER(INDEX_NAME) = LOWER(?)
                ORDER BY TABLE_NAME, SEQ_IN_INDEX;
                """,
                [db, index_name],
            )
        if not res.rows:
            return None, None
        tbl_name = _dec(res.rows[0][0])
        non_unique = int(res.rows[0][1])
        idx_type = _dec(res.rows[0][4]).upper()
        cols_parts: list[str] = []
        for row in res.rows:
            cname = self.quote_ident(_dec(row[2]))
            sub_part = row[3]
            cols_parts.append(f"{cname}({int(sub_part)})" if sub_part else cname)
        prefix = "CREATE UNIQUE INDEX" if non_unique == 0 else (
            f"CREATE {idx_type} INDEX" if idx_type in ("FULLTEXT", "SPATIAL") else "CREATE INDEX"
        )
        create_sql = f"{prefix} {self.quote_ident(index_name)} ON {self._qualify(tbl_name, db)} ({', '.join(cols_parts)});"
        return tbl_name, create_sql

    def _execute_index_ddl(
        self,
        stmt: ParsedStatement,
        *,
        in_client_tx: bool,
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.index_name is not None
        db = stmt.schema or self._current_db()
        ops: list[MutationOp] = []
        if stmt.kind == StatementKind.CREATE_INDEX:
            existing_tbl, _ = self._mysql_index_def(db, stmt.table, stmt.index_name)
            res = self._client.query(stmt.raw_sql)
            if existing_tbl is None:
                ops.append(
                    MutationOp(
                        op_type="ALTER_CREATE_INDEX",
                        table=stmt.table or "",
                        schema=db,
                        pk_columns=[],
                        column_types={},
                        extra_ddl=[json.dumps({"index_name": stmt.index_name})],
                    )
                )
            tag = "CREATE INDEX"
        else:
            idx_tbl, create_sql = self._mysql_index_def(db, stmt.table, stmt.index_name)
            res = self._client.query(stmt.raw_sql)
            if create_sql and idx_tbl:
                ops.append(
                    MutationOp(
                        op_type="ALTER_DROP_INDEX",
                        table=idx_tbl,
                        schema=db,
                        pk_columns=[],
                        column_types={},
                        extra_ddl=[json.dumps({"index_name": stmt.index_name, "create_sql": create_sql})],
                    )
                )
            tag = "DROP INDEX"
        return (
            QueryResult(rowcount=res.affected_rows, command_tag=tag, warnings=warnings),
            ops,
            warnings,
        )

    @staticmethod
    def _from_join_sql(from_join_clause: str | None) -> str:
        if not from_join_clause:
            return ""
        upper = from_join_clause.lstrip().upper()
        if upper.startswith(("JOIN ", "INNER ", "LEFT ", "RIGHT ", "CROSS ", "STRAIGHT_JOIN ")):
            return f" {from_join_clause}"
        return f", {from_join_clause}"

    @staticmethod
    def _extract_probe_count(res: MySQLResult) -> int:
        if len(res.rows) == 1 and res.rows[0] and len(res.rows[0]) == 1:
            val = res.rows[0][0]
            if isinstance(val, int):
                return val
            if isinstance(val, (bytes, bytearray)):
                val = val.decode("utf-8", errors="replace")
            if isinstance(val, str) and val.isdigit():
                return int(val)
        return len(res.rows)

    def _check_blast_radius(
        self,
        table: str,
        qual: str,
        alias_sql: str,
        where_sql: str,
        where_params: Sequence[Any],
        *,
        from_join_sql: str = "",
    ) -> None:
        if self.max_capture_rows is None:
            return
        probe_sql = (
            f"SELECT COUNT(*) FROM (SELECT 1 FROM {qual}{alias_sql}{from_join_sql}{where_sql} "
            f"LIMIT {self.max_capture_rows + 1}) AS _br;"
        )
        res = self._client.execute(probe_sql, where_params)
        cnt = self._extract_probe_count(res)
        if cnt > self.max_capture_rows:
            raise BlastRadiusExceededError(
                table=table,
                limit=self.max_capture_rows,
                observed_at_least=cnt,
            )

    def _supports_side_table(self) -> bool:
        if self.side_table_threshold <= 0:
            return False
        if self._is_real_mysql is not None:
            return self._is_real_mysql
        try:
            res = self._client.execute("SELECT VERSION();", ())
            ver = str(res.rows[0][0]).lower() if res.rows else ""
            self._is_real_mysql = bool(ver) and "sqlite" not in ver
        except Exception:
            self._is_real_mysql = False
        return self._is_real_mysql

    def _should_use_side_table(
        self,
        qual: str,
        alias_sql: str,
        where_sql: str,
        where_params: Sequence[Any],
        *,
        from_join_sql: str = "",
    ) -> bool:
        if not self._supports_side_table():
            return False
        probe_sql = (
            f"SELECT COUNT(*) FROM (SELECT 1 FROM {qual}{alias_sql}{from_join_sql}{where_sql} "
            f"LIMIT {self.side_table_threshold + 1}) AS _st;"
        )
        res = self._client.execute(probe_sql, where_params)
        return self._extract_probe_count(res) > self.side_table_threshold

    @staticmethod
    def _mysql_update_touches_pk(raw_sql: str, pk_columns: Sequence[str]) -> bool:
        m = re.search(r"\bSET\b(.*?)(?:\bWHERE\b|$)", raw_sql, re.IGNORECASE | re.DOTALL)
        if not m:
            return True
        set_part = m.group(1)
        pks_l = {pk.lower() for pk in pk_columns}
        for assign in re.finditer(r"(?:[A-Za-z_][A-Za-z0-9_`]*\.)?(`[^`]+`|[A-Za-z_][A-Za-z0-9_]*)\s*=", set_part):
            col = assign.group(1).strip("`").lower()
            if col in pks_l:
                return True
        return False

    def _create_side_tables(
        self, t_schema: TableSchema, names: Sequence[str], *, out_of_band: bool
    ) -> None:
        qdb = self.quote_ident(QUARANTINE_DB)
        qual = self._qualify(t_schema.table, t_schema.schema)
        show_res = self._client.query(f"SHOW COLUMNS FROM {qual};")
        pk_set = set(t_schema.pk_columns)
        col_defs: list[str] = []
        for r in show_res.rows:
            cname = r[0].decode("utf-8") if isinstance(r[0], (bytes, bytearray)) else str(r[0])
            ctype = r[1].decode("utf-8") if isinstance(r[1], (bytes, bytearray)) else str(r[1])
            null_spec = "NOT NULL" if cname in pk_set else "NULL"
            col_defs.append(f"{self.quote_ident(cname)} {ctype} {null_spec}")
        if t_schema.pk_columns:
            pks_q = ", ".join(self.quote_ident(pk) for pk in t_schema.pk_columns)
            col_defs.append(f"PRIMARY KEY ({pks_q})")
        cols_ddl = ", ".join(col_defs)
        client = MySQLWireClient(**self._conn_params) if out_of_band else self._client
        try:
            client.query(f"CREATE DATABASE IF NOT EXISTS {qdb};")
            for name in names:
                client.query(f"CREATE TABLE {qdb}.{self.quote_ident(name)} ({cols_ddl}) ENGINE=InnoDB;")
        finally:
            if out_of_band:
                client.close()

    def drop_side_tables(self, items: Sequence[tuple[str, str | None]]) -> None:
        qdb = self.quote_ident(QUARANTINE_DB)
        for tname, _sch in items:
            if tname:
                try:
                    self._client.query(f"DROP TABLE IF EXISTS {qdb}.{self.quote_ident(tname)};")
                except Exception:
                    pass

    def materialize_side_op(self, op: MutationOp) -> tuple[MutationOp, list[str]]:
        """Read MySQL DB-side snapshot tables into Python rows for durable disk spill."""
        drop_names: list[str] = []
        before_rows = list(op.before_rows)
        after_rows = list(op.after_rows)
        if op.side_table_before and self._table_exists(op.side_table_before, QUARANTINE_DB):
            qb = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(op.side_table_before)}"
            before_rows = self._res_to_dicts(self._client.query(f"SELECT * FROM {qb};"))
            drop_names.append(op.side_table_before)
        if op.side_table_after and self._table_exists(op.side_table_after, QUARANTINE_DB):
            qa = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(op.side_table_after)}"
            after_rows = self._res_to_dicts(self._client.query(f"SELECT * FROM {qa};"))
            drop_names.append(op.side_table_after)
        new_op = MutationOp(
            op_type=op.op_type,
            table=op.table,
            schema=op.schema,
            pk_columns=list(op.pk_columns),
            column_types=dict(op.column_types),
            before_rows=before_rows,
            after_rows=after_rows,
            quarantine_name=op.quarantine_name,
            using_rowid_fallback=op.using_rowid_fallback,
            rowid_column=op.rowid_column,
            extra_ddl=list(op.extra_ddl),
            rbr_fde_b64=op.rbr_fde_b64,
            rbr_undo_events=list(op.rbr_undo_events),
            phase_timings=dict(op.phase_timings),
        )
        return new_op, drop_names

    @staticmethod
    def _format_sql_val(val: Any) -> str:
        if val is None:
            return "NULL"
        if isinstance(val, bool):
            return "1" if val else "0"
        if isinstance(val, (int, float)):
            return str(val)
        if isinstance(val, (bytes, bytearray, memoryview)):
            return "X'" + bytes(val).hex() + "'"
        s = (
            str(val)
            .replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\x00", "\\0")
        )
        return f"'{s}'"

    def _bulk_populate_side_table(
        self,
        side_name: str,
        columns: Sequence[str],
        rows: Sequence[dict[str, Any]],
        *,
        batch_rows: int = 5000,
    ) -> None:
        if not rows:
            return
        q_tbl = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(side_name)}"
        cols_q = ", ".join(self.quote_ident(c) for c in columns)
        fmt = self._format_sql_val
        self._client.query("BEGIN;")
        try:
            for start in range(0, len(rows), batch_rows):
                chunk = rows[start : start + batch_rows]
                tuples_sql = ",".join(
                    "(" + ",".join(fmt(r.get(c)) for c in columns) + ")" for r in chunk
                )
                self._client.query(f"INSERT INTO {q_tbl} ({cols_q}) VALUES {tuples_sql};")
            self._client.query("COMMIT;")
        except Exception:
            try:
                self._client.query("ROLLBACK;")
            except Exception:
                pass
            raise

    def _stage_spilled_record_ops(
        self, record: UndoRecord, *, force: bool
    ) -> tuple[UndoRecord, list[tuple[str, str | None]]]:
        if not self._supports_side_table():
            return record, []
        new_ops: list[MutationOp] = []
        temp_tables: list[tuple[str, str | None]] = []
        default_db = self._current_db()
        for op in record.ops:
            db = op.schema or default_db
            if (
                op.op_type in ("UPDATE", "DELETE")
                and not op.side_table_before
                and len(op.before_rows) > self.side_table_threshold
                and self._table_exists(op.table, db)
            ):
                t_schema = self.inspect_table(op.table, db)
                live_cols = set(t_schema.columns)
                sample_rows = op.after_rows if (op.op_type == "UPDATE" and op.after_rows) else op.before_rows
                sample_keys = list(sample_rows[0].keys()) if sample_rows else []
                dropped = [c for c in sample_keys if c not in live_cols]
                if not (dropped and not force):
                    tag_hex = uuid.uuid4().hex[:10]
                    rev_b = f"_rev_b_{op.table}_{tag_hex}"
                    active_cols = [c for c in t_schema.columns if c in sample_keys]
                    if op.op_type == "UPDATE" and len(op.after_rows) == len(op.before_rows):
                        rev_a = f"_rev_a_{op.table}_{tag_hex}"
                        self._create_side_tables(t_schema, [rev_b, rev_a], out_of_band=False)
                        temp_tables.append((rev_b, db))
                        temp_tables.append((rev_a, db))
                        self._bulk_populate_side_table(rev_b, active_cols, op.before_rows)
                        self._bulk_populate_side_table(rev_a, active_cols, op.after_rows)
                        new_ops.append(
                            dataclasses.replace(
                                op,
                                before_rows=[],
                                after_rows=[],
                                side_table_before=rev_b,
                                side_table_after=rev_a,
                                side_rowcount=len(op.before_rows),
                            )
                        )
                        continue
                    elif op.op_type == "DELETE":
                        self._create_side_tables(t_schema, [rev_b], out_of_band=False)
                        temp_tables.append((rev_b, db))
                        self._bulk_populate_side_table(rev_b, active_cols, op.before_rows)
                        new_ops.append(
                            dataclasses.replace(
                                op,
                                before_rows=[],
                                after_rows=[],
                                side_table_before=rev_b,
                                side_rowcount=len(op.before_rows),
                            )
                        )
                        continue
            new_ops.append(op)
        if not temp_tables:
            return record, []
        return dataclasses.replace(record, ops=new_ops), temp_tables

    def _extract_insert_pk_rows(
        self, sql: str, t_schema: TableSchema, params: Sequence[Any]
    ) -> list[dict[str, Any]] | None:
        """Extract explicit PK tuples from `INSERT INTO tbl [(cols)] VALUES (...), (...)`."""
        val_dicts = extract_insert_value_dicts(sql, t_schema.columns, params)
        if not val_dicts:
            return None
        if not all(all(pk in d for pk in t_schema.pk_columns) for d in val_dicts):
            return None
        return [{pk: d[pk] for pk in t_schema.pk_columns} for d in val_dicts]

    def _fetch_rows_by_pks(
        self, t_schema: TableSchema, pk_dicts: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if not pk_dicts:
            return []
        dummy_op = MutationOp(
            op_type="UPDATE",
            table=t_schema.table,
            schema=t_schema.schema,
            pk_columns=t_schema.pk_columns,
            column_types=t_schema.column_types,
        )
        found = self._prefetch_current_rows(dummy_op, pk_dicts)
        rows: list[dict[str, Any]] = []
        for pk_dict in pk_dicts:
            key = tuple(pk_dict[pk] for pk in t_schema.pk_columns)
            if key in found:
                rows.append(found[key])
        return rows

    def purge_quarantine_table(self, quarantine_name: str, schema: str | None = None) -> bool:
        if not self._table_exists(quarantine_name, QUARANTINE_DB):
            return False
        self._client.query("SET FOREIGN_KEY_CHECKS=0;")
        try:
            self._client.query(
                f"DROP TABLE IF EXISTS {self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(quarantine_name)};"
            )
        finally:
            self._client.query("SET FOREIGN_KEY_CHECKS=1;")
        return True

    def _execute_insert(
        self,
        stmt: ParsedStatement,
        *,
        tx_id: str = "",
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        db = stmt.schema or self._current_db()
        with self._ensure_tx(in_client_tx):
            if tx_id:
                self._maybe_emit_binlog_marker(tx_id=tx_id)
            t_schema = self.inspect_table(stmt.table, db)
            qual = self._qualify(stmt.table, db)

            existing_by_pk: dict[tuple[Any, ...], dict[str, Any]] = {}
            upsert_pre_captured = False
            if stmt.is_upsert:
                val_dicts = extract_insert_value_dicts(stmt.raw_sql, t_schema.columns, params)
                if val_dicts and all(all(pk in d for pk in t_schema.pk_columns) for d in val_dicts):
                    dummy_op = MutationOp(
                        op_type="UPDATE",
                        table=stmt.table,
                        schema=db,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                    )
                    existing_by_pk = self._prefetch_current_rows(
                        dummy_op, [{pk: d[pk] for pk in t_schema.pk_columns} for d in val_dicts]
                    )
                    upsert_pre_captured = True

            ins_res = self._client.execute(stmt.raw_sql, params)
            affected = ins_res.affected_rows
            last_id = ins_res.last_insert_id

            after_rows: list[dict[str, Any]] = []
            if affected > 0:
                if last_id > 0 and len(t_schema.pk_columns) == 1 and not stmt.is_upsert:
                    pk_col = self.quote_ident(t_schema.pk_columns[0])
                    if affected == 1:
                        sel = self._client.execute(
                            f"SELECT * FROM {qual} WHERE {pk_col} = ?;", [last_id]
                        )
                    else:
                        sel = self._client.execute(
                            f"SELECT * FROM {qual} WHERE {pk_col} >= ? ORDER BY {pk_col} LIMIT ?;",
                            [last_id, affected],
                        )
                    after_rows = self._res_to_dicts(sel)
                else:
                    pk_dicts = self._extract_insert_pk_rows(stmt.raw_sql, t_schema, params)
                    if pk_dicts:
                        after_rows = self._fetch_rows_by_pks(t_schema, pk_dicts)
                    elif last_id > 0 and len(t_schema.pk_columns) == 1:
                        pk_col = self.quote_ident(t_schema.pk_columns[0])
                        sel = self._client.execute(
                            f"SELECT * FROM {qual} WHERE {pk_col} = ?;", [last_id]
                        )
                        after_rows = self._res_to_dicts(sel)
                    else:
                        warnings.append(
                            "Could not capture inserted rows automatically without LAST_INSERT_ID or literal PKs."
                        )

        ops: list[MutationOp] = []
        if stmt.is_upsert and upsert_pre_captured:
            upd_before: list[dict[str, Any]] = []
            upd_after: list[dict[str, Any]] = []
            ins_after: list[dict[str, Any]] = []
            for row in after_rows:
                pk_key = self._pk_key(row, t_schema.pk_columns)
                if pk_key in existing_by_pk:
                    if existing_by_pk[pk_key] != row:
                        upd_before.append(existing_by_pk[pk_key])
                        upd_after.append(row)
                else:
                    ins_after.append(row)
            if upd_after:
                ops.append(
                    MutationOp(
                        op_type="UPDATE",
                        table=stmt.table,
                        schema=db,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                        before_rows=upd_before,
                        after_rows=upd_after,
                    )
                )
            if ins_after:
                ops.append(
                    MutationOp(
                        op_type="INSERT",
                        table=stmt.table,
                        schema=db,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                        before_rows=[],
                        after_rows=ins_after,
                    )
                )
        else:
            if stmt.is_upsert:
                warnings.append(
                    "Upsert clause could not extract pre-image PKs from VALUES; treating as INSERT (partial)."
                )
            ops.append(
                MutationOp(
                    op_type="INSERT",
                    table=stmt.table,
                    schema=db,
                    pk_columns=t_schema.pk_columns,
                    column_types=t_schema.column_types,
                    before_rows=[],
                    after_rows=after_rows,
                )
            )

        return (
            QueryResult(
                rowcount=affected,
                command_tag=f"INSERT 0 {affected}",
                warnings=warnings,
            ),
            ops,
            warnings,
        )

    def _where_params(
        self, raw_sql: str, where_clause: str | None, params: Sequence[Any]
    ) -> list[Any]:
        if not params or not where_clause:
            return []
        where_pos = raw_sql.upper().rfind(where_clause.upper())
        if where_pos == -1:
            return []
        before_q = sum(1 for t in tokenize(raw_sql[:where_pos]) if t.kind == "OP" and t.text == "?")
        where_q = sum(1 for t in tokenize(where_clause) if t.kind == "OP" and t.text == "?")
        return list(params[before_q : before_q + where_q])

    def _execute_update(
        self,
        stmt: ParsedStatement,
        *,
        tx_id: str = "",
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        db = stmt.schema or self._current_db()
        t_schema = self.inspect_table(stmt.table, db)
        qual = self._qualify(stmt.table, db)
        alias_sql = f" AS {self.quote_ident(stmt.alias)}" if stmt.alias else ""
        from_join_sql = self._from_join_sql(stmt.from_join_clause)
        prefix = f"{self.quote_ident(stmt.alias)}." if stmt.alias else (f"{qual}." if stmt.from_join_clause else "")
        where_sql = f" WHERE {stmt.where_clause}" if stmt.where_clause else ""
        where_params = self._where_params(stmt.raw_sql, stmt.where_clause, params)
        t_br0 = time.perf_counter()
        self._check_blast_radius(
            stmt.table, qual, alias_sql, where_sql, where_params, from_join_sql=from_join_sql
        )
        use_side = (
            not in_client_tx
            and bool(t_schema.pk_columns)
            and not stmt.from_join_clause
            and not self._mysql_update_touches_pk(stmt.raw_sql, t_schema.pk_columns)
            and self._should_use_side_table(
                qual, alias_sql, where_sql, where_params, from_join_sql=from_join_sql
            )
        )
        t_br_dt = time.perf_counter() - t_br0
        if use_side:
            t_c0 = time.perf_counter()
            tag_hex = uuid.uuid4().hex[:10]
            snap_b = f"_side_b_{stmt.table}_{tag_hex}"
            snap_a = f"_side_a_{stmt.table}_{tag_hex}"
            self._create_side_tables(t_schema, [snap_b, snap_a], out_of_band=False)
            t_create_dt = time.perf_counter() - t_c0
            with self._ensure_tx(in_client_tx):
                if tx_id:
                    self._maybe_emit_binlog_marker(tx_id=tx_id, db=db, table=stmt.table)
                qdb = self.quote_ident(QUARANTINE_DB)
                qb = f"{qdb}.{self.quote_ident(snap_b)}"
                qa = f"{qdb}.{self.quote_ident(snap_a)}"
                t_cap0 = time.perf_counter()
                self._client.execute(
                    f"INSERT INTO {qb} SELECT * FROM {qual}{alias_sql}{where_sql} FOR UPDATE;",
                    where_params,
                )
                t_cap_dt = time.perf_counter() - t_cap0
                t_dml0 = time.perf_counter()
                upd_res = self._client.execute(stmt.raw_sql, params)
                pk_join = " AND ".join(
                    f"t.{self.quote_ident(pk)} = b.{self.quote_ident(pk)}" for pk in t_schema.pk_columns
                )
                self._client.query(
                    f"INSERT INTO {qa} SELECT t.* FROM {qual} AS t INNER JOIN {qb} AS b ON {pk_join};"
                )
                t_dml_dt = time.perf_counter() - t_dml0
            side_op = MutationOp(
                op_type="UPDATE",
                table=stmt.table,
                schema=db,
                pk_columns=t_schema.pk_columns,
                column_types=t_schema.column_types,
                side_table_before=snap_b,
                side_table_after=snap_a,
                side_rowcount=upd_res.affected_rows,
                phase_timings={
                    "blast_radius_check_s": round(t_br_dt, 4),
                    "side_table_create_s": round(t_create_dt, 4),
                    "snapshot_capture_s": round(t_cap_dt, 4),
                    "dml_exec_s": round(t_dml_dt, 4),
                    "commit_s": round(self._last_commit_s, 4),
                },
            )
            return (
                QueryResult(
                    rowcount=upd_res.affected_rows,
                    command_tag=f"UPDATE {upd_res.affected_rows}",
                    warnings=warnings,
                ),
                [side_op],
                warnings,
            )

        with self._ensure_tx(in_client_tx):
            if tx_id:
                self._maybe_emit_binlog_marker(tx_id=tx_id)
            pre_sql = f"SELECT {prefix}* FROM {qual}{alias_sql}{from_join_sql}{where_sql} FOR UPDATE;"
            raw_before = self._res_to_dicts(self._client.execute(pre_sql, where_params))
            seen_pks: set[tuple[Any, ...]] = set()
            before_rows: list[dict[str, Any]] = []
            for r in raw_before:
                pk_k = self._pk_key(r, t_schema.pk_columns)
                if pk_k not in seen_pks:
                    seen_pks.add(pk_k)
                    before_rows.append(r)

            upd_res = self._client.execute(stmt.raw_sql, params)
            pk_dicts = [{pk: r[pk] for pk in t_schema.pk_columns} for r in before_rows]
            after_rows = self._fetch_rows_by_pks(t_schema, pk_dicts)

        op = MutationOp(
            op_type="UPDATE",
            table=stmt.table,
            schema=db,
            pk_columns=t_schema.pk_columns,
            column_types=t_schema.column_types,
            before_rows=before_rows,
            after_rows=after_rows,
        )
        return (
            QueryResult(
                rowcount=upd_res.affected_rows,
                command_tag=f"UPDATE {upd_res.affected_rows}",
                warnings=warnings,
            ),
            [op],
            warnings,
        )

    def _collect_cascade_delete_ops(
        self,
        parent_table: str,
        parent_rows: list[dict[str, Any]],
        cascade_edges: list[ForeignKeyEdge],
        seen_keys: set[tuple[str, str, tuple[Any, ...]]],
    ) -> list[MutationOp]:
        if not parent_rows or not cascade_edges:
            return []
        ops: list[MutationOp] = []
        for edge in cascade_edges:
            if edge.parent_table != parent_table:
                continue
            key_tuples: list[tuple[Any, ...]] = []
            seen_vals: set[tuple[Any, ...]] = set()
            for row in parent_rows:
                vals = tuple(row.get(pc) for pc in edge.parent_columns)
                if any(v is None for v in vals):
                    continue
                if vals not in seen_vals:
                    seen_vals.add(vals)
                    key_tuples.append(vals)
            if not key_tuples:
                continue

            child_db = edge.schema or self._current_db()
            c_t_schema = self.inspect_table(edge.child_table, child_db)
            c_qual = self._qualify(edge.child_table, child_db)

            params: list[Any] = []
            or_clauses: list[str] = []
            for kt in key_tuples:
                parts: list[str] = []
                for ccol, val in zip(edge.child_columns, kt):
                    parts.append(f"{self.quote_ident(ccol)} = ?")
                    params.append(val)
                or_clauses.append(f"({' AND '.join(parts)})" if len(parts) > 1 else parts[0])
            where_sql = " OR ".join(or_clauses)
            sel_sql = f"SELECT * FROM {c_qual} WHERE {where_sql} FOR UPDATE;"
            c_rows_all = self._res_to_dicts(self._client.execute(sel_sql, params))
            c_rows: list[dict[str, Any]] = []
            for cr in c_rows_all:
                pk_k = self._pk_key(cr, c_t_schema.pk_columns)
                full_k = (child_db, edge.child_table, pk_k)
                if full_k not in seen_keys:
                    seen_keys.add(full_k)
                    c_rows.append(cr)
            if not c_rows:
                continue

            ops.extend(
                self._collect_cascade_delete_ops(
                    edge.child_table, c_rows, cascade_edges, seen_keys
                )
            )
            ops.append(
                MutationOp(
                    op_type="DELETE",
                    table=edge.child_table,
                    schema=child_db,
                    pk_columns=c_t_schema.pk_columns,
                    column_types=c_t_schema.column_types,
                    before_rows=c_rows,
                    after_rows=[],
                )
            )
        return ops

    def _execute_delete(
        self,
        stmt: ParsedStatement,
        *,
        tx_id: str = "",
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        db = stmt.schema or self._current_db()
        cascade_ops: list[MutationOp] = []
        t_schema = self.inspect_table(stmt.table, db)
        qual = self._qualify(stmt.table, db)
        alias_sql = f" AS {self.quote_ident(stmt.alias)}" if stmt.alias else ""
        from_join_sql = self._from_join_sql(stmt.from_join_clause)
        prefix = f"{self.quote_ident(stmt.alias)}." if stmt.alias else (f"{qual}." if stmt.from_join_clause else "")
        where_sql = f" WHERE {stmt.where_clause}" if stmt.where_clause else ""
        where_params = self._where_params(stmt.raw_sql, stmt.where_clause, params)
        t_br0 = time.perf_counter()
        self._check_blast_radius(
            stmt.table, qual, alias_sql, where_sql, where_params, from_join_sql=from_join_sql
        )
        cascade_edges = [e for e in self.inspect_foreign_keys() if e.on_delete == "CASCADE"]
        has_cascade_children = any(e.parent_table == stmt.table for e in cascade_edges)
        use_side = (
            not in_client_tx
            and bool(t_schema.pk_columns)
            and not stmt.from_join_clause
            and not has_cascade_children
            and self._should_use_side_table(
                qual, alias_sql, where_sql, where_params, from_join_sql=from_join_sql
            )
        )
        t_br_dt = time.perf_counter() - t_br0
        if use_side:
            t_c0 = time.perf_counter()
            snap_b = f"_side_b_{stmt.table}_{uuid.uuid4().hex[:10]}"
            self._create_side_tables(t_schema, [snap_b], out_of_band=False)
            t_create_dt = time.perf_counter() - t_c0
            with self._ensure_tx(in_client_tx):
                if tx_id:
                    self._maybe_emit_binlog_marker(tx_id=tx_id, db=db, table=stmt.table)
                qdb = self.quote_ident(QUARANTINE_DB)
                qb = f"{qdb}.{self.quote_ident(snap_b)}"
                t_cap0 = time.perf_counter()
                self._client.execute(
                    f"INSERT INTO {qb} SELECT * FROM {qual}{alias_sql}{where_sql} FOR UPDATE;",
                    where_params,
                )
                t_cap_dt = time.perf_counter() - t_cap0
                t_dml0 = time.perf_counter()
                del_res = self._client.execute(stmt.raw_sql, params)
                t_dml_dt = time.perf_counter() - t_dml0
            side_op = MutationOp(
                op_type="DELETE",
                table=stmt.table,
                schema=db,
                pk_columns=t_schema.pk_columns,
                column_types=t_schema.column_types,
                side_table_before=snap_b,
                side_rowcount=del_res.affected_rows,
                phase_timings={
                    "blast_radius_check_s": round(t_br_dt, 4),
                    "side_table_create_s": round(t_create_dt, 4),
                    "snapshot_capture_s": round(t_cap_dt, 4),
                    "dml_exec_s": round(t_dml_dt, 4),
                    "commit_s": round(self._last_commit_s, 4),
                },
            )
            return (
                QueryResult(
                    rowcount=del_res.affected_rows,
                    command_tag=f"DELETE {del_res.affected_rows}",
                    warnings=warnings,
                ),
                [side_op],
                warnings,
            )

        with self._ensure_tx(in_client_tx):
            if tx_id:
                self._maybe_emit_binlog_marker(tx_id=tx_id)
            pre_sql = f"SELECT {prefix}* FROM {qual}{alias_sql}{from_join_sql}{where_sql} FOR UPDATE;"
            raw_before = self._res_to_dicts(self._client.execute(pre_sql, where_params))
            seen_pks: set[tuple[Any, ...]] = set()
            before_rows: list[dict[str, Any]] = []
            for r in raw_before:
                pk_k = self._pk_key(r, t_schema.pk_columns)
                if pk_k not in seen_pks:
                    seen_pks.add(pk_k)
                    before_rows.append(r)

            if before_rows and has_cascade_children:
                seen_keys = {
                    (db, stmt.table, self._pk_key(r, t_schema.pk_columns))
                    for r in before_rows
                }
                cascade_ops = self._collect_cascade_delete_ops(
                    stmt.table, before_rows, cascade_edges, seen_keys
                )

            del_res = self._client.execute(stmt.raw_sql, params)

        op = MutationOp(
            op_type="DELETE",
            table=stmt.table,
            schema=db,
            pk_columns=t_schema.pk_columns,
            column_types=t_schema.column_types,
            before_rows=before_rows,
            after_rows=[],
        )
        return (
            QueryResult(
                rowcount=del_res.affected_rows,
                command_tag=f"DELETE {del_res.affected_rows}",
                warnings=warnings,
            ),
            [*cascade_ops, op],
            warnings,
        )

    def _fetch_current_row(
        self, op: MutationOp, pk_values: dict[str, Any], *, for_update: bool = False
    ) -> dict[str, Any] | None:
        qual = self._qualify(op.table, op.schema)
        where_parts = [f"{self.quote_ident(pk)} <=> ?" for pk in op.pk_columns]
        lock_sql = " FOR UPDATE" if for_update else ""
        sql = f"SELECT * FROM {qual} WHERE {' AND '.join(where_parts)} LIMIT 1{lock_sql};"
        res = self._client.execute(sql, [pk_values[pk] for pk in op.pk_columns])
        rows = self._res_to_dicts(res)
        return rows[0] if rows else None

    def _prefetch_current_rows(
        self,
        op: MutationOp,
        pk_dicts: list[dict[str, Any]],
        *,
        for_update: bool = False,
    ) -> dict[tuple[Any, ...], dict[str, Any]]:
        if not pk_dicts:
            return {}
        qual = self._qualify(op.table, op.schema)
        found: dict[tuple[Any, ...], dict[str, Any]] = {}
        non_null_pks: list[dict[str, Any]] = []
        for pk_vals in pk_dicts:
            if any(pk_vals[pk] is None for pk in op.pk_columns):
                row = self._fetch_current_row(op, pk_vals, for_update=for_update)
                if row is not None:
                    found[self._pk_key(row, op.pk_columns)] = row
            else:
                non_null_pks.append(pk_vals)

        if not non_null_pks:
            return found

        num_pk = len(op.pk_columns)
        chunk_size = 2000 if num_pk == 1 else max(50, 2000 // num_pk)
        lock_sql = " FOR UPDATE" if for_update else ""
        if num_pk == 1:
            pk_col = self.quote_ident(op.pk_columns[0])
            for i in range(0, len(non_null_pks), chunk_size):
                chunk = non_null_pks[i : i + chunk_size]
                placeholders = ", ".join("?" for _ in chunk)
                sql = f"SELECT * FROM {qual} WHERE {pk_col} IN ({placeholders}){lock_sql};"
                res = self._client.execute(sql, [d[op.pk_columns[0]] for d in chunk])
                for row in self._res_to_dicts(res):
                    found[self._pk_key(row, op.pk_columns)] = row
        else:
            pk_cols_sql = ", ".join(self.quote_ident(pk) for pk in op.pk_columns)
            row_tuple = "(" + ", ".join("?" for _ in op.pk_columns) + ")"
            for i in range(0, len(non_null_pks), chunk_size):
                chunk = non_null_pks[i : i + chunk_size]
                tuples_sql = ", ".join(row_tuple for _ in chunk)
                sql = f"SELECT * FROM {qual} WHERE ({pk_cols_sql}) IN ({tuples_sql}){lock_sql};"
                params = [d[pk] for d in chunk for pk in op.pk_columns]
                res = self._client.execute(sql, params)
                for row in self._res_to_dicts(res):
                    found[self._pk_key(row, op.pk_columns)] = row
        return found

    @staticmethod
    def _pk_key(row: dict[str, Any], pk_columns: list[str]) -> tuple[Any, ...]:
        return tuple(row[col] for col in pk_columns)

    def build_reverse_plan(
        self, record: UndoRecord, *, force: bool = False, lock_rows: bool = False
    ) -> tuple[list[ReversePlanStep], list[DriftConflict]]:
        steps: list[ReversePlanStep] = []
        conflicts: list[DriftConflict] = []
        for op in reversed(record.ops):
            op_steps, op_conflicts = self._build_op_reverse_plan(
                op, force=force, lock_rows=lock_rows
            )
            steps.extend(op_steps)
            conflicts.extend(op_conflicts)
        return steps, conflicts

    def _build_op_reverse_plan(
        self, op: MutationOp, *, force: bool = False, lock_rows: bool = False
    ) -> tuple[list[ReversePlanStep], list[DriftConflict]]:
        steps: list[ReversePlanStep] = []
        conflicts: list[DriftConflict] = []
        for op in [op]:
            db = op.schema or self._current_db()
            qual = self._qualify(op.table, db)

            if op.op_type == "QUARANTINE_DROP":
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, QUARANTINE_DB):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=None,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined table '{QUARANTINE_DB}.{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                if self._table_exists(op.table, db):
                    if not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={},
                                column=None,
                                expected_after=None,
                                actual_current=op.table,
                                reason=f"Table '{db}.{op.table}' was recreated since DROP.",
                            )
                        )
                        continue
                    steps.append(
                        ReversePlanStep(
                            description=f"Force-drop recreated table '{db}.{op.table}'",
                            sql=f"DROP TABLE {qual};",
                        )
                    )
                steps.append(
                    ReversePlanStep(
                        description=f"Restore quarantined table '{db}.{op.table}'",
                        sql=(
                            f"RENAME TABLE {self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(op.quarantine_name)} "
                            f"TO {qual};"
                        ),
                    )
                )
                continue

            if op.op_type == "QUARANTINE_TRUNCATE":
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, QUARANTINE_DB):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=None,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined truncate snapshot '{QUARANTINE_DB}.{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                q_qual = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(op.quarantine_name)}"
                if self._table_exists(op.table, db):
                    cnt_res = self._client.query(f"SELECT COUNT(*) FROM {qual};")
                    new_count = int(cnt_res.rows[0][0]) if cnt_res.rows else 0
                    if new_count > 0 and not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={},
                                column=None,
                                expected_after=0,
                                actual_current=new_count,
                                reason=f"Table '{db}.{op.table}' has {new_count} new row(s) inserted since TRUNCATE.",
                            )
                        )
                        continue
                    steps.append(
                        ReversePlanStep(
                            description=f"Drop post-truncate table '{db}.{op.table}'",
                            sql=f"DROP TABLE {qual};",
                        )
                    )
                steps.append(
                    ReversePlanStep(
                        description=f"Restore truncated table '{db}.{op.table}' from quarantine",
                        sql=f"RENAME TABLE {q_qual} TO {qual};",
                    )
                )
                continue

            if op.op_type == "ALTER_ADD_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                col = str(meta["column"])
                live_cols = {c.lower() for c in self.inspect_table(op.table, db).columns} if self._table_exists(op.table, db) else set()
                if col.lower() not in live_cols:
                    if not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={},
                                column=col,
                                expected_after=col,
                                actual_current=None,
                                row_missing=True,
                                reason=f"Column '{col}' no longer exists on '{db}.{op.table}'.",
                            )
                        )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Drop added column '{col}' from '{db}.{op.table}'",
                        sql=f"ALTER TABLE {qual} DROP COLUMN {self.quote_ident(col)};",
                    )
                )
                continue

            if op.op_type == "QUARANTINE_DROP_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                col = str(meta["column"])
                col_type = str(meta.get("col_type") or "TEXT")
                mysql_col_def = meta.get("mysql_col_def")
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, QUARANTINE_DB):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined column snapshot '{QUARANTINE_DB}.{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                live_cols = {c.lower() for c in self.inspect_table(op.table, db).columns} if self._table_exists(op.table, db) else set()
                if col.lower() in live_cols and not force:
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=None,
                            actual_current=col,
                            reason=f"Column '{col}' was recreated on '{db}.{op.table}' since DROP COLUMN.",
                        )
                    )
                    continue
                q_tbl = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(op.quarantine_name)}"
                if col.lower() not in live_cols:
                    steps.append(
                        ReversePlanStep(
                            description=f"Re-add dropped column '{col}' on '{db}.{op.table}'",
                            sql=f"ALTER TABLE {qual} ADD COLUMN {self.quote_ident(col)} {col_type} NULL;",
                        )
                    )
                if op.pk_columns:
                    join_cond = " AND ".join(
                        f"t.{self.quote_ident(pk)} = q.{self.quote_ident(pk)}"
                        for pk in op.pk_columns
                    )
                    steps.append(
                        ReversePlanStep(
                            description=f"Backfill values for '{db}.{op.table}.{col}' from quarantine",
                            sql=(
                                f"UPDATE {qual} AS t JOIN {q_tbl} AS q ON {join_cond} "
                                f"SET t.{self.quote_ident(col)} = q.{self.quote_ident(col)};"
                            ),
                        )
                    )
                if mysql_col_def and col.lower() not in live_cols:
                    steps.append(
                        ReversePlanStep(
                            description=f"Restore column constraints/defaults on '{db}.{op.table}.{col}'",
                            sql=f"ALTER TABLE {qual} MODIFY COLUMN {self.quote_ident(col)} {mysql_col_def};",
                        )
                    )
                steps.append(
                    ReversePlanStep(
                        description=f"Clean up column quarantine snapshot '{op.quarantine_name}'",
                        sql=f"DROP TABLE {q_tbl};",
                    )
                )
                continue

            if op.op_type == "ALTER_RENAME_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                old_name = str(meta["old_name"])
                new_name = str(meta["new_name"])
                live_cols = {c.lower() for c in self.inspect_table(op.table, db).columns} if self._table_exists(op.table, db) else set()
                if new_name.lower() not in live_cols or (old_name.lower() in live_cols and not force):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=new_name,
                            expected_after=new_name,
                            actual_current=old_name if old_name.lower() in live_cols else None,
                            reason=f"Column rename state drifted on '{db}.{op.table}' ({old_name} -> {new_name}).",
                        )
                    )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Rename column '{new_name}' back to '{old_name}' on '{db}.{op.table}'",
                        sql=f"ALTER TABLE {qual} RENAME COLUMN {self.quote_ident(new_name)} TO {self.quote_ident(old_name)};",
                    )
                )
                continue

            if op.op_type == "ALTER_RENAME_TABLE":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                old_db = str(meta.get("old_schema") or db)
                old_tbl = str(meta["old_table"])
                new_db = str(meta.get("new_schema") or old_db)
                new_tbl = str(meta["new_table"])
                if not self._table_exists(new_tbl, new_db) or (self._table_exists(old_tbl, old_db) and not force):
                    conflicts.append(
                        DriftConflict(
                            table=new_tbl,
                            pk={},
                            column=None,
                            expected_after=new_tbl,
                            actual_current=old_tbl if self._table_exists(old_tbl, old_db) else None,
                            reason=f"Table rename state drifted ({old_tbl} -> {new_tbl}).",
                        )
                    )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Rename table '{new_tbl}' back to '{old_tbl}'",
                        sql=f"RENAME TABLE {self._qualify(new_tbl, new_db)} TO {self._qualify(old_tbl, old_db)};",
                    )
                )
                continue

            if op.op_type == "QUARANTINE_ALTER_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                old_name = str(meta.get("old_name") or meta["column"])
                new_name = str(meta.get("new_name") or old_name)
                col_type = str(meta.get("col_type") or "TEXT")
                mysql_col_def = meta.get("mysql_col_def")
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, QUARANTINE_DB):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=new_name,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined column snapshot '{QUARANTINE_DB}.{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                live_cols = {c.lower() for c in self.inspect_table(op.table, db).columns} if self._table_exists(op.table, db) else set()
                if new_name.lower() not in live_cols or (new_name.lower() != old_name.lower() and old_name.lower() in live_cols and not force):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=new_name,
                            expected_after=new_name,
                            actual_current=old_name if old_name.lower() in live_cols else None,
                            reason=f"Column alter state drifted on '{db}.{op.table}' ({old_name} -> {new_name}).",
                        )
                    )
                    continue
                q_tbl = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(op.quarantine_name)}"
                if new_name.lower() != old_name.lower():
                    steps.append(
                        ReversePlanStep(
                            description=f"Rename and widen column '{new_name}' back to '{old_name}'",
                            sql=f"ALTER TABLE {qual} CHANGE COLUMN {self.quote_ident(new_name)} {self.quote_ident(old_name)} {col_type} NULL;",
                        )
                    )
                else:
                    steps.append(
                        ReversePlanStep(
                            description=f"Revert column type of '{db}.{op.table}.{old_name}' to '{col_type}'",
                            sql=f"ALTER TABLE {qual} MODIFY COLUMN {self.quote_ident(old_name)} {col_type} NULL;",
                        )
                    )
                if op.pk_columns:
                    join_cond = " AND ".join(
                        f"t.{self.quote_ident(pk)} = q.{self.quote_ident(pk)}"
                        for pk in op.pk_columns
                    )
                    steps.append(
                        ReversePlanStep(
                            description=f"Backfill original values for '{db}.{op.table}.{old_name}' from quarantine",
                            sql=(
                                f"UPDATE {qual} AS t JOIN {q_tbl} AS q ON {join_cond} "
                                f"SET t.{self.quote_ident(old_name)} = q.{self.quote_ident(old_name)};"
                            ),
                        )
                    )
                if mysql_col_def:
                    steps.append(
                        ReversePlanStep(
                            description=f"Restore column constraints/defaults on '{db}.{op.table}.{old_name}'",
                            sql=f"ALTER TABLE {qual} MODIFY COLUMN {self.quote_ident(old_name)} {mysql_col_def};",
                        )
                    )
                steps.append(
                    ReversePlanStep(
                        description=f"Clean up column quarantine snapshot '{op.quarantine_name}'",
                        sql=f"DROP TABLE {q_tbl};",
                    )
                )
                continue

            if op.op_type == "ALTER_COLUMN_ATTR":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                col = str(meta["column"])
                mysql_col_def = meta.get("mysql_col_def")
                live_cols = {c.lower() for c in self.inspect_table(op.table, db).columns} if self._table_exists(op.table, db) else set()
                if col.lower() not in live_cols:
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=col,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Column '{col}' no longer exists on '{db}.{op.table}'.",
                        )
                    )
                    continue
                if mysql_col_def:
                    steps.append(
                        ReversePlanStep(
                            description=f"Restore column attributes on '{db}.{op.table}.{col}'",
                            sql=f"ALTER TABLE {qual} MODIFY COLUMN {self.quote_ident(col)} {mysql_col_def};",
                        )
                    )
                continue

            if op.op_type == "ALTER_CREATE_INDEX":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                idx_name = str(meta["index_name"])
                existing_tbl, _ = self._mysql_index_def(db, op.table or None, idx_name)
                if existing_tbl is None:
                    if not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={},
                                column=None,
                                expected_after=idx_name,
                                actual_current=None,
                                row_missing=True,
                                reason=f"Index '{idx_name}' no longer exists on '{db}.{op.table}'.",
                            )
                        )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Drop created index '{idx_name}' from '{db}.{existing_tbl}'",
                        sql=f"DROP INDEX {self.quote_ident(idx_name)} ON {self._qualify(existing_tbl, db)};",
                    )
                )
                continue

            if op.op_type == "ALTER_DROP_INDEX":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                idx_name = str(meta["index_name"])
                create_sql = str(meta["create_sql"])
                existing_tbl, _ = self._mysql_index_def(db, op.table or None, idx_name)
                if existing_tbl is not None and not force:
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=None,
                            expected_after=None,
                            actual_current=idx_name,
                            reason=f"Index '{idx_name}' already exists on '{db}.{existing_tbl}'.",
                        )
                    )
                    continue
                if existing_tbl is None:
                    steps.append(
                        ReversePlanStep(
                            description=f"Recreate dropped index '{idx_name}' on '{db}.{op.table}'",
                            sql=create_sql if create_sql.rstrip().endswith(";") else f"{create_sql};",
                        )
                    )
                continue

            if op.op_type == "INSERT":
                live_cols = set(self.inspect_table(op.table, db).columns) if self._table_exists(op.table, db) else set()
                current_map = self._prefetch_current_rows(
                    op,
                    [{pk: row[pk] for pk in op.pk_columns} for row in op.after_rows],
                    for_update=lock_rows,
                )
                for row in reversed(op.after_rows):
                    pk_vals = {pk: row[pk] for pk in op.pk_columns}
                    current = current_map.get(self._pk_key(row, op.pk_columns))
                    if current is None:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk=pk_vals,
                                column=None,
                                expected_after=row,
                                actual_current=None,
                                row_missing=True,
                                reason="Inserted row was already deleted.",
                            )
                        )
                        continue
                    for col, expected_val in row.items():
                        if live_cols and col not in live_cols:
                            if not force:
                                conflicts.append(
                                    DriftConflict(
                                        table=op.table,
                                        pk=pk_vals,
                                        column=col,
                                        expected_after=expected_val,
                                        actual_current=None,
                                        reason=f"Schema changed: column '{col}' was dropped since INSERT.",
                                    )
                                )
                            continue
                        if current.get(col) != expected_val:
                            conflicts.append(
                                DriftConflict(
                                    table=op.table,
                                    pk=pk_vals,
                                    column=col,
                                    expected_after=expected_val,
                                    actual_current=current.get(col),
                                    reason=f"Column '{col}' modified since INSERT.",
                                )
                            )
                    where_parts = [f"{self.quote_ident(pk)} <=> ?" for pk in op.pk_columns]
                    steps.append(
                        ReversePlanStep(
                            description=f"Delete inserted row {pk_vals} from '{db}.{op.table}'",
                            sql=f"DELETE FROM {qual} WHERE {' AND '.join(where_parts)};",
                            params=[pk_vals[pk] for pk in op.pk_columns],
                        )
                    )
                continue

            if op.op_type == "DELETE" and op.side_table_before and not op.before_rows and self._table_exists(op.side_table_before, QUARANTINE_DB):
                qb = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(op.side_table_before)}"
                t_schema = self.inspect_table(op.table, db)
                pk_eq = " AND ".join(f"t.{self.quote_ident(pk)} = b.{self.quote_ident(pk)}" for pk in op.pk_columns)
                if not force:
                    conf_res = self._client.query(
                        f"SELECT t.* FROM {qual} AS t INNER JOIN {qb} AS b ON {pk_eq} LIMIT 25 FOR UPDATE;"
                    )
                    for crow in self._res_to_dicts(conf_res):
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={pk: crow[pk] for pk in op.pk_columns},
                                column=None,
                                expected_after=None,
                                actual_current=crow,
                                reason="A row with the same primary key was inserted since DELETE.",
                            )
                        )
                cols_q = ", ".join(self.quote_ident(c) for c in t_schema.columns)
                ins_sql = f"INSERT INTO {qual} ({cols_q}) SELECT {cols_q} FROM {qb}"
                if force:
                    non_pk = [c for c in t_schema.columns if c not in op.pk_columns]
                    if non_pk:
                        upd_set = ", ".join(
                            f"{self.quote_ident(c)} = VALUES({self.quote_ident(c)})" for c in non_pk
                        )
                        ins_sql += f" ON DUPLICATE KEY UPDATE {upd_set}"
                ins_sql += ";"
                tag_lbl = "[spilled_temp_table]" if op.side_table_before.startswith("_rev_") else "[side_table]"
                steps.append(
                    ReversePlanStep(
                        description=f"{tag_lbl} Restore deleted rows from DB-side snapshot '{op.side_table_before}' into '{db}.{op.table}'",
                        sql=ins_sql,
                    )
                )
                continue

            if op.op_type == "DELETE":
                live_cols = set(self.inspect_table(op.table, db).columns) if self._table_exists(op.table, db) else set()
                current_map = (
                    {}
                    if force
                    else self._prefetch_current_rows(
                        op,
                        [{pk: row[pk] for pk in op.pk_columns} for row in op.before_rows],
                        for_update=lock_rows,
                    )
                )
                for row in reversed(op.before_rows):
                    pk_vals = {pk: row[pk] for pk in op.pk_columns}
                    current = current_map.get(self._pk_key(row, op.pk_columns))
                    if current is not None and not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk=pk_vals,
                                column=None,
                                expected_after=None,
                                actual_current=current,
                                reason="A row with the same primary key was inserted since DELETE.",
                            )
                        )
                        continue
                    dropped = [c for c in row.keys() if live_cols and c not in live_cols]
                    if dropped and not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk=pk_vals,
                                column=dropped[0],
                                expected_after=row[dropped[0]],
                                actual_current=None,
                                reason=f"Schema changed: column '{dropped[0]}' was dropped since DELETE.",
                            )
                        )
                        continue
                    cols = [c for c in row.keys() if not live_cols or c in live_cols]
                    quoted_cols = ", ".join(self.quote_ident(c) for c in cols)
                    placeholders = ", ".join("?" for _ in cols)
                    sql = f"INSERT INTO {qual} ({quoted_cols}) VALUES ({placeholders})"
                    if force:
                        updates = ", ".join(
                            f"{self.quote_ident(c)} = VALUES({self.quote_ident(c)})"
                            for c in cols
                            if c not in op.pk_columns
                        )
                        if updates:
                            sql += f" ON DUPLICATE KEY UPDATE {updates}"
                    sql += ";"
                    steps.append(
                        ReversePlanStep(
                            description=f"Re-insert deleted row {pk_vals} into '{db}.{op.table}'",
                            sql=sql,
                            params=[row[c] for c in cols],
                        )
                    )
                continue

            if op.op_type == "UPDATE" and op.side_table_before and op.side_table_after and not op.before_rows and self._table_exists(op.side_table_before, QUARANTINE_DB):
                qb = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(op.side_table_before)}"
                qa = f"{self.quote_ident(QUARANTINE_DB)}.{self.quote_ident(op.side_table_after)}"
                t_schema = self.inspect_table(op.table, db)
                pk_eq_a = " AND ".join(f"t.{self.quote_ident(pk)} = a.{self.quote_ident(pk)}" for pk in op.pk_columns)
                pk_eq_b = " AND ".join(f"t.{self.quote_ident(pk)} = b.{self.quote_ident(pk)}" for pk in op.pk_columns)
                if lock_rows:
                    self._client.query(
                        f"SELECT COUNT(t.{self.quote_ident(op.pk_columns[0])}) FROM {qual} AS t INNER JOIN {qa} AS a ON {pk_eq_a} FOR UPDATE;"
                    )
                if not force:
                    pk0_q = self.quote_ident(op.pk_columns[0])
                    miss_res = self._client.query(
                        f"SELECT a.* FROM {qa} AS a LEFT JOIN {qual} AS t ON {pk_eq_a} WHERE t.{pk0_q} IS NULL LIMIT 25;"
                    )
                    for mrow in self._res_to_dicts(miss_res):
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={pk: mrow[pk] for pk in op.pk_columns},
                                column=None,
                                expected_after=mrow,
                                actual_current=None,
                                row_missing=True,
                                reason="Updated row was deleted since UPDATE.",
                            )
                        )
                    diff_preds = " OR ".join(
                        f"NOT (t.{self.quote_ident(c)} <=> a.{self.quote_ident(c)})"
                        for c in t_schema.columns
                    )
                    if diff_preds:
                        diff_res = self._client.query(
                            f"SELECT t.* FROM {qual} AS t INNER JOIN {qa} AS a ON {pk_eq_a} WHERE ({diff_preds}) LIMIT 25;"
                        )
                        for drow in self._res_to_dicts(diff_res):
                            conflicts.append(
                                DriftConflict(
                                    table=op.table,
                                    pk={pk: drow[pk] for pk in op.pk_columns},
                                    column=None,
                                    expected_after=None,
                                    actual_current=drow,
                                    reason="Row modified since UPDATE.",
                                )
                            )
                non_pk_cols = [c for c in t_schema.columns if c not in op.pk_columns]
                set_cols = non_pk_cols or list(t_schema.columns)
                set_sql = ", ".join(
                    f"t.{self.quote_ident(c)} = b.{self.quote_ident(c)}" for c in set_cols
                )
                tag_lbl = "[spilled_temp_table]" if op.side_table_before.startswith("_rev_") else "[side_table]"
                steps.append(
                    ReversePlanStep(
                        description=f"{tag_lbl} Restore updated rows from DB-side snapshot '{op.side_table_before}' into '{db}.{op.table}'",
                        sql=f"UPDATE {qual} AS t INNER JOIN {qb} AS b ON {pk_eq_b} SET {set_sql};",
                    )
                )
                continue

            if op.op_type == "UPDATE":
                live_cols = set(self.inspect_table(op.table, db).columns) if self._table_exists(op.table, db) else set()
                after_by_pk = {self._pk_key(r, op.pk_columns): r for r in op.after_rows}
                pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
                for idx, before in enumerate(reversed(op.before_rows)):
                    orig_idx = len(op.before_rows) - 1 - idx
                    before_pk = self._pk_key(before, op.pk_columns)
                    after = after_by_pk.get(before_pk)
                    if after is None and orig_idx < len(op.after_rows):
                        after = op.after_rows[orig_idx]
                    if after is not None:
                        pairs.append((before, after))

                current_map = self._prefetch_current_rows(
                    op,
                    [{pk: after[pk] for pk in op.pk_columns} for _, after in pairs],
                    for_update=lock_rows,
                )
                for before, after in pairs:
                    after_pk_vals = {pk: after[pk] for pk in op.pk_columns}
                    current = current_map.get(self._pk_key(after, op.pk_columns))
                    if current is None:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk=after_pk_vals,
                                column=None,
                                expected_after=after,
                                actual_current=None,
                                row_missing=True,
                                reason="Updated row was deleted since UPDATE.",
                            )
                        )
                        continue
                    for col, expected_val in after.items():
                        if live_cols and col not in live_cols:
                            if not force:
                                conflicts.append(
                                    DriftConflict(
                                        table=op.table,
                                        pk=after_pk_vals,
                                        column=col,
                                        expected_after=expected_val,
                                        actual_current=None,
                                        reason=f"Schema changed: column '{col}' was dropped since UPDATE.",
                                    )
                                )
                            continue
                        if current.get(col) != expected_val:
                            conflicts.append(
                                DriftConflict(
                                    table=op.table,
                                    pk=after_pk_vals,
                                    column=col,
                                    expected_after=expected_val,
                                    actual_current=current.get(col),
                                    reason=f"Column '{col}' modified since UPDATE.",
                                )
                            )
                    cols = [c for c in before.keys() if not live_cols or c in live_cols]
                    set_sql = ", ".join(f"{self.quote_ident(c)} = ?" for c in cols)
                    where_parts = [f"{self.quote_ident(pk)} <=> ?" for pk in op.pk_columns]
                    params = [before[c] for c in cols] + [
                        after_pk_vals[pk] for pk in op.pk_columns
                    ]
                    steps.append(
                        ReversePlanStep(
                            description=f"Revert row {after_pk_vals} in '{db}.{op.table}'",
                            sql=f"UPDATE {qual} SET {set_sql} WHERE {' AND '.join(where_parts)};",
                            params=params,
                        )
                    )

        return steps, conflicts

    _RE_INSERT_BATCH = re.compile(
        r"^INSERT\s+INTO\s+(.+?)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\);?$",
        re.IGNORECASE | re.DOTALL,
    )
    _RE_DELETE_SINGLE_PK = re.compile(
        r"^DELETE\s+FROM\s+(.+?)\s+WHERE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_]*))\s*<=>\s*\?;?$",
        re.IGNORECASE,
    )
    _RE_UPDATE_SINGLE_PK = re.compile(
        r"^UPDATE\s+(.+?)\s+SET\s+(.+?)\s+WHERE\s+((?:`[^`]+`|[A-Za-z_][A-Za-z0-9_]*))\s*<=>\s*\?;?$",
        re.IGNORECASE | re.DOTALL,
    )

    def _execute_batched_steps(self, steps: Sequence[ReversePlanStep]) -> None:
        idx = 0
        n = len(steps)
        while idx < n:
            sql = steps[idx].sql
            if not steps[idx].params:
                self._client.execute(sql, ())
                idx += 1
                continue
            end = idx + 1
            while end < n and steps[end].sql == sql and steps[end].params:
                end += 1
            run = steps[idx:end]
            idx = end

            if len(run) == 1:
                self._client.execute(sql, run[0].params)
                continue

            m_ins = self._RE_INSERT_BATCH.match(sql)
            if m_ins:
                tbl_sql, cols_sql, ph_sql = m_ins.groups()
                for c_start in range(0, len(run), 500):
                    chunk = run[c_start : c_start + 500]
                    vals = ", ".join(f"({ph_sql})" for _ in chunk)
                    flat = [p for s in chunk for p in s.params]
                    self._client.execute(f"INSERT INTO {tbl_sql} ({cols_sql}) VALUES {vals};", flat)
                continue

            m_del = self._RE_DELETE_SINGLE_PK.match(sql)
            if m_del and all(s.params[0] is not None for s in run):
                tbl_sql, pk_sql = m_del.groups()
                for c_start in range(0, len(run), 500):
                    chunk = run[c_start : c_start + 500]
                    phs = ", ".join("?" for _ in chunk)
                    flat = [s.params[0] for s in chunk]
                    self._client.execute(f"DELETE FROM {tbl_sql} WHERE {pk_sql} IN ({phs});", flat)
                continue

            m_upd = self._RE_UPDATE_SINGLE_PK.match(sql)
            if m_upd and len(run) >= 4:
                tbl_sql, set_clause, pk_sql = m_upd.groups()
                set_cols = [
                    m.group(1)
                    for m in re.finditer(r"(`[^`]+`|[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\?", set_clause)
                ]
                if set_cols and len(set_cols) + 1 == len(run[0].params):
                    for c_start in range(0, len(run), 200):
                        chunk = run[c_start : c_start + 200]
                        pks = [s.params[-1] for s in chunk]
                        if any(pk is None for pk in pks) or len(set(pks)) != len(pks):
                            for s in chunk:
                                self._client.execute(s.sql, s.params)
                            continue
                        set_parts: list[str] = []
                        flat: list[Any] = []
                        for ci, col_sql in enumerate(set_cols):
                            whens = " ".join("WHEN ? THEN ?" for _ in chunk)
                            set_parts.append(f"{col_sql} = CASE {pk_sql} {whens} END")
                            for s in chunk:
                                flat.append(s.params[-1])
                                flat.append(s.params[ci])
                        in_phs = ", ".join("?" for _ in chunk)
                        flat.extend(pks)
                        self._client.execute(
                            f"UPDATE {tbl_sql} SET {', '.join(set_parts)} WHERE {pk_sql} IN ({in_phs});",
                            flat,
                        )
                    continue

            for s in run:
                self._client.execute(s.sql, s.params)

    def apply_reverse(
        self,
        record: UndoRecord,
        *,
        dry_run: bool = False,
        force: bool = False,
    ) -> ReverseResult:
        if dry_run:
            steps, conflicts = self.build_reverse_plan(record, force=force)
            if conflicts and not force:
                return ReverseResult(
                    tx_id=record.tx_id,
                    success=False,
                    dry_run=True,
                    steps=steps,
                    conflicts=conflicts,
                    error=f"Drift detected ({len(conflicts)} conflict(s)); pass FORCE to override.",
                )
            return ReverseResult(
                tx_id=record.tx_id,
                success=True,
                dry_run=True,
                reversed_rows=len(steps),
                steps=steps,
                conflicts=conflicts,
            )

        if self.binlog_marker_enabled and not self._marker_table_ready:
            self._ensure_marker_table()

        rev_warnings: list[str] = []
        default_db = self._current_db()
        use_rbr = (
            not force
            and any(
                op.rbr_fde_b64
                and op.rbr_undo_events
                and self._table_has_triggers(op.table, op.schema or default_db)
                for op in record.ops
            )
        )

        op_steps_list: list[tuple[MutationOp, list[ReversePlanStep]]] = []
        steps: list[ReversePlanStep] = []
        conflicts: list[DriftConflict] = []

        if use_rbr:
            try:
                seen_fdes: set[str] = set()
                for op in reversed(record.ops):
                    if op.rbr_fde_b64 and op.rbr_fde_b64 not in seen_fdes:
                        seen_fdes.add(op.rbr_fde_b64)
                        self._client.query(f"BINLOG '{op.rbr_fde_b64}';")
                self._client.query("BEGIN;")
                for op in reversed(record.ops):
                    op_steps, op_conflicts = self._build_op_reverse_plan(
                        op, force=force, lock_rows=True
                    )
                    op_steps_list.append((op, op_steps))
                    steps.extend(op_steps)
                    conflicts.extend(op_conflicts)
                if conflicts and not force:
                    self._client.query("ROLLBACK;")
                    return ReverseResult(
                        tx_id=record.tx_id,
                        success=False,
                        dry_run=False,
                        steps=steps,
                        conflicts=conflicts,
                        error=f"Drift detected ({len(conflicts)} conflict(s)); pass FORCE to override.",
                    )
                self._maybe_emit_binlog_marker(is_reverse=True)
                for op, op_steps in op_steps_list:
                    if op.rbr_fde_b64 and op.rbr_undo_events:
                        for blob in reversed(op.rbr_undo_events):
                            self._client.query(f"BINLOG '{blob}';")
                    else:
                        self._execute_batched_steps(op_steps)
                self._client.query("COMMIT;")
                rev_count = max(len(steps), sum(op.side_rowcount for op in record.ops))
                return ReverseResult(
                    tx_id=record.tx_id,
                    success=True,
                    dry_run=False,
                    reversed_rows=rev_count,
                    steps=steps,
                    conflicts=conflicts,
                    warnings=rev_warnings,
                )
            except MySQLError as exc:
                try:
                    self._client.query("ROLLBACK;")
                except Exception:
                    pass
                if exc.code not in (1227, 1044, 1045):
                    return ReverseResult(
                        tx_id=record.tx_id,
                        success=False,
                        dry_run=False,
                        steps=steps,
                        conflicts=conflicts,
                        error=f"Reverse execution failed: {exc}",
                    )
                rev_warnings.append(
                    "Backend MySQL user lacks BINLOG_ADMIN/SUPER privilege; SQL fallback executed and active triggers may have fired."
                )
            except Exception as exc:
                try:
                    self._client.query("ROLLBACK;")
                except Exception:
                    pass
                return ReverseResult(
                    tx_id=record.tx_id,
                    success=False,
                    dry_run=False,
                    steps=steps,
                    conflicts=conflicts,
                    error=f"Reverse execution failed: {exc}",
                )

        staged_rec, temp_side_tables = self._stage_spilled_record_ops(record, force=force)
        try:
            self._client.query("BEGIN;")
            try:
                steps, conflicts = self.build_reverse_plan(staged_rec, force=force, lock_rows=True)
                if conflicts and not force:
                    self._client.query("ROLLBACK;")
                    return ReverseResult(
                        tx_id=record.tx_id,
                        success=False,
                        dry_run=False,
                        steps=steps,
                        conflicts=conflicts,
                        error=f"Drift detected ({len(conflicts)} conflict(s)); pass FORCE to override.",
                    )
                self._maybe_emit_binlog_marker(is_reverse=True)
                self._execute_batched_steps(steps)
                self._client.query("COMMIT;")
            except Exception as exc:
                try:
                    self._client.query("ROLLBACK;")
                except Exception:
                    pass
                return ReverseResult(
                    tx_id=record.tx_id,
                    success=False,
                    dry_run=False,
                    steps=steps,
                    conflicts=conflicts,
                    error=f"Reverse execution failed: {exc}",
                )
        finally:
            if temp_side_tables:
                self.drop_side_tables(temp_side_tables)

        rev_count = max(
            len(steps),
            sum(max(op.side_rowcount, len(op.before_rows), len(op.after_rows)) for op in record.ops),
        )
        r_path = "row_batched"
        if any("[side_table]" in s.description for s in steps):
            r_path = "side_table"
        elif any("[spilled_temp_table]" in s.description for s in steps):
            r_path = "spilled_temp_table"
        elif any(op.op_type.startswith(("QUARANTINE_", "ALTER_")) for op in record.ops):
            r_path = "ddl_quarantine"
        return ReverseResult(
            tx_id=record.tx_id,
            success=True,
            dry_run=False,
            reversed_rows=rev_count,
            steps=steps,
            conflicts=conflicts,
            warnings=rev_warnings,
            restore_path=r_path,
        )
