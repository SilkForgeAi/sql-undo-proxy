"""SQLite EngineDriver implementation with atomic row capture, DDL quarantine, and drift-checked reversal."""

from __future__ import annotations

import json
import sqlite3
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
from ..parser import extract_insert_value_dicts, tokenize
from .base import EngineDriver

PROXY_ROWID_ALIAS = "__proxy_rowid__"


class SQLiteDriver(EngineDriver):
    """EngineDriver for SQLite 3.35+ (leverages RETURNING and manual tx control)."""

    engine_type = EngineType.SQLITE

    def __init__(self, db_path: str = ":memory:", *, max_capture_rows: int | None = None) -> None:
        self.db_path = db_path
        self.max_capture_rows = max_capture_rows
        self._conn = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA foreign_keys = ON;")

    def close(self) -> None:
        self._conn.close()

    def quote_ident(self, name: str) -> str:
        return '"' + name.replace('"', '""') + '"'

    def _qualify(self, table: str, schema: str | None = None) -> str:
        if schema:
            return f"{self.quote_ident(schema)}.{self.quote_ident(table)}"
        return self.quote_ident(table)

    def _table_exists(self, table: str, schema: str | None = None) -> bool:
        master = f"{self.quote_ident(schema)}.sqlite_master" if schema else "sqlite_master"
        cur = self._conn.execute(
            f"SELECT 1 FROM {master} WHERE type = 'table' AND name = ? LIMIT 1",
            (table,),
        )
        return cur.fetchone() is not None

    def inspect_table(self, table: str, schema: str | None = None) -> TableSchema:
        pragma_target = (
            f"{self.quote_ident(schema)}.table_info({self.quote_ident(table)})"
            if schema
            else f"table_info({self.quote_ident(table)})"
        )
        rows = self._conn.execute(f"PRAGMA {pragma_target};").fetchall()
        if not rows:
            raise ValueError(f"Table '{table}' does not exist or has no columns.")

        columns: list[str] = []
        column_types: dict[str, str] = {}
        pk_indexed: list[tuple[int, str]] = []

        for cid, name, col_type, notnull, dflt_value, pk in rows:
            columns.append(name)
            column_types[name] = col_type or "ANY"
            if pk and pk > 0:
                pk_indexed.append((pk, name))

        pk_indexed.sort(key=lambda item: item[0])
        pk_columns = [name for _, name in pk_indexed]
        using_rowid_fallback = False
        rowid_column: str | None = None

        if not pk_columns:
            using_rowid_fallback = True
            rowid_column = PROXY_ROWID_ALIAS
            pk_columns = [PROXY_ROWID_ALIAS]

        return TableSchema(
            table=table,
            schema=schema,
            columns=columns,
            pk_columns=pk_columns,
            column_types=column_types,
            using_rowid_fallback=using_rowid_fallback,
            rowid_column=rowid_column,
        )

    def inspect_foreign_keys(self) -> list[ForeignKeyEdge]:
        tables = [
            r[0]
            for r in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_reverse_quarantine%';"
            ).fetchall()
        ]
        edges: list[ForeignKeyEdge] = []
        for child in tables:
            fk_rows = self._conn.execute(
                f"PRAGMA foreign_key_list({self.quote_ident(child)});"
            ).fetchall()
            grouped: dict[int, list[tuple[str, str, str, str]]] = {}
            for fk_id, _seq, ref_tbl, from_col, to_col, _on_upd, on_del, _match in fk_rows:
                grouped.setdefault(fk_id, []).append((ref_tbl, from_col, to_col, on_del.upper()))
            for entries in grouped.values():
                edges.append(
                    ForeignKeyEdge(
                        child_table=child,
                        child_columns=[e[1] for e in entries],
                        parent_table=entries[0][0],
                        parent_columns=[e[2] for e in entries],
                        on_delete=entries[0][3],
                    )
                )
        return edges

    @contextmanager
    def _ensure_tx(self, in_client_tx: bool) -> Iterator[None]:
        if in_client_tx:
            yield
            return
        self._conn.execute("BEGIN IMMEDIATE;")
        try:
            yield
        except Exception:
            self._conn.execute("ROLLBACK;")
            raise
        else:
            self._conn.execute("COMMIT;")

    def begin_tx(self) -> None:
        self._conn.execute("BEGIN;")

    def commit_tx(self) -> None:
        self._conn.execute("COMMIT;")

    def rollback_tx(self) -> None:
        self._conn.execute("ROLLBACK;")

    def savepoint(self, name: str) -> None:
        self._conn.execute(f"SAVEPOINT {self.quote_ident(name)};")

    def rollback_to_savepoint(self, name: str) -> None:
        self._conn.execute(f"ROLLBACK TO SAVEPOINT {self.quote_ident(name)};")

    def release_savepoint(self, name: str) -> None:
        self._conn.execute(f"RELEASE SAVEPOINT {self.quote_ident(name)};")

    def execute_read(self, sql: str, params: Sequence[Any] = ()) -> QueryResult:
        cur = self._conn.execute(sql, params)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchall() if cur.description else []
        return QueryResult(
            columns=cols,
            rows=rows,
            rowcount=len(rows) if cols else (cur.rowcount if cur.rowcount >= 0 else 0),
            command_tag="SELECT",
        )

    def _rows_to_dicts(
        self, cursor: sqlite3.Cursor, rows: list[tuple[Any, ...]]
    ) -> list[dict[str, Any]]:
        if not cursor.description:
            return []
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, r)) for r in rows]

    def _select_projection(
        self, schema: TableSchema, alias: str | None = None, *, qual_table: str | None = None
    ) -> str:
        ref = self.quote_ident(alias) if alias else qual_table
        prefix = f"{ref}." if ref else ""
        if schema.using_rowid_fallback:
            return f"{prefix}rowid AS {self.quote_ident(PROXY_ROWID_ALIAS)}, {prefix}*"
        return f"{prefix}*"

    @staticmethod
    def _from_join_sql(from_join_clause: str | None) -> str:
        if not from_join_clause:
            return ""
        upper = from_join_clause.lstrip().upper()
        if upper.startswith(("JOIN ", "INNER ", "LEFT ", "CROSS ")):
            return f" {from_join_clause}"
        return f", {from_join_clause}"

    def _returning_projection(self, schema: TableSchema) -> str:
        if schema.using_rowid_fallback:
            return f"rowid AS {self.quote_ident(PROXY_ROWID_ALIAS)}, *"
        return "*"

    def _pk_key(self, row: dict[str, Any], pk_columns: list[str]) -> tuple[Any, ...]:
        return tuple(row[col] for col in pk_columns)

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
                cur = self._conn.execute(stmt.raw_sql, params)
                rc = cur.rowcount if cur.rowcount >= 0 else 0
            return (
                QueryResult(rowcount=rc, command_tag=stmt.kind.value.upper(), warnings=warnings),
                [],
                warnings,
            )

        if not stmt.table:
            raise ValueError(f"Could not determine target table for statement: {stmt.raw_sql}")

        if stmt.kind == StatementKind.INSERT:
            return self._execute_insert(
                stmt, in_client_tx=in_client_tx, params=params, warnings=warnings
            )
        if stmt.kind == StatementKind.UPDATE:
            return self._execute_update(
                stmt, in_client_tx=in_client_tx, params=params, warnings=warnings
            )
        if stmt.kind == StatementKind.DELETE:
            return self._execute_delete(
                stmt, in_client_tx=in_client_tx, params=params, warnings=warnings
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
        assert stmt.table is not None
        with self._ensure_tx(in_client_tx):
            if not self._table_exists(stmt.table, stmt.schema):
                if stmt.if_exists:
                    return (
                        QueryResult(rowcount=0, command_tag="DROP TABLE", warnings=warnings),
                        [],
                        warnings,
                    )
                raise sqlite3.OperationalError(f"no such table: {stmt.table}")

            t_schema = self.inspect_table(stmt.table, stmt.schema)
            quarantine_name = f"_reverse_quarantine__{tx_id}__{stmt.table}"
            src = self._qualify(stmt.table, stmt.schema)
            dst = self.quote_ident(quarantine_name)
            self._conn.execute(f"ALTER TABLE {src} RENAME TO {dst};")

        op = MutationOp(
            op_type="QUARANTINE_DROP",
            table=stmt.table,
            schema=stmt.schema,
            pk_columns=t_schema.pk_columns,
            column_types=t_schema.column_types,
            quarantine_name=quarantine_name,
            using_rowid_fallback=t_schema.using_rowid_fallback,
            rowid_column=t_schema.rowid_column,
        )
        return (
            QueryResult(rowcount=0, command_tag="DROP TABLE", warnings=warnings),
            [op],
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
        with self._ensure_tx(in_client_tx):
            if not self._table_exists(stmt.table, stmt.schema):
                raise sqlite3.OperationalError(f"no such table: {stmt.table}")

            t_schema = self.inspect_table(stmt.table, stmt.schema)
            master = (
                f"{self.quote_ident(stmt.schema)}.sqlite_master"
                if stmt.schema
                else "sqlite_master"
            )
            ddl_rows = self._conn.execute(
                f"SELECT type, name, sql FROM {master} WHERE tbl_name = ? AND sql IS NOT NULL ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END;",
                (stmt.table,),
            ).fetchall()

            quarantine_name = f"_reverse_quarantine__{tx_id}__{stmt.table}"
            src = self._qualify(stmt.table, stmt.schema)
            dst = self.quote_ident(quarantine_name)
            self._conn.execute(f"ALTER TABLE {src} RENAME TO {dst};")

            index_names = [r[1] for r in ddl_rows if r[0] == "index"]
            index_sqls = [r[2] for r in ddl_rows if r[0] == "index"]
            for idx_name in index_names:
                self._conn.execute(f"DROP INDEX IF EXISTS {self.quote_ident(idx_name)};")

            # Recreate fresh empty table & indexes from original DDL
            for obj_type, _obj_name, obj_sql in ddl_rows:
                if obj_type in ("table", "index"):
                    self._conn.execute(obj_sql)

        op = MutationOp(
            op_type="QUARANTINE_TRUNCATE",
            table=stmt.table,
            schema=stmt.schema,
            pk_columns=t_schema.pk_columns,
            column_types=t_schema.column_types,
            quarantine_name=quarantine_name,
            using_rowid_fallback=t_schema.using_rowid_fallback,
            rowid_column=t_schema.rowid_column,
            extra_ddl=index_sqls,
        )
        return (
            QueryResult(rowcount=0, command_tag="TRUNCATE TABLE", warnings=warnings),
            [op],
            warnings,
        )

    def _sqlite_col_def(self, table: str, col: str, schema: str | None = None) -> dict[str, Any] | None:
        pragma = (
            f"PRAGMA {self.quote_ident(schema)}.table_info({self.quote_ident(table)});"
            if schema
            else f"PRAGMA table_info({self.quote_ident(table)});"
        )
        for _cid, name, col_type, notnull, dflt_value, _pk in self._conn.execute(pragma).fetchall():
            if str(name).lower() == col.lower():
                return {
                    "column": str(name),
                    "col_type": str(col_type or "TEXT"),
                    "not_null": bool(notnull),
                    "col_default": str(dflt_value) if dflt_value is not None else None,
                }
        return None

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
        with self._ensure_tx(in_client_tx):
            cur_schema_name = stmt.schema
            cur_table = stmt.table
            table_exists = self._table_exists(cur_table, cur_schema_name)
            t_schema = self.inspect_table(cur_table, cur_schema_name) if table_exists else None

            pre_snapshots: list[tuple[dict[str, Any], dict[str, Any], str]] = []
            effective_actions: list[dict[str, Any]] = []

            for act in stmt.alter_actions:
                kind = act["action"]
                if kind == "ADD_COLUMN":
                    col = act["column"]
                    if act.get("if_not_exists") and t_schema and col.lower() in {c.lower() for c in t_schema.columns}:
                        continue
                    effective_actions.append(act)
                elif kind == "DROP_COLUMN":
                    col = act["column"]
                    col_meta = self._sqlite_col_def(cur_table, col, cur_schema_name) if table_exists else None
                    if col_meta is None:
                        if act.get("if_exists"):
                            continue
                    else:
                        assert t_schema is not None
                        q_name = f"_reverse_quarantine__{tx_id}__{cur_table}__col_{col_meta['column']}"
                        if t_schema.using_rowid_fallback:
                            key_cols_sql = f"rowid AS {self.quote_ident(PROXY_ROWID_ALIAS)}"
                            idx_cols_sql = self.quote_ident(PROXY_ROWID_ALIAS)
                        else:
                            key_cols_sql = ", ".join(self.quote_ident(pk) for pk in t_schema.pk_columns)
                            idx_cols_sql = key_cols_sql
                        src = self._qualify(cur_table, cur_schema_name)
                        q_qual = self._qualify(q_name, cur_schema_name)
                        self._conn.execute(
                            f"CREATE TABLE {q_qual} AS SELECT {key_cols_sql}, {self.quote_ident(col_meta['column'])} FROM {src};"
                        )
                        idx_qual = self._qualify(f"_idx_{q_name}", cur_schema_name)
                        self._conn.execute(
                            f"CREATE INDEX IF NOT EXISTS {idx_qual} ON {self.quote_ident(q_name)} ({idx_cols_sql});"
                        )
                        pre_snapshots.append((act, col_meta, q_name))
                        effective_actions.append(act)
                elif kind in ("RENAME_COLUMN", "RENAME_TABLE"):
                    effective_actions.append(act)

            self._conn.execute(stmt.raw_sql)

            snap_iter = iter(pre_snapshots)
            for act in effective_actions:
                kind = act["action"]
                assert t_schema is not None
                if kind == "ADD_COLUMN":
                    ops.append(
                        MutationOp(
                            op_type="ALTER_ADD_COLUMN",
                            table=cur_table,
                            schema=cur_schema_name,
                            pk_columns=t_schema.pk_columns,
                            column_types=t_schema.column_types,
                            extra_ddl=[json.dumps({"column": act["column"]})],
                        )
                    )
                elif kind == "DROP_COLUMN":
                    _act, col_meta, q_name = next(snap_iter)
                    ops.append(
                        MutationOp(
                            op_type="QUARANTINE_DROP_COLUMN",
                            table=cur_table,
                            schema=cur_schema_name,
                            pk_columns=t_schema.pk_columns,
                            column_types=t_schema.column_types,
                            quarantine_name=q_name,
                            using_rowid_fallback=t_schema.using_rowid_fallback,
                            rowid_column=t_schema.rowid_column,
                            extra_ddl=[json.dumps(col_meta)],
                        )
                    )
                elif kind == "RENAME_COLUMN":
                    ops.append(
                        MutationOp(
                            op_type="ALTER_RENAME_COLUMN",
                            table=cur_table,
                            schema=cur_schema_name,
                            pk_columns=t_schema.pk_columns,
                            column_types=t_schema.column_types,
                            extra_ddl=[json.dumps({"old_name": act["old_name"], "new_name": act["new_name"]})],
                        )
                    )
                elif kind == "RENAME_TABLE":
                    new_tbl = act["new_table"]
                    new_sch = act.get("new_schema") or cur_schema_name
                    ops.append(
                        MutationOp(
                            op_type="ALTER_RENAME_TABLE",
                            table=cur_table,
                            schema=cur_schema_name,
                            pk_columns=t_schema.pk_columns,
                            column_types=t_schema.column_types,
                            extra_ddl=[
                                json.dumps(
                                    {
                                        "old_schema": cur_schema_name,
                                        "old_table": cur_table,
                                        "new_schema": new_sch,
                                        "new_table": new_tbl,
                                    }
                                )
                            ],
                        )
                    )
                    cur_table = new_tbl
                    cur_schema_name = new_sch

        return (
            QueryResult(rowcount=0, command_tag="ALTER TABLE", warnings=warnings),
            ops,
            warnings,
        )

    def _sqlite_index_def(self, index_name: str, schema: str | None = None) -> tuple[str | None, str | None]:
        master = f"{self.quote_ident(schema)}.sqlite_master" if schema else "sqlite_master"
        row = self._conn.execute(
            f"SELECT tbl_name, sql FROM {master} WHERE type = 'index' AND LOWER(name) = LOWER(?) LIMIT 1;",
            (index_name,),
        ).fetchone()
        if not row:
            return None, None
        return (str(row[0]), str(row[1]) if row[1] is not None else None)

    def _execute_index_ddl(
        self,
        stmt: ParsedStatement,
        *,
        in_client_tx: bool,
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.index_name is not None
        ops: list[MutationOp] = []
        with self._ensure_tx(in_client_tx):
            if stmt.kind == StatementKind.CREATE_INDEX:
                existing_tbl, _ = self._sqlite_index_def(stmt.index_name, stmt.schema)
                self._conn.execute(stmt.raw_sql)
                if existing_tbl is None:
                    ops.append(
                        MutationOp(
                            op_type="ALTER_CREATE_INDEX",
                            table=stmt.table or "",
                            schema=stmt.schema,
                            pk_columns=[],
                            column_types={},
                            extra_ddl=[json.dumps({"index_name": stmt.index_name})],
                        )
                    )
                tag = "CREATE INDEX"
            else:
                idx_tbl, idx_sql = self._sqlite_index_def(stmt.index_name, stmt.schema)
                self._conn.execute(stmt.raw_sql)
                if idx_sql:
                    ops.append(
                        MutationOp(
                            op_type="ALTER_DROP_INDEX",
                            table=idx_tbl or stmt.table or "",
                            schema=stmt.schema,
                            pk_columns=[],
                            column_types={},
                            extra_ddl=[json.dumps({"index_name": stmt.index_name, "create_sql": idx_sql})],
                        )
                    )
                tag = "DROP INDEX"
        return (
            QueryResult(rowcount=0, command_tag=tag, warnings=warnings),
            ops,
            warnings,
        )

    def purge_quarantine_table(self, quarantine_name: str, schema: str | None = None) -> bool:
        if not self._table_exists(quarantine_name, schema):
            return False
        self._conn.execute(f"DROP TABLE IF EXISTS {self._qualify(quarantine_name, schema)};")
        return True

    def _execute_insert(
        self,
        stmt: ParsedStatement,
        *,
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        with self._ensure_tx(in_client_tx):
            t_schema = self.inspect_table(stmt.table, stmt.schema)
            if t_schema.using_rowid_fallback:
                warnings.append(
                    f"Table '{stmt.table}' has no explicit primary key; using SQLite rowid fallback."
                )

            existing_by_pk: dict[tuple[Any, ...], dict[str, Any]] = {}
            upsert_pre_captured = False
            if stmt.is_upsert and not t_schema.using_rowid_fallback:
                val_dicts = extract_insert_value_dicts(stmt.raw_sql, t_schema.columns, params)
                if val_dicts and all(all(pk in d for pk in t_schema.pk_columns) for d in val_dicts):
                    dummy_op = MutationOp(
                        op_type="UPDATE",
                        table=stmt.table,
                        schema=stmt.schema,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                    )
                    existing_by_pk = self._prefetch_current_rows(
                        dummy_op, [{pk: d[pk] for pk in t_schema.pk_columns} for d in val_dicts]
                    )
                    upsert_pre_captured = True

            if not stmt.has_returning:
                sql_with_ret = (
                    f"{stmt.raw_sql.rstrip().rstrip(';')} RETURNING "
                    f"{self._returning_projection(t_schema)}"
                )
                cur = self._conn.execute(sql_with_ret, params)
                raw_rows = cur.fetchall()
                after_rows = self._rows_to_dicts(cur, raw_rows)
                user_cols: list[str] = []
                user_rows: list[tuple[Any, ...]] = []
            else:
                cur = self._conn.execute(stmt.raw_sql, params)
                user_cols = [d[0] for d in cur.description] if cur.description else []
                user_rows = cur.fetchall() if cur.description else []
                returned_dicts = self._rows_to_dicts(cur, user_rows)
                after_rows = self._resolve_rows_from_returning(t_schema, returned_dicts, warnings)

        ops: list[MutationOp] = []
        if stmt.is_upsert and upsert_pre_captured:
            upd_before: list[dict[str, Any]] = []
            upd_after: list[dict[str, Any]] = []
            ins_after: list[dict[str, Any]] = []
            for row in after_rows:
                pk_key = self._pk_key(row, t_schema.pk_columns)
                if pk_key in existing_by_pk:
                    upd_before.append(existing_by_pk[pk_key])
                    upd_after.append(row)
                else:
                    ins_after.append(row)
            if upd_after:
                ops.append(
                    MutationOp(
                        op_type="UPDATE",
                        table=stmt.table,
                        schema=stmt.schema,
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
                        schema=stmt.schema,
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
                    schema=stmt.schema,
                    pk_columns=t_schema.pk_columns,
                    column_types=t_schema.column_types,
                    before_rows=[],
                    after_rows=after_rows,
                    using_rowid_fallback=t_schema.using_rowid_fallback,
                    rowid_column=t_schema.rowid_column,
                )
            )

        return (
            QueryResult(
                columns=user_cols,
                rows=user_rows,
                rowcount=len(after_rows),
                command_tag=f"INSERT 0 {len(after_rows)}",
                warnings=warnings,
            ),
            ops,
            warnings,
        )

    def _resolve_rows_from_returning(
        self,
        t_schema: TableSchema,
        returned_dicts: list[dict[str, Any]],
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        if not returned_dicts:
            return []
        if set(t_schema.columns).issubset(returned_dicts[0].keys()) and not t_schema.using_rowid_fallback:
            return returned_dicts
        if all(pk in returned_dicts[0] for pk in t_schema.pk_columns):
            rows: list[dict[str, Any]] = []
            qual = self._qualify(t_schema.table, t_schema.schema)
            where_parts = [f"{self.quote_ident(pk)} IS ?" for pk in t_schema.pk_columns]
            select_sql = f"SELECT {self._select_projection(t_schema)} FROM {qual} WHERE {' AND '.join(where_parts)}"
            for r in returned_dicts:
                cur = self._conn.execute(select_sql, [r[pk] for pk in t_schema.pk_columns])
                fetched = cur.fetchall()
                rows.extend(self._rows_to_dicts(cur, fetched))
            return rows
        warnings.append(
            "User-supplied RETURNING clause omitted primary key columns; full row capture may be incomplete."
        )
        return returned_dicts

    def _where_params(
        self, raw_sql: str, where_clause: str | None, params: Sequence[Any]
    ) -> Sequence[Any]:
        if not params or not where_clause:
            return ()
        # If numbered placeholders (?1, ?2, ...) are used, SQLite allows passing full tuple
        tokens = tokenize(raw_sql)
        has_numbered = any(
            t.kind == "OP"
            and t.text == "?"
            and i + 1 < len(tokens)
            and tokens[i + 1].kind == "NUMBER"
            and tokens[i + 1].start == t.end
            for i, t in enumerate(tokens)
        )
        if has_numbered:
            return params
        has_positional = any(t.kind == "OP" and t.text == "?" for t in tokens)
        if not has_positional:
            return ()
        # Positional `?`: count occurrences before WHERE and inside WHERE
        where_pos = raw_sql.upper().rfind(where_clause.upper())
        if where_pos == -1:
            return ()
        before_q = sum(1 for t in tokenize(raw_sql[:where_pos]) if t.text == "?")
        where_q = sum(1 for t in tokenize(where_clause) if t.text == "?")
        return tuple(params[before_q : before_q + where_q])

    def _check_blast_radius(
        self,
        table: str,
        qual: str,
        alias_sql: str,
        where_sql: str,
        where_params: Sequence[Any],
    ) -> None:
        if self.max_capture_rows is None:
            return
        probe_sql = f"SELECT 1 FROM {qual}{alias_sql}{where_sql} LIMIT {self.max_capture_rows + 1};"
        rows = self._conn.execute(probe_sql, where_params).fetchall()
        if len(rows) > self.max_capture_rows:
            raise BlastRadiusExceededError(
                table=table,
                limit=self.max_capture_rows,
                observed_at_least=len(rows),
            )

    def _find_cascade_children(
        self, parent_table: str
    ) -> list[tuple[str, list[tuple[str, str]]]]:
        tables = [
            r[0]
            for r in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '_reverse_quarantine%';"
            ).fetchall()
        ]
        results: list[tuple[str, list[tuple[str, str]]]] = []
        for child in tables:
            fk_rows = self._conn.execute(
                f"PRAGMA foreign_key_list({self.quote_ident(child)});"
            ).fetchall()
            grouped: dict[int, list[tuple[str, str, str, str]]] = {}
            for fk_id, _seq, ref_tbl, from_col, to_col, _on_upd, on_del, _match in fk_rows:
                grouped.setdefault(fk_id, []).append(
                    (ref_tbl, from_col, to_col, on_del.upper())
                )
            for entries in grouped.values():
                if (
                    entries[0][0].lower() == parent_table.lower()
                    and entries[0][3] == "CASCADE"
                ):
                    col_pairs = [(from_c, to_c) for _, from_c, to_c, _ in entries]
                    results.append((child, col_pairs))
        return results

    def _capture_cascade_descendants(
        self,
        parent_table: str,
        parent_rows: list[dict[str, Any]],
        *,
        schema: str | None = None,
        visited: set[str] | None = None,
    ) -> list[MutationOp]:
        if not parent_rows:
            return []
        visited = set(visited or {parent_table})
        ops: list[MutationOp] = []

        for child_tbl, col_pairs in self._find_cascade_children(parent_table):
            if child_tbl in visited:
                continue
            child_schema = self.inspect_table(child_tbl, schema)
            qual = self._qualify(child_tbl, schema)
            proj = self._select_projection(child_schema)
            where_parts = [f"{self.quote_ident(from_c)} IS ?" for from_c, _ in col_pairs]
            sel_sql = f"SELECT {proj} FROM {qual} WHERE {' AND '.join(where_parts)};"

            seen_pks: set[tuple[Any, ...]] = set()
            child_rows: list[dict[str, Any]] = []
            for p_row in parent_rows:
                vals = [p_row.get(to_c) for _, to_c in col_pairs]
                cur = self._conn.execute(sel_sql, vals)
                for row_dict in self._rows_to_dicts(cur, cur.fetchall()):
                    pk_key = self._pk_key(row_dict, child_schema.pk_columns)
                    if pk_key not in seen_pks:
                        seen_pks.add(pk_key)
                        child_rows.append(row_dict)
                        if (
                            self.max_capture_rows is not None
                            and len(child_rows) > self.max_capture_rows
                        ):
                            raise BlastRadiusExceededError(
                                table=child_tbl,
                                limit=self.max_capture_rows,
                                observed_at_least=len(child_rows),
                            )

            if child_rows:
                # Recurse deeper first so ops are ordered [grandchild, child] -> reversed becomes [parent, child, grandchild]
                ops.extend(
                    self._capture_cascade_descendants(
                        child_tbl,
                        child_rows,
                        schema=schema,
                        visited=visited | {child_tbl},
                    )
                )
                ops.append(
                    MutationOp(
                        op_type="DELETE",
                        table=child_tbl,
                        schema=schema,
                        pk_columns=child_schema.pk_columns,
                        column_types=child_schema.column_types,
                        before_rows=child_rows,
                        after_rows=[],
                        using_rowid_fallback=child_schema.using_rowid_fallback,
                        rowid_column=child_schema.rowid_column,
                    )
                )
        return ops

    def _execute_update(
        self,
        stmt: ParsedStatement,
        *,
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        with self._ensure_tx(in_client_tx):
            t_schema = self.inspect_table(stmt.table, stmt.schema)
            if t_schema.using_rowid_fallback:
                warnings.append(
                    f"Table '{stmt.table}' has no explicit primary key; using SQLite rowid fallback."
                )

            qual = self._qualify(stmt.table, stmt.schema)
            alias_sql = f" AS {self.quote_ident(stmt.alias)}" if stmt.alias else ""
            from_join_sql = self._from_join_sql(stmt.from_join_clause)
            where_sql = f" WHERE {stmt.where_clause}" if stmt.where_clause else ""
            proj = self._select_projection(
                t_schema, stmt.alias, qual_table=(qual if stmt.from_join_clause else None)
            )
            pre_sql = f"SELECT {proj} FROM {qual}{alias_sql}{from_join_sql}{where_sql}"

            where_params = self._where_params(stmt.raw_sql, stmt.where_clause, params)
            self._check_blast_radius(stmt.table, qual, alias_sql, f"{from_join_sql}{where_sql}", where_params)
            pre_cur = self._conn.execute(pre_sql, where_params)
            raw_before = self._rows_to_dicts(pre_cur, pre_cur.fetchall())
            seen_pks: set[tuple[Any, ...]] = set()
            before_rows: list[dict[str, Any]] = []
            for r in raw_before:
                pk_k = self._pk_key(r, t_schema.pk_columns)
                if pk_k not in seen_pks:
                    seen_pks.add(pk_k)
                    before_rows.append(r)

            if not stmt.has_returning:
                upd_sql = (
                    f"{stmt.raw_sql.rstrip().rstrip(';')} RETURNING "
                    f"{self._returning_projection(t_schema)}"
                )
                upd_cur = self._conn.execute(upd_sql, params)
                after_rows = self._rows_to_dicts(upd_cur, upd_cur.fetchall())
                user_cols: list[str] = []
                user_rows: list[tuple[Any, ...]] = []
            else:
                upd_cur = self._conn.execute(stmt.raw_sql, params)
                user_cols = [d[0] for d in upd_cur.description] if upd_cur.description else []
                user_rows = upd_cur.fetchall() if upd_cur.description else []
                after_rows = self._resolve_rows_from_returning(
                    t_schema, self._rows_to_dicts(upd_cur, user_rows), warnings
                )

        op = MutationOp(
            op_type="UPDATE",
            table=stmt.table,
            schema=stmt.schema,
            pk_columns=t_schema.pk_columns,
            column_types=t_schema.column_types,
            before_rows=before_rows,
            after_rows=after_rows,
            using_rowid_fallback=t_schema.using_rowid_fallback,
            rowid_column=t_schema.rowid_column,
        )
        return (
            QueryResult(
                columns=user_cols,
                rows=user_rows,
                rowcount=len(after_rows),
                command_tag=f"UPDATE {len(after_rows)}",
                warnings=warnings,
            ),
            [op],
            warnings,
        )

    def _execute_delete(
        self,
        stmt: ParsedStatement,
        *,
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        with self._ensure_tx(in_client_tx):
            t_schema = self.inspect_table(stmt.table, stmt.schema)
            if t_schema.using_rowid_fallback:
                warnings.append(
                    f"Table '{stmt.table}' has no explicit primary key; using SQLite rowid fallback."
                )

            qual = self._qualify(stmt.table, stmt.schema)
            alias_sql = f" AS {self.quote_ident(stmt.alias)}" if stmt.alias else ""
            where_sql = f" WHERE {stmt.where_clause}" if stmt.where_clause else ""
            where_params = self._where_params(stmt.raw_sql, stmt.where_clause, params)
            self._check_blast_radius(stmt.table, qual, alias_sql, where_sql, where_params)

            # Capture any ON DELETE CASCADE child rows before deleting parent
            cascade_children = self._find_cascade_children(stmt.table)
            cascade_ops: list[MutationOp] = []
            if cascade_children:
                pre_sql = f"SELECT {self._select_projection(t_schema, stmt.alias)} FROM {qual}{alias_sql}{where_sql}"
                pre_cur = self._conn.execute(pre_sql, where_params)
                pre_parent_rows = self._rows_to_dicts(pre_cur, pre_cur.fetchall())
                cascade_ops = self._capture_cascade_descendants(
                    stmt.table, pre_parent_rows, schema=stmt.schema
                )
                if cascade_ops:
                    cascaded_tables = ", ".join(dict.fromkeys(op.table for op in cascade_ops))
                    warnings.append(
                        f"Captured ON DELETE CASCADE rows from child table(s): {cascaded_tables}."
                    )

            if not stmt.has_returning:
                del_sql = (
                    f"{stmt.raw_sql.rstrip().rstrip(';')} RETURNING "
                    f"{self._returning_projection(t_schema)}"
                )
                del_cur = self._conn.execute(del_sql, params)
                before_rows = self._rows_to_dicts(del_cur, del_cur.fetchall())
                user_cols: list[str] = []
                user_rows: list[tuple[Any, ...]] = []
            else:
                pre_sql = f"SELECT {self._select_projection(t_schema, stmt.alias)} FROM {qual}{alias_sql}{where_sql}"
                pre_cur = self._conn.execute(pre_sql, where_params)
                before_rows = self._rows_to_dicts(pre_cur, pre_cur.fetchall())

                del_cur = self._conn.execute(stmt.raw_sql, params)
                user_cols = [d[0] for d in del_cur.description] if del_cur.description else []
                user_rows = del_cur.fetchall() if del_cur.description else []

        parent_op = MutationOp(
            op_type="DELETE",
            table=stmt.table,
            schema=stmt.schema,
            pk_columns=t_schema.pk_columns,
            column_types=t_schema.column_types,
            before_rows=before_rows,
            after_rows=[],
            using_rowid_fallback=t_schema.using_rowid_fallback,
            rowid_column=t_schema.rowid_column,
        )
        # Order: [grandchild_ops..., child_ops..., parent_op] so reversed(ops) inserts parent first!
        all_ops = cascade_ops + [parent_op]
        return (
            QueryResult(
                columns=user_cols,
                rows=user_rows,
                rowcount=len(before_rows),
                command_tag=f"DELETE {len(before_rows)}",
                warnings=warnings,
            ),
            all_ops,
            warnings,
        )

    def _actual_col_name(self, op: MutationOp, col: str) -> str:
        if op.using_rowid_fallback and col == PROXY_ROWID_ALIAS:
            return "rowid"
        return col

    def _fetch_current_row(
        self, op: MutationOp, pk_values: dict[str, Any]
    ) -> dict[str, Any] | None:
        qual = self._qualify(op.table, op.schema)
        proj = (
            f"rowid AS {self.quote_ident(PROXY_ROWID_ALIAS)}, *"
            if op.using_rowid_fallback
            else "*"
        )
        where_parts = [
            f"{self.quote_ident(self._actual_col_name(op, pk))} IS ?"
            for pk in op.pk_columns
        ]
        sql = f"SELECT {proj} FROM {qual} WHERE {' AND '.join(where_parts)} LIMIT 1;"
        cur = self._conn.execute(sql, [pk_values[pk] for pk in op.pk_columns])
        rows = self._rows_to_dicts(cur, cur.fetchall())
        return rows[0] if rows else None

    def _prefetch_current_rows(
        self, op: MutationOp, pk_dicts: list[dict[str, Any]]
    ) -> dict[tuple[Any, ...], dict[str, Any]]:
        """Batch-fetch current DB rows for drift checking (chunked IN / tuple-VALUES)."""
        if not pk_dicts:
            return {}
        qual = self._qualify(op.table, op.schema)
        proj = (
            f"rowid AS {self.quote_ident(PROXY_ROWID_ALIAS)}, *"
            if op.using_rowid_fallback
            else "*"
        )
        found: dict[tuple[Any, ...], dict[str, Any]] = {}
        non_null_pks: list[dict[str, Any]] = []
        for pk_vals in pk_dicts:
            if any(pk_vals[pk] is None for pk in op.pk_columns):
                row = self._fetch_current_row(op, pk_vals)
                if row is not None:
                    found[self._pk_key(row, op.pk_columns)] = row
            else:
                non_null_pks.append(pk_vals)

        if not non_null_pks:
            return found

        num_pk = len(op.pk_columns)
        chunk_size = 400 if num_pk == 1 else max(50, 400 // num_pk)

        if num_pk == 1:
            pk_col = self.quote_ident(self._actual_col_name(op, op.pk_columns[0]))
            for i in range(0, len(non_null_pks), chunk_size):
                chunk = non_null_pks[i : i + chunk_size]
                placeholders = ", ".join("?" for _ in chunk)
                sql = f"SELECT {proj} FROM {qual} WHERE {pk_col} IN ({placeholders});"
                params = [d[op.pk_columns[0]] for d in chunk]
                cur = self._conn.execute(sql, params)
                for row in self._rows_to_dicts(cur, cur.fetchall()):
                    found[self._pk_key(row, op.pk_columns)] = row
        else:
            pk_cols_sql = ", ".join(
                self.quote_ident(self._actual_col_name(op, pk)) for pk in op.pk_columns
            )
            row_tuple = "(" + ", ".join("?" for _ in op.pk_columns) + ")"
            for i in range(0, len(non_null_pks), chunk_size):
                chunk = non_null_pks[i : i + chunk_size]
                values_sql = ", ".join(row_tuple for _ in chunk)
                sql = f"SELECT {proj} FROM {qual} WHERE ({pk_cols_sql}) IN (VALUES {values_sql});"
                params = [d[pk] for d in chunk for pk in op.pk_columns]
                cur = self._conn.execute(sql, params)
                for row in self._rows_to_dicts(cur, cur.fetchall()):
                    found[self._pk_key(row, op.pk_columns)] = row

        return found

    def build_reverse_plan(
        self, record: UndoRecord, *, force: bool = False
    ) -> tuple[list[ReversePlanStep], list[DriftConflict]]:
        steps: list[ReversePlanStep] = []
        conflicts: list[DriftConflict] = []

        # Reverse ops in reverse execution order
        for op in reversed(record.ops):
            qual = self._qualify(op.table, op.schema)

            if op.op_type == "QUARANTINE_DROP":
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, op.schema):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=None,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined table '{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                if self._table_exists(op.table, op.schema):
                    if not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={},
                                column=None,
                                expected_after=None,
                                actual_current=op.table,
                                reason=f"Table '{op.table}' was recreated since DROP.",
                            )
                        )
                        continue
                    steps.append(
                        ReversePlanStep(
                            description=f"Force-drop recreated table '{op.table}'",
                            sql=f"DROP TABLE {qual};",
                        )
                    )
                steps.append(
                    ReversePlanStep(
                        description=f"Restore quarantined table '{op.table}'",
                        sql=f"ALTER TABLE {self.quote_ident(op.quarantine_name)} RENAME TO {self.quote_ident(op.table)};",
                    )
                )
                continue

            if op.op_type == "QUARANTINE_TRUNCATE":
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, op.schema):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=None,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined truncate snapshot '{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                if self._table_exists(op.table, op.schema):
                    new_count = self._conn.execute(f"SELECT COUNT(*) FROM {qual};").fetchone()[0]
                    if new_count > 0 and not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={},
                                column=None,
                                expected_after=0,
                                actual_current=new_count,
                                reason=f"Table '{op.table}' has {new_count} new row(s) inserted since TRUNCATE.",
                            )
                        )
                        continue
                    steps.append(
                        ReversePlanStep(
                            description=f"Drop empty/post-truncate table '{op.table}'",
                            sql=f"DROP TABLE {qual};",
                        )
                    )
                steps.append(
                    ReversePlanStep(
                        description=f"Restore truncated table '{op.table}' from quarantine",
                        sql=f"ALTER TABLE {self.quote_ident(op.quarantine_name)} RENAME TO {self.quote_ident(op.table)};",
                    )
                )
                for idx_sql in op.extra_ddl:
                    steps.append(
                        ReversePlanStep(
                            description=f"Restore index on '{op.table}'",
                            sql=idx_sql,
                        )
                    )
                continue

            if op.op_type == "ALTER_ADD_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                col = str(meta["column"])
                live_cols = {c.lower() for c in self.inspect_table(op.table, op.schema).columns} if self._table_exists(op.table, op.schema) else set()
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
                                reason=f"Column '{col}' no longer exists on '{op.table}'.",
                            )
                        )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Drop added column '{col}' from '{op.table}'",
                        sql=f"ALTER TABLE {qual} DROP COLUMN {self.quote_ident(col)};",
                    )
                )
                continue

            if op.op_type == "QUARANTINE_DROP_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                col = str(meta["column"])
                col_type = str(meta.get("col_type") or "TEXT")
                col_default = meta.get("col_default")
                not_null = bool(meta.get("not_null"))
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, op.schema):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined column snapshot '{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                live_cols = {c.lower() for c in self.inspect_table(op.table, op.schema).columns} if self._table_exists(op.table, op.schema) else set()
                if col.lower() in live_cols and not force:
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=None,
                            actual_current=col,
                            reason=f"Column '{col}' was recreated on '{op.table}' since DROP COLUMN.",
                        )
                    )
                    continue
                q_qual = self._qualify(op.quarantine_name, op.schema)
                if col.lower() not in live_cols:
                    default_sql = f" DEFAULT {col_default}" if col_default is not None else ""
                    nn_sql = " NOT NULL" if (not_null and col_default is not None and str(col_default).upper() != "NULL") else ""
                    steps.append(
                        ReversePlanStep(
                            description=f"Re-add dropped column '{col}' on '{op.table}'",
                            sql=f"ALTER TABLE {qual} ADD COLUMN {self.quote_ident(col)} {col_type}{nn_sql}{default_sql};",
                        )
                    )
                if op.using_rowid_fallback:
                    join_cond = f"q.{self.quote_ident(PROXY_ROWID_ALIAS)} = {qual}.rowid"
                else:
                    join_cond = " AND ".join(
                        f"q.{self.quote_ident(pk)} = {qual}.{self.quote_ident(pk)}"
                        for pk in op.pk_columns
                    )
                steps.append(
                    ReversePlanStep(
                        description=f"Backfill values for '{op.table}.{col}' from quarantine",
                        sql=(
                            f"UPDATE {qual} SET {self.quote_ident(col)} = q.{self.quote_ident(col)} "
                            f"FROM {q_qual} AS q WHERE {join_cond};"
                        ),
                    )
                )
                steps.append(
                    ReversePlanStep(
                        description=f"Clean up column quarantine snapshot '{op.quarantine_name}'",
                        sql=f"DROP TABLE {q_qual};",
                    )
                )
                continue

            if op.op_type == "ALTER_RENAME_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                old_name = str(meta["old_name"])
                new_name = str(meta["new_name"])
                live_cols = {c.lower() for c in self.inspect_table(op.table, op.schema).columns} if self._table_exists(op.table, op.schema) else set()
                if new_name.lower() not in live_cols or (old_name.lower() in live_cols and not force):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=new_name,
                            expected_after=new_name,
                            actual_current=old_name if old_name.lower() in live_cols else None,
                            reason=f"Column rename state drifted on '{op.table}' ({old_name} -> {new_name}).",
                        )
                    )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Rename column '{new_name}' back to '{old_name}' on '{op.table}'",
                        sql=f"ALTER TABLE {qual} RENAME COLUMN {self.quote_ident(new_name)} TO {self.quote_ident(old_name)};",
                    )
                )
                continue

            if op.op_type == "ALTER_RENAME_TABLE":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                old_sch = meta.get("old_schema")
                old_tbl = str(meta["old_table"])
                new_sch = meta.get("new_schema")
                new_tbl = str(meta["new_table"])
                if not self._table_exists(new_tbl, new_sch) or (self._table_exists(old_tbl, old_sch) and not force):
                    conflicts.append(
                        DriftConflict(
                            table=new_tbl,
                            pk={},
                            column=None,
                            expected_after=new_tbl,
                            actual_current=old_tbl if self._table_exists(old_tbl, old_sch) else None,
                            reason=f"Table rename state drifted ({old_tbl} -> {new_tbl}).",
                        )
                    )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Rename table '{new_tbl}' back to '{old_tbl}'",
                        sql=f"ALTER TABLE {self._qualify(new_tbl, new_sch)} RENAME TO {self.quote_ident(old_tbl)};",
                    )
                )
                continue

            if op.op_type == "ALTER_CREATE_INDEX":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                idx_name = str(meta["index_name"])
                existing_tbl, _ = self._sqlite_index_def(idx_name, op.schema)
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
                                reason=f"Index '{idx_name}' no longer exists.",
                            )
                        )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Drop created index '{idx_name}'",
                        sql=f"DROP INDEX {self._qualify(idx_name, op.schema)};",
                    )
                )
                continue

            if op.op_type == "ALTER_DROP_INDEX":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                idx_name = str(meta["index_name"])
                create_sql = str(meta["create_sql"])
                existing_tbl, _ = self._sqlite_index_def(idx_name, op.schema)
                if existing_tbl is not None and not force:
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=None,
                            expected_after=None,
                            actual_current=idx_name,
                            reason=f"Index '{idx_name}' already exists.",
                        )
                    )
                    continue
                if existing_tbl is None:
                    steps.append(
                        ReversePlanStep(
                            description=f"Recreate dropped index '{idx_name}'",
                            sql=create_sql if create_sql.rstrip().endswith(";") else f"{create_sql};",
                        )
                    )
                continue

            if op.op_type == "INSERT":
                live_cols = set(self.inspect_table(op.table, op.schema).columns) if self._table_exists(op.table, op.schema) else set()
                pk_list = [{pk: row[pk] for pk in op.pk_columns} for row in op.after_rows]
                current_map = self._prefetch_current_rows(op, pk_list)
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
                        if live_cols and col not in live_cols and not (op.using_rowid_fallback and col == PROXY_ROWID_ALIAS):
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
                    where_parts = [
                        f"{self.quote_ident(self._actual_col_name(op, pk))} IS ?"
                        for pk in op.pk_columns
                    ]
                    steps.append(
                        ReversePlanStep(
                            description=f"Delete inserted row {pk_vals} from '{op.table}'",
                            sql=f"DELETE FROM {qual} WHERE {' AND '.join(where_parts)};",
                            params=[pk_vals[pk] for pk in op.pk_columns],
                        )
                    )
                continue

            if op.op_type == "DELETE":
                live_cols = set(self.inspect_table(op.table, op.schema).columns) if self._table_exists(op.table, op.schema) else set()
                current_map = (
                    {}
                    if force
                    else self._prefetch_current_rows(
                        op, [{pk: row[pk] for pk in op.pk_columns} for row in op.before_rows]
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
                    dropped = [
                        c for c in row.keys()
                        if live_cols and c not in live_cols and not (op.using_rowid_fallback and c == PROXY_ROWID_ALIAS)
                    ]
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
                    cols = [
                        c for c in row.keys()
                        if not live_cols or c in live_cols or (op.using_rowid_fallback and c == PROXY_ROWID_ALIAS)
                    ]
                    actual_cols = [self._actual_col_name(op, c) for c in cols]
                    quoted_cols = ", ".join(self.quote_ident(c) for c in actual_cols)
                    placeholders = ", ".join("?" for _ in cols)
                    insert_verb = "INSERT OR REPLACE INTO" if force else "INSERT INTO"
                    steps.append(
                        ReversePlanStep(
                            description=f"Re-insert deleted row {pk_vals} into '{op.table}'",
                            sql=f"{insert_verb} {qual} ({quoted_cols}) VALUES ({placeholders});",
                            params=[row[c] for c in cols],
                        )
                    )
                continue

            if op.op_type == "UPDATE":
                live_cols = set(self.inspect_table(op.table, op.schema).columns) if self._table_exists(op.table, op.schema) else set()
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
                    op, [{pk: after[pk] for pk in op.pk_columns} for _, after in pairs]
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
                        if live_cols and col not in live_cols and not (op.using_rowid_fallback and col == PROXY_ROWID_ALIAS):
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

                    update_cols = [
                        c for c in before.keys()
                        if (not (op.using_rowid_fallback and c == PROXY_ROWID_ALIAS))
                        and (not live_cols or c in live_cols)
                    ]
                    set_sql = ", ".join(
                        f"{self.quote_ident(c)} = ?" for c in update_cols
                    )
                    where_parts = [
                        f"{self.quote_ident(self._actual_col_name(op, pk))} IS ?"
                        for pk in op.pk_columns
                    ]
                    params = [before[c] for c in update_cols] + [
                        after_pk_vals[pk] for pk in op.pk_columns
                    ]
                    steps.append(
                        ReversePlanStep(
                            description=f"Revert row {after_pk_vals} in '{op.table}'",
                            sql=f"UPDATE {qual} SET {set_sql} WHERE {' AND '.join(where_parts)};",
                            params=params,
                        )
                    )

        return steps, conflicts

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

        steps: list[ReversePlanStep] = []
        conflicts: list[DriftConflict] = []
        self._conn.execute("BEGIN IMMEDIATE;")
        try:
            steps, conflicts = self.build_reverse_plan(record, force=force)
            if conflicts and not force:
                self._conn.execute("ROLLBACK;")
                return ReverseResult(
                    tx_id=record.tx_id,
                    success=False,
                    dry_run=False,
                    steps=steps,
                    conflicts=conflicts,
                    error=f"Drift detected ({len(conflicts)} conflict(s)); pass FORCE to override.",
                )
            idx = 0
            n = len(steps)
            while idx < n:
                sql = steps[idx].sql
                if steps[idx].params:
                    end = idx + 1
                    while end < n and steps[end].sql == sql and steps[end].params:
                        end += 1
                    if end - idx > 1:
                        self._conn.executemany(sql, [s.params for s in steps[idx:end]])
                    else:
                        self._conn.execute(sql, steps[idx].params)
                    idx = end
                else:
                    self._conn.execute(sql)
                    idx += 1
            self._conn.execute("COMMIT;")
        except Exception as exc:
            self._conn.execute("ROLLBACK;")
            return ReverseResult(
                tx_id=record.tx_id,
                success=False,
                dry_run=False,
                steps=steps,
                conflicts=conflicts,
                error=f"Reverse execution failed: {exc}",
            )

        rev_warnings: list[str] = []
        for op in record.ops:
            if op.op_type == "QUARANTINE_DROP_COLUMN" and op.extra_ddl:
                meta = json.loads(op.extra_ddl[0])
                col_default = meta.get("col_default")
                if meta.get("not_null") and (col_default is None or str(col_default).upper() == "NULL"):
                    rev_warnings.append(
                        f"SQLite restored '{op.table}.{meta.get('column')}' and all values, "
                        "but omitted NOT NULL (SQLite ADD COLUMN requires a non-NULL DEFAULT)."
                    )

        return ReverseResult(
            tx_id=record.tx_id,
            success=True,
            dry_run=False,
            reversed_rows=len(steps),
            steps=steps,
            conflicts=conflicts,
            warnings=rev_warnings,
        )
