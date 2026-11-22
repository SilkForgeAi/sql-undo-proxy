"""PostgreSQL EngineDriver implementation over pgwire v3."""

from __future__ import annotations

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
from ..parser import extract_insert_value_dicts, tokenize
from .base import EngineDriver
from .pgwire_client import PgError, PgWireClient, PgWireResult

PROXY_ROWID_ALIAS = "__proxy_rowid__"
QUARANTINE_SCHEMA = "_reverse_quarantine"


class PostgresDriver(EngineDriver):
    """EngineDriver for PostgreSQL using pure-Python pgwire v3 transport."""

    engine_type = EngineType.POSTGRES

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 5432,
        user: str = "postgres",
        password: str = "",
        database: str = "postgres",
        max_capture_rows: int | None = None,
        emit_wal_marker: bool = False,
        client: PgWireClient | None = None,
        side_table_threshold: int = 500,
    ) -> None:
        self._owns_client = client is None
        self.max_capture_rows = max_capture_rows
        self.emit_wal_marker = emit_wal_marker
        self.side_table_threshold = side_table_threshold
        self._pg_ver_num: int | None = None
        self._quarantine_ready = False
        self._last_commit_s: float = 0.0
        self._last_undo_stage_s: float = 0.0
        self._last_undo_conflict_s: float = 0.0
        self._client = client or PgWireClient(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def quote_ident(self, name: str) -> str:
        return '"' + name.replace('"', '""') + '"'

    def _qualify(self, table: str, schema: str | None = None) -> str:
        if schema:
            return f"{self.quote_ident(schema)}.{self.quote_ident(table)}"
        return self.quote_ident(table)

    def _table_exists(self, table: str, schema: str | None = None) -> bool:
        target = f"{schema}.{table}" if schema else table
        res = self._client.execute("SELECT to_regclass($1)::text;", [target])
        return bool(res.rows and res.rows[0][0] is not None)

    def inspect_table(self, table: str, schema: str | None = None) -> TableSchema:
        eff_schema = schema or "public"
        col_sql = """
            SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod)
            FROM pg_catalog.pg_attribute a
            JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = $1 AND c.relname = $2
              AND a.attnum > 0 AND NOT a.attisdropped
            ORDER BY a.attnum;
        """
        col_res = self._client.execute(col_sql, [eff_schema, table])
        if not col_res.rows:
            raise ValueError(f"Table '{eff_schema}.{table}' does not exist or has no columns.")

        columns = [str(r[0]) for r in col_res.rows]
        column_types = {str(r[0]): str(r[1]) for r in col_res.rows}

        pk_sql = """
            SELECT a.attname
            FROM pg_catalog.pg_index i
            JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
            JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
            WHERE n.nspname = $1 AND c.relname = $2 AND i.indisprimary
            ORDER BY k.ord;
        """
        pk_res = self._client.execute(pk_sql, [eff_schema, table])
        pk_columns = [str(r[0]) for r in pk_res.rows]

        using_rowid_fallback = False
        rowid_column: str | None = None
        if not pk_columns:
            using_rowid_fallback = True
            rowid_column = PROXY_ROWID_ALIAS
            pk_columns = [PROXY_ROWID_ALIAS]

        return TableSchema(
            table=table,
            schema=eff_schema,
            columns=columns,
            pk_columns=pk_columns,
            column_types=column_types,
            using_rowid_fallback=using_rowid_fallback,
            rowid_column=rowid_column,
        )

    def inspect_foreign_keys(self) -> list[ForeignKeyEdge]:
        sql = """
            SELECT
                c_child.relname AS child_table,
                a_child.attname AS child_col,
                c_parent.relname AS parent_table,
                a_parent.attname AS parent_col,
                con.confdeltype::text AS del_type,
                n_child.nspname AS child_schema,
                con.oid AS con_oid,
                k.ord AS ord
            FROM pg_catalog.pg_constraint con
            JOIN pg_catalog.pg_class c_child ON c_child.oid = con.conrelid
            JOIN pg_catalog.pg_namespace n_child ON n_child.oid = c_child.relnamespace
            JOIN pg_catalog.pg_class c_parent ON c_parent.oid = con.confrelid
            JOIN LATERAL unnest(con.conkey, con.confkey) WITH ORDINALITY AS k(ck, fk, ord) ON true
            JOIN pg_catalog.pg_attribute a_child ON a_child.attrelid = c_child.oid AND a_child.attnum = k.ck
            JOIN pg_catalog.pg_attribute a_parent ON a_parent.attrelid = c_parent.oid AND a_parent.attnum = k.fk
            WHERE con.contype = 'f'
              AND n_child.nspname NOT IN ('pg_catalog', 'information_schema', '_reverse_quarantine')
            ORDER BY con.oid, k.ord;
        """
        try:
            res = self._client.query(sql)
        except Exception:
            return []
        if not res or not res[0].rows:
            return []
        del_map = {"a": "NO ACTION", "r": "RESTRICT", "c": "CASCADE", "n": "SET NULL", "d": "SET DEFAULT"}
        grouped: dict[Any, list[tuple[Any, ...]]] = {}
        for row in res[0].rows:
            grouped.setdefault(row[6], []).append(row)
        edges: list[ForeignKeyEdge] = []
        for rows in grouped.values():
            edges.append(
                ForeignKeyEdge(
                    child_table=str(rows[0][0]),
                    child_columns=[str(r[1]) for r in rows],
                    parent_table=str(rows[0][2]),
                    parent_columns=[str(r[3]) for r in rows],
                    on_delete=del_map.get(str(rows[0][4]), "NO ACTION"),
                    schema=str(rows[0][5]),
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

    @staticmethod
    def _parse_rowcount_from_tag(tag: str, default: int = 0) -> int:
        parts = tag.strip().split()
        if parts and parts[-1].isdigit():
            return int(parts[-1])
        return default

    def execute_read(self, sql: str, params: Sequence[Any] = ()) -> QueryResult:
        res = self._client.execute(sql, params)
        return QueryResult(
            columns=res.columns,
            rows=res.rows,
            rowcount=len(res.rows) if res.columns else self._parse_rowcount_from_tag(res.command_tag),
            command_tag=res.command_tag or "SELECT",
            warnings=res.notices,
        )

    @staticmethod
    def _res_to_dicts(res: PgWireResult) -> list[dict[str, Any]]:
        if not res.columns:
            return []
        return [dict(zip(res.columns, r)) for r in res.rows]

    def _select_projection(
        self, schema: TableSchema, alias: str | None = None, *, qual_table: str | None = None
    ) -> str:
        ref = self.quote_ident(alias) if alias else qual_table
        prefix = f"{ref}." if ref else ""
        if schema.using_rowid_fallback:
            return f"{prefix}ctid::text AS {self.quote_ident(PROXY_ROWID_ALIAS)}, {prefix}*"
        return f"{prefix}*"

    @staticmethod
    def _from_join_sql(from_join_clause: str | None) -> str:
        if not from_join_clause:
            return ""
        upper = from_join_clause.lstrip().upper()
        if upper.startswith(("JOIN ", "INNER ", "LEFT ", "RIGHT ", "FULL ", "CROSS ")):
            return f" {from_join_clause}"
        return f", {from_join_clause}"

    def _returning_projection(
        self, schema: TableSchema, alias: str | None = None, *, qual_table: str | None = None
    ) -> str:
        ref = self.quote_ident(alias) if alias else qual_table
        prefix = f"{ref}." if ref else ""
        if schema.using_rowid_fallback:
            return f"{prefix}ctid::text AS {self.quote_ident(PROXY_ROWID_ALIAS)}, {prefix}*"
        return f"{prefix}*"

    @staticmethod
    def _remap_where_params(
        where_clause: str | None, params: Sequence[Any]
    ) -> tuple[str | None, list[Any]]:
        """Remap `$N` placeholders inside `where_clause` to contiguous `$1..$k` for pre-image SELECT."""
        if not where_clause or not params:
            return where_clause, []
        tokens = tokenize(where_clause)
        mapping: dict[int, int] = {}
        remapped_params: list[Any] = []
        out: list[str] = []
        last = 0
        for tok in tokens:
            if tok.kind == "WORD" and tok.text.startswith("$") and tok.text[1:].isdigit():
                orig_idx = int(tok.text[1:])
                if 1 <= orig_idx <= len(params):
                    if orig_idx not in mapping:
                        remapped_params.append(params[orig_idx - 1])
                        mapping[orig_idx] = len(remapped_params)
                    out.append(where_clause[last : tok.start])
                    out.append(f"${mapping[orig_idx]}")
                    last = tok.end
        out.append(where_clause[last:])
        return "".join(out), remapped_params

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
                rc = self._parse_rowcount_from_tag(res.command_tag)
            return (
                QueryResult(
                    rowcount=rc,
                    command_tag=res.command_tag or stmt.kind.value.upper(),
                    warnings=warnings,
                ),
                [],
                warnings,
            )

        if not stmt.table:
            raise ValueError(f"Could not determine target table for statement: {stmt.raw_sql}")

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
        if stmt.kind == StatementKind.MERGE:
            return self._execute_merge(
                stmt, tx_id=tx_id, in_client_tx=in_client_tx, params=params, warnings=warnings
            )

        raise ValueError(f"Unsupported mutating statement kind: {stmt.kind}")

    def _rename_quarantine_indexes(
        self, schema: str, table: str, suffix: str, *, add: bool
    ) -> None:
        try:
            res = self._client.execute(
                "SELECT indexname FROM pg_catalog.pg_indexes WHERE schemaname = $1 AND tablename = $2;",
                [schema, table],
            )
        except Exception:
            return
        for (idx_name,) in res.rows:
            name = str(idx_name)
            if add:
                new_name = f"{name}{suffix}"
            else:
                if not name.endswith(suffix):
                    continue
                new_name = name[: -len(suffix)]
            self._client.query(
                f"ALTER INDEX {self.quote_ident(schema)}.{self.quote_ident(name)} "
                f"RENAME TO {self.quote_ident(new_name)};"
            )

    def _owned_sequences(self, schema: str, table: str) -> list[str]:
        try:
            res = self._client.execute(
                "SELECT s.relname "
                "FROM pg_catalog.pg_class s "
                "JOIN pg_catalog.pg_depend d ON d.objid = s.oid "
                "JOIN pg_catalog.pg_class t ON t.oid = d.refobjid "
                "JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace "
                "WHERE s.relkind = 'S' AND d.deptype IN ('a', 'i') "
                "  AND n.nspname = $1 AND t.relname = $2;",
                [schema, table],
            )
            return [str(r[0]) for r in res.rows]
        except Exception:
            return []

    def _rename_quarantine_sequences(
        self, schema: str, table: str, suffix: str, *, add: bool
    ) -> None:
        for seq_name in self._owned_sequences(schema, table):
            if add:
                new_name = f"{seq_name}{suffix}"
            else:
                if not seq_name.endswith(suffix):
                    continue
                new_name = seq_name[: -len(suffix)]
            self._client.query(
                f"ALTER SEQUENCE {self.quote_ident(schema)}.{self.quote_ident(seq_name)} "
                f"RENAME TO {self.quote_ident(new_name)};"
            )

    def _restore_quarantine_objects_steps(
        self, quarantine_name: str, table: str, eff_schema: str
    ) -> list[ReversePlanStep]:
        steps: list[ReversePlanStep] = []
        if not quarantine_name.startswith(f"{table}__"):
            return steps
        suffix = quarantine_name[len(table) :]
        eff_q = self.quote_ident(eff_schema)
        try:
            idx_res = self._client.execute(
                "SELECT indexname FROM pg_catalog.pg_indexes WHERE schemaname = $1 AND tablename = $2;",
                [QUARANTINE_SCHEMA, quarantine_name],
            )
            for (idx_name,) in idx_res.rows:
                name = str(idx_name)
                if name.endswith(suffix):
                    orig = name[: -len(suffix)]
                    steps.append(
                        ReversePlanStep(
                            description=f"Restore index name '{orig}'",
                            sql=(
                                f"ALTER INDEX {eff_q}.{self.quote_ident(name)} "
                                f"RENAME TO {self.quote_ident(orig)};"
                            ),
                        )
                    )
        except Exception:
            pass
        for seq_name in self._owned_sequences(QUARANTINE_SCHEMA, quarantine_name):
            if seq_name.endswith(suffix):
                orig = seq_name[: -len(suffix)]
                steps.append(
                    ReversePlanStep(
                        description=f"Restore sequence name '{orig}'",
                        sql=(
                            f"ALTER SEQUENCE {eff_q}.{self.quote_ident(seq_name)} "
                            f"RENAME TO {self.quote_ident(orig)};"
                        ),
                    )
                )
        return steps

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
        ops: list[MutationOp] = []
        with self._ensure_tx(in_client_tx):
            q_schema = self.quote_ident(QUARANTINE_SCHEMA)
            self._client.query(f"CREATE SCHEMA IF NOT EXISTS {q_schema};")
            for t_sch, t_tbl in targets:
                eff_schema = t_sch or "public"
                if not self._table_exists(t_tbl, eff_schema):
                    if stmt.if_exists:
                        continue
                    raise PgError(f'table "{t_tbl}" does not exist', sqlstate="42P01")

                t_schema = self.inspect_table(t_tbl, eff_schema)
                quarantine_name = f"{t_tbl}__{tx_id}"
                src = self._qualify(t_tbl, eff_schema)
                self._rename_quarantine_sequences(eff_schema, t_tbl, f"__{tx_id}", add=True)
                self._rename_quarantine_indexes(eff_schema, t_tbl, f"__{tx_id}", add=True)
                self._client.query(f"ALTER TABLE {src} SET SCHEMA {q_schema};")
                self._client.query(
                    f"ALTER TABLE {q_schema}.{self.quote_ident(t_tbl)} "
                    f"RENAME TO {self.quote_ident(quarantine_name)};"
                )
                ops.append(
                    MutationOp(
                        op_type="QUARANTINE_DROP",
                        table=t_tbl,
                        schema=eff_schema,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                        quarantine_name=quarantine_name,
                        using_rowid_fallback=t_schema.using_rowid_fallback,
                        rowid_column=t_schema.rowid_column,
                    )
                )

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
        targets = stmt.drop_targets or ([(stmt.schema, stmt.table)] if stmt.table else [])
        if not targets:
            raise ValueError(f"Could not determine target table for TRUNCATE TABLE: {stmt.raw_sql}")
        ops: list[MutationOp] = []
        with self._ensure_tx(in_client_tx):
            q_schema = self.quote_ident(QUARANTINE_SCHEMA)
            self._client.query(f"CREATE SCHEMA IF NOT EXISTS {q_schema};")
            for t_sch, t_tbl in targets:
                eff_schema = t_sch or "public"
                if not self._table_exists(t_tbl, eff_schema):
                    raise PgError(f'relation "{eff_schema}.{t_tbl}" does not exist', sqlstate="42P01")

                t_schema = self.inspect_table(t_tbl, eff_schema)
                quarantine_name = f"{t_tbl}__{tx_id}"
                src = self._qualify(t_tbl, eff_schema)
                q_tbl = f"{q_schema}.{self.quote_ident(quarantine_name)}"

                self._rename_quarantine_sequences(eff_schema, t_tbl, f"__{tx_id}", add=True)
                self._rename_quarantine_indexes(eff_schema, t_tbl, f"__{tx_id}", add=True)
                self._client.query(f"ALTER TABLE {src} SET SCHEMA {q_schema};")
                self._client.query(
                    f"ALTER TABLE {q_schema}.{self.quote_ident(t_tbl)} "
                    f"RENAME TO {self.quote_ident(quarantine_name)};"
                )
                self._client.query(f"CREATE TABLE {src} (LIKE {q_tbl} INCLUDING ALL);")
                ops.append(
                    MutationOp(
                        op_type="QUARANTINE_TRUNCATE",
                        table=t_tbl,
                        schema=eff_schema,
                        pk_columns=t_schema.pk_columns,
                        column_types=t_schema.column_types,
                        quarantine_name=quarantine_name,
                        using_rowid_fallback=t_schema.using_rowid_fallback,
                        rowid_column=t_schema.rowid_column,
                    )
                )

        return (
            QueryResult(rowcount=0, command_tag="TRUNCATE TABLE", warnings=warnings),
            ops,
            warnings,
        )

    def _pg_col_def(self, schema: str, table: str, col: str) -> dict[str, Any] | None:
        res = self._client.execute(
            """
            SELECT a.attname,
                   pg_catalog.format_type(a.atttypid, a.atttypmod) AS col_type,
                   a.attnotnull,
                   pg_catalog.pg_get_expr(d.adbin, d.adrelid) AS col_default
            FROM pg_catalog.pg_attribute a
            JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
            WHERE n.nspname = $1 AND c.relname = $2 AND LOWER(a.attname) = LOWER($3)
              AND a.attnum > 0 AND NOT a.attisdropped
            LIMIT 1;
            """,
            [schema, table, col],
        )
        if not res.rows:
            return None
        name, col_type, not_null, col_default = res.rows[0]
        return {
            "column": str(name),
            "col_type": str(col_type),
            "not_null": bool(not_null),
            "col_default": str(col_default) if col_default is not None else None,
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
        with self._ensure_tx(in_client_tx):
            cur_schema = stmt.schema or "public"
            cur_table = stmt.table
            table_exists = self._table_exists(cur_table, cur_schema)
            t_schema = self.inspect_table(cur_table, cur_schema) if table_exists else None

            pre_snapshots: list[tuple[dict[str, Any], dict[str, Any], str]] = []
            effective_actions: list[dict[str, Any]] = []

            for act in stmt.alter_actions:
                kind = act["action"]
                if kind == "ADD_COLUMN":
                    col = act["column"]
                    if act.get("if_not_exists") and t_schema and col.lower() in {c.lower() for c in t_schema.columns}:
                        continue
                    effective_actions.append(act)
                elif kind in ("DROP_COLUMN", "ALTER_COLUMN_TYPE"):
                    col = act["column"]
                    col_meta = self._pg_col_def(cur_schema, cur_table, col) if table_exists else None
                    if col_meta is None:
                        if kind == "DROP_COLUMN" and act.get("if_exists"):
                            continue
                    else:
                        assert t_schema is not None
                        tag = "col" if kind == "DROP_COLUMN" else "type"
                        q_name = f"{cur_table}__{tag}_{col_meta['column']}__{tx_id}"
                        q_schema = self.quote_ident(QUARANTINE_SCHEMA)
                        self._client.query(f"CREATE SCHEMA IF NOT EXISTS {q_schema};")
                        if t_schema.using_rowid_fallback:
                            key_cols_sql = f"ctid::text AS {self.quote_ident(PROXY_ROWID_ALIAS)}"
                        else:
                            key_cols_sql = ", ".join(self.quote_ident(pk) for pk in t_schema.pk_columns)
                        src = self._qualify(cur_table, cur_schema)
                        q_tbl = f"{q_schema}.{self.quote_ident(q_name)}"
                        self._client.query(
                            f"CREATE TABLE {q_tbl} AS SELECT {key_cols_sql}, {self.quote_ident(col_meta['column'])} FROM {src};"
                        )
                        pre_snapshots.append((act, col_meta, q_name))
                        effective_actions.append(act)
                elif kind in ("ALTER_COLUMN_DEFAULT", "ALTER_COLUMN_NOT_NULL"):
                    col = act["column"]
                    col_meta = self._pg_col_def(cur_schema, cur_table, col) if table_exists else None
                    if col_meta is not None:
                        pre_snapshots.append((act, col_meta, ""))
                        effective_actions.append(act)
                elif kind in ("RENAME_COLUMN", "RENAME_TABLE"):
                    effective_actions.append(act)

            res = self._client.query(stmt.raw_sql)
            cmd_tag = res[0].command_tag if res and res[0].command_tag else "ALTER TABLE"

            snap_iter = iter(pre_snapshots)
            for act in effective_actions:
                kind = act["action"]
                assert t_schema is not None
                if kind == "ADD_COLUMN":
                    ops.append(
                        MutationOp(
                            op_type="ALTER_ADD_COLUMN",
                            table=cur_table,
                            schema=cur_schema,
                            pk_columns=t_schema.pk_columns,
                            column_types=t_schema.column_types,
                            extra_ddl=[json.dumps({"column": act["column"]})],
                        )
                    )
                elif kind in ("DROP_COLUMN", "ALTER_COLUMN_TYPE"):
                    _act, col_meta, q_name = next(snap_iter)
                    op_kind = "QUARANTINE_DROP_COLUMN" if kind == "DROP_COLUMN" else "QUARANTINE_ALTER_COLUMN"
                    ops.append(
                        MutationOp(
                            op_type=op_kind,
                            table=cur_table,
                            schema=cur_schema,
                            pk_columns=t_schema.pk_columns,
                            column_types=t_schema.column_types,
                            quarantine_name=q_name,
                            using_rowid_fallback=t_schema.using_rowid_fallback,
                            rowid_column=t_schema.rowid_column,
                            extra_ddl=[json.dumps(col_meta)],
                        )
                    )
                elif kind in ("ALTER_COLUMN_DEFAULT", "ALTER_COLUMN_NOT_NULL"):
                    _act, col_meta, _ = next(snap_iter)
                    col_meta = {**col_meta, "attr_kind": kind}
                    ops.append(
                        MutationOp(
                            op_type="ALTER_COLUMN_ATTR",
                            table=cur_table,
                            schema=cur_schema,
                            pk_columns=t_schema.pk_columns,
                            column_types=t_schema.column_types,
                            extra_ddl=[json.dumps(col_meta)],
                        )
                    )
                elif kind == "RENAME_COLUMN":
                    ops.append(
                        MutationOp(
                            op_type="ALTER_RENAME_COLUMN",
                            table=cur_table,
                            schema=cur_schema,
                            pk_columns=t_schema.pk_columns,
                            column_types=t_schema.column_types,
                            extra_ddl=[json.dumps({"old_name": act["old_name"], "new_name": act["new_name"]})],
                        )
                    )
                elif kind == "RENAME_TABLE":
                    new_tbl = act["new_table"]
                    new_sch = act.get("new_schema") or cur_schema
                    ops.append(
                        MutationOp(
                            op_type="ALTER_RENAME_TABLE",
                            table=cur_table,
                            schema=cur_schema,
                            pk_columns=t_schema.pk_columns,
                            column_types=t_schema.column_types,
                            extra_ddl=[
                                json.dumps(
                                    {
                                        "old_schema": cur_schema,
                                        "old_table": cur_table,
                                        "new_schema": new_sch,
                                        "new_table": new_tbl,
                                    }
                                )
                            ],
                        )
                    )
                    cur_table = new_tbl
                    cur_schema = new_sch

        return (
            QueryResult(rowcount=0, command_tag=cmd_tag, warnings=warnings),
            ops,
            warnings,
        )

    def _pg_index_def(self, schema: str, index_name: str) -> tuple[str | None, str | None]:
        res = self._client.execute(
            "SELECT tablename, indexdef FROM pg_catalog.pg_indexes "
            "WHERE schemaname = $1 AND LOWER(indexname) = LOWER($2) LIMIT 1;",
            [schema, index_name],
        )
        if not res.rows:
            return None, None
        return str(res.rows[0][0]), str(res.rows[0][1])

    def _execute_index_ddl(
        self,
        stmt: ParsedStatement,
        *,
        in_client_tx: bool,
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.index_name is not None
        eff_schema = stmt.schema or "public"
        ops: list[MutationOp] = []
        with self._ensure_tx(in_client_tx):
            if stmt.kind == StatementKind.CREATE_INDEX:
                existing_tbl, _ = self._pg_index_def(eff_schema, stmt.index_name)
                self._client.query(stmt.raw_sql)
                if existing_tbl is None:
                    ops.append(
                        MutationOp(
                            op_type="ALTER_CREATE_INDEX",
                            table=stmt.table or "",
                            schema=eff_schema,
                            pk_columns=[],
                            column_types={},
                            extra_ddl=[json.dumps({"index_name": stmt.index_name})],
                        )
                    )
                tag = "CREATE INDEX"
            else:
                idx_tbl, idx_def = self._pg_index_def(eff_schema, stmt.index_name)
                self._client.query(stmt.raw_sql)
                if idx_def:
                    ops.append(
                        MutationOp(
                            op_type="ALTER_DROP_INDEX",
                            table=idx_tbl or stmt.table or "",
                            schema=eff_schema,
                            pk_columns=[],
                            column_types={},
                            extra_ddl=[json.dumps({"index_name": stmt.index_name, "create_sql": idx_def})],
                        )
                    )
                tag = "DROP INDEX"
        return (
            QueryResult(rowcount=0, command_tag=tag, warnings=warnings),
            ops,
            warnings,
        )

    @staticmethod
    def _extract_probe_count(res: PgWireResult) -> int:
        if len(res.rows) == 1 and res.rows[0] and len(res.rows[0]) == 1:
            val = res.rows[0][0]
            if isinstance(val, int):
                return val
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

    def _pg_version_num(self) -> int:
        if self._pg_ver_num is not None:
            return self._pg_ver_num
        try:
            res = self._client.execute("SHOW server_version_num;", ())
            self._pg_ver_num = int(str(res.rows[0][0])) if res.rows else 0
        except Exception:
            self._pg_ver_num = 0
        return self._pg_ver_num

    def _supports_side_table(self) -> bool:
        return self.side_table_threshold > 0 and self._pg_version_num() >= 120000

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

    def _ensure_quarantine_schema(self) -> None:
        if not self._quarantine_ready:
            self._client.query(
                f"CREATE SCHEMA IF NOT EXISTS {self.quote_ident(QUARANTINE_SCHEMA)};"
            )
            self._quarantine_ready = True

    @staticmethod
    def _format_copy_cell(val: Any) -> str:
        if val is None:
            return "\\N"
        if isinstance(val, bool):
            return "t" if val else "f"
        if isinstance(val, (int, float)):
            return str(val)
        if isinstance(val, (bytes, bytearray, memoryview)):
            return "\\\\x" + bytes(val).hex()
        s = str(val)
        return (
            s.replace("\\", "\\\\")
            .replace("\t", "\\t")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )

    def _copy_rows_to_temp_table(
        self,
        temp_table_qual: str,
        columns: Sequence[str],
        rows: Sequence[dict[str, Any]],
        *,
        chunk_rows: int = 10000,
    ) -> None:
        cols_q = ", ".join(self.quote_ident(c) for c in columns)
        copy_sql = f"COPY {temp_table_qual} ({cols_q}) FROM STDIN;"
        fmt = self._format_copy_cell

        def _gen_chunks() -> Iterator[bytes]:
            lines: list[str] = []
            for r in rows:
                lines.append("\t".join(fmt(r.get(c)) for c in columns) + "\n")
                if len(lines) >= chunk_rows:
                    yield "".join(lines).encode("utf-8")
                    lines.clear()
            if lines:
                yield "".join(lines).encode("utf-8")

        self._client.copy_from_stdin(copy_sql, _gen_chunks())

    def drop_side_tables(self, items: Sequence[tuple[str, str | None]]) -> None:
        for tname, _sch in items:
            if tname:
                try:
                    self._client.query(
                        f"DROP TABLE IF EXISTS {self.quote_ident(QUARANTINE_SCHEMA)}.{self.quote_ident(tname)};"
                    )
                except Exception:
                    pass

    def materialize_side_op(self, op: MutationOp) -> tuple[MutationOp, list[str]]:
        """Read DB-side UNLOGGED snapshot tables into Python rows for durable disk spill."""
        drop_names: list[str] = []
        before_rows = list(op.before_rows)
        after_rows = list(op.after_rows)
        if op.side_table_before:
            if not self._table_exists(op.side_table_before, QUARANTINE_SCHEMA):
                raise RuntimeError(
                    f"Missing unspilled side-table snapshot '{QUARANTINE_SCHEMA}.{op.side_table_before}'"
                )
            qb = self._qualify(op.side_table_before, QUARANTINE_SCHEMA)
            before_rows = self._res_to_dicts(self._client.query(f"SELECT * FROM {qb};")[0])
            if op.side_rowcount > 0 and len(before_rows) == 0:
                raise RuntimeError(
                    f"Empty/truncated unspilled side-table snapshot '{QUARANTINE_SCHEMA}.{op.side_table_before}'"
                )
            drop_names.append(op.side_table_before)
        if op.side_table_after:
            if not self._table_exists(op.side_table_after, QUARANTINE_SCHEMA):
                raise RuntimeError(
                    f"Missing unspilled side-table snapshot '{QUARANTINE_SCHEMA}.{op.side_table_after}'"
                )
            qa = self._qualify(op.side_table_after, QUARANTINE_SCHEMA)
            after_rows = self._res_to_dicts(self._client.query(f"SELECT * FROM {qa};")[0])
            if op.side_rowcount > 0 and len(after_rows) == 0:
                raise RuntimeError(
                    f"Empty/truncated unspilled side-table snapshot '{QUARANTINE_SCHEMA}.{op.side_table_after}'"
                )
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

    def purge_quarantine_table(self, quarantine_name: str, schema: str | None = None) -> bool:
        if not self._table_exists(quarantine_name, QUARANTINE_SCHEMA):
            return False
        self._client.query(
            f"DROP TABLE IF EXISTS {self.quote_ident(QUARANTINE_SCHEMA)}.{self.quote_ident(quarantine_name)} CASCADE;"
        )
        return True

    def _table_has_triggers(self, table: str, schema: str | None = None) -> bool:
        eff_schema = schema or "public"
        try:
            res = self._client.execute(
                """
                SELECT 1
                FROM pg_catalog.pg_trigger t
                JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
                JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = $1 AND c.relname = $2 AND NOT t.tgisinternal
                LIMIT 1;
                """,
                [eff_schema, table],
            )
            return bool(res.rows)
        except Exception:
            return False

    def _maybe_emit_wal_marker(
        self, tx_id: str, *, schema: str | None = None, table: str | None = None
    ) -> None:
        if not self.emit_wal_marker:
            return
        meta: dict[str, Any] = {"tx_id": tx_id}
        if schema:
            meta["schema"] = schema
        if table:
            meta["table"] = table
            if not self._table_has_triggers(table, schema):
                meta["skip_wal_dml"] = True
        payload = json.dumps(meta)
        self._client.execute(
            "SELECT pg_catalog.pg_logical_emit_message(true, 'reverse_proxy', $1);",
            [payload],
        )

    def _execute_insert(
        self,
        stmt: ParsedStatement,
        tx_id: str = "",
        *,
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        eff_schema = stmt.schema or "public"
        with self._ensure_tx(in_client_tx):
            if tx_id:
                self._maybe_emit_wal_marker(tx_id)
            t_schema = self.inspect_table(stmt.table, eff_schema)
            if t_schema.using_rowid_fallback:
                warnings.append(
                    f"Table '{eff_schema}.{stmt.table}' has no explicit primary key; using PostgreSQL ctid fallback."
                )

            existing_by_pk: dict[tuple[Any, ...], dict[str, Any]] = {}
            upsert_pre_captured = False
            if stmt.is_upsert and not t_schema.using_rowid_fallback:
                val_dicts = extract_insert_value_dicts(stmt.raw_sql, t_schema.columns, params)
                if val_dicts and all(all(pk in d for pk in t_schema.pk_columns) for d in val_dicts):
                    dummy_op = MutationOp(
                        op_type="UPDATE",
                        table=stmt.table,
                        schema=eff_schema,
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
                    f"{self._returning_projection(t_schema)};"
                )
                res = self._client.execute(sql_with_ret, params)
                after_rows = self._res_to_dicts(res)
                user_cols: list[str] = []
                user_rows: list[tuple[Any, ...]] = []
            else:
                res = self._client.execute(stmt.raw_sql, params)
                user_cols = res.columns
                user_rows = res.rows
                after_rows = self._resolve_rows_from_returning(
                    t_schema, self._res_to_dicts(res), warnings
                )

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
                        schema=eff_schema,
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
                        schema=eff_schema,
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
                    schema=eff_schema,
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
        if (
            set(t_schema.columns).issubset(returned_dicts[0].keys())
            and not t_schema.using_rowid_fallback
        ):
            return returned_dicts
        if all(pk in returned_dicts[0] for pk in t_schema.pk_columns):
            rows: list[dict[str, Any]] = []
            qual = self._qualify(t_schema.table, t_schema.schema)
            where_parts = [
                f"{self.quote_ident(pk)} IS NOT DISTINCT FROM ${i + 1}"
                for i, pk in enumerate(t_schema.pk_columns)
            ]
            select_sql = (
                f"SELECT {self._select_projection(t_schema)} FROM {qual} "
                f"WHERE {' AND '.join(where_parts)};"
            )
            for r in returned_dicts:
                res = self._client.execute(select_sql, [r[pk] for pk in t_schema.pk_columns])
                rows.extend(self._res_to_dicts(res))
            return rows
        warnings.append(
            "User-supplied RETURNING clause omitted primary key columns; full row capture may be incomplete."
        )
        return returned_dicts

    def _execute_update(
        self,
        stmt: ParsedStatement,
        tx_id: str = "",
        *,
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        eff_schema = stmt.schema or "public"
        side_op: MutationOp | None = None
        side_rc = 0
        with self._ensure_tx(in_client_tx):
            if tx_id:
                self._maybe_emit_wal_marker(tx_id, schema=eff_schema, table=stmt.table)
            t_schema = self.inspect_table(stmt.table, eff_schema)
            if t_schema.using_rowid_fallback:
                warnings.append(
                    f"Table '{eff_schema}.{stmt.table}' has no explicit primary key; using PostgreSQL ctid fallback."
                )

            qual = self._qualify(stmt.table, eff_schema)
            alias_sql = f" AS {self.quote_ident(stmt.alias)}" if stmt.alias else ""
            from_join_sql = self._from_join_sql(stmt.from_join_clause)
            remapped_where, where_params = self._remap_where_params(stmt.where_clause, params)
            where_sql = f" WHERE {remapped_where}" if remapped_where else ""
            t_br0 = time.perf_counter()
            self._check_blast_radius(
                stmt.table, qual, alias_sql, where_sql, where_params, from_join_sql=from_join_sql
            )
            use_side = (
                not stmt.has_returning
                and not t_schema.using_rowid_fallback
                and not stmt.from_join_clause
                and self._should_use_side_table(
                    qual, alias_sql, where_sql, where_params, from_join_sql=from_join_sql
                )
            )
            t_br_dt = time.perf_counter() - t_br0
            if use_side:
                t_c0 = time.perf_counter()
                self._ensure_quarantine_schema()
                tag_hex = uuid.uuid4().hex[:10]
                snap_b = f"_side_b_{stmt.table}_{tag_hex}"
                snap_a = f"_side_a_{stmt.table}_{tag_hex}"
                qb = self._qualify(snap_b, QUARANTINE_SCHEMA)
                qa = self._qualify(snap_a, QUARANTINE_SCHEMA)
                self._client.query(f"CREATE UNLOGGED TABLE {qb} (LIKE {qual});")
                self._client.query(f"CREATE UNLOGGED TABLE {qa} (LIKE {qual});")
                t_create_dt = time.perf_counter() - t_c0
                raw_clean = stmt.raw_sql.rstrip().rstrip(";")
                if self._pg_version_num() >= 180000:
                    t_cap_dt = 0.0
                    t_dml0 = time.perf_counter()
                    cols_q = ", ".join(self.quote_ident(c) for c in t_schema.columns)
                    old_sel = ", ".join(
                        f"OLD.{self.quote_ident(c)} AS _o{i}" for i, c in enumerate(t_schema.columns)
                    )
                    new_sel = ", ".join(
                        f"NEW.{self.quote_ident(c)} AS _n{i}" for i, c in enumerate(t_schema.columns)
                    )
                    o_aliases = ", ".join(f"_o{i}" for i in range(len(t_schema.columns)))
                    n_aliases = ", ".join(f"_n{i}" for i in range(len(t_schema.columns)))
                    cap_sql = (
                        f"WITH _u AS ({raw_clean} RETURNING {old_sel}, {new_sel}), "
                        f"_ib AS (INSERT INTO {qb} ({cols_q}) SELECT {o_aliases} FROM _u) "
                        f"INSERT INTO {qa} ({cols_q}) SELECT {n_aliases} FROM _u;"
                    )
                    ins_res = self._client.execute(cap_sql, params)
                    side_rc = self._parse_rowcount_from_tag(ins_res.command_tag)
                    t_dml_dt = time.perf_counter() - t_dml0
                else:
                    t_cap0 = time.perf_counter()
                    proj = self._select_projection(t_schema, stmt.alias)
                    self._client.execute(
                        f"INSERT INTO {qb} SELECT {proj} FROM {qual}{alias_sql}{where_sql} FOR UPDATE;",
                        where_params,
                    )
                    t_cap_dt = time.perf_counter() - t_cap0
                    t_dml0 = time.perf_counter()
                    ins_res = self._client.execute(
                        f"WITH _u AS ({raw_clean} RETURNING *) INSERT INTO {qa} SELECT * FROM _u;",
                        params,
                    )
                    side_rc = self._parse_rowcount_from_tag(ins_res.command_tag)
                    t_dml_dt = time.perf_counter() - t_dml0
                side_op = MutationOp(
                    op_type="UPDATE",
                    table=stmt.table,
                    schema=eff_schema,
                    pk_columns=t_schema.pk_columns,
                    column_types=t_schema.column_types,
                    side_table_before=snap_b,
                    side_table_after=snap_a,
                    side_rowcount=side_rc,
                    phase_timings={
                        "blast_radius_check_s": round(t_br_dt, 4),
                        "side_table_create_s": round(t_create_dt, 4),
                        "snapshot_capture_s": round(t_cap_dt, 4),
                        "dml_exec_s": round(t_dml_dt, 4),
                    },
                )

            if side_op is None:
                for_upd_ref = self.quote_ident(stmt.alias or stmt.table)
                proj = self._select_projection(
                    t_schema, stmt.alias, qual_table=(qual if stmt.from_join_clause else None)
                )
                for_upd = f"FOR UPDATE OF {for_upd_ref}" if stmt.from_join_clause else "FOR UPDATE"
                pre_sql = f"SELECT {proj} FROM {qual}{alias_sql}{from_join_sql}{where_sql} {for_upd};"
                pre_res = self._client.execute(pre_sql, where_params)
                raw_before = self._res_to_dicts(pre_res)
                seen_pks: set[tuple[Any, ...]] = set()
                before_rows: list[dict[str, Any]] = []
                for r in raw_before:
                    pk_k = self._pk_key(r, t_schema.pk_columns)
                    if pk_k not in seen_pks:
                        seen_pks.add(pk_k)
                        before_rows.append(r)

                if not stmt.has_returning:
                    ret_proj = self._returning_projection(
                        t_schema, stmt.alias, qual_table=(self.quote_ident(stmt.table) if stmt.from_join_clause else None)
                    )
                    upd_sql = (
                        f"{stmt.raw_sql.rstrip().rstrip(';')} RETURNING {ret_proj};"
                    )
                    upd_res = self._client.execute(upd_sql, params)
                    after_rows = self._res_to_dicts(upd_res)
                    user_cols: list[str] = []
                    user_rows: list[tuple[Any, ...]] = []
                else:
                    upd_res = self._client.execute(stmt.raw_sql, params)
                    user_cols = upd_res.columns
                    user_rows = upd_res.rows
                    after_rows = self._resolve_rows_from_returning(
                        t_schema, self._res_to_dicts(upd_res), warnings
                    )

        if side_op is not None:
            side_op.phase_timings["commit_s"] = round(self._last_commit_s, 4)
            return (
                QueryResult(rowcount=side_rc, command_tag=f"UPDATE {side_rc}", warnings=warnings),
                [side_op],
                warnings,
            )

        op = MutationOp(
            op_type="UPDATE",
            table=stmt.table,
            schema=eff_schema,
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

            child_schema_name = edge.schema or "public"
            c_t_schema = self.inspect_table(edge.child_table, child_schema_name)
            c_qual = self._qualify(edge.child_table, child_schema_name)
            c_proj = self._select_projection(c_t_schema)

            params: list[Any] = []
            or_clauses: list[str] = []
            idx = 1
            for kt in key_tuples:
                parts: list[str] = []
                for ccol, val in zip(edge.child_columns, kt):
                    parts.append(f"{self.quote_ident(ccol)} = ${idx}")
                    params.append(val)
                    idx += 1
                or_clauses.append(f"({' AND '.join(parts)})" if len(parts) > 1 else parts[0])
            where_sql = " OR ".join(or_clauses)
            sel_sql = f"SELECT {c_proj} FROM {c_qual} WHERE {where_sql} FOR UPDATE;"
            c_res = self._client.execute(sel_sql, params)
            c_rows_all = self._res_to_dicts(c_res)
            c_rows: list[dict[str, Any]] = []
            for cr in c_rows_all:
                pk_k = self._pk_key(cr, c_t_schema.pk_columns)
                full_k = (child_schema_name, edge.child_table, pk_k)
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
                    schema=child_schema_name,
                    pk_columns=c_t_schema.pk_columns,
                    column_types=c_t_schema.column_types,
                    before_rows=c_rows,
                    after_rows=[],
                    using_rowid_fallback=c_t_schema.using_rowid_fallback,
                    rowid_column=c_t_schema.rowid_column,
                )
            )
        return ops

    def _execute_delete(
        self,
        stmt: ParsedStatement,
        tx_id: str = "",
        *,
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        eff_schema = stmt.schema or "public"
        cascade_ops: list[MutationOp] = []
        side_op: MutationOp | None = None
        side_rc = 0
        with self._ensure_tx(in_client_tx):
            if tx_id:
                self._maybe_emit_wal_marker(tx_id, schema=eff_schema, table=stmt.table)
            t_schema = self.inspect_table(stmt.table, eff_schema)
            if t_schema.using_rowid_fallback:
                warnings.append(
                    f"Table '{eff_schema}.{stmt.table}' has no explicit primary key; using PostgreSQL ctid fallback."
                )

            qual = self._qualify(stmt.table, eff_schema)
            alias_sql = f" AS {self.quote_ident(stmt.alias)}" if stmt.alias else ""
            from_join_sql = self._from_join_sql(stmt.from_join_clause)
            remapped_where, where_params = self._remap_where_params(stmt.where_clause, params)
            where_sql = f" WHERE {remapped_where}" if remapped_where else ""
            t_br0 = time.perf_counter()
            self._check_blast_radius(
                stmt.table, qual, alias_sql, where_sql, where_params, from_join_sql=from_join_sql
            )

            cascade_edges = [e for e in self.inspect_foreign_keys() if e.on_delete == "CASCADE"]
            has_cascade_children = any(e.parent_table == stmt.table for e in cascade_edges)
            use_side = (
                not stmt.has_returning
                and not t_schema.using_rowid_fallback
                and not stmt.from_join_clause
                and not has_cascade_children
                and self._should_use_side_table(
                    qual, alias_sql, where_sql, where_params, from_join_sql=from_join_sql
                )
            )
            t_br_dt = time.perf_counter() - t_br0
            if use_side:
                t_c0 = time.perf_counter()
                self._ensure_quarantine_schema()
                snap_b = f"_side_b_{stmt.table}_{uuid.uuid4().hex[:10]}"
                qb = self._qualify(snap_b, QUARANTINE_SCHEMA)
                self._client.query(f"CREATE UNLOGGED TABLE {qb} (LIKE {qual});")
                t_create_dt = time.perf_counter() - t_c0
                t_dml0 = time.perf_counter()
                raw_clean = stmt.raw_sql.rstrip().rstrip(";")
                ins_res = self._client.execute(
                    f"WITH _d AS ({raw_clean} RETURNING *) INSERT INTO {qb} SELECT * FROM _d;",
                    params,
                )
                side_rc = self._parse_rowcount_from_tag(ins_res.command_tag)
                t_dml_dt = time.perf_counter() - t_dml0
                side_op = MutationOp(
                    op_type="DELETE",
                    table=stmt.table,
                    schema=eff_schema,
                    pk_columns=t_schema.pk_columns,
                    column_types=t_schema.column_types,
                    side_table_before=snap_b,
                    side_rowcount=side_rc,
                    phase_timings={
                        "blast_radius_check_s": round(t_br_dt, 4),
                        "side_table_create_s": round(t_create_dt, 4),
                        "snapshot_capture_s": 0.0,
                        "dml_exec_s": round(t_dml_dt, 4),
                    },
                )

            if side_op is None:
                if has_cascade_children or stmt.has_returning:
                    for_upd_ref = self.quote_ident(stmt.alias or stmt.table)
                    proj = self._select_projection(
                        t_schema, stmt.alias, qual_table=(qual if stmt.from_join_clause else None)
                    )
                    for_upd = f"FOR UPDATE OF {for_upd_ref}" if stmt.from_join_clause else "FOR UPDATE"
                    pre_sql = f"SELECT {proj} FROM {qual}{alias_sql}{from_join_sql}{where_sql} {for_upd};"
                    pre_res = self._client.execute(pre_sql, where_params)
                    pre_rows = self._res_to_dicts(pre_res)
                    if has_cascade_children and pre_rows:
                        seen_keys = {
                            (eff_schema, stmt.table, self._pk_key(r, t_schema.pk_columns))
                            for r in pre_rows
                        }
                        cascade_ops = self._collect_cascade_delete_ops(
                            stmt.table, pre_rows, cascade_edges, seen_keys
                        )
                else:
                    pre_rows = []

                if not stmt.has_returning:
                    ret_proj = self._returning_projection(
                        t_schema,
                        stmt.alias,
                        qual_table=(self.quote_ident(stmt.table) if stmt.from_join_clause else None),
                    )
                    del_sql = f"{stmt.raw_sql.rstrip().rstrip(';')} RETURNING {ret_proj};"
                    del_res = self._client.execute(del_sql, params)
                    before_rows = self._res_to_dicts(del_res)
                    user_cols: list[str] = []
                    user_rows: list[tuple[Any, ...]] = []
                else:
                    before_rows = pre_rows
                    del_res = self._client.execute(stmt.raw_sql, params)
                    user_cols = del_res.columns
                    user_rows = del_res.rows

        if side_op is not None:
            side_op.phase_timings["commit_s"] = round(self._last_commit_s, 4)
            return (
                QueryResult(rowcount=side_rc, command_tag=f"DELETE {side_rc}", warnings=warnings),
                [side_op],
                warnings,
            )

        op = MutationOp(
            op_type="DELETE",
            table=stmt.table,
            schema=eff_schema,
            pk_columns=t_schema.pk_columns,
            column_types=t_schema.column_types,
            before_rows=before_rows,
            after_rows=[],
            using_rowid_fallback=t_schema.using_rowid_fallback,
            rowid_column=t_schema.rowid_column,
        )
        return (
            QueryResult(
                columns=user_cols,
                rows=user_rows,
                rowcount=len(before_rows),
                command_tag=f"DELETE {len(before_rows)}",
                warnings=warnings,
            ),
            [*cascade_ops, op],
            warnings,
        )

    def _execute_merge(
        self,
        stmt: ParsedStatement,
        tx_id: str = "",
        *,
        in_client_tx: bool,
        params: Sequence[Any],
        warnings: list[str],
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        assert stmt.table is not None
        eff_schema = stmt.schema or "public"
        with self._ensure_tx(in_client_tx):
            if tx_id:
                self._maybe_emit_wal_marker(tx_id)
            t_schema = self.inspect_table(stmt.table, eff_schema)
            qual = self._qualify(stmt.table, eff_schema)
            alias_sql = f" AS {self.quote_ident(stmt.alias)}" if stmt.alias else ""
            proj = self._select_projection(
                t_schema, stmt.alias, qual_table=self.quote_ident(stmt.table)
            )
            if not (stmt.merge_using and stmt.merge_on):
                raise ValueError(f"Could not parse USING/ON clauses in MERGE: {stmt.raw_sql}")

            join_sql = (
                f"SELECT {proj} FROM {qual}{alias_sql} "
                f"JOIN {stmt.merge_using} ON {stmt.merge_on};"
            )
            pre_res = self._client.query(join_sql)[0]
            before_by_pk = {
                self._pk_key(r, t_schema.pk_columns): r for r in self._res_to_dicts(pre_res)
            }

            merge_res = self._client.execute(stmt.raw_sql, params)
            rc = self._parse_rowcount_from_tag(merge_res.command_tag)

            post_res = self._client.query(join_sql)[0]
            after_by_pk = {
                self._pk_key(r, t_schema.pk_columns): r for r in self._res_to_dicts(post_res)
            }

        upd_before: list[dict[str, Any]] = []
        upd_after: list[dict[str, Any]] = []
        del_before: list[dict[str, Any]] = []
        ins_after: list[dict[str, Any]] = []

        for pk_k, b_row in before_by_pk.items():
            if pk_k in after_by_pk:
                a_row = after_by_pk[pk_k]
                if b_row != a_row:
                    upd_before.append(b_row)
                    upd_after.append(a_row)
            else:
                del_before.append(b_row)
        for pk_k, a_row in after_by_pk.items():
            if pk_k not in before_by_pk:
                ins_after.append(a_row)

        ops: list[MutationOp] = []
        if upd_before:
            ops.append(
                MutationOp(
                    op_type="UPDATE",
                    table=stmt.table,
                    schema=eff_schema,
                    pk_columns=t_schema.pk_columns,
                    column_types=t_schema.column_types,
                    before_rows=upd_before,
                    after_rows=upd_after,
                    using_rowid_fallback=t_schema.using_rowid_fallback,
                    rowid_column=t_schema.rowid_column,
                )
            )
        if del_before:
            ops.append(
                MutationOp(
                    op_type="DELETE",
                    table=stmt.table,
                    schema=eff_schema,
                    pk_columns=t_schema.pk_columns,
                    column_types=t_schema.column_types,
                    before_rows=del_before,
                    after_rows=[],
                    using_rowid_fallback=t_schema.using_rowid_fallback,
                    rowid_column=t_schema.rowid_column,
                )
            )
        if ins_after:
            ops.append(
                MutationOp(
                    op_type="INSERT",
                    table=stmt.table,
                    schema=eff_schema,
                    pk_columns=t_schema.pk_columns,
                    column_types=t_schema.column_types,
                    before_rows=[],
                    after_rows=ins_after,
                    using_rowid_fallback=t_schema.using_rowid_fallback,
                    rowid_column=t_schema.rowid_column,
                )
            )

        return (
            QueryResult(
                rowcount=rc or (len(upd_before) + len(del_before) + len(ins_after)),
                command_tag=merge_res.command_tag or "MERGE",
                warnings=warnings,
            ),
            ops,
            warnings,
        )

    def _pk_where_clause(self, op: MutationOp, start_idx: int = 1) -> str:
        parts: list[str] = []
        for idx, pk in enumerate(op.pk_columns):
            param_ref = f"${start_idx + idx}"
            if op.using_rowid_fallback and pk == PROXY_ROWID_ALIAS:
                parts.append(f"ctid = {param_ref}::tid")
            else:
                parts.append(f"{self.quote_ident(pk)} IS NOT DISTINCT FROM {param_ref}")
        return " AND ".join(parts)

    def _fetch_current_row(
        self, op: MutationOp, pk_values: dict[str, Any], *, for_update: bool = False
    ) -> dict[str, Any] | None:
        qual = self._qualify(op.table, op.schema)
        proj = (
            f"ctid::text AS {self.quote_ident(PROXY_ROWID_ALIAS)}, *"
            if op.using_rowid_fallback
            else "*"
        )
        where_sql = self._pk_where_clause(op, start_idx=1)
        lock_sql = " FOR UPDATE" if for_update else ""
        sql = f"SELECT {proj} FROM {qual} WHERE {where_sql} LIMIT 1{lock_sql};"
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
        if not pk_dicts or op.using_rowid_fallback:
            found: dict[tuple[Any, ...], dict[str, Any]] = {}
            for pk_vals in pk_dicts:
                row = self._fetch_current_row(op, pk_vals, for_update=for_update)
                if row is not None:
                    found[self._pk_key(row, op.pk_columns)] = row
            return found

        qual = self._qualify(op.table, op.schema)
        found = {}
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
                placeholders = ", ".join(f"${j + 1}" for j in range(len(chunk)))
                sql = f"SELECT * FROM {qual} WHERE {pk_col} IN ({placeholders}){lock_sql};"
                res = self._client.execute(sql, [d[op.pk_columns[0]] for d in chunk])
                for row in self._res_to_dicts(res):
                    found[self._pk_key(row, op.pk_columns)] = row
        else:
            pk_cols_sql = ", ".join(self.quote_ident(pk) for pk in op.pk_columns)
            for i in range(0, len(non_null_pks), chunk_size):
                chunk = non_null_pks[i : i + chunk_size]
                tuples_sql: list[str] = []
                params: list[Any] = []
                p_idx = 1
                for d in chunk:
                    ph = ", ".join(f"${p_idx + k}" for k in range(num_pk))
                    tuples_sql.append(f"({ph})")
                    params.extend(d[pk] for pk in op.pk_columns)
                    p_idx += num_pk
                sql = f"SELECT * FROM {qual} WHERE ({pk_cols_sql}) IN ({', '.join(tuples_sql)}){lock_sql};"
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
        self._last_undo_stage_s = 0.0
        self._last_undo_conflict_s = 0.0

        for op in reversed(record.ops):
            eff_schema = op.schema or "public"
            qual = self._qualify(op.table, eff_schema)

            if op.op_type == "QUARANTINE_DROP":
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, QUARANTINE_SCHEMA):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=None,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined table '{QUARANTINE_SCHEMA}.{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                if self._table_exists(op.table, eff_schema):
                    if not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={},
                                column=None,
                                expected_after=None,
                                actual_current=op.table,
                                reason=f"Table '{eff_schema}.{op.table}' was recreated since DROP.",
                            )
                        )
                        continue
                    steps.append(
                        ReversePlanStep(
                            description=f"Force-drop recreated table '{eff_schema}.{op.table}'",
                            sql=f"DROP TABLE {qual};",
                        )
                    )
                q_schema = self.quote_ident(QUARANTINE_SCHEMA)
                steps.append(
                    ReversePlanStep(
                        description=f"Rename quarantined table back to '{op.table}'",
                        sql=(
                            f"ALTER TABLE {q_schema}.{self.quote_ident(op.quarantine_name)} "
                            f"RENAME TO {self.quote_ident(op.table)};"
                        ),
                    )
                )
                steps.append(
                    ReversePlanStep(
                        description=f"Move '{op.table}' back to schema '{eff_schema}'",
                        sql=(
                            f"ALTER TABLE {q_schema}.{self.quote_ident(op.table)} "
                            f"SET SCHEMA {self.quote_ident(eff_schema)};"
                        ),
                    )
                )
                steps.extend(
                    self._restore_quarantine_objects_steps(op.quarantine_name, op.table, eff_schema)
                )
                continue

            if op.op_type == "QUARANTINE_TRUNCATE":
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, QUARANTINE_SCHEMA):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=None,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined truncate snapshot '{QUARANTINE_SCHEMA}.{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                if self._table_exists(op.table, eff_schema):
                    cnt_res = self._client.query(f"SELECT COUNT(*) FROM {qual};")
                    new_count = int(cnt_res[0].rows[0][0]) if cnt_res and cnt_res[0].rows else 0
                    if new_count > 0 and not force:
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk={},
                                column=None,
                                expected_after=0,
                                actual_current=new_count,
                                reason=f"Table '{eff_schema}.{op.table}' has {new_count} new row(s) inserted since TRUNCATE.",
                            )
                        )
                        continue
                    steps.append(
                        ReversePlanStep(
                            description=f"Drop post-truncate table '{eff_schema}.{op.table}'",
                            sql=f"DROP TABLE {qual};",
                        )
                    )
                q_schema = self.quote_ident(QUARANTINE_SCHEMA)
                steps.append(
                    ReversePlanStep(
                        description=f"Rename truncated snapshot back to '{op.table}'",
                        sql=(
                            f"ALTER TABLE {q_schema}.{self.quote_ident(op.quarantine_name)} "
                            f"RENAME TO {self.quote_ident(op.table)};"
                        ),
                    )
                )
                steps.append(
                    ReversePlanStep(
                        description=f"Move '{op.table}' back to schema '{eff_schema}'",
                        sql=(
                            f"ALTER TABLE {q_schema}.{self.quote_ident(op.table)} "
                            f"SET SCHEMA {self.quote_ident(eff_schema)};"
                        ),
                    )
                )
                steps.extend(
                    self._restore_quarantine_objects_steps(op.quarantine_name, op.table, eff_schema)
                )
                continue

            if op.op_type == "ALTER_ADD_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                col = str(meta["column"])
                live_cols = {c.lower() for c in self.inspect_table(op.table, eff_schema).columns} if self._table_exists(op.table, eff_schema) else set()
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
                                reason=f"Column '{col}' no longer exists on '{eff_schema}.{op.table}'.",
                            )
                        )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Drop added column '{col}' from '{eff_schema}.{op.table}'",
                        sql=f"ALTER TABLE {qual} DROP COLUMN {self.quote_ident(col)};",
                    )
                )
                continue

            if op.op_type == "QUARANTINE_DROP_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                col = str(meta["column"])
                col_type = str(meta.get("col_type") or "text")
                col_default = meta.get("col_default")
                not_null = bool(meta.get("not_null"))
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, QUARANTINE_SCHEMA):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined column snapshot '{QUARANTINE_SCHEMA}.{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                live_cols = {c.lower() for c in self.inspect_table(op.table, eff_schema).columns} if self._table_exists(op.table, eff_schema) else set()
                if col.lower() in live_cols and not force:
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=None,
                            actual_current=col,
                            reason=f"Column '{col}' was recreated on '{eff_schema}.{op.table}' since DROP COLUMN.",
                        )
                    )
                    continue
                q_tbl = f"{self.quote_ident(QUARANTINE_SCHEMA)}.{self.quote_ident(op.quarantine_name)}"
                if col.lower() not in live_cols:
                    default_sql = f" DEFAULT {col_default}" if col_default is not None else ""
                    steps.append(
                        ReversePlanStep(
                            description=f"Re-add dropped column '{col}' on '{eff_schema}.{op.table}'",
                            sql=f"ALTER TABLE {qual} ADD COLUMN {self.quote_ident(col)} {col_type}{default_sql};",
                        )
                    )
                if op.using_rowid_fallback:
                    join_cond = f"t.ctid = q.{self.quote_ident(PROXY_ROWID_ALIAS)}::tid"
                else:
                    join_cond = " AND ".join(
                        f"t.{self.quote_ident(pk)} = q.{self.quote_ident(pk)}"
                        for pk in op.pk_columns
                    )
                steps.append(
                    ReversePlanStep(
                        description=f"Backfill values for '{eff_schema}.{op.table}.{col}' from quarantine",
                        sql=(
                            f"UPDATE {qual} AS t SET {self.quote_ident(col)} = q.{self.quote_ident(col)} "
                            f"FROM {q_tbl} AS q WHERE {join_cond};"
                        ),
                    )
                )
                if not_null and col.lower() not in live_cols:
                    steps.append(
                        ReversePlanStep(
                            description=f"Restore NOT NULL constraint on '{eff_schema}.{op.table}.{col}'",
                            sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} SET NOT NULL;",
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
                live_cols = {c.lower() for c in self.inspect_table(op.table, eff_schema).columns} if self._table_exists(op.table, eff_schema) else set()
                if new_name.lower() not in live_cols or (old_name.lower() in live_cols and not force):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=new_name,
                            expected_after=new_name,
                            actual_current=old_name if old_name.lower() in live_cols else None,
                            reason=f"Column rename state drifted on '{eff_schema}.{op.table}' ({old_name} -> {new_name}).",
                        )
                    )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Rename column '{new_name}' back to '{old_name}' on '{eff_schema}.{op.table}'",
                        sql=f"ALTER TABLE {qual} RENAME COLUMN {self.quote_ident(new_name)} TO {self.quote_ident(old_name)};",
                    )
                )
                continue

            if op.op_type == "ALTER_RENAME_TABLE":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                old_sch = str(meta.get("old_schema") or eff_schema)
                old_tbl = str(meta["old_table"])
                new_sch = str(meta.get("new_schema") or old_sch)
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
                if new_sch != old_sch:
                    steps.append(
                        ReversePlanStep(
                            description=f"Move '{old_tbl}' back to schema '{old_sch}'",
                            sql=f"ALTER TABLE {self._qualify(old_tbl, new_sch)} SET SCHEMA {self.quote_ident(old_sch)};",
                        )
                    )
                continue

            if op.op_type == "QUARANTINE_ALTER_COLUMN":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                col = str(meta["column"])
                col_type = str(meta.get("col_type") or "text")
                col_default = meta.get("col_default")
                not_null = bool(meta.get("not_null"))
                assert op.quarantine_name is not None
                if not self._table_exists(op.quarantine_name, QUARANTINE_SCHEMA):
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=op.quarantine_name,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Quarantined column snapshot '{QUARANTINE_SCHEMA}.{op.quarantine_name}' no longer exists.",
                        )
                    )
                    continue
                live_cols = {c.lower() for c in self.inspect_table(op.table, eff_schema).columns} if self._table_exists(op.table, eff_schema) else set()
                if col.lower() not in live_cols:
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=col,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Column '{col}' no longer exists on '{eff_schema}.{op.table}'.",
                        )
                    )
                    continue
                q_tbl = f"{self.quote_ident(QUARANTINE_SCHEMA)}.{self.quote_ident(op.quarantine_name)}"
                steps.append(
                    ReversePlanStep(
                        description=f"Temporarily allow NULL on '{eff_schema}.{op.table}.{col}'",
                        sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} DROP NOT NULL;",
                    )
                )
                steps.append(
                    ReversePlanStep(
                        description=f"Revert column type of '{eff_schema}.{op.table}.{col}' to '{col_type}'",
                        sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} TYPE {col_type} USING NULL::{col_type};",
                    )
                )
                if op.using_rowid_fallback:
                    join_cond = f"t.ctid = q.{self.quote_ident(PROXY_ROWID_ALIAS)}::tid"
                else:
                    join_cond = " AND ".join(
                        f"t.{self.quote_ident(pk)} = q.{self.quote_ident(pk)}"
                        for pk in op.pk_columns
                    )
                steps.append(
                    ReversePlanStep(
                        description=f"Backfill original values for '{eff_schema}.{op.table}.{col}' from quarantine",
                        sql=(
                            f"UPDATE {qual} AS t SET {self.quote_ident(col)} = q.{self.quote_ident(col)} "
                            f"FROM {q_tbl} AS q WHERE {join_cond};"
                        ),
                    )
                )
                if col_default is not None:
                    steps.append(
                        ReversePlanStep(
                            description=f"Restore DEFAULT on '{eff_schema}.{op.table}.{col}'",
                            sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} SET DEFAULT {col_default};",
                        )
                    )
                else:
                    steps.append(
                        ReversePlanStep(
                            description=f"Drop any added DEFAULT on '{eff_schema}.{op.table}.{col}'",
                            sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} DROP DEFAULT;",
                        )
                    )
                if not_null:
                    steps.append(
                        ReversePlanStep(
                            description=f"Restore NOT NULL constraint on '{eff_schema}.{op.table}.{col}'",
                            sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} SET NOT NULL;",
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
                attr_kind = str(meta.get("attr_kind") or "")
                live_cols = {c.lower() for c in self.inspect_table(op.table, eff_schema).columns} if self._table_exists(op.table, eff_schema) else set()
                if col.lower() not in live_cols:
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=col,
                            expected_after=col,
                            actual_current=None,
                            row_missing=True,
                            reason=f"Column '{col}' no longer exists on '{eff_schema}.{op.table}'.",
                        )
                    )
                    continue
                if attr_kind == "ALTER_COLUMN_NOT_NULL":
                    if meta.get("not_null"):
                        steps.append(
                            ReversePlanStep(
                                description=f"Restore NOT NULL on '{eff_schema}.{op.table}.{col}'",
                                sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} SET NOT NULL;",
                            )
                        )
                    else:
                        steps.append(
                            ReversePlanStep(
                                description=f"Drop NOT NULL on '{eff_schema}.{op.table}.{col}'",
                                sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} DROP NOT NULL;",
                            )
                        )
                elif attr_kind == "ALTER_COLUMN_DEFAULT":
                    if meta.get("col_default") is not None:
                        steps.append(
                            ReversePlanStep(
                                description=f"Restore DEFAULT on '{eff_schema}.{op.table}.{col}'",
                                sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} SET DEFAULT {meta['col_default']};",
                            )
                        )
                    else:
                        steps.append(
                            ReversePlanStep(
                                description=f"Drop DEFAULT on '{eff_schema}.{op.table}.{col}'",
                                sql=f"ALTER TABLE {qual} ALTER COLUMN {self.quote_ident(col)} DROP DEFAULT;",
                            )
                        )
                continue

            if op.op_type == "ALTER_CREATE_INDEX":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                idx_name = str(meta["index_name"])
                existing_tbl, _ = self._pg_index_def(eff_schema, idx_name)
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
                                reason=f"Index '{eff_schema}.{idx_name}' no longer exists.",
                            )
                        )
                    continue
                steps.append(
                    ReversePlanStep(
                        description=f"Drop created index '{eff_schema}.{idx_name}'",
                        sql=f"DROP INDEX {self._qualify(idx_name, eff_schema)};",
                    )
                )
                continue

            if op.op_type == "ALTER_DROP_INDEX":
                meta = json.loads(op.extra_ddl[0]) if op.extra_ddl else {}
                idx_name = str(meta["index_name"])
                create_sql = str(meta["create_sql"])
                existing_tbl, _ = self._pg_index_def(eff_schema, idx_name)
                if existing_tbl is not None and not force:
                    conflicts.append(
                        DriftConflict(
                            table=op.table,
                            pk={},
                            column=None,
                            expected_after=None,
                            actual_current=idx_name,
                            reason=f"Index '{eff_schema}.{idx_name}' already exists.",
                        )
                    )
                    continue
                if existing_tbl is None:
                    steps.append(
                        ReversePlanStep(
                            description=f"Recreate dropped index '{eff_schema}.{idx_name}'",
                            sql=create_sql if create_sql.rstrip().endswith(";") else f"{create_sql};",
                        )
                    )
                continue

            if op.op_type == "INSERT":
                live_cols = set(self.inspect_table(op.table, eff_schema).columns) if self._table_exists(op.table, eff_schema) else set()
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
                    where_sql = self._pk_where_clause(op, start_idx=1)
                    steps.append(
                        ReversePlanStep(
                            description=f"Delete inserted row {pk_vals} from '{eff_schema}.{op.table}'",
                            sql=f"DELETE FROM {qual} WHERE {where_sql};",
                            params=[pk_vals[pk] for pk in op.pk_columns],
                        )
                    )
                continue

            if op.op_type == "DELETE" and op.side_table_before and not op.before_rows:
                if not self._table_exists(op.side_table_before, QUARANTINE_SCHEMA):
                    raise RuntimeError(
                        f"Missing unspilled side-table snapshot '{QUARANTINE_SCHEMA}.{op.side_table_before}'"
                    )
                qb = self._qualify(op.side_table_before, QUARANTINE_SCHEMA)
                if op.side_rowcount > 0:
                    has_r = self._client.query(f"SELECT 1 FROM {qb} LIMIT 1;")[0]
                    if not has_r.rows:
                        raise RuntimeError(
                            f"Empty/truncated unspilled side-table snapshot '{QUARANTINE_SCHEMA}.{op.side_table_before}'"
                        )
                t_schema = self.inspect_table(op.table, eff_schema)
                pk_eq = " AND ".join(f"t.{self.quote_ident(pk)} = b.{self.quote_ident(pk)}" for pk in op.pk_columns)
                if not force:
                    t_c0 = time.perf_counter()
                    conf_res = self._client.query(
                        f"WITH _has_rows AS MATERIALIZED (SELECT 1 FROM {qual} LIMIT 1), "
                        f"_chk AS MATERIALIZED ("
                        f"SELECT t.* FROM {qual} AS t INNER JOIN {qb} AS b ON {pk_eq} "
                        f"WHERE EXISTS (SELECT 1 FROM _has_rows)"
                        f") SELECT * FROM _chk LIMIT 25;"
                    )[0]
                    self._last_undo_conflict_s += time.perf_counter() - t_c0
                    for crow in self._res_to_dicts(conf_res):
                        pk_vals = {pk: crow[pk] for pk in op.pk_columns}
                        conflicts.append(
                            DriftConflict(
                                table=op.table,
                                pk=pk_vals,
                                column=None,
                                expected_after=None,
                                actual_current=crow,
                                reason="A row with the same primary key was inserted since DELETE.",
                            )
                        )
                cols_q = ", ".join(self.quote_ident(c) for c in t_schema.columns)
                ins_sql = f"INSERT INTO {qual} ({cols_q}) SELECT {cols_q} FROM {qb}"
                if force:
                    pk_list = ", ".join(self.quote_ident(pk) for pk in op.pk_columns)
                    non_pk = [c for c in t_schema.columns if c not in op.pk_columns]
                    if non_pk:
                        upd_set = ", ".join(f"{self.quote_ident(c)} = EXCLUDED.{self.quote_ident(c)}" for c in non_pk)
                        ins_sql += f" ON CONFLICT ({pk_list}) DO UPDATE SET {upd_set}"
                    else:
                        ins_sql += f" ON CONFLICT ({pk_list}) DO NOTHING"
                ins_sql += ";"
                steps.append(
                    ReversePlanStep(
                        description=f"[side_table] Restore deleted rows from DB-side snapshot '{op.side_table_before}' into '{eff_schema}.{op.table}'",
                        sql=ins_sql,
                    )
                )
                continue

            if (
                op.op_type == "DELETE"
                and lock_rows
                and not op.using_rowid_fallback
                and len(op.before_rows) > self.side_table_threshold
                and self._supports_side_table()
                and hasattr(self._client, "copy_from_stdin")
                and self._table_exists(op.table, eff_schema)
            ):
                t_schema = self.inspect_table(op.table, eff_schema)
                live_cols = set(t_schema.columns)
                sample_keys = list(op.before_rows[0].keys())
                dropped = [c for c in sample_keys if c not in live_cols]
                if not (dropped and not force):
                    tb_name = f"_rev_b_{uuid.uuid4().hex[:10]}"
                    tb = self.quote_ident(tb_name)
                    t_s0 = time.perf_counter()
                    self._client.query(f"CREATE TEMP TABLE {tb} (LIKE {qual}) ON COMMIT DROP;")
                    active_cols = [c for c in t_schema.columns if c in sample_keys]
                    self._copy_rows_to_temp_table(tb, active_cols, op.before_rows)
                    self._last_undo_stage_s += time.perf_counter() - t_s0
                    pk_eq = " AND ".join(
                        f"t.{self.quote_ident(pk)} = b.{self.quote_ident(pk)}" for pk in op.pk_columns
                    )
                    if not force:
                        t_c0 = time.perf_counter()
                        conf_res = self._client.query(
                            f"WITH _has_rows AS MATERIALIZED (SELECT 1 FROM {qual} LIMIT 1), "
                            f"_chk AS MATERIALIZED ("
                            f"SELECT t.* FROM {qual} AS t INNER JOIN {tb} AS b ON {pk_eq} "
                            f"WHERE EXISTS (SELECT 1 FROM _has_rows)"
                            f") SELECT * FROM _chk LIMIT 25;"
                        )[0]
                        self._last_undo_conflict_s += time.perf_counter() - t_c0
                        for crow in self._res_to_dicts(conf_res):
                            pk_vals = {pk: crow[pk] for pk in op.pk_columns}
                            conflicts.append(
                                DriftConflict(
                                    table=op.table,
                                    pk=pk_vals,
                                    column=None,
                                    expected_after=None,
                                    actual_current=crow,
                                    reason="A row with the same primary key was inserted since DELETE.",
                                )
                            )
                    cols_q = ", ".join(self.quote_ident(c) for c in active_cols)
                    ins_sql = f"INSERT INTO {qual} ({cols_q}) SELECT {cols_q} FROM {tb}"
                    if force:
                        pk_list = ", ".join(self.quote_ident(pk) for pk in op.pk_columns)
                        non_pk = [c for c in active_cols if c not in op.pk_columns]
                        if non_pk:
                            upd_set = ", ".join(
                                f"{self.quote_ident(c)} = EXCLUDED.{self.quote_ident(c)}" for c in non_pk
                            )
                            ins_sql += f" ON CONFLICT ({pk_list}) DO UPDATE SET {upd_set}"
                        else:
                            ins_sql += f" ON CONFLICT ({pk_list}) DO NOTHING"
                    ins_sql += ";"
                    steps.append(
                        ReversePlanStep(
                            description=f"[spilled_temp_table] Restore deleted rows via temp table '{tb_name}' into '{eff_schema}.{op.table}'",
                            sql=ins_sql,
                        )
                    )
                    continue

            if op.op_type == "DELETE":
                live_cols = set(self.inspect_table(op.table, eff_schema).columns) if self._table_exists(op.table, eff_schema) else set()
                current_map = (
                    {}
                    if (force or op.using_rowid_fallback)
                    else self._prefetch_current_rows(
                        op,
                        [{pk: row[pk] for pk in op.pk_columns} for row in op.before_rows],
                        for_update=lock_rows,
                    )
                )
                for row in reversed(op.before_rows):
                    pk_vals = {pk: row[pk] for pk in op.pk_columns}
                    if not op.using_rowid_fallback:
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
                        c
                        for c in row.keys()
                        if (not (op.using_rowid_fallback and c == PROXY_ROWID_ALIAS))
                        and (not live_cols or c in live_cols)
                    ]
                    quoted_cols = ", ".join(self.quote_ident(c) for c in cols)
                    placeholders = ", ".join(f"${i + 1}" for i in range(len(cols)))
                    sql = f"INSERT INTO {qual} ({quoted_cols}) VALUES ({placeholders})"
                    if force and not op.using_rowid_fallback:
                        pk_list = ", ".join(self.quote_ident(pk) for pk in op.pk_columns)
                        non_pk = [c for c in cols if c not in op.pk_columns]
                        if non_pk:
                            set_clause = ", ".join(
                                f"{self.quote_ident(c)} = EXCLUDED.{self.quote_ident(c)}"
                                for c in non_pk
                            )
                            sql += f" ON CONFLICT ({pk_list}) DO UPDATE SET {set_clause}"
                        else:
                            sql += f" ON CONFLICT ({pk_list}) DO NOTHING"
                    sql += ";"
                    steps.append(
                        ReversePlanStep(
                            description=f"Re-insert deleted row {pk_vals} into '{eff_schema}.{op.table}'",
                            sql=sql,
                            params=[row[c] for c in cols],
                        )
                    )
                continue

            if op.op_type == "UPDATE" and op.side_table_before and op.side_table_after and not op.before_rows:
                if not (
                    self._table_exists(op.side_table_before, QUARANTINE_SCHEMA)
                    and self._table_exists(op.side_table_after, QUARANTINE_SCHEMA)
                ):
                    raise RuntimeError(
                        f"Missing unspilled side-table snapshot '{QUARANTINE_SCHEMA}.{op.side_table_before}'"
                    )
                qb = self._qualify(op.side_table_before, QUARANTINE_SCHEMA)
                qa = self._qualify(op.side_table_after, QUARANTINE_SCHEMA)
                if op.side_rowcount > 0:
                    has_b = self._client.query(f"SELECT 1 FROM {qb} LIMIT 1;")[0]
                    if not has_b.rows:
                        raise RuntimeError(
                            f"Empty/truncated unspilled side-table snapshot '{QUARANTINE_SCHEMA}.{op.side_table_before}'"
                        )
                t_schema = self.inspect_table(op.table, eff_schema)
                pk_eq_a = " AND ".join(f"t.{self.quote_ident(pk)} = a.{self.quote_ident(pk)}" for pk in op.pk_columns)
                pk_eq_b = " AND ".join(f"t.{self.quote_ident(pk)} = b.{self.quote_ident(pk)}" for pk in op.pk_columns)
                t_c0 = time.perf_counter()
                if lock_rows:
                    # Lock all target rows atomically in this tx before conflict evaluation & restore
                    self._client.query(
                        f"SELECT COUNT(*) FROM (SELECT 1 FROM {qual} AS t INNER JOIN {qa} AS a ON {pk_eq_a} FOR UPDATE OF t) _lk;"
                    )
                if not force:
                    pk0_q = self.quote_ident(op.pk_columns[0])
                    miss_res = self._client.query(
                        f"WITH _miss AS MATERIALIZED ("
                        f"SELECT a.* FROM {qa} AS a LEFT JOIN {qual} AS t ON {pk_eq_a} WHERE t.{pk0_q} IS NULL"
                        f") SELECT * FROM _miss LIMIT 25;"
                    )[0]
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
                        f"t.{self.quote_ident(c)} IS DISTINCT FROM a.{self.quote_ident(c)}"
                        for c in t_schema.columns
                    )
                    if diff_preds:
                        diff_res = self._client.query(
                            f"WITH _diff AS MATERIALIZED ("
                            f"SELECT t.* FROM {qual} AS t INNER JOIN {qa} AS a ON {pk_eq_a} WHERE ({diff_preds})"
                            f") SELECT * FROM _diff LIMIT 25;"
                        )[0]
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
                self._last_undo_conflict_s += time.perf_counter() - t_c0
                non_pk_cols = [c for c in t_schema.columns if c not in op.pk_columns]
                set_cols = non_pk_cols or list(t_schema.columns)
                set_sql = ", ".join(
                    f"{self.quote_ident(c)} = b.{self.quote_ident(c)}" for c in set_cols
                )
                steps.append(
                    ReversePlanStep(
                        description=f"[side_table] Restore updated rows from DB-side snapshot '{op.side_table_before}' into '{eff_schema}.{op.table}'",
                        sql=f"UPDATE {qual} AS t SET {set_sql} FROM {qb} AS b WHERE {pk_eq_b};",
                    )
                )
                continue

            if (
                op.op_type == "UPDATE"
                and lock_rows
                and not op.using_rowid_fallback
                and len(op.before_rows) > self.side_table_threshold
                and len(op.after_rows) == len(op.before_rows)
                and self._supports_side_table()
                and hasattr(self._client, "copy_from_stdin")
                and self._table_exists(op.table, eff_schema)
            ):
                t_schema = self.inspect_table(op.table, eff_schema)
                live_cols = set(t_schema.columns)
                sample_keys = list(op.after_rows[0].keys())
                dropped = [c for c in sample_keys if c not in live_cols]
                if not (dropped and not force):
                    tag_hex = uuid.uuid4().hex[:10]
                    tb_name = f"_rev_b_{tag_hex}"
                    ta_name = f"_rev_a_{tag_hex}"
                    tb = self.quote_ident(tb_name)
                    ta = self.quote_ident(ta_name)
                    active_cols = [c for c in t_schema.columns if c in sample_keys]
                    t_s0 = time.perf_counter()
                    self._client.query(f"CREATE TEMP TABLE {tb} (LIKE {qual}) ON COMMIT DROP;")
                    self._copy_rows_to_temp_table(tb, active_cols, op.before_rows)
                    self._client.query(f"CREATE TEMP TABLE {ta} (LIKE {qual}) ON COMMIT DROP;")
                    self._copy_rows_to_temp_table(ta, active_cols, op.after_rows)
                    self._last_undo_stage_s += time.perf_counter() - t_s0
                    pk_eq_a = " AND ".join(
                        f"t.{self.quote_ident(pk)} = a.{self.quote_ident(pk)}" for pk in op.pk_columns
                    )
                    pk_eq_b = " AND ".join(
                        f"t.{self.quote_ident(pk)} = b.{self.quote_ident(pk)}" for pk in op.pk_columns
                    )
                    t_c0 = time.perf_counter()
                    self._client.query(
                        f"SELECT COUNT(*) FROM (SELECT 1 FROM {qual} AS t INNER JOIN {ta} AS a ON {pk_eq_a} FOR UPDATE OF t) _lk;"
                    )
                    if not force:
                        pk0_q = self.quote_ident(op.pk_columns[0])
                        miss_res = self._client.query(
                            f"WITH _miss AS MATERIALIZED ("
                            f"SELECT a.* FROM {ta} AS a LEFT JOIN {qual} AS t ON {pk_eq_a} WHERE t.{pk0_q} IS NULL"
                            f") SELECT * FROM _miss LIMIT 25;"
                        )[0]
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
                            f"t.{self.quote_ident(c)} IS DISTINCT FROM a.{self.quote_ident(c)}"
                            for c in active_cols
                        )
                        if diff_preds:
                            diff_res = self._client.query(
                                f"WITH _diff AS MATERIALIZED ("
                                f"SELECT t.* FROM {qual} AS t INNER JOIN {ta} AS a ON {pk_eq_a} WHERE ({diff_preds})"
                                f") SELECT * FROM _diff LIMIT 25;"
                            )[0]
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
                    self._last_undo_conflict_s += time.perf_counter() - t_c0
                    non_pk_cols = [c for c in active_cols if c not in op.pk_columns]
                    set_cols = non_pk_cols or list(active_cols)
                    set_sql = ", ".join(
                        f"{self.quote_ident(c)} = b.{self.quote_ident(c)}" for c in set_cols
                    )
                    steps.append(
                        ReversePlanStep(
                            description=f"[spilled_temp_table] Restore updated rows via temp table '{tb_name}' into '{eff_schema}.{op.table}'",
                            sql=f"UPDATE {qual} AS t SET {set_sql} FROM {tb} AS b WHERE {pk_eq_b};",
                        )
                    )
                    continue

            if op.op_type == "UPDATE":
                live_cols = set(self.inspect_table(op.table, eff_schema).columns) if self._table_exists(op.table, eff_schema) else set()
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
                        c
                        for c in before.keys()
                        if (not (op.using_rowid_fallback and c == PROXY_ROWID_ALIAS))
                        and (not live_cols or c in live_cols)
                    ]
                    set_sql = ", ".join(
                        f"{self.quote_ident(c)} = ${i + 1}" for i, c in enumerate(update_cols)
                    )
                    where_sql = self._pk_where_clause(op, start_idx=len(update_cols) + 1)
                    params = [before[c] for c in update_cols] + [
                        after_pk_vals[pk] for pk in op.pk_columns
                    ]
                    steps.append(
                        ReversePlanStep(
                            description=f"Revert row {after_pk_vals} in '{eff_schema}.{op.table}'",
                            sql=f"UPDATE {qual} SET {set_sql} WHERE {where_sql};",
                            params=params,
                        )
                    )

        return steps, conflicts

    _RE_INSERT_BATCH = re.compile(
        r"^INSERT\s+INTO\s+(.+?)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)(.*?);?$",
        re.IGNORECASE | re.DOTALL,
    )
    _RE_DELETE_SINGLE_PK = re.compile(
        r'^DELETE\s+FROM\s+(.+?)\s+WHERE\s+((?:"[^"]+"|[A-Za-z_][A-Za-z0-9_]*))\s+IS\s+NOT\s+DISTINCT\s+FROM\s+\$1;?$',
        re.IGNORECASE,
    )
    _RE_UPDATE_SINGLE_PK = re.compile(
        r'^UPDATE\s+(.+?)\s+SET\s+(.+?)\s+WHERE\s+((?:"[^"]+"|[A-Za-z_][A-Za-z0-9_]*))\s+IS\s+NOT\s+DISTINCT\s+FROM\s+\$\d+;?$',
        re.IGNORECASE | re.DOTALL,
    )

    def _execute_batched_steps(
        self,
        steps: Sequence[ReversePlanStep],
        *,
        col_types_by_tbl: dict[str, dict[str, str]] | None = None,
    ) -> None:
        idx = 0
        n_steps = len(steps)
        types_cache: dict[str, dict[str, str]] = dict(col_types_by_tbl or {})
        while idx < n_steps:
            sql = steps[idx].sql
            if not steps[idx].params:
                self._client.execute(sql, ())
                idx += 1
                continue
            end = idx + 1
            while end < n_steps and steps[end].sql == sql and steps[end].params:
                end += 1
            run = steps[idx:end]
            idx = end

            if len(run) == 1:
                self._client.execute(sql, run[0].params)
                continue

            m_ins = self._RE_INSERT_BATCH.match(sql)
            if m_ins:
                tbl_sql, cols_sql, _ph_sql, suffix = m_ins.groups()
                ncol = len(run[0].params)
                if ncol >= 1:
                    for c_start in range(0, len(run), 500):
                        chunk = run[c_start : c_start + 500]
                        row_groups: list[str] = []
                        p_idx = 1
                        for _ in chunk:
                            row_groups.append(
                                "(" + ", ".join(f"${p_idx + j}" for j in range(ncol)) + ")"
                            )
                            p_idx += ncol
                        flat = [p for s in chunk for p in s.params]
                        self._client.execute(
                            f"INSERT INTO {tbl_sql} ({cols_sql}) VALUES {', '.join(row_groups)}{suffix};",
                            flat,
                        )
                    continue

            m_del = self._RE_DELETE_SINGLE_PK.match(sql)
            if m_del and all(s.params[0] is not None for s in run):
                tbl_sql, pk_sql = m_del.groups()
                for c_start in range(0, len(run), 1000):
                    chunk = run[c_start : c_start + 1000]
                    phs = ", ".join(f"${j + 1}" for j in range(len(chunk)))
                    flat = [s.params[0] for s in chunk]
                    self._client.execute(
                        f"DELETE FROM {tbl_sql} WHERE {pk_sql} IN ({phs});",
                        flat,
                    )
                continue

            m_upd = self._RE_UPDATE_SINGLE_PK.match(sql)
            if m_upd and len(run) >= 4:
                tbl_sql, set_clause, pk_sql = m_upd.groups()
                set_cols = [
                    m.group(1)
                    for m in re.finditer(
                        r'("[^"]+"|[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$\d+', set_clause
                    )
                ]
                tbl_types = types_cache.get(tbl_sql, {})
                col_type_list: list[str] = []
                if set_cols and len(set_cols) + 1 == len(run[0].params):
                    for col_sql in set_cols:
                        raw_col = (
                            col_sql[1:-1].replace('""', '"')
                            if col_sql.startswith('"') and col_sql.endswith('"')
                            else col_sql
                        )
                        ctype = tbl_types.get(raw_col)
                        if not ctype:
                            col_type_list = []
                            break
                        col_type_list.append(ctype)
                if set_cols and col_type_list and len(set_cols) + 1 == len(run[0].params):
                    for c_start in range(0, len(run), 250):
                        chunk = run[c_start : c_start + 250]
                        pks = [s.params[-1] for s in chunk]
                        if any(pk is None for pk in pks) or len(set(pks)) != len(pks):
                            self._client.executemany(sql, [s.params for s in chunk])
                            continue
                        active_cols = [
                            (ci, col_sql, col_type_list[ci])
                            for ci, col_sql in enumerate(set_cols)
                            if not (
                                col_sql == pk_sql
                                and all(s.params[ci] == s.params[-1] for s in chunk)
                            )
                        ]
                        if not active_cols:
                            continue
                        set_parts: list[str] = []
                        flat: list[Any] = []
                        p_idx = 1
                        for ci, col_sql, col_type in active_cols:
                            when_parts: list[str] = []
                            for s in chunk:
                                when_parts.append(
                                    f"WHEN ${p_idx} THEN CAST(${p_idx + 1} AS {col_type})"
                                )
                                flat.append(s.params[-1])
                                flat.append(s.params[ci])
                                p_idx += 2
                            set_parts.append(
                                f"{col_sql} = CASE {pk_sql} {' '.join(when_parts)} END"
                            )
                        in_phs = ", ".join(f"${p_idx + j}" for j in range(len(chunk)))
                        flat.extend(pks)
                        self._client.execute(
                            f"UPDATE {tbl_sql} SET {', '.join(set_parts)} WHERE {pk_sql} IN ({in_phs});",
                            flat,
                        )
                    continue

            self._client.executemany(sql, [s.params for s in run])

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
        t_plan0 = time.perf_counter()
        self._client.query("BEGIN;")
        try:
            steps, conflicts = self.build_reverse_plan(record, force=force, lock_rows=True)
            t_plan_total = time.perf_counter() - t_plan0
            stage_s = round(self._last_undo_stage_s, 6)
            conflict_s = round(
                self._last_undo_conflict_s if self._last_undo_conflict_s > 0 else max(0.0, t_plan_total - self._last_undo_stage_s),
                6,
            )
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
            t_exec0 = time.perf_counter()
            if self.emit_wal_marker:
                self._client.execute(
                    "SELECT pg_catalog.pg_logical_emit_message(true, 'reverse_proxy', $1);",
                    [json.dumps({"is_reverse": True, "reversed_tx_id": record.tx_id})],
                )
            # Suppress triggers during state restoration when permitted (falls back cleanly if unprivileged)
            self._client.query("SAVEPOINT _proxy_rep_role;")
            try:
                self._client.query("SET LOCAL session_replication_role = 'replica';")
            except Exception:
                self._client.query("ROLLBACK TO SAVEPOINT _proxy_rep_role;")
            self._client.query("RELEASE SAVEPOINT _proxy_rep_role;")
            col_types_by_tbl: dict[str, dict[str, str]] = {}
            for op in record.ops:
                if op.column_types:
                    eff_s = op.schema or self.default_schema
                    col_types_by_tbl[self._qualify(op.table, eff_s)] = dict(op.column_types)
            self._execute_batched_steps(steps, col_types_by_tbl=col_types_by_tbl)
            restore_exec_s = round(time.perf_counter() - t_exec0, 6)
            t_commit0 = time.perf_counter()
            self._client.query("COMMIT;")
            commit_s = round(time.perf_counter() - t_commit0, 6)
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
            restore_path=r_path,
            undo_phase_timings={
                "stage_temp_s": stage_s,
                "conflict_and_lock_s": conflict_s,
                "restore_exec_s": restore_exec_s,
                "commit_s": commit_s,
            },
        )
