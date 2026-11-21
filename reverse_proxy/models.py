"""Canonical data models for the Universal SQL Reverse Proxy."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EngineType(str, Enum):
    SQLITE = "sqlite"
    POSTGRES = "postgres"
    MYSQL = "mysql"


class BlastRadiusExceededError(RuntimeError):
    """Raised when a mutation exceeds the configured max_capture_rows safety limit."""

    def __init__(self, table: str, limit: int, observed_at_least: int) -> None:
        super().__init__(
            f"Blast radius guard: mutation on '{table}' affects at least {observed_at_least} rows "
            f"(limit={limit}). Increase max_capture_rows or narrow the WHERE clause."
        )
        self.table = table
        self.limit = limit
        self.observed_at_least = observed_at_least


class StatementKind(str, Enum):
    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    MERGE = "merge"
    DROP_TABLE = "drop_table"
    TRUNCATE_TABLE = "truncate_table"
    ALTER_TABLE = "alter_table"
    CREATE_INDEX = "create_index"
    DROP_INDEX = "drop_index"
    TX_BEGIN = "tx_begin"
    TX_COMMIT = "tx_commit"
    TX_ROLLBACK = "tx_rollback"
    SAVEPOINT = "savepoint"
    RELEASE_SAVEPOINT = "release_savepoint"
    ROLLBACK_TO_SAVEPOINT = "rollback_to_savepoint"
    PROXY_HISTORY = "proxy_history"
    PROXY_REVERSE = "proxy_reverse"
    PROXY_DIFF = "proxy_diff"
    PROXY_PURGE = "proxy_purge"
    OTHER_DDL = "other_ddl"
    OTHER = "other"


class ReversibilityStatus(str, Enum):
    EXACT = "exact"
    QUARANTINE = "quarantine"
    PARTIAL = "partial"
    IRREVERSIBLE = "irreversible"
    REVERSED = "reversed"


@dataclass
class ParsedStatement:
    raw_sql: str
    kind: StatementKind
    table: str | None = None
    schema: str | None = None
    alias: str | None = None
    from_join_clause: str | None = None
    where_clause: str | None = None
    merge_using: str | None = None
    merge_on: str | None = None
    has_returning: bool = False
    if_exists: bool = False
    savepoint_name: str | None = None
    proxy_tx_id: str | None = None
    proxy_dry_run: bool = False
    proxy_force: bool = False
    proxy_cascade: bool = False
    proxy_limit: int = 25
    is_upsert: bool = False
    alter_actions: list[dict[str, Any]] = field(default_factory=list)
    drop_targets: list[tuple[str | None, str]] = field(default_factory=list)
    index_name: str | None = None
    purge_mode: str = "quarantine"
    purge_target: str | None = None
    purge_days: float | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class ForeignKeyEdge:
    child_table: str
    child_columns: list[str]
    parent_table: str
    parent_columns: list[str]
    on_delete: str = "NO ACTION"
    schema: str | None = None


@dataclass
class TableSchema:
    table: str
    schema: str | None
    columns: list[str]
    pk_columns: list[str]
    column_types: dict[str, str]
    using_rowid_fallback: bool = False
    rowid_column: str | None = None


@dataclass
class MutationOp:
    op_type: str  # "INSERT", "UPDATE", "DELETE", "QUARANTINE_DROP", "QUARANTINE_TRUNCATE"
    table: str
    schema: str | None
    pk_columns: list[str]
    column_types: dict[str, str]
    before_rows: list[dict[str, Any]] = field(default_factory=list)
    after_rows: list[dict[str, Any]] = field(default_factory=list)
    quarantine_name: str | None = None
    using_rowid_fallback: bool = False
    rowid_column: str | None = None
    extra_ddl: list[str] = field(default_factory=list)
    rbr_fde_b64: str | None = None
    rbr_undo_events: list[str] = field(default_factory=list)
    side_table_before: str | None = None
    side_table_after: str | None = None
    side_rowcount: int = 0
    phase_timings: dict[str, float] = field(default_factory=dict)


@dataclass
class UndoRecord:
    tx_id: str
    seq_no: int
    created_at: str
    engine: EngineType
    session_id: str
    raw_sql: str
    status: ReversibilityStatus
    ops: list[MutationOp] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    reversed_at: str | None = None
    reversed_by_tx_id: str | None = None
    rows_affected: int | None = None
    actor: str = "anonymous"


@dataclass
class DriftConflict:
    table: str
    pk: dict[str, Any]
    column: str | None
    expected_after: Any
    actual_current: Any
    row_missing: bool = False
    reason: str = ""


@dataclass
class ReversePlanStep:
    description: str
    sql: str
    params: list[Any] = field(default_factory=list)


@dataclass
class ReverseResult:
    tx_id: str
    success: bool
    dry_run: bool
    reversed_rows: int = 0
    steps: list[ReversePlanStep] = field(default_factory=list)
    conflicts: list[DriftConflict] = field(default_factory=list)
    error: str | None = None
    reverse_tx_id: str | None = None
    cascaded_tx_ids: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    restore_path: str = "row_batched"


@dataclass
class QueryResult:
    columns: list[str] = field(default_factory=list)
    rows: list[tuple[Any, ...]] = field(default_factory=list)
    rowcount: int = 0
    command_tag: str = ""
    tx_id: str | None = None
    reversibility: ReversibilityStatus | None = None
    warnings: list[str] = field(default_factory=list)
