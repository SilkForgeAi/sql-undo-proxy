"""Abstract EngineDriver interface for multi-engine reversibility."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from ..models import (
    DriftConflict,
    EngineType,
    ForeignKeyEdge,
    MutationOp,
    ParsedStatement,
    QueryResult,
    ReversePlanStep,
    ReverseResult,
    TableSchema,
    UndoRecord,
)


class EngineDriver(ABC):
    """Per-dialect backend adapter encapsulating wire/SQL differences."""

    engine_type: EngineType

    @abstractmethod
    def quote_ident(self, name: str) -> str:
        """Quote an identifier safely for this SQL dialect."""

    @abstractmethod
    def inspect_table(self, table: str, schema: str | None = None) -> TableSchema:
        """Inspect table columns, types, and primary key (or rowid fallback)."""

    def inspect_foreign_keys(self) -> list[ForeignKeyEdge]:
        """Inspect foreign key relationships across tables (for causal undo graph)."""
        return []

    def purge_quarantine_table(self, quarantine_name: str, schema: str | None = None) -> bool:
        """Drop a quarantined DROP/TRUNCATE snapshot table permanently. Returns True if dropped."""
        return False

    @abstractmethod
    def execute_read(self, sql: str, params: Sequence[Any] = ()) -> QueryResult:
        """Execute a read-only statement."""

    @abstractmethod
    def execute_and_capture(
        self,
        stmt: ParsedStatement,
        tx_id: str,
        *,
        in_client_tx: bool,
        params: Sequence[Any] = (),
    ) -> tuple[QueryResult, list[MutationOp], list[str]]:
        """Execute a mutating statement and capture structured before/after row images."""

    @abstractmethod
    def begin_tx(self) -> None:
        """Start an explicit transaction on the backend connection."""

    @abstractmethod
    def commit_tx(self) -> None:
        """Commit the current backend transaction."""

    @abstractmethod
    def rollback_tx(self) -> None:
        """Roll back the current backend transaction."""

    @abstractmethod
    def savepoint(self, name: str) -> None:
        """Create a transaction savepoint."""

    @abstractmethod
    def rollback_to_savepoint(self, name: str) -> None:
        """Roll back to a named savepoint."""

    @abstractmethod
    def release_savepoint(self, name: str) -> None:
        """Release a named savepoint."""

    @abstractmethod
    def build_reverse_plan(
        self, record: UndoRecord, *, force: bool = False
    ) -> tuple[list[ReversePlanStep], list[DriftConflict]]:
        """Inspect current DB state for drift and build compensating SQL steps."""

    @abstractmethod
    def apply_reverse(
        self,
        record: UndoRecord,
        *,
        dry_run: bool = False,
        force: bool = False,
    ) -> ReverseResult:
        """Verify drift and execute (or preview) compensating SQL atomically."""
