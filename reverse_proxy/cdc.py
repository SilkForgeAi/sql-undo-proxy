"""Hybrid CDC / WAL event ingestor converting Debezium/pgoutput/binlog events into UndoRecords."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .ledger import UndoLedger, new_tx_id
from .models import EngineType, MutationOp, ReversibilityStatus, UndoRecord


@dataclass
class CDCChangeEvent:
    """Normalized row-level change event from pgoutput, MySQL binlog, or Debezium."""

    op: str  # "c" (create/insert), "u" (update), "d" (delete)
    table: str
    pk_columns: list[str]
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    schema: str | None = None
    column_types: dict[str, str] = field(default_factory=dict)
    tx_id: str | None = None
    raw_sql: str = ""
    session_id: str = "cdc"


class CDCIngestor:
    """
    Buffers row-level CDC/WAL events by correlation `tx_id` and flushes them
    into `UndoLedger` as atomic, reversible `UndoRecord`s (closing trigger/stored-proc blind spots).
    """

    def __init__(self, ledger: UndoLedger, engine_type: EngineType) -> None:
        self.ledger = ledger
        self.engine_type = engine_type
        self._pending: dict[str, list[CDCChangeEvent]] = {}
        self._meta: dict[str, tuple[str, str]] = {}  # tx_id -> (session_id, raw_sql)

    def begin_marker(
        self, tx_id: str, *, session_id: str = "cdc", raw_sql: str = ""
    ) -> None:
        """Record proxy attribution marker (e.g. from `pg_logical_emit_message`)."""
        self._pending.setdefault(tx_id, [])
        self._meta[tx_id] = (session_id, raw_sql)

    def ingest_event(self, event: CDCChangeEvent) -> None:
        tx_id = event.tx_id or "default_cdc"
        self._pending.setdefault(tx_id, []).append(event)
        if tx_id not in self._meta:
            self._meta[tx_id] = (event.session_id, event.raw_sql)

    def ingest_debezium_envelope(self, envelope: dict[str, Any]) -> None:
        """Parse a standard Debezium JSON payload (`before`, `after`, `op`, `source`, `transaction`)."""
        payload = envelope.get("payload", envelope)
        source = payload.get("source", {})
        tx_info = payload.get("transaction") or {}
        tx_id = tx_info.get("id") or payload.get("tx_id") or new_tx_id()
        op = str(payload.get("op", "")).lower()
        if op == "r":  # snapshot read
            return
        table = str(source.get("table") or payload.get("table"))
        schema = source.get("schema") or source.get("db")
        pk_cols = list(payload.get("pk_columns") or [])
        before = payload.get("before")
        after = payload.get("after")
        if not pk_cols:
            sample = after or before or {}
            if "id" in sample:
                pk_cols = ["id"]
            else:
                pk_cols = list(sample.keys())

        self.ingest_event(
            CDCChangeEvent(
                op=op,
                table=table,
                schema=schema,
                pk_columns=pk_cols,
                before=before,
                after=after,
                tx_id=str(tx_id),
                raw_sql=str(payload.get("raw_sql", f"/* CDC {op.upper()} {table} */")),
                session_id=str(payload.get("session_id", "cdc")),
            )
        )

    def commit_tx(self, tx_id: str) -> UndoRecord | None:
        """Coalesce buffered CDC events for `tx_id` into contiguous `MutationOp`s and persist."""
        events = self._pending.pop(tx_id, [])
        session_id, raw_sql = self._meta.pop(tx_id, ("cdc", ""))
        if not events:
            return None

        op_map = {"c": "INSERT", "u": "UPDATE", "d": "DELETE"}
        ops: list[MutationOp] = []
        sql_parts: list[str] = []

        for ev in events:
            op_type = op_map.get(ev.op.lower(), ev.op.upper())
            if ev.raw_sql and ev.raw_sql not in sql_parts:
                sql_parts.append(ev.raw_sql)

            # Group consecutive events of the same op_type and table for compact storage
            if (
                ops
                and ops[-1].op_type == op_type
                and ops[-1].table == ev.table
                and ops[-1].schema == ev.schema
            ):
                target = ops[-1]
            else:
                target = MutationOp(
                    op_type=op_type,
                    table=ev.table,
                    schema=ev.schema,
                    pk_columns=list(ev.pk_columns),
                    column_types=dict(ev.column_types),
                )
                ops.append(target)

            if op_type == "INSERT" and ev.after is not None:
                target.after_rows.append(dict(ev.after))
            elif op_type == "DELETE" and ev.before is not None:
                target.before_rows.append(dict(ev.before))
            elif op_type == "UPDATE" and ev.before is not None and ev.after is not None:
                target.before_rows.append(dict(ev.before))
                target.after_rows.append(dict(ev.after))

        effective_sql = raw_sql or "; ".join(sql_parts) or f"/* CDC tx {tx_id} */"
        return self.ledger.record_transaction(
            tx_id=tx_id,
            engine=self.engine_type,
            session_id=session_id,
            raw_sql=effective_sql,
            status=ReversibilityStatus.EXACT,
            ops=ops,
        )

    def rollback_tx(self, tx_id: str) -> None:
        self._pending.pop(tx_id, None)
        self._meta.pop(tx_id, None)
