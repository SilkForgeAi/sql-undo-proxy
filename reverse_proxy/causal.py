"""Causal Dependency Graph for cross-transaction cascading undo."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .ledger import UndoLedger
from .models import ForeignKeyEdge, MutationOp, ReversibilityStatus, UndoRecord


@dataclass
class DependencyReason:
    tx_id: str
    depends_on_tx_id: str
    kind: str  # "row_mutation" | "fk_child" | "ddl_shadow"
    detail: str


@dataclass
class CausalPlan:
    root_tx_id: str
    ordered_tx_ids: list[str]  # Descending seq_no (reverse execution order)
    reasons: list[DependencyReason] = field(default_factory=list)


def _row_pk_tuple(op: MutationOp, row: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(row.get(pk) for pk in op.pk_columns)


def _op_row_keys(op: MutationOp) -> set[tuple[str, tuple[Any, ...]]]:
    tname = op.table.lower()
    keys: set[tuple[str, tuple[Any, ...]]] = set()
    for row in op.before_rows:
        keys.add((tname, _row_pk_tuple(op, row)))
    for row in op.after_rows:
        keys.add((tname, _row_pk_tuple(op, row)))
    return keys


def _op_fk_parent_refs(
    op: MutationOp, fk_by_child: dict[str, list[ForeignKeyEdge]]
) -> set[tuple[str, tuple[Any, ...]]]:
    """Return `(parent_table_lower, parent_col_values_tuple)` referenced by rows in `op`."""
    refs: set[tuple[str, tuple[Any, ...]]] = set()
    edges = fk_by_child.get(op.table.lower(), [])
    if not edges:
        return refs
    for row in op.after_rows + op.before_rows:
        for edge in edges:
            vals = tuple(row.get(c) for c in edge.child_columns)
            if all(v is not None for v in vals):
                refs.add((edge.parent_table.lower(), vals))
    return refs


def _op_fk_parent_keys(
    op: MutationOp, fk_by_parent: dict[str, list[ForeignKeyEdge]]
) -> set[tuple[str, tuple[Any, ...]]]:
    """Return `(parent_table_lower, parent_col_values_tuple)` for parent rows mutated in `op`."""
    keys: set[tuple[str, tuple[Any, ...]]] = set()
    edges = fk_by_parent.get(op.table.lower(), [])
    if not edges:
        return keys
    for row in op.after_rows + op.before_rows:
        for edge in edges:
            vals = tuple(row.get(c) for c in edge.parent_columns)
            if all(v is not None for v in vals):
                keys.add((edge.parent_table.lower(), vals))
    return keys


def build_causal_reverse_plan(
    target_tx_id: str,
    ledger: UndoLedger,
    fk_edges: list[ForeignKeyEdge],
) -> CausalPlan:
    """
    Compute the causal closure of active transactions that must be reversed
    before `target_tx_id` can be safely undone without drift or FK violations.
    """
    target = ledger.get_record(target_tx_id)
    if target is None:
        raise ValueError(f"Transaction '{target_tx_id}' not found in undo ledger.")

    # Load all active records from target onward in chronological order
    # (list_summaries gives newest-first, so inspect seq_no >= target.seq_no)
    all_summaries = ledger.list_summaries(limit=10000)
    candidate_ids = [
        s.tx_id
        for s in reversed(all_summaries)
        if s.seq_no >= target.seq_no and s.status != ReversibilityStatus.REVERSED
    ]
    records: list[UndoRecord] = []
    for tid in candidate_ids:
        rec = ledger.get_record(tid)
        if rec is not None:
            records.append(rec)

    if not any(r.tx_id == target_tx_id for r in records):
        return CausalPlan(root_tx_id=target_tx_id, ordered_tx_ids=[target_tx_id])

    fk_by_child: dict[str, list[ForeignKeyEdge]] = {}
    fk_by_parent: dict[str, list[ForeignKeyEdge]] = {}
    for edge in fk_edges:
        fk_by_child.setdefault(edge.child_table.lower(), []).append(edge)
        fk_by_parent.setdefault(edge.parent_table.lower(), []).append(edge)

    # Precompute per-record indexes
    rec_row_keys: dict[str, set[tuple[str, tuple[Any, ...]]]] = {}
    rec_tables: dict[str, set[str]] = {}
    rec_ddl_tables: dict[str, set[str]] = {}
    rec_parent_created_keys: dict[str, set[tuple[str, tuple[Any, ...]]]] = {}
    rec_parent_deleted_keys: dict[str, set[tuple[str, tuple[Any, ...]]]] = {}
    rec_child_created_refs: dict[str, set[tuple[str, tuple[Any, ...]]]] = {}
    rec_child_deleted_refs: dict[str, set[tuple[str, tuple[Any, ...]]]] = {}

    for rec in records:
        rkeys: set[tuple[str, tuple[Any, ...]]] = set()
        tables: set[str] = set()
        ddl_tables: set[str] = set()
        p_created: set[tuple[str, tuple[Any, ...]]] = set()
        p_deleted: set[tuple[str, tuple[Any, ...]]] = set()
        c_created: set[tuple[str, tuple[Any, ...]]] = set()
        c_deleted: set[tuple[str, tuple[Any, ...]]] = set()

        for op in rec.ops:
            tlow = op.table.lower()
            tables.add(tlow)
            rkeys |= _op_row_keys(op)
            if op.op_type.startswith(("QUARANTINE_", "ALTER_")):
                ddl_tables.add(tlow)
                if op.op_type == "ALTER_RENAME_TABLE" and op.extra_ddl:
                    try:
                        import json as _json
                        meta = _json.loads(op.extra_ddl[0])
                        new_t = str(meta.get("new_table") or "").lower()
                        if new_t:
                            tables.add(new_t)
                            ddl_tables.add(new_t)
                    except Exception:
                        pass
            if op.op_type in ("INSERT", "UPDATE"):
                p_created |= _op_fk_parent_keys(op, fk_by_parent)
                c_created |= _op_fk_parent_refs(op, fk_by_child)
            if op.op_type in ("DELETE", "UPDATE"):
                p_deleted |= _op_fk_parent_keys(op, fk_by_parent)
                c_deleted |= _op_fk_parent_refs(op, fk_by_child)

        rec_row_keys[rec.tx_id] = rkeys
        rec_tables[rec.tx_id] = tables
        rec_ddl_tables[rec.tx_id] = ddl_tables
        rec_parent_created_keys[rec.tx_id] = p_created
        rec_parent_deleted_keys[rec.tx_id] = p_deleted
        rec_child_created_refs[rec.tx_id] = c_created
        rec_child_deleted_refs[rec.tx_id] = c_deleted

    # Build directed dependency edges A -> B (meaning B happened after A and must be reversed before A)
    adj: dict[str, list[str]] = {r.tx_id: [] for r in records}
    edge_reasons: list[DependencyReason] = []

    for i in range(len(records)):
        a = records[i]
        for j in range(i + 1, len(records)):
            b = records[j]
            reason: DependencyReason | None = None

            shared_rows = rec_row_keys[a.tx_id] & rec_row_keys[b.tx_id]
            if shared_rows:
                sample_tbl, sample_pk = next(iter(shared_rows))
                reason = DependencyReason(
                    tx_id=b.tx_id,
                    depends_on_tx_id=a.tx_id,
                    kind="row_mutation",
                    detail=f"{b.tx_id} modified same row {sample_pk} in '{sample_tbl}'.",
                )
            elif rec_ddl_tables[b.tx_id] & rec_tables[a.tx_id]:
                tbl = next(iter(rec_ddl_tables[b.tx_id] & rec_tables[a.tx_id]))
                reason = DependencyReason(
                    tx_id=b.tx_id,
                    depends_on_tx_id=a.tx_id,
                    kind="ddl_shadow",
                    detail=f"{b.tx_id} ran DROP/TRUNCATE on '{tbl}' after {a.tx_id}.",
                )
            elif rec_ddl_tables[a.tx_id] & rec_tables[b.tx_id]:
                tbl = next(iter(rec_ddl_tables[a.tx_id] & rec_tables[b.tx_id]))
                reason = DependencyReason(
                    tx_id=b.tx_id,
                    depends_on_tx_id=a.tx_id,
                    kind="ddl_shadow",
                    detail=f"{b.tx_id} modified '{tbl}' after {a.tx_id} ran DROP/TRUNCATE.",
                )
            else:
                fk_insert_link = rec_parent_created_keys[a.tx_id] & rec_child_created_refs[b.tx_id]
                fk_delete_link = rec_child_deleted_refs[a.tx_id] & rec_parent_deleted_keys[b.tx_id]
                if fk_insert_link:
                    ptbl, pvals = next(iter(fk_insert_link))
                    reason = DependencyReason(
                        tx_id=b.tx_id,
                        depends_on_tx_id=a.tx_id,
                        kind="fk_child",
                        detail=f"{b.tx_id} inserted/linked child row referencing '{ptbl}' {pvals} from {a.tx_id}.",
                    )
                elif fk_delete_link:
                    ptbl, pvals = next(iter(fk_delete_link))
                    reason = DependencyReason(
                        tx_id=b.tx_id,
                        depends_on_tx_id=a.tx_id,
                        kind="fk_child",
                        detail=f"{b.tx_id} deleted parent row '{ptbl}' {pvals} referenced by row deleted in {a.tx_id}.",
                    )

            if reason is not None:
                adj[a.tx_id].append(b.tx_id)
                edge_reasons.append(reason)

    # BFS closure from target_tx_id
    visited: set[str] = {target_tx_id}
    queue = deque([target_tx_id])
    while queue:
        curr = queue.popleft()
        for nxt in adj.get(curr, []):
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)

    seq_map = {r.tx_id: r.seq_no for r in records}
    ordered_tx_ids = sorted(visited, key=lambda tid: seq_map.get(tid, 0), reverse=True)
    relevant_reasons = [
        er for er in edge_reasons if er.tx_id in visited and er.depends_on_tx_id in visited
    ]
    return CausalPlan(
        root_tx_id=target_tx_id,
        ordered_tx_ids=ordered_tx_ids,
        reasons=relevant_reasons,
    )
