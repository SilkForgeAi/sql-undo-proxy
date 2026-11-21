"""Core ReverseProxyEngine orchestrating sessions, transactions, capture, and reversal."""

from __future__ import annotations

import contextlib
import json
import queue
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .causal import CausalPlan, build_causal_reverse_plan
from .drivers.base import EngineDriver
from .ledger import UndoLedger, new_tx_id
from .models import (
    MutationOp,
    ParsedStatement,
    QueryResult,
    ReverseResult,
    ReversibilityStatus,
    StatementKind,
    UndoRecord,
)
from .parser import parse_statement, split_statements


@dataclass
class _SavepointMarker:
    name: str
    op_index: int
    sql_index: int
    warning_index: int


@dataclass
class _SessionState:
    session_id: str
    driver: EngineDriver
    lock: threading.RLock
    actor: str = "anonymous"
    in_tx: bool = False
    tx_id: str | None = None
    buffered_ops: list[MutationOp] = field(default_factory=list)
    buffered_sqls: list[str] = field(default_factory=list)
    buffered_warnings: list[str] = field(default_factory=list)
    savepoints: list[_SavepointMarker] = field(default_factory=list)

    def reset_tx(self) -> None:
        self.in_tx = False
        self.tx_id = None
        self.buffered_ops.clear()
        self.buffered_sqls.clear()
        self.buffered_warnings.clear()
        self.savepoints.clear()


class ReverseProxyEngine:
    """Coordinates query interception, per-session backend isolation, undo ledger, and reversal."""

    def __init__(
        self,
        driver_or_factory: EngineDriver | Callable[[], EngineDriver],
        ledger: UndoLedger,
        *,
        require_where_on_delete: bool = False,
        require_where_on_update: bool = False,
        wal_sync_fn: Callable[[], Any] | None = None,
        side_spill_delay_seconds: float = 5.0,
    ) -> None:
        if isinstance(driver_or_factory, EngineDriver):
            self.is_shared_driver = True
            self._driver_factory: Callable[[], EngineDriver] | None = None
            self.driver: EngineDriver = driver_or_factory
        else:
            self.is_shared_driver = False
            self._driver_factory = driver_or_factory
            self.driver = driver_or_factory()

        self.ledger = ledger
        self.require_where_on_delete = require_where_on_delete
        self.require_where_on_update = require_where_on_update
        self.wal_sync_fn = wal_sync_fn
        self.side_spill_delay_seconds = max(0.0, float(side_spill_delay_seconds))
        self._lock = threading.RLock()
        self._sessions: dict[str, _SessionState] = {}
        self._spill_tx_locks: dict[str, threading.RLock] = {}
        self._spill_tx_locks_guard = threading.Lock()
        self._spill_queue: queue.Queue[tuple[str, float] | None] = queue.Queue()
        self._spill_flush_event = threading.Event()
        self._spill_stop = threading.Event()
        self._spill_thread: threading.Thread | None = None
        self._spill_driver: EngineDriver | None = None

    def _get_tx_spill_lock(self, tx_id: str) -> threading.RLock:
        with self._spill_tx_locks_guard:
            lk = self._spill_tx_locks.get(tx_id)
            if lk is None:
                lk = threading.RLock()
                self._spill_tx_locks[tx_id] = lk
            return lk

    def _ensure_spill_worker(self) -> None:
        if self._driver_factory is None or self._spill_thread is not None:
            return
        with self._spill_tx_locks_guard:
            if self._spill_thread is None and not self._spill_stop.is_set():
                self._spill_thread = threading.Thread(target=self._run_spill_worker, daemon=True)
                self._spill_thread.start()

    def _enqueue_side_spill_if_needed(self, tx_id: str, ops: Sequence[MutationOp]) -> None:
        if any(op.side_table_before for op in ops):
            import time as _t
            self._ensure_spill_worker()
            self._spill_queue.put((tx_id, _t.monotonic() + self.side_spill_delay_seconds))

    def _materialize_tx_with_driver(self, tx_id: str, drv: EngineDriver) -> None:
        mat_fn = getattr(drv, "materialize_side_op", None)
        drop_fn = getattr(drv, "drop_side_tables", None)
        if not callable(mat_fn):
            return
        import time as _t
        with self._get_tx_spill_lock(tx_id):
            t_sp0 = _t.perf_counter()
            rec = self.ledger.get_record(tx_id)
            if rec is None or not any(op.side_table_before for op in rec.ops):
                return
            new_ops: list[MutationOp] = []
            to_drop: list[tuple[str, str | None]] = []
            for op in rec.ops:
                if op.side_table_before:
                    mat_op, drop_names = mat_fn(op)
                    new_ops.append(mat_op)
                    for dn in drop_names:
                        to_drop.append((dn, op.schema))
                else:
                    new_ops.append(op)
            if callable(drop_fn) and to_drop:
                drop_fn(to_drop)
            spill_dt = round(_t.perf_counter() - t_sp0, 4)
            for nop in new_ops:
                nop.phase_timings["spill_s"] = spill_dt
            self.ledger.materialize_side_ops(tx_id, new_ops)

    def _run_spill_worker(self) -> None:
        assert self._driver_factory is not None
        import time as _t
        drv: EngineDriver | None = None
        try:
            drv = self._driver_factory()
            self._spill_driver = drv
            while not self._spill_stop.is_set():
                try:
                    item = self._spill_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                if item is None:
                    self._spill_queue.task_done()
                    break
                tx_id, eligible_at = item
                try:
                    while not self._spill_stop.is_set() and not self._spill_flush_event.is_set():
                        rem = eligible_at - _t.monotonic()
                        if rem <= 0:
                            break
                        self._spill_flush_event.wait(timeout=min(rem, 0.25))
                    if not self._spill_stop.is_set():
                        self._materialize_tx_with_driver(tx_id, drv)
                except Exception as exc:
                    import sys as _sys
                    print(f"[reverse-proxy] warning: background spill failed for {tx_id}: {exc}", file=_sys.stderr, flush=True)
                finally:
                    self._spill_queue.task_done()
        finally:
            if drv is not None:
                close_fn = getattr(drv, "close", None)
                if callable(close_fn):
                    try:
                        close_fn()
                    except Exception:
                        pass
                self._spill_driver = None

    def flush_spills(self, timeout: float = 120.0) -> None:
        """Wait until all queued side-table spills have finished materializing."""
        if self._spill_thread is None:
            return
        import time as _t
        self._spill_flush_event.set()
        try:
            end = _t.monotonic() + timeout
            while self._spill_queue.unfinished_tasks > 0 and _t.monotonic() < end:
                _t.sleep(0.02)
        finally:
            self._spill_flush_event.clear()

    def _sync_wal(self) -> None:
        if self.wal_sync_fn is not None:
            try:
                self.wal_sync_fn()
            except Exception:
                pass

    def _resolve_tx_id(self, tx_id: str, *, for_reverse: bool = False) -> str:
        norm = (tx_id or "").strip().upper()
        if norm not in ("", "LAST", "LATEST"):
            return tx_id
        for summary in self.ledger.list_summaries(limit=50):
            if for_reverse:
                if summary.status in (ReversibilityStatus.REVERSED, ReversibilityStatus.IRREVERSIBLE):
                    continue
                full = self.ledger.get_record(summary.tx_id)
                if full is None or not full.ops:
                    continue
            return summary.tx_id
        return tx_id

    def _get_session(self, session_id: str) -> _SessionState:
        with self._lock:
            if session_id not in self._sessions:
                if self.is_shared_driver:
                    sess_driver = self.driver
                    sess_lock = self._lock
                else:
                    assert self._driver_factory is not None
                    sess_driver = self._driver_factory()
                    sess_lock = threading.RLock()
                self._sessions[session_id] = _SessionState(
                    session_id=session_id,
                    driver=sess_driver,
                    lock=sess_lock,
                )
            return self._sessions[session_id]

    def set_session_actor(self, session_id: str, actor: str) -> None:
        sess = self._get_session(session_id)
        sess.actor = actor or "anonymous"

    def close_session(self, session_id: str) -> None:
        with self._lock:
            sess = self._sessions.pop(session_id, None)
        if sess is not None and not self.is_shared_driver:
            with sess.lock:
                close_fn = getattr(sess.driver, "close", None)
                if callable(close_fn):
                    close_fn()

    def close(self) -> None:
        if self._spill_thread is not None and self._spill_queue.unfinished_tasks > 0:
            self.flush_spills(timeout=120.0)
        self._spill_stop.set()
        self._spill_flush_event.set()
        if self._spill_thread is not None:
            self._spill_queue.put(None)
            self._spill_thread.join(timeout=5.0)
            self._spill_thread = None
        with self._lock:
            session_ids = list(self._sessions.keys())
        for sid in session_ids:
            self.close_session(sid)
        if not self.is_shared_driver:
            close_fn = getattr(self.driver, "close", None)
            if callable(close_fn):
                close_fn()

    @staticmethod
    def _has_effective_changes(ops: list[MutationOp]) -> bool:
        for op in ops:
            if op.op_type.startswith(("QUARANTINE_", "ALTER_")):
                return True
            if op.before_rows or op.after_rows or op.side_table_before:
                return True
        return False

    @staticmethod
    def _classify_status(ops: list[MutationOp], warnings: list[str]) -> ReversibilityStatus:
        if any(op.op_type.startswith("QUARANTINE_") for op in ops):
            return ReversibilityStatus.QUARANTINE
        if any("partial" in w.lower() or "upsert" in w.lower() or "omitted" in w.lower() for w in warnings):
            return ReversibilityStatus.PARTIAL
        return ReversibilityStatus.EXACT

    def execute(
        self,
        sql: str,
        *,
        session_id: str = "default",
        params: Sequence[Any] = (),
        actor: str | None = None,
    ) -> list[QueryResult]:
        """Execute one or more SQL statements through the reversibility proxy."""
        statements = split_statements(sql)
        if not statements:
            return []
        if len(statements) > 1 and params:
            raise ValueError("Bound parameters cannot be used with multi-statement SQL batches.")

        sess = self._get_session(session_id)
        if actor is not None:
            sess.actor = actor

        results: list[QueryResult] = []
        with sess.lock:
            for raw_stmt in statements:
                parsed = parse_statement(raw_stmt)
                res = self._execute_one(parsed, sess=sess, params=params)
                results.append(res)
        return results

    def execute_one(
        self,
        sql: str,
        *,
        session_id: str = "default",
        params: Sequence[Any] = (),
        actor: str | None = None,
    ) -> QueryResult:
        results = self.execute(sql, session_id=session_id, params=params, actor=actor)
        if not results:
            return QueryResult(command_tag="EMPTY")
        return results[-1]

    def _execute_one(
        self,
        stmt: ParsedStatement,
        *,
        sess: _SessionState,
        params: Sequence[Any],
    ) -> QueryResult:
        drv = sess.driver
        session_id = sess.session_id

        # --- Proxy Control Commands ---
        if stmt.kind == StatementKind.PROXY_HISTORY:
            return self._handle_proxy_history(stmt.proxy_limit)
        if stmt.kind == StatementKind.PROXY_DIFF:
            assert stmt.proxy_tx_id is not None
            return self._handle_proxy_diff(stmt.proxy_tx_id)
        if stmt.kind == StatementKind.PROXY_REVERSE:
            assert stmt.proxy_tx_id is not None
            return self._handle_proxy_reverse(
                stmt.proxy_tx_id,
                dry_run=stmt.proxy_dry_run,
                force=stmt.proxy_force,
                cascade=stmt.proxy_cascade,
            )
        if stmt.kind == StatementKind.PROXY_PURGE:
            return self._handle_proxy_purge(stmt, actor=sess.actor)

        # --- Transaction Lifecycle ---
        if stmt.kind == StatementKind.TX_BEGIN:
            if not sess.in_tx:
                drv.begin_tx()
                sess.in_tx = True
                sess.tx_id = new_tx_id()
            return QueryResult(command_tag="BEGIN", tx_id=sess.tx_id)

        if stmt.kind == StatementKind.SAVEPOINT:
            if sess.in_tx and stmt.savepoint_name:
                drv.savepoint(stmt.savepoint_name)
                sess.savepoints.append(
                    _SavepointMarker(
                        name=stmt.savepoint_name,
                        op_index=len(sess.buffered_ops),
                        sql_index=len(sess.buffered_sqls),
                        warning_index=len(sess.buffered_warnings),
                    )
                )
            return QueryResult(command_tag="SAVEPOINT", tx_id=sess.tx_id)

        if stmt.kind == StatementKind.ROLLBACK_TO_SAVEPOINT:
            if sess.in_tx and stmt.savepoint_name:
                drv.rollback_to_savepoint(stmt.savepoint_name)
                for idx in range(len(sess.savepoints) - 1, -1, -1):
                    if sess.savepoints[idx].name == stmt.savepoint_name:
                        marker = sess.savepoints[idx]
                        sess.buffered_ops = sess.buffered_ops[: marker.op_index]
                        sess.buffered_sqls = sess.buffered_sqls[: marker.sql_index]
                        sess.buffered_warnings = sess.buffered_warnings[: marker.warning_index]
                        sess.savepoints = sess.savepoints[: idx + 1]
                        break
            return QueryResult(command_tag="ROLLBACK", tx_id=sess.tx_id)

        if stmt.kind == StatementKind.RELEASE_SAVEPOINT:
            if sess.in_tx and stmt.savepoint_name:
                drv.release_savepoint(stmt.savepoint_name)
                for idx in range(len(sess.savepoints) - 1, -1, -1):
                    if sess.savepoints[idx].name == stmt.savepoint_name:
                        sess.savepoints = sess.savepoints[:idx]
                        break
            return QueryResult(command_tag="RELEASE", tx_id=sess.tx_id)

        if stmt.kind == StatementKind.TX_ROLLBACK:
            if sess.in_tx:
                drv.rollback_tx()
                sess.reset_tx()
            return QueryResult(command_tag="ROLLBACK")

        if stmt.kind == StatementKind.TX_COMMIT:
            if not sess.in_tx:
                return QueryResult(command_tag="COMMIT")
            drv.commit_tx()
            recorded_tx_id: str | None = None
            status: ReversibilityStatus | None = None
            if self._has_effective_changes(sess.buffered_ops):
                tx_id = sess.tx_id or new_tx_id()
                status = self._classify_status(sess.buffered_ops, sess.buffered_warnings)
                self.ledger.record_transaction(
                    tx_id=tx_id,
                    engine=drv.engine_type,
                    session_id=session_id,
                    raw_sql=";\n".join(sess.buffered_sqls),
                    status=status,
                    ops=list(sess.buffered_ops),
                    warnings=list(sess.buffered_warnings),
                    actor=sess.actor,
                )
                self._enqueue_side_spill_if_needed(tx_id, sess.buffered_ops)
                recorded_tx_id = tx_id
            sess.reset_tx()
            return QueryResult(
                command_tag="COMMIT",
                tx_id=recorded_tx_id,
                reversibility=status,
            )

        # --- Read-Only Pass-Through ---
        if stmt.kind == StatementKind.SELECT:
            return drv.execute_read(stmt.raw_sql, params)

        # --- Guardrails ---
        if stmt.kind == StatementKind.DELETE and self.require_where_on_delete and not stmt.where_clause:
            raise ValueError("Safety policy blocked DELETE without a WHERE clause.")
        if stmt.kind == StatementKind.UPDATE and self.require_where_on_update and not stmt.where_clause:
            raise ValueError("Safety policy blocked UPDATE without a WHERE clause.")

        # --- Mutating Statements ---
        tx_id = sess.tx_id if sess.in_tx and sess.tx_id else new_tx_id()
        result, ops, warnings = drv.execute_and_capture(
            stmt,
            tx_id,
            in_client_tx=sess.in_tx,
            params=params,
        )

        if sess.in_tx:
            if ops:
                sess.buffered_ops.extend(ops)
                sess.buffered_sqls.append(stmt.raw_sql)
                sess.buffered_warnings.extend(warnings)
            result.tx_id = tx_id
            if ops:
                result.reversibility = self._classify_status(ops, warnings)
            return result

        # Autocommit mode: persist immediately if anything mutated
        if self._has_effective_changes(ops):
            status = self._classify_status(ops, warnings)
            self.ledger.record_transaction(
                tx_id=tx_id,
                engine=drv.engine_type,
                session_id=session_id,
                raw_sql=stmt.raw_sql,
                status=status,
                ops=ops,
                warnings=warnings,
                actor=sess.actor,
            )
            self._enqueue_side_spill_if_needed(tx_id, ops)
            result.tx_id = tx_id
            result.reversibility = status
        return result

    # --- Programmatic & SQL Control Plane API ---

    def history(self, limit: int = 25) -> list[UndoRecord]:
        self._sync_wal()
        with self._lock:
            return self.ledger.list_summaries(limit=limit)

    def diff(self, tx_id: str) -> UndoRecord | None:
        self._sync_wal()
        with self._lock:
            resolved = self._resolve_tx_id(tx_id, for_reverse=False)
            rec = self.ledger.get_record(resolved)
        if rec is not None and any(op.side_table_before for op in rec.ops):
            self._materialize_tx_with_driver(resolved, self.driver)
            with self._lock:
                return self.ledger.get_record(resolved)
        return rec

    def analyze_dependencies(self, tx_id: str) -> CausalPlan:
        self._sync_wal()
        with self._lock:
            resolved = self._resolve_tx_id(tx_id, for_reverse=True)
            fk_edges = self.driver.inspect_foreign_keys()
            return build_causal_reverse_plan(resolved, self.ledger, fk_edges)

    def reverse(
        self,
        tx_id: str,
        *,
        dry_run: bool = False,
        force: bool = False,
        cascade: bool = False,
    ) -> ReverseResult:
        norm = (tx_id or "").strip().upper()
        wal_sync_s = 0.0
        synced = False
        if norm in ("", "LAST", "LATEST") or cascade:
            t_wal0 = time.perf_counter()
            self._sync_wal()
            wal_sync_s = round(time.perf_counter() - t_wal0, 6)
            synced = True
        with self._lock:
            tx_id = self._resolve_tx_id(tx_id, for_reverse=True)
            if cascade:
                return self._reverse_cascade(tx_id, dry_run=dry_run, force=force)

        exec_lock = self._lock if self.is_shared_driver else contextlib.nullcontext()
        with exec_lock:
            with self._get_tx_spill_lock(tx_id):
                t_load0 = time.perf_counter()
                record = self.ledger.get_record(tx_id)
                if record is None and not synced:
                    t_wal0 = time.perf_counter()
                    self._sync_wal()
                    wal_sync_s = round(time.perf_counter() - t_wal0, 6)
                    synced = True
                    t_load0 = time.perf_counter()
                    record = self.ledger.get_record(tx_id)
                elif (
                    record is not None
                    and not synced
                    and not all(
                        op.op_type.startswith(("QUARANTINE_", "ALTER_")) for op in record.ops
                    )
                ):
                    t_wal0 = time.perf_counter()
                    self._sync_wal()
                    wal_sync_s = round(time.perf_counter() - t_wal0, 6)
                    synced = True
                    t_load0 = time.perf_counter()
                    record = self.ledger.get_record(tx_id)
                ledger_load_s = round(time.perf_counter() - t_load0, 6)
                if record is None:
                    return ReverseResult(
                        tx_id=tx_id,
                        success=False,
                        dry_run=dry_run,
                        error=f"Transaction '{tx_id}' not found in undo ledger.",
                    )
                if record.status == ReversibilityStatus.REVERSED and not force:
                    return ReverseResult(
                        tx_id=tx_id,
                        success=False,
                        dry_run=dry_run,
                        error=f"Transaction '{tx_id}' was already reversed at {record.reversed_at}.",
                    )

                res = self.driver.apply_reverse(record, dry_run=dry_run, force=force)
                merged_timings: dict[str, float] = {
                    "wal_sync_s": wal_sync_s,
                    "ledger_load_s": ledger_load_s,
                }
                merged_timings.update(res.undo_phase_timings or {})
                res.undo_phase_timings = merged_timings
                if res.success and not dry_run:
                    reverse_tx_id = new_tx_id()
                    res.reverse_tx_id = reverse_tx_id
                    with self._lock:
                        self.ledger.mark_reversed(tx_id, reverse_tx_id)
                return res

    def _reverse_cascade(
        self, tx_id: str, *, dry_run: bool = False, force: bool = False
    ) -> ReverseResult:
        try:
            plan = self.analyze_dependencies(tx_id)
        except ValueError as exc:
            return ReverseResult(
                tx_id=tx_id, success=False, dry_run=dry_run, error=str(exc)
            )

        all_steps = []
        total_rows = 0
        reversed_chain: list[str] = []

        if dry_run:
            for idx, tid in enumerate(plan.ordered_tx_ids):
                rec = self.ledger.get_record(tid)
                if rec is None:
                    continue
                if rec.status == ReversibilityStatus.REVERSED and not force:
                    continue
                res = self.driver.apply_reverse(
                    rec, dry_run=True, force=(force or idx > 0)
                )
                if not res.success:
                    res.cascaded_tx_ids = plan.ordered_tx_ids
                    return res
                all_steps.extend(res.steps)
                total_rows += res.reversed_rows
                reversed_chain.append(tid)
            return ReverseResult(
                tx_id=tx_id,
                success=True,
                dry_run=True,
                reversed_rows=total_rows,
                steps=all_steps,
                cascaded_tx_ids=reversed_chain,
            )

        last_rev_tx_id: str | None = None
        for tid in plan.ordered_tx_ids:
            rec = self.ledger.get_record(tid)
            if rec is None:
                continue
            if rec.status == ReversibilityStatus.REVERSED and not force:
                continue
            res = self.driver.apply_reverse(rec, dry_run=False, force=force)
            if not res.success:
                res.cascaded_tx_ids = reversed_chain
                res.error = f"Cascade halted at {tid}: {res.error}"
                return res
            rev_id = new_tx_id()
            last_rev_tx_id = rev_id
            self.ledger.mark_reversed(tid, rev_id)
            all_steps.extend(res.steps)
            total_rows += res.reversed_rows
            reversed_chain.append(tid)

        return ReverseResult(
            tx_id=tx_id,
            success=True,
            dry_run=False,
            reversed_rows=total_rows,
            steps=all_steps,
            reverse_tx_id=last_rev_tx_id,
            cascaded_tx_ids=reversed_chain,
        )

    def purge_quarantine(self, *, actor: str = "anonymous", log_event: bool = True) -> list[str]:
        """Drop all quarantined DROP/TRUNCATE snapshot tables currently stored in active records."""
        purged: list[str] = []
        with self._lock:
            records = self.ledger.list_quarantine_records(limit=10000)
            for rec in records:
                for op in rec.ops:
                    if (
                        op.op_type
                        in (
                            "QUARANTINE_DROP",
                            "QUARANTINE_TRUNCATE",
                            "QUARANTINE_DROP_COLUMN",
                            "QUARANTINE_ALTER_COLUMN",
                        )
                        and op.quarantine_name
                    ):
                        if self.driver.purge_quarantine_table(op.quarantine_name, op.schema):
                            purged.append(op.quarantine_name)
        if log_event:
            self.ledger.record_purge_event(
                actor=actor,
                mode="quarantine",
                target=None,
                records_erased=0,
                quarantines_dropped=len(purged),
                details=purged,
            )
        return purged

    def _drop_quarantine_list(self, quarantines: list[tuple[str, str | None]]) -> list[str]:
        purged: list[str] = []
        for qname, sch in quarantines:
            if self.driver.purge_quarantine_table(qname, sch):
                purged.append(qname)
        return purged

    def _handle_proxy_purge(
        self, stmt: ParsedStatement | None = None, *, actor: str = "anonymous"
    ) -> QueryResult:
        mode = stmt.purge_mode if stmt else "quarantine"
        if mode == "log":
            events = self.ledger.list_purge_events(limit=stmt.proxy_limit if stmt else 50)
            return QueryResult(
                columns=["id", "purged_at", "actor", "mode", "target", "records_erased", "quarantines_dropped"],
                rows=[
                    (
                        e["id"],
                        e["purged_at"],
                        e["actor"],
                        e["mode"],
                        e["target"] or "",
                        e["records_erased"],
                        e["quarantines_dropped"],
                    )
                    for e in events
                ],
                rowcount=len(events),
                command_tag="PROXY PURGE LOG",
            )
        if mode == "tx" and stmt and stmt.purge_target:
            with self._lock:
                deleted, qs = self.ledger.purge_tx(stmt.purge_target)
                dropped = self._drop_quarantine_list(qs)
            self.ledger.record_purge_event(
                actor=actor,
                mode="tx",
                target=stmt.purge_target,
                records_erased=1 if deleted else 0,
                quarantines_dropped=len(dropped),
                details=dropped,
            )
            return QueryResult(
                columns=["purged_target", "records_erased", "quarantines_dropped"],
                rows=[(stmt.purge_target, 1 if deleted else 0, len(dropped))],
                rowcount=1 if deleted else 0,
                command_tag="PROXY PURGE",
            )
        if mode == "table" and stmt and stmt.purge_target:
            with self._lock:
                count, qs = self.ledger.purge_table(stmt.purge_target)
                dropped = self._drop_quarantine_list(qs)
            self.ledger.record_purge_event(
                actor=actor,
                mode="table",
                target=stmt.purge_target,
                records_erased=count,
                quarantines_dropped=len(dropped),
                details=dropped,
            )
            return QueryResult(
                columns=["purged_target", "records_erased", "quarantines_dropped"],
                rows=[(stmt.purge_target, count, len(dropped))],
                rowcount=count,
                command_tag="PROXY PURGE",
            )
        if mode == "older_than" and stmt and stmt.purge_days is not None:
            with self._lock:
                count, qs = self.ledger.purge_older_than(stmt.purge_days)
                dropped = self._drop_quarantine_list(qs)
            self.ledger.record_purge_event(
                actor=actor,
                mode="older_than",
                target=f"{stmt.purge_days}d",
                records_erased=count,
                quarantines_dropped=len(dropped),
                details=dropped,
            )
            return QueryResult(
                columns=["retention_days", "records_erased", "quarantines_dropped"],
                rows=[(stmt.purge_days, count, len(dropped))],
                rowcount=count,
                command_tag="PROXY PURGE",
            )
        purged = self.purge_quarantine(actor=actor, log_event=True)
        return QueryResult(
            columns=["purged_table"],
            rows=[(name,) for name in purged],
            rowcount=len(purged),
            command_tag="PROXY PURGE",
        )

    def _handle_proxy_history(self, limit: int) -> QueryResult:
        records = self.history(limit=limit)
        cols = ["tx_id", "actor", "created_at", "engine", "status", "rows_affected", "raw_sql"]
        rows: list[tuple[Any, ...]] = []
        for rec in records:
            total_rows = (
                rec.rows_affected
                if rec.rows_affected is not None
                else sum(
                    max(
                        len(op.before_rows),
                        len(op.after_rows),
                        1 if op.op_type.startswith(("QUARANTINE_", "ALTER_")) else 0,
                    )
                    for op in rec.ops
                )
            )
            rows.append(
                (
                    rec.tx_id,
                    rec.actor,
                    rec.created_at,
                    rec.engine.value,
                    rec.status.value,
                    total_rows,
                    rec.raw_sql,
                )
            )
        return QueryResult(columns=cols, rows=rows, rowcount=len(rows), command_tag="PROXY HISTORY")

    def _handle_proxy_diff(self, tx_id: str) -> QueryResult:
        rec = self.diff(tx_id)
        if rec is None:
            raise ValueError(f"Transaction '{tx_id}' not found.")
        cols = ["op_type", "table", "pk", "before_json", "after_json"]
        rows: list[tuple[Any, ...]] = []
        for op in rec.ops:
            if op.op_type.startswith(("QUARANTINE_", "ALTER_")):
                meta_info: dict[str, Any] = {}
                if op.extra_ddl:
                    try:
                        parsed_meta = json.loads(op.extra_ddl[0])
                        if isinstance(parsed_meta, dict):
                            meta_info = parsed_meta
                    except Exception:
                        meta_info = {"extra_ddl": op.extra_ddl}
                rows.append(
                    (
                        op.op_type,
                        op.table,
                        "{}",
                        json.dumps({"table": op.table, **meta_info}),
                        json.dumps({"quarantined_as": op.quarantine_name} if op.quarantine_name else meta_info),
                    )
                )
                continue
            count = max(len(op.before_rows), len(op.after_rows))
            display_count = min(count, 200) if count > 500 else count
            for i in range(display_count):
                b = op.before_rows[i] if i < len(op.before_rows) else None
                a = op.after_rows[i] if i < len(op.after_rows) else None
                sample = b or a or {}
                pk_dict = {pk: sample.get(pk) for pk in op.pk_columns}
                rows.append(
                    (
                        op.op_type,
                        op.table,
                        json.dumps(pk_dict, default=str),
                        json.dumps(b, default=str),
                        json.dumps(a, default=str),
                    )
                )
            if count > display_count:
                rows.append(
                    (
                        op.op_type,
                        op.table,
                        "{}",
                        f"... ({count - display_count} more row diffs omitted; total={count}) ...",
                        json.dumps({"phase_timings": op.phase_timings} if op.phase_timings else {}),
                    )
                )
        return QueryResult(columns=cols, rows=rows, rowcount=len(rows), command_tag="PROXY DIFF")

    def _handle_proxy_reverse(
        self, tx_id: str, *, dry_run: bool, force: bool, cascade: bool = False
    ) -> QueryResult:
        res = self.reverse(tx_id, dry_run=dry_run, force=force, cascade=cascade)
        if not res.success:
            if res.conflicts:
                cols = ["conflict_table", "pk", "column", "expected_after", "actual_current", "reason"]
                rows = [
                    (
                        c.table,
                        json.dumps(c.pk, default=str),
                        c.column,
                        repr(c.expected_after),
                        repr(c.actual_current),
                        c.reason,
                    )
                    for c in res.conflicts
                ]
                return QueryResult(
                    columns=cols,
                    rows=rows,
                    rowcount=len(rows),
                    command_tag="PROXY REVERSE CONFLICT",
                    warnings=[res.error or "Drift conflict detected."],
                )
            raise ValueError(res.error or "Reverse failed.")

        cols = ["step_no", "description", "sql", "params"]
        total_steps = len(res.steps)
        if total_steps > 500:
            rows = [
                (i + 1, s.description, s.sql, json.dumps(s.params, default=str))
                for i, s in enumerate(res.steps[:200])
            ]
            rows.append(
                (
                    total_steps,
                    f"... ({total_steps - 200} more steps omitted; total={total_steps}) ...",
                    "",
                    "[]",
                )
            )
        else:
            rows = [
                (i + 1, s.description, s.sql, json.dumps(s.params, default=str))
                for i, s in enumerate(res.steps)
            ]
        if rows and res.undo_phase_timings and not dry_run:
            r0 = rows[0]
            t_tag = " [undo_timings=" + json.dumps(res.undo_phase_timings, separators=(",", ":")) + "]"
            rows[0] = (r0[0], f"{r0[1]}{t_tag}", r0[2], r0[3])
        tag = "PROXY REVERSE DRY RUN" if dry_run else "PROXY REVERSE OK"
        return QueryResult(
            columns=cols,
            rows=rows,
            rowcount=len(rows),
            command_tag=tag,
            tx_id=res.reverse_tx_id,
            warnings=list(res.warnings),
        )
