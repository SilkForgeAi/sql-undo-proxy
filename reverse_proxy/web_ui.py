"""Control plane HTTP/HTTPS API & Production Web UI ('The Universal Reverse Button')."""

from __future__ import annotations

import base64
import csv
import hmac
import io
import json
import ssl
import threading
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .cdc import CDCIngestor
from .engine import ReverseProxyEngine


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return "0x" + bytes(obj).hex()
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return obj


_HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Universal SQL Reverse Proxy</title>
<style>
  :root {
    --bg: #0b1020; --panel: #131a2e; --border: #253052; --text: #e6ecff;
    --muted: #8b98c2; --accent: #6366f1; --danger: #ef4444; --ok: #10b981; --warn: #f59e0b;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); }
  header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; border-bottom: 1px solid var(--border); background: #0e1427; flex-wrap: wrap; gap: 12px; }
  h1 { margin: 0; font-size: 18px; letter-spacing: 0.2px; }
  .badges { display: flex; gap: 8px; font-size: 12px; flex-wrap: wrap; }
  .badge { padding: 4px 10px; border-radius: 999px; background: var(--panel); border: 1px solid var(--border); color: var(--muted); }
  .badge strong { color: var(--text); }
  main { max-width: 1220px; margin: 24px auto; padding: 0 20px; display: grid; gap: 20px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px 20px; }
  .card h2 { margin: 0 0 12px 0; font-size: 15px; color: #cbd5ff; }
  textarea, input, select { background: #090e1c; color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; font-size: 13px; }
  textarea { width: 100%; min-height: 80px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .row { display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-top: 10px; flex-wrap: wrap; }
  .toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  button, a.btn { cursor: pointer; border: 1px solid var(--border); background: #1d2746; color: var(--text); padding: 7px 12px; border-radius: 8px; font-size: 12px; font-weight: 500; text-decoration: none; display: inline-block; }
  button:hover, a.btn:hover { filter: brightness(1.14); }
  button.primary { background: var(--accent); border-color: var(--accent); color: white; }
  button.reverse { background: #b91c1c; border-color: #dc2626; color: white; }
  button.warn { background: #b45309; border-color: #d97706; color: white; }
  button:disabled { opacity: 0.45; cursor: not-allowed; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  pre { background: #090e1c; border: 1px solid var(--border); border-radius: 8px; padding: 12px; overflow-x: auto; margin: 8px 0 0; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .pill.exact { background: rgba(16,185,129,0.16); color: #34d399; }
  .pill.quarantine { background: rgba(245,158,11,0.18); color: #fbbf24; }
  .pill.partial { background: rgba(245,158,11,0.18); color: #fbbf24; }
  .pill.reversed { background: rgba(139,152,194,0.18); color: #94a3b8; }
  .actions { display: flex; gap: 6px; white-space: nowrap; flex-wrap: wrap; }
  .toast { font-size: 13px; color: var(--muted); }
  .toast.err { color: #f87171; }
  .toast.ok { color: #34d399; }
  .diff-old { background: rgba(239, 68, 68, 0.14); color: #fca5a5; padding: 2px 6px; border-radius: 4px; }
  .diff-new { background: rgba(16, 185, 129, 0.14); color: #6ee7b7; padding: 2px 6px; border-radius: 4px; }
</style>
</head>
<body>
<header>
  <h1>&#8634; Universal SQL Reverse Proxy</h1>
  <div class="badges" id="status-badges">Loading...</div>
</header>
<main>
  <section class="card">
    <h2>SQL Console (Routed Through Reverse Proxy)</h2>
    <textarea id="sql-input" placeholder="INSERT INTO users (id, name) VALUES (1, 'Alice');"></textarea>
    <div class="row">
      <div class="toast" id="query-status"></div>
      <div class="actions">
        <button class="primary" onclick="runQuery()">Execute SQL</button>
      </div>
    </div>
    <div id="query-output"></div>
  </section>

  <section class="card">
    <div class="row" style="margin-top:0; margin-bottom:12px;">
      <h2 style="margin:0;">Transaction Undo Ledger</h2>
      <div class="toolbar">
        <input id="filter-q" placeholder="Filter SQL / tx_id..." oninput="loadHistory()" style="width:190px;" />
        <input id="filter-actor" placeholder="Actor..." oninput="loadHistory()" style="width:110px;" />
        <select id="filter-status" onchange="loadHistory()">
          <option value="">All statuses</option>
          <option value="exact">Exact</option>
          <option value="quarantine">Quarantine</option>
          <option value="partial">Partial</option>
          <option value="reversed">Reversed</option>
        </select>
        <label style="font-size:12px; color:var(--muted); display:flex; align-items:center; gap:4px;">
          <input type="checkbox" id="auto-refresh" onchange="toggleAutoRefresh()" /> Live (2s)
        </label>
        <button onclick="loadHistory()">Refresh</button>
        <a class="btn" href="/api/export?format=json" download="undo_audit.json">Export JSON</a>
        <a class="btn" href="/api/export?format=csv" download="undo_audit.csv">Export CSV</a>
        <button class="warn" onclick="purgeQuarantine()">Purge Quarantine</button>
      </div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Tx ID</th>
          <th>Actor</th>
          <th>Status</th>
          <th>Rows</th>
          <th>SQL</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody id="history-body"></tbody>
    </table>
  </section>

  <section class="card" id="inspector-card" style="display:none;">
    <div class="row" style="margin-top:0;">
      <h2 id="inspector-title" style="margin:0;">Inspector</h2>
      <button onclick="document.getElementById('inspector-card').style.display='none'">Close</button>
    </div>
    <div id="inspector-body"></div>
  </section>
</main>
<script>
let refreshTimer = null;

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  return res.json();
}

function toggleAutoRefresh() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
  if (document.getElementById("auto-refresh").checked) {
    refreshTimer = setInterval(() => { loadStatus(); loadHistory(); }, 2000);
  }
}

async function loadStatus() {
  const s = await api("/api/status");
  const badges = [
    `<span class="badge">Engine: <strong>${s.engine}</strong></span>`,
    `<span class="badge">Records: <strong>${s.records_count}</strong></span>`,
    s.pg_port ? `<span class="badge">pgwire: <strong>:${s.pg_port}</strong></span>` : "",
    s.mysql_port ? `<span class="badge">mysql: <strong>:${s.mysql_port}</strong></span>` : "",
  ].filter(Boolean).join("");
  document.getElementById("status-badges").innerHTML = badges;
}

async function loadHistory() {
  const q = encodeURIComponent(document.getElementById("filter-q").value.trim());
  const actor = encodeURIComponent(document.getElementById("filter-actor").value.trim());
  const status = encodeURIComponent(document.getElementById("filter-status").value);
  const data = await api(`/api/history?limit=100&q=${q}&actor=${actor}&status=${status}`);
  const tbody = document.getElementById("history-body");
  if (!data.records.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted)">No matching transactions found.</td></tr>';
    return;
  }
  tbody.innerHTML = data.records.map(r => {
    const isRev = r.status === "reversed";
    return `<tr>
      <td><code>${r.tx_id}</code></td>
      <td><code>${escapeHtml(r.actor || "anonymous")}</code></td>
      <td><span class="pill ${r.status}">${r.status}</span></td>
      <td>${r.rows_affected}</td>
      <td><code>${escapeHtml(r.raw_sql)}</code></td>
      <td class="actions">
        <button onclick="showDiff('${r.tx_id}')">Diff</button>
        <button onclick="showDeps('${r.tx_id}')" ${isRev ? "disabled" : ""}>Chain</button>
        <button onclick="reverseTx('${r.tx_id}', true, false)" ${isRev ? "disabled" : ""}>Dry Run</button>
        <button class="reverse" onclick="reverseTx('${r.tx_id}', false, false)" ${isRev ? "disabled" : ""}>&#8634; Reverse</button>
      </td>
    </tr>`;
  }).join("");
}

async function runQuery() {
  const sql = document.getElementById("sql-input").value.trim();
  const statusEl = document.getElementById("query-status");
  const outEl = document.getElementById("query-output");
  if (!sql) return;
  const res = await api("/api/query", { method: "POST", body: JSON.stringify({ sql }) });
  if (res.error) {
    statusEl.className = "toast err";
    statusEl.textContent = res.error;
    outEl.innerHTML = "";
    return;
  }
  statusEl.className = "toast ok";
  statusEl.textContent = res.tx_id
    ? `Executed (${res.command_tag}) — captured tx_id=${res.tx_id}`
    : `Executed (${res.command_tag})`;
  if (res.columns && res.columns.length) {
    const head = res.columns.map(c => `<th>${escapeHtml(c)}</th>`).join("");
    const rows = res.rows.map(r => `<tr>${r.map(v => `<td>${escapeHtml(JSON.stringify(v))}</td>`).join("")}</tr>`).join("");
    outEl.innerHTML = `<table style="margin-top:10px"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>`;
  } else {
    outEl.innerHTML = "";
  }
  loadStatus();
  loadHistory();
}

function renderSideBySideDiff(d) {
  let html = "";
  for (const op of d.ops) {
    html += `<p style="margin:10px 0 6px;color:#cbd5ff;"><strong>${escapeHtml(op.op_type)}</strong> on <code>${escapeHtml(op.table)}</code> (before: ${op.total_before_rows}, after: ${op.total_after_rows})</p>`;
    if (op.quarantine_name) {
      html += `<p class="toast">Quarantined snapshot: <code>${escapeHtml(op.quarantine_name)}</code></p>`;
      continue;
    }
    const maxLen = Math.max(op.before_rows.length, op.after_rows.length);
    if (!maxLen) continue;
    html += `<table><thead><tr><th>Row #</th><th>Before</th><th>After</th></tr></thead><tbody>`;
    for (let i = 0; i < maxLen; i++) {
      const b = op.before_rows[i];
      const a = op.after_rows[i];
      html += `<tr>
        <td>${i + 1 + (d.offset || 0)}</td>
        <td>${b ? `<span class="diff-old"><code>${escapeHtml(JSON.stringify(b))}</code></span>` : '<span style="color:var(--muted)">—</span>'}</td>
        <td>${a ? `<span class="diff-new"><code>${escapeHtml(JSON.stringify(a))}</code></span>` : '<span style="color:var(--muted)">—</span>'}</td>
      </tr>`;
    }
    html += `</tbody></table>`;
  }
  html += `<details style="margin-top:12px;"><summary style="cursor:pointer;color:var(--muted);">Raw JSON</summary><pre>${escapeHtml(JSON.stringify(d, null, 2))}</pre></details>`;
  return html;
}

async function showDiff(txId) {
  const d = await api(`/api/diff/${txId}?limit=50`);
  const card = document.getElementById("inspector-card");
  document.getElementById("inspector-title").textContent = `Row Diff for ${txId}`;
  document.getElementById("inspector-body").innerHTML = renderSideBySideDiff(d);
  card.style.display = "block";
}

async function showDeps(txId) {
  const dep = await api(`/api/dependencies/${txId}`);
  const card = document.getElementById("inspector-card");
  document.getElementById("inspector-title").textContent = `Causal Dependency Chain for ${txId}`;
  let html = `<p class="toast">Reverse execution order: <code>${dep.ordered_tx_ids.join(" &rarr; ")}</code></p>`;
  if (dep.ordered_tx_ids.length > 1) {
    html += `<button class="primary" style="margin-bottom:8px;" onclick="reverseTx('${txId}', false, false, true)">Cascade Reverse Entire Chain (${dep.ordered_tx_ids.length} tx)</button>`;
  }
  html += `<pre>${escapeHtml(JSON.stringify(dep, null, 2))}</pre>`;
  document.getElementById("inspector-body").innerHTML = html;
  card.style.display = "block";
}

async function purgeQuarantine() {
  const res = await api("/api/purge", { method: "POST", body: "{}" });
  const card = document.getElementById("inspector-card");
  document.getElementById("inspector-title").textContent = "Quarantine Purge";
  document.getElementById("inspector-body").innerHTML = `<p class="toast ok">Purged ${res.count} quarantined table(s).</p><pre>${escapeHtml(JSON.stringify(res, null, 2))}</pre>`;
  card.style.display = "block";
}

async function reverseTx(txId, dryRun, force, cascade = false) {
  const res = await api(`/api/reverse/${txId}`, {
    method: "POST",
    body: JSON.stringify({ dry_run: dryRun, force, cascade }),
  });
  const card = document.getElementById("inspector-card");
  document.getElementById("inspector-title").textContent = dryRun
    ? `Dry Run Plan for ${txId}`
    : `Reverse Result for ${txId}`;
  let html = "";
  if (!res.success && res.conflicts && res.conflicts.length) {
    html += `<p class="toast err">${escapeHtml(res.error || "Drift detected")}</p>`;
    html += `<div class="actions" style="margin-bottom:8px;">
      <button class="primary" onclick="reverseTx('${txId}', false, false, true)">Cascade Reverse (Unwind Dependents)</button>
      <button class="warn" onclick="reverseTx('${txId}', false, true, false)">Force Reverse (Override Drift)</button>
    </div>`;
  } else if (!res.success) {
    html += `<p class="toast err">${escapeHtml(res.error || "Failed")}</p>`;
  } else {
    html += `<p class="toast ok">${dryRun ? "Dry run ready" : "Reversed successfully"} (${res.reversed_rows} step(s))</p>`;
  }
  html += `<pre>${escapeHtml(JSON.stringify(res, null, 2))}</pre>`;
  document.getElementById("inspector-body").innerHTML = html;
  card.style.display = "block";
  loadStatus();
  loadHistory();
}

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

loadStatus();
loadHistory();
</script>
</body>
</html>
"""


class ControlPlaneServer:
    """Thread-safe HTTP/HTTPS JSON API & Web UI for inspecting, ingesting CDC, and reversing transactions."""

    def __init__(
        self,
        engine: ReverseProxyEngine,
        *,
        host: str = "127.0.0.1",
        port: int = 8080,
        pg_port: int | None = None,
        mysql_port: int | None = None,
        engine_lock: threading.RLock | None = None,
        ssl_context: ssl.SSLContext | None = None,
        wal_health_fn: Callable[[], dict[str, Any]] | None = None,
        auth_users: dict[str, str] | None = None,
    ) -> None:
        self.engine = engine
        self.host = host
        self.port = port
        self.pg_port = pg_port
        self.mysql_port = mysql_port
        self.ssl_context = ssl_context
        self.wal_health_fn = wal_health_fn
        self.auth_users = auth_users
        self._lock = engine_lock or threading.RLock()
        self._cdc = CDCIngestor(engine.ledger, engine.driver.engine_type)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_port = port

    @property
    def bound_port(self) -> int:
        return self._bound_port

    def start(self) -> None:
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _send_json(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(_json_safe(payload)).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0:
                    return {}
                raw = self.rfile.read(length)
                return json.loads(raw.decode("utf-8"))

            def _check_auth(self) -> str | None:
                if not parent.auth_users:
                    return "web_ui"
                auth_hdr = self.headers.get("Authorization", "")
                if auth_hdr.startswith("Basic "):
                    try:
                        raw = base64.b64decode(auth_hdr[6:].strip()).decode("utf-8")
                        if ":" in raw:
                            user, pw = raw.split(":", 1)
                            expected = parent.auth_users.get(user)
                            if expected is not None and hmac.compare_digest(pw, expected):
                                return user
                    except Exception:
                        pass
                body = json.dumps({"error": "Authentication required"}).encode("utf-8")
                self.send_response(HTTPStatus.UNAUTHORIZED)
                self.send_header("WWW-Authenticate", 'Basic realm="sql-reverse-proxy"')
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return None

            def do_GET(self) -> None:  # noqa: N802
                if self._check_auth() is None:
                    return
                parsed = urlparse(self.path)
                path = parsed.path

                if path == "/":
                    body = _HTML_PAGE.encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if path == "/api/status":
                    with parent._lock:
                        count = len(parent.engine.history(limit=10000))
                    status_payload: dict[str, Any] = {
                        "engine": parent.engine.driver.engine_type.value,
                        "records_count": count,
                        "pg_port": parent.pg_port,
                        "mysql_port": parent.mysql_port,
                        "tls": parent.ssl_context is not None,
                    }
                    if parent.wal_health_fn is not None:
                        try:
                            status_payload["wal_slot"] = parent.wal_health_fn()
                        except Exception as exc:
                            status_payload["wal_slot"] = {"error": str(exc)}
                    self._send_json(HTTPStatus.OK, status_payload)
                    return

                if path == "/api/history":
                    qs = parse_qs(parsed.query)
                    limit = int(qs.get("limit", ["50"])[0])
                    q_filter = qs.get("q", [""])[0].strip().lower()
                    actor_filter = qs.get("actor", [""])[0].strip().lower()
                    status_filter = qs.get("status", [""])[0].strip().lower()

                    with parent._lock:
                        records = parent.engine.history(limit=max(limit, 500) if (q_filter or actor_filter or status_filter) else limit)

                    filtered = []
                    for r in records:
                        if status_filter and r.status.value.lower() != status_filter:
                            continue
                        if actor_filter and actor_filter not in r.actor.lower():
                            continue
                        if q_filter and (q_filter not in r.tx_id.lower() and q_filter not in r.raw_sql.lower()):
                            continue
                        filtered.append(r)
                        if len(filtered) >= limit:
                            break

                    payload = [
                        {
                            "tx_id": r.tx_id,
                            "seq_no": r.seq_no,
                            "created_at": r.created_at,
                            "engine": r.engine.value,
                            "session_id": r.session_id,
                            "actor": r.actor,
                            "status": r.status.value,
                            "durability": r.durability,
                            "raw_sql": r.raw_sql,
                            "warnings": r.warnings,
                            "reversed_at": r.reversed_at,
                            "rows_affected": (
                                r.rows_affected
                                if r.rows_affected is not None
                                else sum(
                                    max(
                                        len(op.before_rows),
                                        len(op.after_rows),
                                        1 if op.op_type.startswith(("QUARANTINE_", "ALTER_")) else 0,
                                    )
                                    for op in r.ops
                                )
                            ),
                        }
                        for r in filtered
                    ]
                    self._send_json(HTTPStatus.OK, {"records": payload})
                    return

                if path == "/api/export":
                    qs = parse_qs(parsed.query)
                    fmt = qs.get("format", ["json"])[0].lower()
                    limit = int(qs.get("limit", ["5000"])[0])
                    with parent._lock:
                        records = parent.engine.history(limit=limit)
                    if fmt == "csv":
                        buf = io.StringIO()
                        writer = csv.writer(buf)
                        writer.writerow(
                            ["tx_id", "seq_no", "created_at", "engine", "actor", "status", "rows_affected", "reversed_at", "raw_sql"]
                        )
                        for r in records:
                            writer.writerow(
                                [
                                    r.tx_id,
                                    r.seq_no,
                                    r.created_at,
                                    r.engine.value,
                                    r.actor,
                                    r.status.value,
                                    r.rows_affected or 0,
                                    r.reversed_at or "",
                                    r.raw_sql,
                                ]
                            )
                        body = buf.getvalue().encode("utf-8")
                        self.send_response(HTTPStatus.OK)
                        self.send_header("Content-Type", "text/csv; charset=utf-8")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return

                    export_payload = [
                        {
                            "tx_id": r.tx_id,
                            "seq_no": r.seq_no,
                            "created_at": r.created_at,
                            "engine": r.engine.value,
                            "actor": r.actor,
                            "status": r.status.value,
                            "rows_affected": r.rows_affected or 0,
                            "reversed_at": r.reversed_at,
                            "raw_sql": r.raw_sql,
                        }
                        for r in records
                    ]
                    self._send_json(HTTPStatus.OK, {"records": export_payload})
                    return

                if path.startswith("/api/diff/"):
                    tx_id = path[len("/api/diff/") :]
                    qs = parse_qs(parsed.query)
                    offset = max(0, int(qs.get("offset", ["0"])[0]))
                    limit = max(1, min(1000, int(qs.get("limit", ["100"])[0])))
                    with parent._lock:
                        rec = parent.engine.diff(tx_id)
                    if rec is None:
                        self._send_json(
                            HTTPStatus.NOT_FOUND, {"error": f"Transaction '{tx_id}' not found."}
                        )
                        return
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "tx_id": rec.tx_id,
                            "actor": rec.actor,
                            "status": rec.status.value,
                            "raw_sql": rec.raw_sql,
                            "warnings": rec.warnings,
                            "offset": offset,
                            "limit": limit,
                            "ops": [
                                {
                                    "op_type": op.op_type,
                                    "table": op.table,
                                    "schema": op.schema,
                                    "pk_columns": op.pk_columns,
                                    "total_before_rows": len(op.before_rows),
                                    "total_after_rows": len(op.after_rows),
                                    "before_rows": op.before_rows[offset : offset + limit],
                                    "after_rows": op.after_rows[offset : offset + limit],
                                    "quarantine_name": op.quarantine_name,
                                }
                                for op in rec.ops
                            ],
                        },
                    )
                    return

                if path.startswith("/api/dependencies/"):
                    tx_id = path[len("/api/dependencies/") :]
                    try:
                        with parent._lock:
                            plan = parent.engine.analyze_dependencies(tx_id)
                        self._send_json(
                            HTTPStatus.OK,
                            {
                                "root_tx_id": plan.root_tx_id,
                                "ordered_tx_ids": plan.ordered_tx_ids,
                                "reasons": [
                                    {
                                        "tx_id": r.tx_id,
                                        "depends_on_tx_id": r.depends_on_tx_id,
                                        "kind": r.kind,
                                        "detail": r.detail,
                                    }
                                    for r in plan.reasons
                                ],
                            },
                        )
                    except ValueError as exc:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

            def do_POST(self) -> None:  # noqa: N802
                auth_actor = self._check_auth()
                if auth_actor is None:
                    return
                parsed = urlparse(self.path)
                path = parsed.path

                if path.startswith("/api/reverse/"):
                    tx_id = path[len("/api/reverse/") :]
                    body = self._read_json()
                    dry_run = bool(body.get("dry_run", False))
                    force = bool(body.get("force", False))
                    cascade = bool(body.get("cascade", False))
                    with parent._lock:
                        res = parent.engine.reverse(
                            tx_id, dry_run=dry_run, force=force, cascade=cascade
                        )
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "tx_id": res.tx_id,
                            "success": res.success,
                            "dry_run": res.dry_run,
                            "reversed_rows": res.reversed_rows,
                            "reverse_tx_id": res.reverse_tx_id,
                            "cascaded_tx_ids": res.cascaded_tx_ids,
                            "error": res.error,
                            "steps": [
                                {
                                    "description": s.description,
                                    "sql": s.sql,
                                    "params": s.params,
                                }
                                for s in res.steps
                            ],
                            "conflicts": [
                                {
                                    "table": c.table,
                                    "pk": c.pk,
                                    "column": c.column,
                                    "expected_after": c.expected_after,
                                    "actual_current": c.actual_current,
                                    "row_missing": c.row_missing,
                                    "reason": c.reason,
                                }
                                for c in res.conflicts
                            ],
                        },
                    )
                    return

                if path == "/api/purge":
                    with parent._lock:
                        purged = parent.engine.purge_quarantine(actor=auth_actor)
                    self._send_json(HTTPStatus.OK, {"purged": purged, "count": len(purged)})
                    return

                if path == "/api/cdc/event":
                    body = self._read_json()
                    with parent._lock:
                        parent._cdc.ingest_debezium_envelope(body)
                    self._send_json(HTTPStatus.OK, {"accepted": True})
                    return

                if path.startswith("/api/cdc/commit/"):
                    tx_id = path[len("/api/cdc/commit/") :]
                    with parent._lock:
                        rec = parent._cdc.commit_tx(tx_id)
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "committed": rec is not None,
                            "tx_id": rec.tx_id if rec else tx_id,
                            "ops_count": len(rec.ops) if rec else 0,
                        },
                    )
                    return

                if path.startswith("/api/cdc/rollback/"):
                    tx_id = path[len("/api/cdc/rollback/") :]
                    with parent._lock:
                        parent._cdc.rollback_tx(tx_id)
                    self._send_json(HTTPStatus.OK, {"rolled_back": True, "tx_id": tx_id})
                    return

                if path == "/api/query":
                    body = self._read_json()
                    sql = str(body.get("sql", ""))
                    session_id = str(body.get("session_id", "web_ui"))
                    try:
                        with parent._lock:
                            parent.engine.set_session_actor(session_id, auth_actor)
                            results = parent.engine.execute(sql, session_id=session_id)
                        last = results[-1] if results else None
                        self._send_json(
                            HTTPStatus.OK,
                            {
                                "columns": last.columns if last else [],
                                "rows": last.rows if last else [],
                                "rowcount": last.rowcount if last else 0,
                                "command_tag": last.command_tag if last else "EMPTY",
                                "tx_id": last.tx_id if last else None,
                                "warnings": last.warnings if last else [],
                            },
                        )
                    except Exception as exc:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        if self.ssl_context is not None:
            self._httpd.socket = self.ssl_context.wrap_socket(
                self._httpd.socket, server_side=True
            )
        self._bound_port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
