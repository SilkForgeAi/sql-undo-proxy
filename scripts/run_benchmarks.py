#!/usr/bin/env python3
"""Reproducible end-to-end 1,000,000-row benchmark & README table generator.

Runs fresh benchmarks across PostgreSQL 16, PostgreSQL 18 (native RETURNING OLD/NEW),
MySQL 8.0, and MariaDB 11 (mariadb-binlog --flashback):
  - Measures both pre-spill undo (in-DB `_side_*` snapshot table, `restore_path="side_table"`)
    and post-spill undo (from compressed disk spill file via temp table + set-based join,
    `restore_path="spilled_temp_table"`).
  - Records per-phase timings (`blast_radius_check_s`, `side_table_create_s`,
    `snapshot_capture_s`, `dml_exec_s`, `commit_s`, `spill_s`) in the timestamped JSON.
  - Verifies SHA-256 row hash after every restore and asserts 0 leftover `_side_*` tables.
  - Regenerates the benchmark tables in README.md directly from the JSON artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_DIR))

from reverse_proxy.drivers.mysql_client import MySQLWireClient
from reverse_proxy.drivers.pgwire_client import PgError, PgWireClient

TSV_PATH = REPO_DIR / "benchmark_data" / "ratings_1m.tsv"
BENCH_DIR = REPO_DIR / "benchmarks"
README_PATH = REPO_DIR / "README.md"
ENV = {**os.environ, "PATH": "/usr/local/bin:/opt/homebrew/bin:" + os.environ.get("PATH", "")}


def compute_source_tree_sha256() -> str:
    h = hashlib.sha256()
    paths: list[Path] = []
    for sub in ("reverse_proxy", "scripts"):
        d = REPO_DIR / sub
        if d.exists():
            paths.extend(sorted(p for p in d.rglob("*.py") if "__pycache__" not in p.parts))
    for name in ("pyproject.toml", "Dockerfile", "docker-compose.yml"):
        p = REPO_DIR / name
        if p.exists():
            paths.append(p)
    for p in sorted(set(paths)):
        rel = p.relative_to(REPO_DIR).as_posix()
        h.update(rel.encode("utf-8") + b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def get_git_commit() -> str | None:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(REPO_DIR),
        env=ENV,
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        return proc.stdout.strip()
    return None


def inspect_image(image_ref: str) -> dict[str, Any]:
    proc = subprocess.run(
        ["docker", "image", "inspect", image_ref],
        cwd=str(REPO_DIR),
        env=ENV,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return {"ref": image_ref, "error": proc.stderr.strip()}
    data = json.loads(proc.stdout)[0]
    return {
        "ref": image_ref,
        "id": data.get("Id"),
        "repo_digests": data.get("RepoDigests") or [],
    }


def load_tsv(limit: int = 1_000_000) -> list[tuple[str, float, int]]:
    rows: list[tuple[str, float, int]] = []
    with TSV_PATH.open("r", encoding="utf-8") as f:
        header = f.readline()
        if not header.startswith("tconst"):
            f.seek(0)
        for line in f:
            p = line.rstrip("\n").split("\t")
            rows.append((p[0], float(p[1]), int(p[2])))
            if len(rows) >= limit:
                break
    return rows


def hash_rows(rows: list[tuple[Any, ...]]) -> str:
    h = hashlib.sha256()
    for tconst, avg, votes in rows:
        h.update(f"{tconst}|{float(avg):.2f}|{int(votes)}\n".encode("utf-8"))
    return h.hexdigest()


def extract_restore_path(step_desc: str) -> str:
    if "[side_table]" in step_desc:
        return "side_table"
    if "[spilled_temp_table]" in step_desc:
        return "spilled_temp_table"
    return "row_batched"


def extract_phase_timings_from_diff_rows(rows: list[tuple[Any, ...]]) -> dict[str, float]:
    if not rows:
        return {}
    last_after = str(rows[-1][4]) if len(rows[-1]) >= 5 else "{}"
    try:
        parsed = json.loads(last_after)
        if isinstance(parsed, dict) and isinstance(parsed.get("phase_timings"), dict):
            return {str(k): round(float(v), 4) for k, v in parsed["phase_timings"].items()}
    except Exception:
        pass
    return {}


def run_compose(args: list[str], extra_env: dict[str, str] | None = None) -> None:
    env = {**ENV, **(extra_env or {})}
    subprocess.run(
        ["docker", "compose", *args],
        cwd=str(REPO_DIR),
        env=env,
        check=True,
    )


def pg_exec(sql: str, *, container: str = "", compose_service: str = "postgres", db: str = "app") -> str:
    if container:
        cmd = ["docker", "exec", "-i", container, "psql", "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-tAc", sql]
    else:
        cmd = ["docker", "compose", "exec", "-T", compose_service, "psql", "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", "-tAc", sql]
    return subprocess.run(cmd, cwd=str(REPO_DIR), env=ENV, capture_output=True, text=True, check=True).stdout.strip()


def pg_advance_slot_if_exists(*, container: str = "", compose_service: str = "postgres", slot: str = "reverse_proxy_slot") -> None:
    sql = (
        f"SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = '{slot}' AND NOT active) "
        f"THEN pg_replication_slot_advance('{slot}', pg_current_wal_lsn())::text ELSE 'skip' END;"
    )
    try:
        pg_exec(sql, container=container, compose_service=compose_service)
    except Exception:
        pass


def pg_seed(tsv_rows: list[tuple[str, float, int]], *, container: str = "", compose_service: str = "postgres") -> None:
    pg_exec(
        "DROP TABLE IF EXISTS imdb_ratings CASCADE; "
        "CREATE TABLE imdb_ratings (tconst VARCHAR(16) PRIMARY KEY, average_rating DOUBLE PRECISION, num_votes INTEGER);",
        container=container,
        compose_service=compose_service,
    )
    payload = "".join(f"{t}\t{a}\t{v}\n" for t, a, v in tsv_rows).encode("utf-8")
    if container:
        cmd = ["docker", "exec", "-i", container, "psql", "-U", "postgres", "-d", "app", "-c", "\\copy imdb_ratings (tconst, average_rating, num_votes) FROM STDIN WITH (FORMAT text, DELIMITER E'\\t')"]
    else:
        cmd = ["docker", "compose", "exec", "-T", compose_service, "psql", "-U", "postgres", "-d", "app", "-c", "\\copy imdb_ratings (tconst, average_rating, num_votes) FROM STDIN WITH (FORMAT text, DELIMITER E'\\t')"]
    subprocess.run(cmd, input=payload, cwd=str(REPO_DIR), env=ENV, capture_output=True, check=True)
    pg_advance_slot_if_exists(container=container, compose_service=compose_service)


def pg_hash(*, container: str = "", compose_service: str = "postgres") -> str:
    if container:
        cmd = ["docker", "exec", "-i", container, "psql", "-U", "postgres", "-d", "app", "-c", "\\copy (SELECT tconst, average_rating, num_votes FROM imdb_ratings WHERE tconst LIKE 'tt%' ORDER BY tconst) TO STDOUT"]
    else:
        cmd = ["docker", "compose", "exec", "-T", compose_service, "psql", "-U", "postgres", "-d", "app", "-c", "\\copy (SELECT tconst, average_rating, num_votes FROM imdb_ratings WHERE tconst LIKE 'tt%' ORDER BY tconst) TO STDOUT"]
    proc = subprocess.Popen(cmd, cwd=str(REPO_DIR), env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None
    h = hashlib.sha256()
    cnt = 0
    for line in proc.stdout:
        parts = line.decode("utf-8").rstrip("\n").split("\t")
        h.update(f"{parts[0]}|{float(parts[1]):.2f}|{int(parts[2])}\n".encode("utf-8"))
        cnt += 1
    assert proc.wait() == 0
    assert cnt == 1_000_000, f"PG expected 1M rows, got {cnt}"
    return h.hexdigest()


def pg_direct_timed(sql: str, *, host: str = "127.0.0.1", port: int = 5432, inside_service: str = "proxy-postgres") -> float:
    if inside_service:
        py = (
            "import time; from reverse_proxy.drivers.pgwire_client import PgWireClient; "
            f"c=PgWireClient(host={host!r}, port={port}, user='postgres', password='pgpassword', database='app', timeout=600.0); "
            f"t0=time.perf_counter(); c.query({sql!r}); dt=time.perf_counter()-t0; c.close(); print(f'{{dt:.4f}}')"
        )
        out = subprocess.run(
            ["docker", "compose", "exec", "-T", inside_service, "python", "-c", py],
            cwd=str(REPO_DIR), env=ENV, capture_output=True, text=True, check=True,
        ).stdout.strip()
        return float(out.splitlines()[-1])
    c = PgWireClient(host=host, port=port, user="postgres", password="pgpassword", database="app", timeout=600.0)
    try:
        t0 = time.perf_counter()
        c.query(sql)
        return time.perf_counter() - t0
    finally:
        c.close()


def wait_pg_side_drain(*, container: str = "", compose_service: str = "postgres", timeout: float = 180.0) -> tuple[int, float]:
    t0 = time.perf_counter()
    rem = -1
    while time.perf_counter() - t0 < timeout:
        rem = int(
            pg_exec(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='_reverse_quarantine' AND table_name LIKE '_side_%';",
                container=container,
                compose_service=compose_service,
            )
        )
        if rem == 0:
            break
        time.sleep(0.25)
    return rem, round(time.perf_counter() - t0, 3)


def bench_postgres_16(tsv_rows: list[tuple[str, float, int]], canonical_hash: str) -> dict[str, Any]:
    print("\n=== [1/5] PostgreSQL 16 (Direct Baseline + Pre-Spill & Post-Spill Undo + Phase Timings) ===", flush=True)
    version = pg_exec("SELECT version();")

    # 1. Direct Baselines
    pg_seed(tsv_rows)
    b_upd = pg_direct_timed("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;", host="postgres", port=5432, inside_service="proxy-postgres")
    b_del = pg_direct_timed("DELETE FROM imdb_ratings;", host="postgres", port=5432, inside_service="proxy-postgres")
    pg_seed(tsv_rows)
    b_trunc = pg_direct_timed("TRUNCATE TABLE imdb_ratings;", host="postgres", port=5432, inside_service="proxy-postgres")
    pg_seed(tsv_rows)
    b_dcol = pg_direct_timed("ALTER TABLE imdb_ratings DROP COLUMN num_votes;", host="postgres", port=5432, inside_service="proxy-postgres")
    b_dtbl = pg_direct_timed("DROP TABLE imdb_ratings;", host="postgres", port=5432, inside_service="proxy-postgres")
    print(
        f"[PG16 Direct] DROP={b_dtbl:.3f}s | TRUNCATE={b_trunc:.3f}s | DROP_COL={b_dcol:.3f}s | 1M_UPD={b_upd:.2f}s | 1M_DEL={b_del:.2f}s",
        flush=True,
    )

    # 2. Proxy Operations
    pg_exec("DROP SCHEMA IF EXISTS _reverse_quarantine CASCADE;")
    pg_seed(tsv_rows)
    assert pg_hash() == canonical_hash

    proxy = PgWireClient(host="127.0.0.1", port=5433, user="postgres", password="pgpassword", database="app", timeout=600.0)
    try:
        # Drain any pending WAL on proxy before starting timed tests
        proxy.query("PROXY HISTORY 5;")

        # Live BEGIN; UPDATE; ROLLBACK check
        hist_before = proxy.query("PROXY HISTORY 25;")[0].rows
        proxy.query("BEGIN;")
        proxy.query("UPDATE imdb_ratings SET average_rating = -99.0 WHERE tconst = 'tt0000001';")
        proxy.query("ROLLBACK;")
        hist_after = proxy.query("PROXY HISTORY 25;")[0].rows
        assert len(hist_after) == len(hist_before), "PG ROLLBACK unexpectedly wrote to ledger!"
        assert pg_hash() == canonical_hash, "PG ROLLBACK altered table rows!"
        pg_rollback_ok = True

        # DROP TABLE
        t0 = time.perf_counter()
        proxy.query("DROP TABLE imdb_ratings;")
        p_dtbl_f = time.perf_counter() - t0
        tx_dtbl = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "DROP TABLE imdb_ratings" in str(r[6]))
        t0 = time.perf_counter()
        assert proxy.query(f"PROXY REVERSE {tx_dtbl};")[0].command_tag == "PROXY REVERSE OK"
        p_dtbl_u = time.perf_counter() - t0
        assert pg_hash() == canonical_hash

        # TRUNCATE TABLE
        t0 = time.perf_counter()
        proxy.query("TRUNCATE TABLE imdb_ratings;")
        p_trunc_f = time.perf_counter() - t0
        tx_trunc = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "TRUNCATE TABLE imdb_ratings" in str(r[6]))
        t0 = time.perf_counter()
        assert proxy.query(f"PROXY REVERSE {tx_trunc};")[0].command_tag == "PROXY REVERSE OK"
        p_trunc_u = time.perf_counter() - t0
        assert pg_hash() == canonical_hash

        # ALTER DROP COLUMN
        t0 = time.perf_counter()
        proxy.query("ALTER TABLE imdb_ratings DROP COLUMN num_votes;")
        p_dcol_f = time.perf_counter() - t0
        tx_dcol = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "DROP COLUMN num_votes" in str(r[6]))
        t0 = time.perf_counter()
        assert proxy.query(f"PROXY REVERSE {tx_dcol};")[0].command_tag == "PROXY REVERSE OK"
        p_dcol_u = time.perf_counter() - t0
        assert pg_hash() == canonical_hash

        # 1M UPDATE (A) Pre-spill undo (`side_table`) + concurrent disjoint writers
        t0 = time.perf_counter()
        proxy.query("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;")
        p_upd_f = time.perf_counter() - t0
        tx_upd_pre = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "UPDATE imdb_ratings SET average_rating" in str(r[6]))

        stop_flag = threading.Event()
        latencies: list[float] = []
        errors: list[str] = []

        def writer_pg(tid: int) -> None:
            c = PgWireClient(host="127.0.0.1", port=5433, user="postgres", password="pgpassword", database="app", timeout=120.0)
            try:
                i = 0
                while not stop_flag.is_set() and i < 20:
                    w0 = time.perf_counter()
                    c.query(f"INSERT INTO imdb_ratings VALUES ('zz_conc_{tid}_{i}', 9.9, 1);")
                    latencies.append(time.perf_counter() - w0)
                    i += 1
                    time.sleep(0.05)
            except Exception as exc:
                errors.append(str(exc))
            finally:
                c.close()

        threads = [threading.Thread(target=writer_pg, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.05)
        t0 = time.perf_counter()
        rev_u_pre = proxy.query(f"PROXY REVERSE {tx_upd_pre};")[0]
        p_upd_u_pre = time.perf_counter() - t0
        stop_flag.set()
        for t in threads:
            t.join()
        assert rev_u_pre.command_tag == "PROXY REVERSE OK", rev_u_pre
        upd_pre_path = extract_restore_path(str(rev_u_pre.rows[0][1]))
        assert upd_pre_path == "side_table", f"Expected side_table pre-spill path, got {upd_pre_path}: {rev_u_pre.rows[0][1]}"
        assert not errors, f"PG writer errors: {errors}"
        assert pg_hash() == canonical_hash
        pg_exec("DELETE FROM imdb_ratings WHERE tconst LIKE 'zz_conc_%';")
        # Drain spill of tx_upd_pre before next test so background spill doesn't overlap
        proxy.query(f"PROXY DIFF {tx_upd_pre};")

        # 1M UPDATE (B) Post-spill undo (`spilled_temp_table`) + Phase Timings
        proxy.query("UPDATE imdb_ratings SET average_rating = average_rating + 2.0;")
        tx_upd_post = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "average_rating + 2.0" in str(r[6]))
        diff_u_rows = proxy.query(f"PROXY DIFF {tx_upd_post};")[0].rows
        upd_phases = extract_phase_timings_from_diff_rows(diff_u_rows)
        rem_after_u_spill, _ = wait_pg_side_drain(timeout=30.0)
        assert rem_after_u_spill == 0, f"Expected 0 _side_* tables before post-spill UPDATE undo, got {rem_after_u_spill}"
        t0 = time.perf_counter()
        rev_u_post = proxy.query(f"PROXY REVERSE {tx_upd_post};")[0]
        p_upd_u_post = time.perf_counter() - t0
        assert rev_u_post.command_tag == "PROXY REVERSE OK", rev_u_post
        upd_post_path = extract_restore_path(str(rev_u_post.rows[0][1]))
        assert upd_post_path == "spilled_temp_table", f"Expected spilled_temp_table post-spill path, got {upd_post_path}"
        assert pg_hash() == canonical_hash

        # 1M DELETE (A) Pre-spill undo (`side_table`)
        t0 = time.perf_counter()
        proxy.query("DELETE FROM imdb_ratings;")
        p_del_f = time.perf_counter() - t0
        tx_del_pre = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if str(r[6]).startswith("DELETE FROM imdb_ratings"))
        t0 = time.perf_counter()
        rev_d_pre = proxy.query(f"PROXY REVERSE {tx_del_pre};")[0]
        p_del_u_pre = time.perf_counter() - t0
        assert rev_d_pre.command_tag == "PROXY REVERSE OK", rev_d_pre
        del_pre_path = extract_restore_path(str(rev_d_pre.rows[0][1]))
        assert del_pre_path == "side_table", f"Expected side_table pre-spill path, got {del_pre_path}"
        assert pg_hash() == canonical_hash
        diff_d_rows = proxy.query(f"PROXY DIFF {tx_del_pre};")[0].rows
        del_phases = extract_phase_timings_from_diff_rows(diff_d_rows)

        # 1M DELETE (B) Post-spill undo (`spilled_temp_table`)
        proxy.query("DELETE FROM imdb_ratings WHERE tconst LIKE 'tt%';")
        tx_del_post = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "DELETE FROM imdb_ratings WHERE tconst LIKE" in str(r[6]))
        proxy.query(f"PROXY DIFF {tx_del_post};")
        rem_after_d_spill, _ = wait_pg_side_drain(timeout=30.0)
        assert rem_after_d_spill == 0
        t0 = time.perf_counter()
        rev_d_post = proxy.query(f"PROXY REVERSE {tx_del_post};")[0]
        p_del_u_post = time.perf_counter() - t0
        assert rev_d_post.command_tag == "PROXY REVERSE OK", rev_d_post
        del_post_path = extract_restore_path(str(rev_d_post.rows[0][1]))
        assert del_post_path == "spilled_temp_table", f"Expected spilled_temp_table post-spill path, got {del_post_path}"
        assert pg_hash() == canonical_hash

        rem, drain_s = wait_pg_side_drain(timeout=180.0)
        assert rem == 0, f"PG16 left {rem} orphaned _side_* tables!"
        print(
            f"[PG16 Proxy] 1M_UPD={p_upd_f:.2f}s (undo pre={p_upd_u_pre:.2f}s [{upd_pre_path}], post={p_upd_u_post:.2f}s [{upd_post_path}]) | "
            f"1M_DEL={p_del_f:.2f}s (undo pre={p_del_u_pre:.2f}s [{del_pre_path}], post={p_del_u_post:.2f}s [{del_post_path}]) | "
            f"conc({len(latencies)} writes, max={max(latencies):.3f}s) | side_rem={rem}",
            flush=True,
        )
        pg_exec("DROP TABLE IF EXISTS imdb_ratings CASCADE;")
    finally:
        proxy.close()

    return {
        "server_version": version,
        "rollback_test_passed": pg_rollback_ok,
        "direct_baseline": {
            "drop_table_s": round(b_dtbl, 3),
            "truncate_s": round(b_trunc, 3),
            "drop_column_s": round(b_dcol, 3),
            "update_1m_s": round(b_upd, 2),
            "delete_1m_s": round(b_del, 2),
        },
        "proxy": {
            "drop_table_write_s": round(p_dtbl_f, 3),
            "drop_table_undo_s": round(p_dtbl_u, 3),
            "truncate_write_s": round(p_trunc_f, 3),
            "truncate_undo_s": round(p_trunc_u, 3),
            "drop_column_write_s": round(p_dcol_f, 3),
            "drop_column_undo_s": round(p_dcol_u, 3),
            "update_1m_write_s": round(p_upd_f, 2),
            "update_1m_undo_pre_spill_s": round(p_upd_u_pre, 2),
            "update_1m_undo_pre_spill_path": upd_pre_path,
            "update_1m_undo_post_spill_s": round(p_upd_u_post, 2),
            "update_1m_undo_post_spill_path": upd_post_path,
            "update_1m_phase_timings_s": upd_phases,
            "delete_1m_write_s": round(p_del_f, 2),
            "delete_1m_undo_pre_spill_s": round(p_del_u_pre, 2),
            "delete_1m_undo_pre_spill_path": del_pre_path,
            "delete_1m_undo_post_spill_s": round(p_del_u_post, 2),
            "delete_1m_undo_post_spill_path": del_post_path,
            "delete_1m_phase_timings_s": del_phases,
            "remaining_side_tables_after_drain": rem,
            "spill_drain_s": drain_s,
            "sha256_verified": True,
        },
        "concurrency_during_1m_update_undo": {
            "threads": 4,
            "writes_completed": len(latencies),
            "errors": len(errors),
            "max_wait_s": round(max(latencies) if latencies else 0.0, 3),
            "avg_wait_s": round(sum(latencies) / len(latencies) if latencies else 0.0, 3),
            "key_pattern": "zz_conc_<tid>_<i> (disjoint inserts)",
        },
    }


def bench_postgres_18(tsv_rows: list[tuple[str, float, int]], canonical_hash: str) -> dict[str, Any]:
    print("\n=== [2/5] PostgreSQL 18 (Native RETURNING OLD, NEW + Pre-Spill & Post-Spill Undo) ===", flush=True)
    cname = "revproxy_pg18_bench"
    subprocess.run(["docker", "rm", "-f", cname], env=ENV, capture_output=True)
    subprocess.run(
        [
            "docker", "run", "-d", "--name", cname,
            "-e", "POSTGRES_USER=postgres",
            "-e", "POSTGRES_PASSWORD=pgpassword",
            "-e", "POSTGRES_DB=app",
            "-p", "15432:5432",
            "postgres:18",
        ],
        env=ENV, check=True, capture_output=True,
    )
    proxy_proc: subprocess.Popen[bytes] | None = None
    tmp_dir = tempfile.TemporaryDirectory()
    try:
        for _ in range(40):
            r = subprocess.run(["docker", "exec", cname, "pg_isready", "-U", "postgres"], env=ENV, capture_output=True)
            if r.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("PG18 container did not become ready")

        version = pg_exec("SELECT version();", container=cname)

        # Direct baselines on PG18
        pg_seed(tsv_rows, container=cname)
        b_upd = pg_direct_timed("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;", host="127.0.0.1", port=15432, inside_service="")
        b_del = pg_direct_timed("DELETE FROM imdb_ratings;", host="127.0.0.1", port=15432, inside_service="")

        # Start sql-reverse-proxy targeting PG18
        pg_seed(tsv_rows, container=cname)
        assert pg_hash(container=cname) == canonical_hash
        ledger_path = os.path.join(tmp_dir.name, "pg18_ledger.db")
        proxy_proc = subprocess.Popen(
            [
                sys.executable, "-m", "reverse_proxy.cli",
                "--engine", "postgres",
                "--backend-host", "127.0.0.1",
                "--backend-port", "15432",
                "--backend-user", "postgres",
                "--backend-password", "pgpassword",
                "--backend-db", "app",
                "--ledger-path", ledger_path,
                "--pg-port", "15433",
                "--mysql-port", "0",
                "--ui-port", "0",
                "--max-capture-rows", "2000000",
            ],
            cwd=str(REPO_DIR),
            env=ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(40):
            try:
                c = PgWireClient(host="127.0.0.1", port=15433, user="postgres", password="pgpassword", database="app", timeout=600.0)
                c.query("SELECT 1;")
                break
            except Exception:
                time.sleep(0.25)
        else:
            raise RuntimeError("Local PG18 proxy failed to start")

        try:
            # 1M UPDATE (A) Pre-spill undo (`side_table`)
            t0 = time.perf_counter()
            c.query("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;")
            p_upd_f = time.perf_counter() - t0
            tx_upd_pre = next(r[0] for r in c.query("PROXY HISTORY 10;")[0].rows if "average_rating + 1.0" in str(r[6]))
            t0 = time.perf_counter()
            rev_u_pre = c.query(f"PROXY REVERSE {tx_upd_pre};")[0]
            p_upd_u_pre = time.perf_counter() - t0
            assert rev_u_pre.command_tag == "PROXY REVERSE OK", rev_u_pre
            upd_pre_path = extract_restore_path(str(rev_u_pre.rows[0][1]))
            assert upd_pre_path == "side_table", upd_pre_path
            assert pg_hash(container=cname) == canonical_hash
            diff_u_rows = c.query(f"PROXY DIFF {tx_upd_pre};")[0].rows
            upd_phases = extract_phase_timings_from_diff_rows(diff_u_rows)

            # 1M UPDATE (B) Post-spill undo (`spilled_temp_table`)
            c.query("UPDATE imdb_ratings SET average_rating = average_rating + 2.0;")
            tx_upd_post = next(r[0] for r in c.query("PROXY HISTORY 10;")[0].rows if "average_rating + 2.0" in str(r[6]))
            c.query(f"PROXY DIFF {tx_upd_post};")
            t0 = time.perf_counter()
            rev_u_post = c.query(f"PROXY REVERSE {tx_upd_post};")[0]
            p_upd_u_post = time.perf_counter() - t0
            assert rev_u_post.command_tag == "PROXY REVERSE OK", rev_u_post
            upd_post_path = extract_restore_path(str(rev_u_post.rows[0][1]))
            assert upd_post_path == "spilled_temp_table", upd_post_path
            assert pg_hash(container=cname) == canonical_hash

            # 1M DELETE (A) Pre-spill undo (`side_table`)
            t0 = time.perf_counter()
            c.query("DELETE FROM imdb_ratings;")
            p_del_f = time.perf_counter() - t0
            tx_del_pre = next(r[0] for r in c.query("PROXY HISTORY 10;")[0].rows if str(r[6]).startswith("DELETE FROM imdb_ratings"))
            t0 = time.perf_counter()
            rev_d_pre = c.query(f"PROXY REVERSE {tx_del_pre};")[0]
            p_del_u_pre = time.perf_counter() - t0
            assert rev_d_pre.command_tag == "PROXY REVERSE OK", rev_d_pre
            del_pre_path = extract_restore_path(str(rev_d_pre.rows[0][1]))
            assert del_pre_path == "side_table", del_pre_path
            assert pg_hash(container=cname) == canonical_hash
            diff_d_rows = c.query(f"PROXY DIFF {tx_del_pre};")[0].rows
            del_phases = extract_phase_timings_from_diff_rows(diff_d_rows)

            # 1M DELETE (B) Post-spill undo (`spilled_temp_table`)
            c.query("DELETE FROM imdb_ratings WHERE tconst LIKE 'tt%';")
            tx_del_post = next(r[0] for r in c.query("PROXY HISTORY 10;")[0].rows if "DELETE FROM imdb_ratings WHERE tconst LIKE" in str(r[6]))
            c.query(f"PROXY DIFF {tx_del_post};")
            t0 = time.perf_counter()
            rev_d_post = c.query(f"PROXY REVERSE {tx_del_post};")[0]
            p_del_u_post = time.perf_counter() - t0
            assert rev_d_post.command_tag == "PROXY REVERSE OK", rev_d_post
            del_post_path = extract_restore_path(str(rev_d_post.rows[0][1]))
            assert del_post_path == "spilled_temp_table", del_post_path
            assert pg_hash(container=cname) == canonical_hash

            rem, drain_s = wait_pg_side_drain(container=cname, timeout=180.0)
            assert rem == 0, f"PG18 left {rem} orphaned _side_* tables!"
        finally:
            c.close()

        print(
            f"[PG18 RETURNING OLD/NEW] Direct: UPD={b_upd:.2f}s DEL={b_del:.2f}s | "
            f"Proxy: UPD={p_upd_f:.2f}s (pre={p_upd_u_pre:.2f}s, post={p_upd_u_post:.2f}s) | "
            f"DEL={p_del_f:.2f}s (pre={p_del_u_pre:.2f}s, post={p_del_u_post:.2f}s) | side_rem={rem}",
            flush=True,
        )
        return {
            "server_version": version,
            "direct_baseline": {
                "update_1m_s": round(b_upd, 2),
                "delete_1m_s": round(b_del, 2),
            },
            "proxy": {
                "update_1m_write_s": round(p_upd_f, 2),
                "update_1m_undo_pre_spill_s": round(p_upd_u_pre, 2),
                "update_1m_undo_pre_spill_path": upd_pre_path,
                "update_1m_undo_post_spill_s": round(p_upd_u_post, 2),
                "update_1m_undo_post_spill_path": upd_post_path,
                "update_1m_phase_timings_s": upd_phases,
                "delete_1m_write_s": round(p_del_f, 2),
                "delete_1m_undo_pre_spill_s": round(p_del_u_pre, 2),
                "delete_1m_undo_pre_spill_path": del_pre_path,
                "delete_1m_undo_post_spill_s": round(p_del_u_post, 2),
                "delete_1m_undo_post_spill_path": del_post_path,
                "delete_1m_phase_timings_s": del_phases,
                "remaining_side_tables_after_drain": rem,
                "spill_drain_s": drain_s,
                "sha256_verified": True,
            },
        }
    finally:
        if proxy_proc is not None:
            proxy_proc.terminate()
            try:
                proxy_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy_proc.kill()
        tmp_dir.cleanup()
        subprocess.run(["docker", "rm", "-f", cname], env=ENV, capture_output=True)


def bench_mysql_8(tsv_rows: list[tuple[str, float, int]], canonical_hash: str) -> dict[str, Any]:
    print("\n=== [3/5] MySQL 8.0 (Direct Baseline + Pre-Spill & Post-Spill Undo + Phase Timings) ===", flush=True)
    direct = MySQLWireClient(host="127.0.0.1", port=3306, user="root", password="mysqlpassword", database="app", timeout=600.0)
    proxy = MySQLWireClient(host="127.0.0.1", port=3307, user="root", password="mysqlpassword", database="app", timeout=600.0)

    def my_seed() -> None:
        direct.query("DROP TABLE IF EXISTS imdb_ratings;")
        direct.query("CREATE TABLE imdb_ratings (tconst VARCHAR(16) PRIMARY KEY, average_rating DOUBLE, num_votes INT);")
        for i in range(0, len(tsv_rows), 5000):
            chunk = tsv_rows[i : i + 5000]
            vals = ",".join(f"('{t}',{a},{v})" for t, a, v in chunk)
            direct.query(f"INSERT INTO imdb_ratings (tconst, average_rating, num_votes) VALUES {vals};")

    def my_hash() -> str:
        return hash_rows(direct.query("SELECT tconst, average_rating, num_votes FROM imdb_ratings WHERE tconst LIKE 'tt%' ORDER BY tconst;").rows)

    def my_direct_timed(sql: str) -> float:
        py = (
            "import time; from reverse_proxy.drivers.mysql_client import MySQLWireClient; "
            "c=MySQLWireClient(host='mysql', port=3306, user='root', password='mysqlpassword', database='app', timeout=600.0); "
            f"t0=time.perf_counter(); c.query({sql!r}); dt=time.perf_counter()-t0; c.close(); print(f'{{dt:.4f}}')"
        )
        out = subprocess.run(
            ["docker", "compose", "exec", "-T", "proxy-mysql", "python", "-c", py],
            cwd=str(REPO_DIR), env=ENV, capture_output=True, text=True, check=True,
        ).stdout.strip()
        return float(out.splitlines()[-1])

    try:
        version = str(direct.query("SELECT VERSION();").rows[0][0])

        # 1. Direct Baselines
        my_seed()
        b_upd = my_direct_timed("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;")
        b_del = my_direct_timed("DELETE FROM imdb_ratings;")
        my_seed()
        b_trunc = my_direct_timed("TRUNCATE TABLE imdb_ratings;")
        my_seed()
        b_dcol = my_direct_timed("ALTER TABLE imdb_ratings DROP COLUMN num_votes;")
        b_dtbl = my_direct_timed("DROP TABLE imdb_ratings;")
        print(
            f"[MySQL 8 Direct] DROP={b_dtbl:.3f}s | TRUNCATE={b_trunc:.3f}s | DROP_COL={b_dcol:.3f}s | 1M_UPD={b_upd:.2f}s | 1M_DEL={b_del:.2f}s",
            flush=True,
        )

        # 2. Proxy Operations
        direct.query("DROP DATABASE IF EXISTS _reverse_quarantine;")
        my_seed()
        assert my_hash() == canonical_hash
        time.sleep(2.5)

        # Live BEGIN; UPDATE; ROLLBACK check
        hist_before = proxy.query("PROXY HISTORY 25;").rows
        proxy.query("BEGIN;")
        proxy.query("UPDATE imdb_ratings SET average_rating = -99.0 WHERE tconst = 'tt0000001';")
        proxy.query("ROLLBACK;")
        hist_after = proxy.query("PROXY HISTORY 25;").rows
        assert len(hist_after) == len(hist_before), "MySQL ROLLBACK unexpectedly wrote to ledger!"
        assert my_hash() == canonical_hash, "MySQL ROLLBACK altered table rows!"
        my_rollback_ok = True

        # DROP TABLE
        t0 = time.perf_counter()
        proxy.query("DROP TABLE imdb_ratings;")
        p_dtbl_f = time.perf_counter() - t0
        tx_dtbl = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "DROP TABLE imdb_ratings" in str(r[6]))
        t0 = time.perf_counter()
        assert proxy.query(f"PROXY REVERSE {tx_dtbl};").columns[0] == "step_no"
        p_dtbl_u = time.perf_counter() - t0
        assert my_hash() == canonical_hash

        # TRUNCATE TABLE
        t0 = time.perf_counter()
        proxy.query("TRUNCATE TABLE imdb_ratings;")
        p_trunc_f = time.perf_counter() - t0
        tx_trunc = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "TRUNCATE TABLE imdb_ratings" in str(r[6]))
        t0 = time.perf_counter()
        assert proxy.query(f"PROXY REVERSE {tx_trunc};").columns[0] == "step_no"
        p_trunc_u = time.perf_counter() - t0
        assert my_hash() == canonical_hash

        # ALTER DROP COLUMN
        t0 = time.perf_counter()
        proxy.query("ALTER TABLE imdb_ratings DROP COLUMN num_votes;")
        p_dcol_f = time.perf_counter() - t0
        tx_dcol = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "DROP COLUMN num_votes" in str(r[6]))
        t0 = time.perf_counter()
        assert proxy.query(f"PROXY REVERSE {tx_dcol};").columns[0] == "step_no"
        p_dcol_u = time.perf_counter() - t0
        assert my_hash() == canonical_hash

        # 1M UPDATE (A) Pre-spill undo (`side_table`) + concurrent disjoint writers
        t0 = time.perf_counter()
        proxy.query("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;")
        p_upd_f = time.perf_counter() - t0
        tx_upd_pre = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "average_rating + 1.0" in str(r[6]))

        stop_flag = threading.Event()
        latencies: list[float] = []
        errors: list[str] = []

        def writer_my(tid: int) -> None:
            c = MySQLWireClient(host="127.0.0.1", port=3307, user="root", password="mysqlpassword", database="app", timeout=120.0)
            try:
                i = 0
                while not stop_flag.is_set() and i < 20:
                    w0 = time.perf_counter()
                    c.query(f"INSERT INTO imdb_ratings VALUES ('zz_conc_{tid}_{i}', 9.9, 1);")
                    latencies.append(time.perf_counter() - w0)
                    i += 1
                    time.sleep(0.05)
            except Exception as exc:
                errors.append(str(exc))
            finally:
                c.close()

        threads = [threading.Thread(target=writer_my, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        time.sleep(0.05)
        t0 = time.perf_counter()
        rev_u_pre = proxy.query(f"PROXY REVERSE {tx_upd_pre};")
        p_upd_u_pre = time.perf_counter() - t0
        stop_flag.set()
        for t in threads:
            t.join()
        assert rev_u_pre.columns and rev_u_pre.columns[0] == "step_no", rev_u_pre
        upd_pre_path = extract_restore_path(str(rev_u_pre.rows[0][1]))
        assert upd_pre_path == "side_table", upd_pre_path
        assert my_hash() == canonical_hash
        direct.query("DELETE FROM imdb_ratings WHERE tconst LIKE 'zz_conc_%';")
        diff_u_rows = proxy.query(f"PROXY DIFF {tx_upd_pre};").rows
        upd_phases = extract_phase_timings_from_diff_rows(diff_u_rows)

        # 1M UPDATE (B) Post-spill undo (`spilled_temp_table`)
        proxy.query("UPDATE imdb_ratings SET average_rating = average_rating + 2.0;")
        tx_upd_post = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "average_rating + 2.0" in str(r[6]))
        proxy.query(f"PROXY DIFF {tx_upd_post};")
        t0 = time.perf_counter()
        rev_u_post = proxy.query(f"PROXY REVERSE {tx_upd_post};")
        p_upd_u_post = time.perf_counter() - t0
        assert rev_u_post.columns and rev_u_post.columns[0] == "step_no", rev_u_post
        upd_post_path = extract_restore_path(str(rev_u_post.rows[0][1]))
        assert upd_post_path == "spilled_temp_table", upd_post_path
        assert my_hash() == canonical_hash

        # 1M DELETE (A) Pre-spill undo (`side_table`)
        t0 = time.perf_counter()
        proxy.query("DELETE FROM imdb_ratings;")
        p_del_f = time.perf_counter() - t0
        tx_del_pre = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if str(r[6]).startswith("DELETE FROM imdb_ratings"))
        t0 = time.perf_counter()
        rev_d_pre = proxy.query(f"PROXY REVERSE {tx_del_pre};")
        p_del_u_pre = time.perf_counter() - t0
        assert rev_d_pre.columns and rev_d_pre.columns[0] == "step_no", rev_d_pre
        del_pre_path = extract_restore_path(str(rev_d_pre.rows[0][1]))
        assert del_pre_path == "side_table", del_pre_path
        assert my_hash() == canonical_hash
        diff_d_rows = proxy.query(f"PROXY DIFF {tx_del_pre};").rows
        del_phases = extract_phase_timings_from_diff_rows(diff_d_rows)

        # 1M DELETE (B) Post-spill undo (`spilled_temp_table`)
        proxy.query("DELETE FROM imdb_ratings WHERE tconst LIKE 'tt%';")
        tx_del_post = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "DELETE FROM imdb_ratings WHERE tconst LIKE" in str(r[6]))
        proxy.query(f"PROXY DIFF {tx_del_post};")
        t0 = time.perf_counter()
        rev_d_post = proxy.query(f"PROXY REVERSE {tx_del_post};")
        p_del_u_post = time.perf_counter() - t0
        assert rev_d_post.columns and rev_d_post.columns[0] == "step_no", rev_d_post
        del_post_path = extract_restore_path(str(rev_d_post.rows[0][1]))
        assert del_post_path == "spilled_temp_table", del_post_path
        assert my_hash() == canonical_hash

        t_drain0 = time.perf_counter()
        rem = -1
        while time.perf_counter() - t_drain0 < 180.0:
            rem = int(direct.query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='_reverse_quarantine' AND table_name LIKE '_side_%';").rows[0][0])
            if rem == 0:
                break
            time.sleep(0.25)
        drain_s = round(time.perf_counter() - t_drain0, 3)
        assert rem == 0, f"MySQL left {rem} orphaned _side_* tables!"
        print(
            f"[MySQL 8 Proxy] 1M_UPD={p_upd_f:.2f}s (pre={p_upd_u_pre:.2f}s [{upd_pre_path}], post={p_upd_u_post:.2f}s [{upd_post_path}]) | "
            f"1M_DEL={p_del_f:.2f}s (pre={p_del_u_pre:.2f}s [{del_pre_path}], post={p_del_u_post:.2f}s [{del_post_path}]) | "
            f"conc(ok={len(latencies)}, err={len(errors)}, max={max(latencies) if latencies else 0:.3f}s) | side_rem={rem}",
            flush=True,
        )
        direct.query("DROP TABLE IF EXISTS imdb_ratings;")
    finally:
        direct.close()
        proxy.close()

    return {
        "server_version": version,
        "rollback_test_passed": my_rollback_ok,
        "direct_baseline": {
            "drop_table_s": round(b_dtbl, 3),
            "truncate_s": round(b_trunc, 3),
            "drop_column_s": round(b_dcol, 3),
            "update_1m_s": round(b_upd, 2),
            "delete_1m_s": round(b_del, 2),
        },
        "proxy": {
            "drop_table_write_s": round(p_dtbl_f, 3),
            "drop_table_undo_s": round(p_dtbl_u, 3),
            "truncate_write_s": round(p_trunc_f, 3),
            "truncate_undo_s": round(p_trunc_u, 3),
            "drop_column_write_s": round(p_dcol_f, 3),
            "drop_column_undo_s": round(p_dcol_u, 3),
            "update_1m_write_s": round(p_upd_f, 2),
            "update_1m_undo_pre_spill_s": round(p_upd_u_pre, 2),
            "update_1m_undo_pre_spill_path": upd_pre_path,
            "update_1m_undo_post_spill_s": round(p_upd_u_post, 2),
            "update_1m_undo_post_spill_path": upd_post_path,
            "update_1m_phase_timings_s": upd_phases,
            "delete_1m_write_s": round(p_del_f, 2),
            "delete_1m_undo_pre_spill_s": round(p_del_u_pre, 2),
            "delete_1m_undo_pre_spill_path": del_pre_path,
            "delete_1m_undo_post_spill_s": round(p_del_u_post, 2),
            "delete_1m_undo_post_spill_path": del_post_path,
            "delete_1m_phase_timings_s": del_phases,
            "remaining_side_tables_after_drain": rem,
            "spill_drain_s": drain_s,
            "sha256_verified": True,
        },
        "concurrency_during_1m_update_undo": {
            "threads": 4,
            "writes_completed": len(latencies),
            "errors": len(errors),
            "max_wait_s": round(max(latencies) if latencies else 0.0, 3),
            "avg_wait_s": round(sum(latencies) / len(latencies) if latencies else 0.0, 3),
            "key_pattern": "zz_conc_<tid>_<i> (disjoint inserts)",
        },
    }


def bench_mariadb_11_flashback(tsv_rows: list[tuple[str, float, int]], canonical_hash: str) -> dict[str, Any]:
    print("\n=== [4/5] MariaDB 11 Flashback (mariadb-binlog --flashback) ===", flush=True)
    name = "revproxy_mariadb_bench"
    subprocess.run(["docker", "rm", "-f", name], env=ENV, capture_output=True)
    subprocess.run(
        [
            "docker", "run", "-d", "--name", name,
            "-e", "MYSQL_ROOT_PASSWORD=mariapass",
            "-e", "MYSQL_DATABASE=app",
            "-p", "13308:3306",
            "mariadb:11",
            "--log-bin=mariadb-bin", "--binlog-format=ROW", "--binlog-row-image=FULL",
            "--max-allowed-packet=512M",
        ],
        env=ENV, check=True, capture_output=True,
    )
    try:
        for _ in range(40):
            chk = subprocess.run(["docker", "exec", name, "mariadb-admin", "ping", "-h", "127.0.0.1", "-pmariapass"], env=ENV, capture_output=True)
            if chk.returncode == 0:
                break
            time.sleep(1.0)
        else:
            raise RuntimeError("MariaDB container failed to become ready")

        c = MySQLWireClient(host="127.0.0.1", port=13308, user="root", password="mariapass", database="app", timeout=600.0)
        version = str(c.query("SELECT VERSION();").rows[0][0])
        c.query("CREATE TABLE imdb_ratings (tconst VARCHAR(16) PRIMARY KEY, average_rating DOUBLE, num_votes INT);")
        for i in range(0, len(tsv_rows), 5000):
            chunk = tsv_rows[i : i + 5000]
            vals = ",".join(f"('{t}',{a},{v})" for t, a, v in chunk)
            c.query(f"INSERT INTO imdb_ratings (tconst, average_rating, num_votes) VALUES {vals};")
        assert hash_rows(c.query("SELECT tconst, average_rating, num_votes FROM imdb_ratings ORDER BY tconst;").rows) == canonical_hash

        def binlog_file() -> str:
            return str(c.query("SHOW MASTER STATUS;").rows[0][0])

        # 1M UPDATE
        c.query("FLUSH BINARY LOGS;")
        f_upd = binlog_file()
        t0 = time.perf_counter()
        c.query("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;")
        upd_fwd = time.perf_counter() - t0
        c.query("FLUSH BINARY LOGS;")
        t0 = time.perf_counter()
        subprocess.run(
            ["docker", "exec", name, "sh", "-c", f"mariadb-binlog --flashback /var/lib/mysql/{f_upd} | mariadb --max-allowed-packet=512M -uroot -pmariapass app"],
            env=ENV, check=True, capture_output=True,
        )
        upd_undo = time.perf_counter() - t0
        assert hash_rows(c.query("SELECT tconst, average_rating, num_votes FROM imdb_ratings ORDER BY tconst;").rows) == canonical_hash

        # 1M DELETE
        c.query("FLUSH BINARY LOGS;")
        f_del = binlog_file()
        t0 = time.perf_counter()
        c.query("DELETE FROM imdb_ratings;")
        del_fwd = time.perf_counter() - t0
        c.query("FLUSH BINARY LOGS;")
        t0 = time.perf_counter()
        subprocess.run(
            ["docker", "exec", name, "sh", "-c", f"mariadb-binlog --flashback /var/lib/mysql/{f_del} | mariadb --max-allowed-packet=512M -uroot -pmariapass app"],
            env=ENV, check=True, capture_output=True,
        )
        del_undo = time.perf_counter() - t0
        assert hash_rows(c.query("SELECT tconst, average_rating, num_votes FROM imdb_ratings ORDER BY tconst;").rows) == canonical_hash

        # TRUNCATE TABLE check
        c.query("FLUSH BINARY LOGS;")
        f_tr = binlog_file()
        c.query("TRUNCATE TABLE imdb_ratings;")
        c.query("FLUSH BINARY LOGS;")
        fb_out = subprocess.run(
            ["docker", "exec", name, "sh", "-c", f"mariadb-binlog --flashback /var/lib/mysql/{f_tr}"],
            env=ENV, check=True, capture_output=True, text=True,
        ).stdout
        trunc_reversible = "INSERT INTO" in fb_out
        c.close()

        print(
            f"[MariaDB 11] 1M_UPD={upd_fwd:.2f}s/flashback={upd_undo:.2f}s | 1M_DEL={del_fwd:.2f}s/flashback={del_undo:.2f}s | TRUNCATE reversible={trunc_reversible}",
            flush=True,
        )
        return {
            "server_version": version,
            "update_1m_write_s": round(upd_fwd, 2),
            "update_1m_undo_s": round(upd_undo, 2),
            "delete_1m_write_s": round(del_fwd, 2),
            "delete_1m_undo_s": round(del_undo, 2),
            "truncate_reversible": trunc_reversible,
            "sha256_verified": True,
        }
    finally:
        subprocess.run(["docker", "rm", "-f", name], env=ENV, capture_output=True)


def bench_default_cap_refusal() -> dict[str, Any]:
    print("\n=== [5/5] Default 10,000-Row Blast Radius Guard Check (PG16 + MySQL 8.0) ===", flush=True)
    run_compose(["up", "-d", "--wait"], extra_env={"REVERSE_PROXY_MAX_CAPTURE_ROWS": "10000"})
    pg_exec("DROP TABLE IF EXISTS cap_test CASCADE; CREATE TABLE cap_test (id INT PRIMARY KEY, v INT); INSERT INTO cap_test SELECT g, g FROM generate_series(1, 15000) g;")
    pg = PgWireClient(host="127.0.0.1", port=5433, user="postgres", password="pgpassword", database="app", timeout=60.0)
    try:
        try:
            pg.query("DELETE FROM cap_test;")
            raise AssertionError("PG allowed >10k DELETE under default cap!")
        except PgError as exc:
            assert "limit=10000" in str(exc), str(exc)
        pg_cnt = int(pg_exec("SELECT COUNT(*) FROM cap_test;"))
        assert pg_cnt == 15000
        pg_exec("DROP TABLE IF EXISTS cap_test CASCADE;")
    finally:
        pg.close()

    my_dir = MySQLWireClient(host="127.0.0.1", port=3306, user="root", password="mysqlpassword", database="app", timeout=60.0)
    my = MySQLWireClient(host="127.0.0.1", port=3307, user="root", password="mysqlpassword", database="app", timeout=60.0)
    try:
        my_dir.query("DROP TABLE IF EXISTS cap_test;")
        my_dir.query("CREATE TABLE cap_test (id INT PRIMARY KEY, v INT);")
        for s in range(1, 15001, 3000):
            vals = ",".join(f"({i},{i})" for i in range(s, s + 3000))
            my_dir.query(f"INSERT INTO cap_test VALUES {vals};")
        try:
            my.query("DELETE FROM cap_test;")
            raise AssertionError("MySQL allowed >10k DELETE under default cap!")
        except Exception as exc:
            assert "limit=10000" in str(exc), str(exc)
        my_cnt = int(my_dir.query("SELECT COUNT(*) FROM cap_test;").rows[0][0])
        assert my_cnt == 15000
        my_dir.query("DROP TABLE IF EXISTS cap_test;")
    finally:
        my_dir.close()
        my.close()

    print("[Default Cap] PG16 & MySQL 8.0 both refused 15,000-row DELETE before mutating (limit=10000)", flush=True)
    return {"default_limit": 10000, "test_rows": 15000, "pg16_refused_intact": True, "mysql8_refused_intact": True}


def ratio_str(proxy_s: float, base_s: float) -> str:
    if base_s <= 0:
        return "—"
    return f"`{proxy_s:.2f}s` ({proxy_s / base_s:.1f}x)"


def fmt_phase_row(label: str, ph: dict[str, Any]) -> str:
    return (
        f"| **{label}** | `{ph.get('blast_radius_check_s', 0.0):.3f}s` | "
        f"`{ph.get('side_table_create_s', 0.0):.3f}s` | "
        f"`{ph.get('snapshot_capture_s', 0.0):.3f}s` | "
        f"`{ph.get('dml_exec_s', 0.0):.3f}s` | "
        f"`{ph.get('commit_s', 0.0):.3f}s` | "
        f"`{ph.get('spill_s', 0.0):.2f}s` |"
    )


def render_benchmark_markdown(data: dict[str, Any], json_rel_path: str) -> str:
    pg16 = data["postgres_16"]
    pg18 = data["postgres_18"]
    my8 = data["mysql_8"]
    mdb = data["mariadb_11_flashback"]
    c_pg = pg16["concurrency_during_1m_update_undo"]
    c_my = my8["concurrency_during_1m_update_undo"]

    pg16_b = pg16["direct_baseline"]
    pg16_p = pg16["proxy"]
    pg18_b = pg18["direct_baseline"]
    pg18_p = pg18["proxy"]
    my8_b = my8["direct_baseline"]
    my8_p = my8["proxy"]

    meta = data["metadata"]
    digests = meta["docker_images"]
    git_commit = meta.get("git_commit") or "uncommitted"

    lines = [
        "## Concurrency & Locking During Large Undos",
        "",
        "Conflict verification (`SELECT ... FOR UPDATE` on Postgres/MySQL, `BEGIN IMMEDIATE` on SQLite) runs in the **same transaction** as state restoration, while `ReverseProxyEngine.reverse()` releases the global Python engine lock when multi-session drivers are active (`scripts/run_benchmarks.py`):",
        "",
        f"- **PostgreSQL 16 (MVCC row locks):** During a 1,000,000-row `PROXY REVERSE` undo, {c_pg['threads']} concurrent writer threads completed **{c_pg['writes_completed']} disjoint `INSERT`s** (`{c_pg['key_pattern']}`) with **{c_pg['errors']} errors**, `max_wait = {c_pg['max_wait_s']:.3f}s`, `avg = {c_pg['avg_wait_s']:.3f}s`.",
        f"- **MySQL 8.0 (InnoDB row/gap locks):** During a 1,000,000-row `PROXY REVERSE` undo, {c_my['threads']} concurrent writer threads completed **{c_my['writes_completed']} disjoint trailing-key `INSERT`s** (`{c_my['key_pattern']}`) with **{c_my['errors']} errors**, `max_wait = {c_my['max_wait_s']:.3f}s`, `avg = {c_my['avg_wait_s']:.3f}s`. Under `REPEATABLE READ`, inserts falling *inside* locked primary-key ranges/gaps can block until commit.",
        "",
        "### Durability Note: `UNLOGGED` Side Tables on PostgreSQL",
        "",
        "Bulk `UPDATE`/`DELETE` statements above `side_table_threshold = 500` capture before/after rows into PostgreSQL `CREATE UNLOGGED TABLE` snapshots and stream them asynchronously via `_SideSpillWorker` to compressed SHA-256-verified spill files on disk (`tx_spill_*.undo.zlib`), then drop all `_side_*` tables. Because PostgreSQL skips WAL writes for `UNLOGGED` tables, an unclean PostgreSQL crash (`kill -9` / power loss) *after* commit and *before* background spill completion truncates unspilled `_side_*` tables on crash recovery—losing undo history for that unspilled transaction (primary logged tables remain consistent).",
        "",
        "## Benchmarks (1,000,000 IMDb Rows, `SHA-256` Verified)",
        "",
        f"Generated directly from [`{json_rel_path}`]({json_rel_path}) via [`scripts/run_benchmarks.py`](scripts/run_benchmarks.py) (timestamp: `{meta['timestamp_utc']}`, git commit: `{git_commit}`, source tree SHA-256: `{meta['source_tree_sha256'][:16]}...`, canonical 1M dataset SHA-256: `{meta['dataset']['canonical_sha256'][:16]}...`).",
        "",
        "Both undo paths are measured and labeled below:",
        "- **Pre-Spill Undo (`side_table`)**: `PROXY REVERSE` executed within the in-DB snapshot window while `_side_*` tables are still resident in `_reverse_quarantine`.",
        "- **Post-Spill Undo (`spilled_temp_table`)**: `PROXY REVERSE` executed *after* `_side_*` tables have been spilled to compressed disk files (`tx_spill_*.undo.zlib`) and dropped from the database (loads the spill file into a staging temp table via `COPY FROM STDIN` on Postgres / batched multi-row `INSERT` on MySQL, then runs a single set-based `UPDATE ... FROM` / `UPDATE ... INNER JOIN` or `INSERT ... SELECT` with full `FOR UPDATE` drift checks).",
        "",
        "### PostgreSQL 16 & PostgreSQL 18 (`RETURNING OLD, NEW`)",
        "",
        "| 1,000,000-Row Operation | PG 16 Direct | PG 16 Proxy Write | PG 16 Undo (Pre-Spill `side_table`) | PG 16 Undo (Post-Spill `spilled_temp_table`) | PG 18 Direct | PG 18 Proxy Write (`RETURNING OLD/NEW`) | PG 18 Undo (Pre-Spill `side_table`) | PG 18 Undo (Post-Spill `spilled_temp_table`) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        f"| **`DROP TABLE`** | `{pg16_b['drop_table_s']:.3f}s` | `{pg16_p['drop_table_write_s']:.3f}s` | **`{pg16_p['drop_table_undo_s']:.3f}s`** (`ddl_quarantine`) | — | — | — | — | — |",
        f"| **`TRUNCATE TABLE`** | `{pg16_b['truncate_s']:.3f}s` | `{pg16_p['truncate_write_s']:.3f}s` | **`{pg16_p['truncate_undo_s']:.3f}s`** (`ddl_quarantine`) | — | — | — | — | — |",
        f"| **`ALTER DROP COLUMN`** | `{pg16_b['drop_column_s']:.3f}s` | `{pg16_p['drop_column_write_s']:.3f}s` | **`{pg16_p['drop_column_undo_s']:.3f}s`** (`ddl_quarantine`) | — | — | — | — | — |",
        f"| **1M Bulk `UPDATE`** | `{pg16_b['update_1m_s']:.2f}s` | {ratio_str(pg16_p['update_1m_write_s'], pg16_b['update_1m_s'])} | **`{pg16_p['update_1m_undo_pre_spill_s']:.2f}s`** | **`{pg16_p['update_1m_undo_post_spill_s']:.2f}s`** | `{pg18_b['update_1m_s']:.2f}s` | {ratio_str(pg18_p['update_1m_write_s'], pg18_b['update_1m_s'])} | **`{pg18_p['update_1m_undo_pre_spill_s']:.2f}s`** | **`{pg18_p['update_1m_undo_post_spill_s']:.2f}s`** |",
        f"| **1M Bulk `DELETE`** | `{pg16_b['delete_1m_s']:.2f}s` | {ratio_str(pg16_p['delete_1m_write_s'], pg16_b['delete_1m_s'])} | **`{pg16_p['delete_1m_undo_pre_spill_s']:.2f}s`** | **`{pg16_p['delete_1m_undo_post_spill_s']:.2f}s`** | `{pg18_b['delete_1m_s']:.2f}s` | {ratio_str(pg18_p['delete_1m_write_s'], pg18_b['delete_1m_s'])} | **`{pg18_p['delete_1m_undo_pre_spill_s']:.2f}s`** | **`{pg18_p['delete_1m_undo_post_spill_s']:.2f}s`** |",
        "",
        "### MySQL 8.0 vs. MariaDB 11 Flashback (`mariadb-binlog --flashback`)",
        "",
        "| 1,000,000-Row Operation | MySQL 8.0 Direct | MySQL 8.0 Proxy Write | MySQL 8.0 Undo (Pre-Spill `side_table`) | MySQL 8.0 Undo (Post-Spill `spilled_temp_table`) | MariaDB 11 Flashback (`--flashback`) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
        f"| **`DROP TABLE`** | `{my8_b['drop_table_s']:.3f}s` | `{my8_p['drop_table_write_s']:.3f}s` | **`{my8_p['drop_table_undo_s']:.3f}s`** (`ddl_quarantine`) | — | Not reversible (`DROP`) |",
        f"| **`TRUNCATE TABLE`** | `{my8_b['truncate_s']:.3f}s` | `{my8_p['truncate_write_s']:.3f}s` | **`{my8_p['truncate_undo_s']:.3f}s`** (`ddl_quarantine`) | — | {'Reversible' if mdb['truncate_reversible'] else 'Not reversible (emits no `INSERT`s)'} |",
        f"| **`ALTER DROP COLUMN`** | `{my8_b['drop_column_s']:.3f}s` | `{my8_p['drop_column_write_s']:.3f}s` | **`{my8_p['drop_column_undo_s']:.3f}s`** (`ddl_quarantine`) | — | Not reversible (`ALTER`) |",
        f"| **1M Bulk `UPDATE`** | `{my8_b['update_1m_s']:.2f}s` | {ratio_str(my8_p['update_1m_write_s'], my8_b['update_1m_s'])} | **`{my8_p['update_1m_undo_pre_spill_s']:.2f}s`** | **`{my8_p['update_1m_undo_post_spill_s']:.2f}s`** | Forward `{mdb['update_1m_write_s']:.2f}s` / Flashback **`{mdb['update_1m_undo_s']:.2f}s`** |",
        f"| **1M Bulk `DELETE`** | `{my8_b['delete_1m_s']:.2f}s` | {ratio_str(my8_p['delete_1m_write_s'], my8_b['delete_1m_s'])} | **`{my8_p['delete_1m_undo_pre_spill_s']:.2f}s`** | **`{my8_p['delete_1m_undo_post_spill_s']:.2f}s`** | Forward `{mdb['delete_1m_write_s']:.2f}s` / Flashback **`{mdb['delete_1m_undo_s']:.2f}s`** |",
        "",
        "### Per-Phase Write & Spill Timing Breakdown (1,000,000 Rows)",
        "",
        "| Engine & Operation | Blast-Radius Probe (`COUNT`) | Side-Table Create | Pre-Image Capture (`FOR UPDATE`) | DML Execution | `COMMIT` | Post-Commit Disk Spill (`spill_s`) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        fmt_phase_row("PG 16 — 1M `UPDATE`", pg16_p["update_1m_phase_timings_s"]),
        fmt_phase_row("PG 16 — 1M `DELETE`", pg16_p["delete_1m_phase_timings_s"]),
        fmt_phase_row("PG 18 — 1M `UPDATE` (`RETURNING OLD/NEW`)", pg18_p["update_1m_phase_timings_s"]),
        fmt_phase_row("PG 18 — 1M `DELETE` (`RETURNING *`)", pg18_p["delete_1m_phase_timings_s"]),
        fmt_phase_row("MySQL 8.0 — 1M `UPDATE`", my8_p["update_1m_phase_timings_s"]),
        fmt_phase_row("MySQL 8.0 — 1M `DELETE`", my8_p["delete_1m_phase_timings_s"]),
        "",
        "<details>",
        "<summary>Provenance: Git commit, image digests & cleanup verification</summary>",
        "",
        f"- Git commit: `{git_commit}` (`source_tree_sha256`: `{meta['source_tree_sha256']}`)",
        f"- `postgres:16`: `{digests['postgres_16']['repo_digests'][0] if digests['postgres_16'].get('repo_digests') else digests['postgres_16'].get('id')}`",
        f"- `postgres:18`: `{digests['postgres_18']['repo_digests'][0] if digests['postgres_18'].get('repo_digests') else digests['postgres_18'].get('id')}`",
        f"- `mysql:8.0`: `{digests['mysql_8']['repo_digests'][0] if digests['mysql_8'].get('repo_digests') else digests['mysql_8'].get('id')}`",
        f"- `mariadb:11`: `{digests['mariadb_11']['repo_digests'][0] if digests['mariadb_11'].get('repo_digests') else digests['mariadb_11'].get('id')}`",
        f"- Remaining `_side_*` tables after spill drain: PG 16 = `{pg16_p['remaining_side_tables_after_drain']}`, PG 18 = `{pg18_p['remaining_side_tables_after_drain']}`, MySQL 8.0 = `{my8_p['remaining_side_tables_after_drain']}`.",
        f"- Live `BEGIN; UPDATE; ROLLBACK;` verified: PG 16 = `{pg16['rollback_test_passed']}`, MySQL 8.0 = `{my8['rollback_test_passed']}`.",
        "",
        "</details>",
    ]
    return "\n".join(lines)


def update_readme(data: dict[str, Any], json_rel_path: str) -> None:
    text = README_PATH.read_text(encoding="utf-8")
    start_marker = "<!-- BENCHMARK_SECTION_START -->"
    end_marker = "<!-- BENCHMARK_SECTION_END -->"
    rendered = f"{start_marker}\n{render_benchmark_markdown(data, json_rel_path)}\n{end_marker}"
    if start_marker in text and end_marker in text:
        new_text = re.sub(
            re.escape(start_marker) + r".*?" + re.escape(end_marker),
            rendered,
            text,
            flags=re.DOTALL,
        )
    else:
        raise RuntimeError("README.md missing BENCHMARK_SECTION markers")
    README_PATH.write_text(new_text, encoding="utf-8")
    print(f"\n[README] Regenerated {README_PATH} from {json_rel_path}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run reproducible 1M benchmarks and update README.md from JSON output.")
    parser.add_argument("--render-only", type=str, default="", help="Regenerate README.md from an existing benchmark JSON file.")
    args = parser.parse_args()

    if args.render_only:
        p = Path(args.render_only)
        data = json.loads(p.read_text(encoding="utf-8"))
        try:
            rel = p.resolve().relative_to(REPO_DIR).as_posix()
        except ValueError:
            rel = str(p)
        update_readme(data, rel)
        return

    BENCH_DIR.mkdir(parents=True, exist_ok=True)
    tsv_rows = load_tsv(1_000_000)
    canonical_hash = hash_rows(tsv_rows)
    print(f"Loaded {len(tsv_rows):,} IMDb rows | canonical SHA-256 = {canonical_hash}", flush=True)

    run_compose(["up", "-d", "--build", "--force-recreate", "--wait"], extra_env={"REVERSE_PROXY_MAX_CAPTURE_ROWS": "2000000"})
    try:
        pg16_res = bench_postgres_16(tsv_rows, canonical_hash)
        pg18_res = bench_postgres_18(tsv_rows, canonical_hash)
        my8_res = bench_mysql_8(tsv_rows, canonical_hash)
        mdb_res = bench_mariadb_11_flashback(tsv_rows, canonical_hash)
        cap_res = bench_default_cap_refusal()
    finally:
        run_compose(["up", "-d", "--wait"], extra_env={"REVERSE_PROXY_MAX_CAPTURE_ROWS": "10000"})

    ts = datetime.now(timezone.utc)
    ts_slug = ts.strftime("%Y%m%d_%H%M%SZ")
    payload: dict[str, Any] = {
        "metadata": {
            "timestamp_utc": ts.isoformat(),
            "git_commit": get_git_commit(),
            "source_tree_sha256": compute_source_tree_sha256(),
            "dataset": {
                "path": "benchmark_data/ratings_1m.tsv",
                "rows": len(tsv_rows),
                "canonical_sha256": canonical_hash,
            },
            "docker_images": {
                "postgres_16": inspect_image("postgres:16"),
                "postgres_18": inspect_image("postgres:18"),
                "mysql_8": inspect_image("mysql:8.0"),
                "mariadb_11": inspect_image("mariadb:11"),
                "proxy_postgres": inspect_image("sql-reverse-proxy-proxy-postgres"),
                "proxy_mysql": inspect_image("sql-reverse-proxy-proxy-mysql"),
            },
        },
        "postgres_16": pg16_res,
        "postgres_18": pg18_res,
        "mysql_8": my8_res,
        "mariadb_11_flashback": mdb_res,
        "default_cap_guard": cap_res,
    }

    ts_path = BENCH_DIR / f"results_{ts_slug}.json"
    latest_path = BENCH_DIR / "latest.json"
    encoded = json.dumps(payload, indent=2) + "\n"
    ts_path.write_text(encoded, encoding="utf-8")
    latest_path.write_text(encoded, encoding="utf-8")
    print(f"\n[JSON] Wrote {ts_path} and {latest_path}", flush=True)

    update_readme(payload, f"benchmarks/{ts_path.name}")
    print("\n=== FULL BENCHMARK SUITE + README GENERATION COMPLETE ===", flush=True)


if __name__ == "__main__":
    main()
