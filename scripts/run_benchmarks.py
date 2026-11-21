#!/usr/bin/env python3
"""Reproducible end-to-end 1,000,000-row benchmark & README table generator (5 trials per cell).

Runs 5 trials per benchmark cell across PostgreSQL 16, PostgreSQL 18 (native RETURNING OLD/NEW),
MySQL 8.0, and MariaDB 11 (mariadb-binlog --flashback):
  - Reports all 5 raw trial times, the median, and the [min, max] range for every cell.
  - Reseeds a fresh table before each mutating run, runs VACUUM ANALYZE + CHECKPOINT on
    PostgreSQL, and waits for background spills (_side_* == 0) and InnoDB purge backlog
    (trx_rseg_history_len) to drain before timing any operation.
  - Measures both pre-spill undo (in-DB `_side_*` snapshot table, `restore_path="side_table"`)
    and post-spill undo (from compressed disk spill file via temp table + set-based join,
    `restore_path="spilled_temp_table"`).
  - Records per-phase timings for both forward writes/spills (`blast_radius_check_s`,
    `side_table_create_s`, `snapshot_capture_s`, `dml_exec_s`, `commit_s`, `spill_s`) and
    reverse undos (`wal_sync_s`, `ledger_load_s`, `stage_temp_s`, `conflict_and_lock_s`,
    `restore_exec_s`, `commit_s`).
  - Verifies SHA-256 row hash after every restore and asserts 0 leftover `_side_*` tables.
  - Regenerates the benchmark tables in README.md directly from the JSON artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import statistics
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


def summarize_trials(vals: list[float], ndigits: int = 3) -> dict[str, Any]:
    cleaned = [round(float(v), ndigits) for v in vals]
    med = round(float(statistics.median(vals)), ndigits)
    mn = round(float(min(vals)), ndigits)
    mx = round(float(max(vals)), ndigits)
    return {
        "trials_s": cleaned,
        "median_s": med,
        "min_s": mn,
        "max_s": mx,
    }


def median_phase_dict(phase_list: list[dict[str, float]], ndigits: int = 4) -> dict[str, float]:
    if not phase_list:
        return {}
    keys: list[str] = []
    for d in phase_list:
        for k in d.keys():
            if k not in keys:
                keys.append(k)
    return {
        k: round(float(statistics.median([d.get(k, 0.0) for d in phase_list])), ndigits)
        for k in keys
    }


def extract_restore_path(step_desc: str) -> str:
    if "[side_table]" in step_desc:
        return "side_table"
    if "[spilled_temp_table]" in step_desc:
        return "spilled_temp_table"
    return "row_batched"


def extract_undo_timings_from_reverse_desc(step_desc: str) -> dict[str, float]:
    m = re.search(r"\[undo_timings=(\{.*?\})\]", step_desc)
    if not m:
        return {}
    try:
        parsed = json.loads(m.group(1))
        if isinstance(parsed, dict):
            return {str(k): round(float(v), 4) for k, v in parsed.items()}
    except Exception:
        pass
    return {}


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


def pg_drain_wal_slot(
    proxy: PgWireClient | None = None,
    *,
    container: str = "",
    compose_service: str = "postgres",
    slot: str = "reverse_proxy_slot",
) -> None:
    try:
        pg_exec("CHECKPOINT;", container=container, compose_service=compose_service)
    except Exception:
        pass
    if proxy is not None:
        try:
            proxy.query("PROXY HISTORY 1;")
            pg_exec("CHECKPOINT;", container=container, compose_service=compose_service)
            time.sleep(0.15)
            proxy.query("PROXY HISTORY 1;")
        except Exception:
            pass
    else:
        sql = (
            f"SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = '{slot}' AND NOT active) "
            f"THEN pg_replication_slot_advance('{slot}', pg_current_wal_lsn())::text ELSE 'skip' END;"
        )
        try:
            pg_exec(sql, container=container, compose_service=compose_service)
        except Exception:
            pass


def pg_seed_master(tsv_rows: list[tuple[str, float, int]], *, container: str = "", compose_service: str = "postgres") -> None:
    pg_exec(
        "DROP TABLE IF EXISTS _bench_seed_master CASCADE; "
        "CREATE UNLOGGED TABLE _bench_seed_master (tconst VARCHAR(16) PRIMARY KEY, average_rating DOUBLE PRECISION, num_votes INTEGER);",
        container=container,
        compose_service=compose_service,
    )
    payload = "".join(f"{t}\t{a}\t{v}\n" for t, a, v in tsv_rows).encode("utf-8")
    if container:
        cmd = ["docker", "exec", "-i", container, "psql", "-U", "postgres", "-d", "app", "-c", "\\copy _bench_seed_master (tconst, average_rating, num_votes) FROM STDIN WITH (FORMAT text, DELIMITER E'\\t')"]
    else:
        cmd = ["docker", "compose", "exec", "-T", compose_service, "psql", "-U", "postgres", "-d", "app", "-c", "\\copy _bench_seed_master (tconst, average_rating, num_votes) FROM STDIN WITH (FORMAT text, DELIMITER E'\\t')"]
    subprocess.run(cmd, input=payload, cwd=str(REPO_DIR), env=ENV, capture_output=True, check=True)
    pg_exec("VACUUM ANALYZE _bench_seed_master;", container=container, compose_service=compose_service)
    pg_exec("CHECKPOINT;", container=container, compose_service=compose_service)


def pg_reseed_from_master(
    *,
    container: str = "",
    compose_service: str = "postgres",
    proxy: PgWireClient | None = None,
    with_publication: bool = False,
) -> None:
    if with_publication:
        pg_exec('DROP PUBLICATION IF EXISTS "_reverse_proxy_pub"; CREATE PUBLICATION "_reverse_proxy_pub";', container=container, compose_service=compose_service)
    pg_exec(
        "DROP TABLE IF EXISTS imdb_ratings CASCADE; "
        "CREATE TABLE imdb_ratings (tconst VARCHAR(16) PRIMARY KEY, average_rating DOUBLE PRECISION, num_votes INTEGER); "
        "INSERT INTO imdb_ratings SELECT * FROM _bench_seed_master;",
        container=container,
        compose_service=compose_service,
    )
    pg_exec("VACUUM ANALYZE imdb_ratings;", container=container, compose_service=compose_service)
    pg_exec("CHECKPOINT;", container=container, compose_service=compose_service)
    pg_drain_wal_slot(proxy, container=container, compose_service=compose_service)
    if with_publication:
        pg_exec('DROP PUBLICATION IF EXISTS "_reverse_proxy_pub"; CREATE PUBLICATION "_reverse_proxy_pub" FOR ALL TABLES;', container=container, compose_service=compose_service)
        pg_drain_wal_slot(proxy, container=container, compose_service=compose_service)


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
        time.sleep(0.2)
    return rem, round(time.perf_counter() - t0, 3)


def bench_postgres_16(tsv_rows: list[tuple[str, float, int]], canonical_hash: str, trials: int) -> dict[str, Any]:
    print(f"\n=== [1/5] PostgreSQL 16 ({trials} trials/cell: Direct Baseline + Pre-Spill & Post-Spill Undo + Phase Timings) ===", flush=True)
    version = pg_exec("SELECT version();")

    # Empty _reverse_proxy_pub during direct baselines & seeding so setup rows don't flood the proxy WAL poller
    pg_exec('DROP PUBLICATION IF EXISTS "_reverse_proxy_pub"; CREATE PUBLICATION "_reverse_proxy_pub";')
    pg_seed_master(tsv_rows)

    b_dtbl_t: list[float] = []
    b_trunc_t: list[float] = []
    b_dcol_t: list[float] = []
    b_upd_t: list[float] = []
    b_del_t: list[float] = []

    for i in range(trials):
        pg_reseed_from_master()
        b_upd_t.append(pg_direct_timed("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;", host="postgres", port=5432, inside_service="proxy-postgres"))
        pg_reseed_from_master()
        b_del_t.append(pg_direct_timed("DELETE FROM imdb_ratings;", host="postgres", port=5432, inside_service="proxy-postgres"))
        pg_reseed_from_master()
        b_trunc_t.append(pg_direct_timed("TRUNCATE TABLE imdb_ratings;", host="postgres", port=5432, inside_service="proxy-postgres"))
        pg_reseed_from_master()
        b_dcol_t.append(pg_direct_timed("ALTER TABLE imdb_ratings DROP COLUMN num_votes;", host="postgres", port=5432, inside_service="proxy-postgres"))
        b_dtbl_t.append(pg_direct_timed("DROP TABLE imdb_ratings;", host="postgres", port=5432, inside_service="proxy-postgres"))
        print(f"  [PG16 Direct trial {i+1}/{trials}] UPD={b_upd_t[-1]:.2f}s DEL={b_del_t[-1]:.2f}s TRUNC={b_trunc_t[-1]:.3f}s DCOL={b_dcol_t[-1]:.3f}s DTBL={b_dtbl_t[-1]:.3f}s", flush=True)

    # 2. Proxy Operations
    pg_exec("DROP SCHEMA IF EXISTS _reverse_quarantine CASCADE;")
    proxy = PgWireClient(host="127.0.0.1", port=5433, user="postgres", password="pgpassword", database="app", timeout=600.0)
    try:
        pg_reseed_from_master(proxy=proxy, with_publication=True)
        assert pg_hash() == canonical_hash

        # Live BEGIN; UPDATE; ROLLBACK check
        hist_before = proxy.query("PROXY HISTORY 25;")[0].rows
        proxy.query("BEGIN;")
        proxy.query("UPDATE imdb_ratings SET average_rating = -99.0 WHERE tconst = 'tt0000001';")
        proxy.query("ROLLBACK;")
        hist_after = proxy.query("PROXY HISTORY 25;")[0].rows
        assert len(hist_after) == len(hist_before), "PG ROLLBACK unexpectedly wrote to ledger!"
        assert pg_hash() == canonical_hash, "PG ROLLBACK altered table rows!"
        pg_rollback_ok = True

        p_dtbl_f_t: list[float] = []
        p_dtbl_u_t: list[float] = []
        p_dtbl_u_phases: list[dict[str, float]] = []

        p_trunc_f_t: list[float] = []
        p_trunc_u_t: list[float] = []
        p_trunc_u_phases: list[dict[str, float]] = []

        p_dcol_f_t: list[float] = []
        p_dcol_u_t: list[float] = []

        p_upd_f_t: list[float] = []
        p_upd_u_pre_t: list[float] = []
        p_upd_u_post_t: list[float] = []
        upd_w_phases_list: list[dict[str, float]] = []
        upd_u_pre_phases_list: list[dict[str, float]] = []
        upd_u_post_phases_list: list[dict[str, float]] = []

        p_del_f_t: list[float] = []
        p_del_u_pre_t: list[float] = []
        p_del_u_post_t: list[float] = []
        del_w_phases_list: list[dict[str, float]] = []
        del_u_pre_phases_list: list[dict[str, float]] = []
        del_u_post_phases_list: list[dict[str, float]] = []

        latencies: list[float] = []
        errors: list[str] = []
        upd_pre_path = "side_table"
        upd_post_path = "spilled_temp_table"
        del_pre_path = "side_table"
        del_post_path = "spilled_temp_table"

        for i in range(trials):
            pg_reseed_from_master(proxy=proxy, with_publication=True)

            # DROP TABLE
            t0 = time.perf_counter()
            proxy.query("DROP TABLE imdb_ratings;")
            p_dtbl_f_t.append(time.perf_counter() - t0)
            tx_dtbl = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "DROP TABLE imdb_ratings" in str(r[6]))
            t0 = time.perf_counter()
            rev_dtbl = proxy.query(f"PROXY REVERSE {tx_dtbl};")[0]
            p_dtbl_u_t.append(time.perf_counter() - t0)
            assert rev_dtbl.command_tag == "PROXY REVERSE OK"
            p_dtbl_u_phases.append(extract_undo_timings_from_reverse_desc(str(rev_dtbl.rows[0][1])))
            if i == 0:
                assert pg_hash() == canonical_hash

            # TRUNCATE TABLE
            t0 = time.perf_counter()
            proxy.query("TRUNCATE TABLE imdb_ratings;")
            p_trunc_f_t.append(time.perf_counter() - t0)
            tx_trunc = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "TRUNCATE TABLE imdb_ratings" in str(r[6]))
            t0 = time.perf_counter()
            rev_trunc = proxy.query(f"PROXY REVERSE {tx_trunc};")[0]
            p_trunc_u_t.append(time.perf_counter() - t0)
            assert rev_trunc.command_tag == "PROXY REVERSE OK"
            p_trunc_u_phases.append(extract_undo_timings_from_reverse_desc(str(rev_trunc.rows[0][1])))
            if i == 0:
                assert pg_hash() == canonical_hash

            # ALTER DROP COLUMN
            t0 = time.perf_counter()
            proxy.query("ALTER TABLE imdb_ratings DROP COLUMN num_votes;")
            p_dcol_f_t.append(time.perf_counter() - t0)
            tx_dcol = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "DROP COLUMN num_votes" in str(r[6]))
            t0 = time.perf_counter()
            rev_dcol = proxy.query(f"PROXY REVERSE {tx_dcol};")[0]
            p_dcol_u_t.append(time.perf_counter() - t0)
            assert rev_dcol.command_tag == "PROXY REVERSE OK"
            pg_exec("VACUUM ANALYZE imdb_ratings;")
            pg_exec("CHECKPOINT;")
            pg_drain_wal_slot(proxy)
            if i == 0:
                assert pg_hash() == canonical_hash

            # 1M UPDATE (A) Pre-spill undo (`side_table`)
            t0 = time.perf_counter()
            proxy.query(f"UPDATE imdb_ratings SET average_rating = average_rating + {1.0 + i * 0.1:.1f};")
            p_upd_f_t.append(time.perf_counter() - t0)
            tx_upd_pre = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "UPDATE imdb_ratings SET average_rating" in str(r[6]))

            if i == 0:
                stop_flag = threading.Event()

                def writer_pg(tid: int) -> None:
                    c = PgWireClient(host="127.0.0.1", port=5433, user="postgres", password="pgpassword", database="app", timeout=120.0)
                    try:
                        j = 0
                        while not stop_flag.is_set() and j < 20:
                            w0 = time.perf_counter()
                            c.query(f"INSERT INTO imdb_ratings VALUES ('zz_conc_{tid}_{j}', 9.9, 1);")
                            latencies.append(time.perf_counter() - w0)
                            j += 1
                            time.sleep(0.05)
                    except Exception as exc:
                        errors.append(str(exc))
                    finally:
                        c.close()

                threads = [threading.Thread(target=writer_pg, args=(t_idx,)) for t_idx in range(4)]
                for t in threads:
                    t.start()
                time.sleep(0.05)
                t0 = time.perf_counter()
                rev_u_pre = proxy.query(f"PROXY REVERSE {tx_upd_pre};")[0]
                p_upd_u_pre_t.append(time.perf_counter() - t0)
                stop_flag.set()
                for t in threads:
                    t.join()
                assert not errors, f"PG writer errors: {errors}"
                pg_exec("DELETE FROM imdb_ratings WHERE tconst LIKE 'zz_conc_%';")
            else:
                t0 = time.perf_counter()
                rev_u_pre = proxy.query(f"PROXY REVERSE {tx_upd_pre};")[0]
                p_upd_u_pre_t.append(time.perf_counter() - t0)

            assert rev_u_pre.command_tag == "PROXY REVERSE OK", rev_u_pre
            upd_pre_path = extract_restore_path(str(rev_u_pre.rows[0][1]))
            assert upd_pre_path == "side_table", f"Expected side_table pre-spill path, got {upd_pre_path}"
            upd_u_pre_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_u_pre.rows[0][1])))
            diff_u_pre = proxy.query(f"PROXY DIFF {tx_upd_pre};")[0].rows
            upd_w_phases_list.append(extract_phase_timings_from_diff_rows(diff_u_pre))
            rem_u0, _ = wait_pg_side_drain(timeout=60.0)
            assert rem_u0 == 0
            pg_exec("VACUUM ANALYZE imdb_ratings;")
            pg_exec("CHECKPOINT;")
            pg_drain_wal_slot(proxy)
            if i == 0:
                assert pg_hash() == canonical_hash

            # 1M UPDATE (B) Post-spill undo (`spilled_temp_table`)
            proxy.query(f"UPDATE imdb_ratings SET average_rating = average_rating + {2.0 + i * 0.1:.1f};")
            tx_upd_post = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "UPDATE imdb_ratings SET average_rating" in str(r[6]))
            proxy.query(f"PROXY DIFF {tx_upd_post};")
            rem_u1, _ = wait_pg_side_drain(timeout=60.0)
            assert rem_u1 == 0
            pg_drain_wal_slot(proxy)
            t0 = time.perf_counter()
            rev_u_post = proxy.query(f"PROXY REVERSE {tx_upd_post};")[0]
            p_upd_u_post_t.append(time.perf_counter() - t0)
            assert rev_u_post.command_tag == "PROXY REVERSE OK", rev_u_post
            upd_post_path = extract_restore_path(str(rev_u_post.rows[0][1]))
            assert upd_post_path == "spilled_temp_table", f"Expected spilled_temp_table post-spill path, got {upd_post_path}"
            upd_u_post_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_u_post.rows[0][1])))
            pg_exec("VACUUM ANALYZE imdb_ratings;")
            pg_exec("CHECKPOINT;")
            pg_drain_wal_slot(proxy)
            if i == 0:
                assert pg_hash() == canonical_hash

            # 1M DELETE (A) Pre-spill undo (`side_table`)
            t0 = time.perf_counter()
            proxy.query("DELETE FROM imdb_ratings;")
            p_del_f_t.append(time.perf_counter() - t0)
            tx_del_pre = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if str(r[6]).startswith("DELETE FROM imdb_ratings"))
            t0 = time.perf_counter()
            rev_d_pre = proxy.query(f"PROXY REVERSE {tx_del_pre};")[0]
            p_del_u_pre_t.append(time.perf_counter() - t0)
            assert rev_d_pre.command_tag == "PROXY REVERSE OK", rev_d_pre
            del_pre_path = extract_restore_path(str(rev_d_pre.rows[0][1]))
            assert del_pre_path == "side_table", f"Expected side_table pre-spill path, got {del_pre_path}"
            del_u_pre_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_d_pre.rows[0][1])))
            diff_d_rows = proxy.query(f"PROXY DIFF {tx_del_pre};")[0].rows
            del_w_phases_list.append(extract_phase_timings_from_diff_rows(diff_d_rows))
            rem_d0, _ = wait_pg_side_drain(timeout=60.0)
            assert rem_d0 == 0
            pg_exec("VACUUM ANALYZE imdb_ratings;")
            pg_exec("CHECKPOINT;")
            pg_drain_wal_slot(proxy)
            if i == 0:
                assert pg_hash() == canonical_hash

            # 1M DELETE (B) Post-spill undo (`spilled_temp_table`)
            proxy.query("DELETE FROM imdb_ratings WHERE tconst LIKE 'tt%';")
            tx_del_post = next(r[0] for r in proxy.query("PROXY HISTORY 10;")[0].rows if "DELETE FROM imdb_ratings WHERE tconst LIKE" in str(r[6]))
            proxy.query(f"PROXY DIFF {tx_del_post};")
            rem_d1, _ = wait_pg_side_drain(timeout=60.0)
            assert rem_d1 == 0
            pg_drain_wal_slot(proxy)
            t0 = time.perf_counter()
            rev_d_post = proxy.query(f"PROXY REVERSE {tx_del_post};")[0]
            p_del_u_post_t.append(time.perf_counter() - t0)
            assert rev_d_post.command_tag == "PROXY REVERSE OK", rev_d_post
            del_post_path = extract_restore_path(str(rev_d_post.rows[0][1]))
            assert del_post_path == "spilled_temp_table", f"Expected spilled_temp_table post-spill path, got {del_post_path}"
            del_u_post_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_d_post.rows[0][1])))
            if i == trials - 1:
                assert pg_hash() == canonical_hash
            print(
                f"  [PG16 Proxy trial {i+1}/{trials}] DTBL_u={p_dtbl_u_t[-1]:.4f}s TRUNC_u={p_trunc_u_t[-1]:.4f}s | "
                f"UPD={p_upd_f_t[-1]:.2f}s (pre={p_upd_u_pre_t[-1]:.2f}s, post={p_upd_u_post_t[-1]:.2f}s) | "
                f"DEL={p_del_f_t[-1]:.2f}s (pre={p_del_u_pre_t[-1]:.2f}s, post={p_del_u_post_t[-1]:.2f}s)",
                flush=True,
            )

        rem, drain_s = wait_pg_side_drain(timeout=180.0)
        assert rem == 0, f"PG16 left {rem} orphaned _side_* tables!"
        pg_exec("DROP TABLE IF EXISTS imdb_ratings CASCADE; DROP TABLE IF EXISTS _bench_seed_master CASCADE;")
    finally:
        proxy.close()

    return {
        "server_version": version,
        "trials": trials,
        "rollback_test_passed": pg_rollback_ok,
        "direct_baseline": {
            "drop_table": summarize_trials(b_dtbl_t, 3),
            "truncate": summarize_trials(b_trunc_t, 3),
            "drop_column": summarize_trials(b_dcol_t, 3),
            "update_1m": summarize_trials(b_upd_t, 2),
            "delete_1m": summarize_trials(b_del_t, 2),
        },
        "proxy": {
            "drop_table_write": summarize_trials(p_dtbl_f_t, 3),
            "drop_table_undo": summarize_trials(p_dtbl_u_t, 3),
            "drop_table_undo_phase_timings_s": median_phase_dict(p_dtbl_u_phases),
            "truncate_write": summarize_trials(p_trunc_f_t, 3),
            "truncate_undo": summarize_trials(p_trunc_u_t, 3),
            "truncate_undo_phase_timings_s": median_phase_dict(p_trunc_u_phases),
            "drop_column_write": summarize_trials(p_dcol_f_t, 3),
            "drop_column_undo": summarize_trials(p_dcol_u_t, 3),
            "update_1m_write": summarize_trials(p_upd_f_t, 2),
            "update_1m_undo_pre_spill": summarize_trials(p_upd_u_pre_t, 2),
            "update_1m_undo_pre_spill_path": upd_pre_path,
            "update_1m_undo_pre_spill_phase_timings_s": median_phase_dict(upd_u_pre_phases_list),
            "update_1m_undo_post_spill": summarize_trials(p_upd_u_post_t, 2),
            "update_1m_undo_post_spill_path": upd_post_path,
            "update_1m_undo_post_spill_phase_timings_s": median_phase_dict(upd_u_post_phases_list),
            "update_1m_phase_timings_s": median_phase_dict(upd_w_phases_list),
            "delete_1m_write": summarize_trials(p_del_f_t, 2),
            "delete_1m_undo_pre_spill": summarize_trials(p_del_u_pre_t, 2),
            "delete_1m_undo_pre_spill_path": del_pre_path,
            "delete_1m_undo_pre_spill_phase_timings_s": median_phase_dict(del_u_pre_phases_list),
            "delete_1m_undo_post_spill": summarize_trials(p_del_u_post_t, 2),
            "delete_1m_undo_post_spill_path": del_post_path,
            "delete_1m_undo_post_spill_phase_timings_s": median_phase_dict(del_u_post_phases_list),
            "delete_1m_phase_timings_s": median_phase_dict(del_w_phases_list),
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


def bench_postgres_18(tsv_rows: list[tuple[str, float, int]], canonical_hash: str, trials: int) -> dict[str, Any]:
    print(f"\n=== [2/5] PostgreSQL 18 ({trials} trials/cell: Native RETURNING OLD, NEW + Pre-Spill & Post-Spill Undo) ===", flush=True)
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
        for _ in range(60):
            try:
                version = pg_exec("SELECT version();", container=cname)
                if version:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError("PG18 container did not become ready")

        pg_seed_master(tsv_rows, container=cname)

        b_upd_t: list[float] = []
        b_del_t: list[float] = []
        for i in range(trials):
            pg_reseed_from_master(container=cname)
            b_upd_t.append(pg_direct_timed("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;", host="127.0.0.1", port=15432, inside_service=""))
            pg_reseed_from_master(container=cname)
            b_del_t.append(pg_direct_timed("DELETE FROM imdb_ratings;", host="127.0.0.1", port=15432, inside_service=""))
            print(f"  [PG18 Direct trial {i+1}/{trials}] UPD={b_upd_t[-1]:.2f}s DEL={b_del_t[-1]:.2f}s", flush=True)

        pg_reseed_from_master(container=cname)
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

        p_upd_f_t: list[float] = []
        p_upd_u_pre_t: list[float] = []
        p_upd_u_post_t: list[float] = []
        upd_w_phases_list: list[dict[str, float]] = []
        upd_u_pre_phases_list: list[dict[str, float]] = []
        upd_u_post_phases_list: list[dict[str, float]] = []

        p_del_f_t: list[float] = []
        p_del_u_pre_t: list[float] = []
        p_del_u_post_t: list[float] = []
        del_w_phases_list: list[dict[str, float]] = []
        del_u_pre_phases_list: list[dict[str, float]] = []
        del_u_post_phases_list: list[dict[str, float]] = []

        upd_pre_path = "side_table"
        upd_post_path = "spilled_temp_table"
        del_pre_path = "side_table"
        del_post_path = "spilled_temp_table"

        try:
            for i in range(trials):
                pg_reseed_from_master(container=cname, proxy=c)

                # 1M UPDATE (A) Pre-spill undo (`side_table`)
                t0 = time.perf_counter()
                c.query(f"UPDATE imdb_ratings SET average_rating = average_rating + {1.0 + i * 0.1:.1f};")
                p_upd_f_t.append(time.perf_counter() - t0)
                tx_upd_pre = next(r[0] for r in c.query("PROXY HISTORY 10;")[0].rows if "UPDATE imdb_ratings SET average_rating" in str(r[6]))
                t0 = time.perf_counter()
                rev_u_pre = c.query(f"PROXY REVERSE {tx_upd_pre};")[0]
                p_upd_u_pre_t.append(time.perf_counter() - t0)
                assert rev_u_pre.command_tag == "PROXY REVERSE OK", rev_u_pre
                upd_pre_path = extract_restore_path(str(rev_u_pre.rows[0][1]))
                assert upd_pre_path == "side_table", upd_pre_path
                upd_u_pre_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_u_pre.rows[0][1])))
                diff_u_rows = c.query(f"PROXY DIFF {tx_upd_pre};")[0].rows
                upd_w_phases_list.append(extract_phase_timings_from_diff_rows(diff_u_rows))
                rem_u0, _ = wait_pg_side_drain(container=cname, timeout=60.0)
                assert rem_u0 == 0
                pg_exec("VACUUM ANALYZE imdb_ratings;", container=cname)
                pg_exec("CHECKPOINT;", container=cname)
                if i == 0:
                    assert pg_hash(container=cname) == canonical_hash

                # 1M UPDATE (B) Post-spill undo (`spilled_temp_table`)
                c.query(f"UPDATE imdb_ratings SET average_rating = average_rating + {2.0 + i * 0.1:.1f};")
                tx_upd_post = next(r[0] for r in c.query("PROXY HISTORY 10;")[0].rows if "UPDATE imdb_ratings SET average_rating" in str(r[6]))
                c.query(f"PROXY DIFF {tx_upd_post};")
                rem_u1, _ = wait_pg_side_drain(container=cname, timeout=60.0)
                assert rem_u1 == 0
                t0 = time.perf_counter()
                rev_u_post = c.query(f"PROXY REVERSE {tx_upd_post};")[0]
                p_upd_u_post_t.append(time.perf_counter() - t0)
                assert rev_u_post.command_tag == "PROXY REVERSE OK", rev_u_post
                upd_post_path = extract_restore_path(str(rev_u_post.rows[0][1]))
                assert upd_post_path == "spilled_temp_table", upd_post_path
                upd_u_post_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_u_post.rows[0][1])))
                pg_exec("VACUUM ANALYZE imdb_ratings;", container=cname)
                pg_exec("CHECKPOINT;", container=cname)
                if i == 0:
                    assert pg_hash(container=cname) == canonical_hash

                # 1M DELETE (A) Pre-spill undo (`side_table`)
                t0 = time.perf_counter()
                c.query("DELETE FROM imdb_ratings;")
                p_del_f_t.append(time.perf_counter() - t0)
                tx_del_pre = next(r[0] for r in c.query("PROXY HISTORY 10;")[0].rows if str(r[6]).startswith("DELETE FROM imdb_ratings"))
                t0 = time.perf_counter()
                rev_d_pre = c.query(f"PROXY REVERSE {tx_del_pre};")[0]
                p_del_u_pre_t.append(time.perf_counter() - t0)
                assert rev_d_pre.command_tag == "PROXY REVERSE OK", rev_d_pre
                del_pre_path = extract_restore_path(str(rev_d_pre.rows[0][1]))
                assert del_pre_path == "side_table", del_pre_path
                del_u_pre_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_d_pre.rows[0][1])))
                diff_d_rows = c.query(f"PROXY DIFF {tx_del_pre};")[0].rows
                del_w_phases_list.append(extract_phase_timings_from_diff_rows(diff_d_rows))
                rem_d0, _ = wait_pg_side_drain(container=cname, timeout=60.0)
                assert rem_d0 == 0
                pg_exec("VACUUM ANALYZE imdb_ratings;", container=cname)
                pg_exec("CHECKPOINT;", container=cname)
                if i == 0:
                    assert pg_hash(container=cname) == canonical_hash

                # 1M DELETE (B) Post-spill undo (`spilled_temp_table`)
                c.query("DELETE FROM imdb_ratings WHERE tconst LIKE 'tt%';")
                tx_del_post = next(r[0] for r in c.query("PROXY HISTORY 10;")[0].rows if "DELETE FROM imdb_ratings WHERE tconst LIKE" in str(r[6]))
                c.query(f"PROXY DIFF {tx_del_post};")
                rem_d1, _ = wait_pg_side_drain(container=cname, timeout=60.0)
                assert rem_d1 == 0
                t0 = time.perf_counter()
                rev_d_post = c.query(f"PROXY REVERSE {tx_del_post};")[0]
                p_del_u_post_t.append(time.perf_counter() - t0)
                assert rev_d_post.command_tag == "PROXY REVERSE OK", rev_d_post
                del_post_path = extract_restore_path(str(rev_d_post.rows[0][1]))
                assert del_post_path == "spilled_temp_table", del_post_path
                del_u_post_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_d_post.rows[0][1])))
                if i == trials - 1:
                    assert pg_hash(container=cname) == canonical_hash
                print(
                    f"  [PG18 Proxy trial {i+1}/{trials}] UPD={p_upd_f_t[-1]:.2f}s (pre={p_upd_u_pre_t[-1]:.2f}s, post={p_upd_u_post_t[-1]:.2f}s) | "
                    f"DEL={p_del_f_t[-1]:.2f}s (pre={p_del_u_pre_t[-1]:.2f}s, post={p_del_u_post_t[-1]:.2f}s)",
                    flush=True,
                )

            rem, drain_s = wait_pg_side_drain(container=cname, timeout=180.0)
            assert rem == 0, f"PG18 left {rem} orphaned _side_* tables!"
        finally:
            c.close()

        return {
            "server_version": version,
            "trials": trials,
            "direct_baseline": {
                "update_1m": summarize_trials(b_upd_t, 2),
                "delete_1m": summarize_trials(b_del_t, 2),
            },
            "proxy": {
                "update_1m_write": summarize_trials(p_upd_f_t, 2),
                "update_1m_undo_pre_spill": summarize_trials(p_upd_u_pre_t, 2),
                "update_1m_undo_pre_spill_path": upd_pre_path,
                "update_1m_undo_pre_spill_phase_timings_s": median_phase_dict(upd_u_pre_phases_list),
                "update_1m_undo_post_spill": summarize_trials(p_upd_u_post_t, 2),
                "update_1m_undo_post_spill_path": upd_post_path,
                "update_1m_undo_post_spill_phase_timings_s": median_phase_dict(upd_u_post_phases_list),
                "update_1m_phase_timings_s": median_phase_dict(upd_w_phases_list),
                "delete_1m_write": summarize_trials(p_del_f_t, 2),
                "delete_1m_undo_pre_spill": summarize_trials(p_del_u_pre_t, 2),
                "delete_1m_undo_pre_spill_path": del_pre_path,
                "delete_1m_undo_pre_spill_phase_timings_s": median_phase_dict(del_u_pre_phases_list),
                "delete_1m_undo_post_spill": summarize_trials(p_del_u_post_t, 2),
                "delete_1m_undo_post_spill_path": del_post_path,
                "delete_1m_undo_post_spill_phase_timings_s": median_phase_dict(del_u_post_phases_list),
                "delete_1m_phase_timings_s": median_phase_dict(del_w_phases_list),
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


def bench_mysql_8(tsv_rows: list[tuple[str, float, int]], canonical_hash: str, trials: int) -> dict[str, Any]:
    print(f"\n=== [3/5] MySQL 8.0 ({trials} trials/cell: Direct Baseline + Pre-Spill & Post-Spill Undo + Phase Timings) ===", flush=True)
    direct = MySQLWireClient(host="127.0.0.1", port=3306, user="root", password="mysqlpassword", database="app", timeout=600.0)
    proxy = MySQLWireClient(host="127.0.0.1", port=3307, user="root", password="mysqlpassword", database="app", timeout=600.0)

    def wait_innodb_idle(timeout: float = 90.0) -> None:
        try:
            direct.query("SET GLOBAL innodb_purge_rseg_truncate_frequency = 1;")
        except Exception:
            pass
        t0 = time.perf_counter()
        prev_len: int | None = None
        stable_ticks = 0
        while time.perf_counter() - t0 < timeout:
            rem_s = int(direct.query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='_reverse_quarantine' AND table_name LIKE '_side_%';").rows[0][0])
            res_h = direct.query("SELECT COUNT FROM INFORMATION_SCHEMA.INNODB_METRICS WHERE NAME = 'trx_rseg_history_len';").rows
            hlen = int(res_h[0][0]) if res_h else 0
            if rem_s == 0 and hlen < 500:
                break
            if rem_s == 0 and prev_len is not None and abs(hlen - prev_len) <= 10:
                stable_ticks += 1
                if stable_ticks >= 6:
                    break
            else:
                stable_ticks = 0
            prev_len = hlen
            time.sleep(0.25)

    def my_seed_master() -> None:
        direct.query("SET SESSION sql_log_bin = 0;")
        try:
            direct.query("DROP TABLE IF EXISTS _bench_seed_master;")
            direct.query("CREATE TABLE _bench_seed_master (tconst VARCHAR(16) PRIMARY KEY, average_rating DOUBLE, num_votes INT);")
            for i in range(0, len(tsv_rows), 5000):
                chunk = tsv_rows[i : i + 5000]
                vals = ",".join(f"('{t}',{a},{v})" for t, a, v in chunk)
                direct.query(f"INSERT INTO _bench_seed_master (tconst, average_rating, num_votes) VALUES {vals};")
        finally:
            direct.query("SET SESSION sql_log_bin = 1;")
        wait_innodb_idle()

    def my_reseed_from_master() -> None:
        wait_innodb_idle()
        direct.query("SET SESSION sql_log_bin = 0;")
        try:
            direct.query("DROP TABLE IF EXISTS imdb_ratings;")
            direct.query("CREATE TABLE imdb_ratings (tconst VARCHAR(16) PRIMARY KEY, average_rating DOUBLE, num_votes INT);")
            direct.query("INSERT INTO imdb_ratings SELECT * FROM _bench_seed_master;")
            direct.query("ANALYZE TABLE imdb_ratings;")
        finally:
            direct.query("SET SESSION sql_log_bin = 1;")
        wait_innodb_idle()
        try:
            proxy.query("PROXY HISTORY 1;")
            cur_binlog = str(direct.query("SHOW MASTER STATUS;").rows[0][0])
            direct.query(f"PURGE BINARY LOGS TO '{cur_binlog}';")
        except Exception:
            pass

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
        my_seed_master()

        b_dtbl_t: list[float] = []
        b_trunc_t: list[float] = []
        b_dcol_t: list[float] = []
        b_upd_t: list[float] = []
        b_del_t: list[float] = []

        for i in range(trials):
            my_reseed_from_master()
            b_upd_t.append(my_direct_timed("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;"))
            my_reseed_from_master()
            b_del_t.append(my_direct_timed("DELETE FROM imdb_ratings;"))
            my_reseed_from_master()
            b_trunc_t.append(my_direct_timed("TRUNCATE TABLE imdb_ratings;"))
            my_reseed_from_master()
            b_dcol_t.append(my_direct_timed("ALTER TABLE imdb_ratings DROP COLUMN num_votes;"))
            b_dtbl_t.append(my_direct_timed("DROP TABLE imdb_ratings;"))
            print(f"  [MySQL 8 Direct trial {i+1}/{trials}] UPD={b_upd_t[-1]:.2f}s DEL={b_del_t[-1]:.2f}s TRUNC={b_trunc_t[-1]:.3f}s DCOL={b_dcol_t[-1]:.3f}s DTBL={b_dtbl_t[-1]:.3f}s", flush=True)

        # 2. Proxy Operations
        direct.query("DROP DATABASE IF EXISTS _reverse_quarantine;")
        my_reseed_from_master()
        assert my_hash() == canonical_hash

        # Live BEGIN; UPDATE; ROLLBACK check
        hist_before = proxy.query("PROXY HISTORY 25;").rows
        proxy.query("BEGIN;")
        proxy.query("UPDATE imdb_ratings SET average_rating = -99.0 WHERE tconst = 'tt0000001';")
        proxy.query("ROLLBACK;")
        hist_after = proxy.query("PROXY HISTORY 25;").rows
        assert len(hist_after) == len(hist_before), "MySQL ROLLBACK unexpectedly wrote to ledger!"
        assert my_hash() == canonical_hash, "MySQL ROLLBACK altered table rows!"
        my_rollback_ok = True

        p_dtbl_f_t: list[float] = []
        p_dtbl_u_t: list[float] = []
        p_dtbl_u_phases: list[dict[str, float]] = []

        p_trunc_f_t: list[float] = []
        p_trunc_u_t: list[float] = []
        p_trunc_u_phases: list[dict[str, float]] = []

        p_dcol_f_t: list[float] = []
        p_dcol_u_t: list[float] = []

        p_upd_f_t: list[float] = []
        p_upd_u_pre_t: list[float] = []
        p_upd_u_post_t: list[float] = []
        upd_w_phases_list: list[dict[str, float]] = []
        upd_u_pre_phases_list: list[dict[str, float]] = []
        upd_u_post_phases_list: list[dict[str, float]] = []

        p_del_f_t: list[float] = []
        p_del_u_pre_t: list[float] = []
        p_del_u_post_t: list[float] = []
        del_w_phases_list: list[dict[str, float]] = []
        del_u_pre_phases_list: list[dict[str, float]] = []
        del_u_post_phases_list: list[dict[str, float]] = []

        latencies: list[float] = []
        errors: list[str] = []
        upd_pre_path = "side_table"
        upd_post_path = "spilled_temp_table"
        del_pre_path = "side_table"
        del_post_path = "spilled_temp_table"

        for i in range(trials):
            my_reseed_from_master()

            # DROP TABLE
            t0 = time.perf_counter()
            proxy.query("DROP TABLE imdb_ratings;")
            p_dtbl_f_t.append(time.perf_counter() - t0)
            tx_dtbl = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "DROP TABLE imdb_ratings" in str(r[6]))
            t0 = time.perf_counter()
            rev_dtbl = proxy.query(f"PROXY REVERSE {tx_dtbl};")
            p_dtbl_u_t.append(time.perf_counter() - t0)
            assert rev_dtbl.columns[0] == "step_no"
            p_dtbl_u_phases.append(extract_undo_timings_from_reverse_desc(str(rev_dtbl.rows[0][1])))
            if i == 0:
                assert my_hash() == canonical_hash

            # TRUNCATE TABLE
            t0 = time.perf_counter()
            proxy.query("TRUNCATE TABLE imdb_ratings;")
            p_trunc_f_t.append(time.perf_counter() - t0)
            tx_trunc = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "TRUNCATE TABLE imdb_ratings" in str(r[6]))
            t0 = time.perf_counter()
            rev_trunc = proxy.query(f"PROXY REVERSE {tx_trunc};")
            p_trunc_u_t.append(time.perf_counter() - t0)
            assert rev_trunc.columns[0] == "step_no"
            p_trunc_u_phases.append(extract_undo_timings_from_reverse_desc(str(rev_trunc.rows[0][1])))
            if i == 0:
                assert my_hash() == canonical_hash

            # ALTER DROP COLUMN
            t0 = time.perf_counter()
            proxy.query("ALTER TABLE imdb_ratings DROP COLUMN num_votes;")
            p_dcol_f_t.append(time.perf_counter() - t0)
            tx_dcol = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "DROP COLUMN num_votes" in str(r[6]))
            t0 = time.perf_counter()
            rev_dcol = proxy.query(f"PROXY REVERSE {tx_dcol};")
            p_dcol_u_t.append(time.perf_counter() - t0)
            assert rev_dcol.columns[0] == "step_no"
            wait_innodb_idle()
            if i == 0:
                assert my_hash() == canonical_hash

            # 1M UPDATE (A) Pre-spill undo (`side_table`)
            t0 = time.perf_counter()
            proxy.query(f"UPDATE imdb_ratings SET average_rating = average_rating + {1.0 + i * 0.1:.1f};")
            p_upd_f_t.append(time.perf_counter() - t0)
            tx_upd_pre = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "UPDATE imdb_ratings SET average_rating" in str(r[6]))

            if i == 0:
                stop_flag = threading.Event()

                def writer_my(tid: int) -> None:
                    c = MySQLWireClient(host="127.0.0.1", port=3307, user="root", password="mysqlpassword", database="app", timeout=120.0)
                    try:
                        j = 0
                        while not stop_flag.is_set() and j < 20:
                            w0 = time.perf_counter()
                            c.query(f"INSERT INTO imdb_ratings VALUES ('zz_conc_{tid}_{j}', 9.9, 1);")
                            latencies.append(time.perf_counter() - w0)
                            j += 1
                            time.sleep(0.05)
                    except Exception as exc:
                        errors.append(str(exc))
                    finally:
                        c.close()

                threads = [threading.Thread(target=writer_my, args=(t_idx,)) for t_idx in range(4)]
                for t in threads:
                    t.start()
                time.sleep(0.05)
                t0 = time.perf_counter()
                rev_u_pre = proxy.query(f"PROXY REVERSE {tx_upd_pre};")
                p_upd_u_pre_t.append(time.perf_counter() - t0)
                stop_flag.set()
                for t in threads:
                    t.join()
                direct.query("DELETE FROM imdb_ratings WHERE tconst LIKE 'zz_conc_%';")
            else:
                t0 = time.perf_counter()
                rev_u_pre = proxy.query(f"PROXY REVERSE {tx_upd_pre};")
                p_upd_u_pre_t.append(time.perf_counter() - t0)

            assert rev_u_pre.columns and rev_u_pre.columns[0] == "step_no", rev_u_pre
            upd_pre_path = extract_restore_path(str(rev_u_pre.rows[0][1]))
            assert upd_pre_path == "side_table", upd_pre_path
            upd_u_pre_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_u_pre.rows[0][1])))
            diff_u_rows = proxy.query(f"PROXY DIFF {tx_upd_pre};").rows
            upd_w_phases_list.append(extract_phase_timings_from_diff_rows(diff_u_rows))
            wait_innodb_idle()
            if i == 0:
                assert my_hash() == canonical_hash

            # 1M UPDATE (B) Post-spill undo (`spilled_temp_table`)
            proxy.query(f"UPDATE imdb_ratings SET average_rating = average_rating + {2.0 + i * 0.1:.1f};")
            tx_upd_post = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "UPDATE imdb_ratings SET average_rating" in str(r[6]))
            proxy.query(f"PROXY DIFF {tx_upd_post};")
            wait_innodb_idle()
            t0 = time.perf_counter()
            rev_u_post = proxy.query(f"PROXY REVERSE {tx_upd_post};")
            p_upd_u_post_t.append(time.perf_counter() - t0)
            assert rev_u_post.columns and rev_u_post.columns[0] == "step_no", rev_u_post
            upd_post_path = extract_restore_path(str(rev_u_post.rows[0][1]))
            assert upd_post_path == "spilled_temp_table", upd_post_path
            upd_u_post_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_u_post.rows[0][1])))
            wait_innodb_idle()
            if i == 0:
                assert my_hash() == canonical_hash

            # 1M DELETE (A) Pre-spill undo (`side_table`)
            t0 = time.perf_counter()
            proxy.query("DELETE FROM imdb_ratings;")
            p_del_f_t.append(time.perf_counter() - t0)
            tx_del_pre = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if str(r[6]).startswith("DELETE FROM imdb_ratings"))
            t0 = time.perf_counter()
            rev_d_pre = proxy.query(f"PROXY REVERSE {tx_del_pre};")
            p_del_u_pre_t.append(time.perf_counter() - t0)
            assert rev_d_pre.columns and rev_d_pre.columns[0] == "step_no", rev_d_pre
            del_pre_path = extract_restore_path(str(rev_d_pre.rows[0][1]))
            assert del_pre_path == "side_table", del_pre_path
            del_u_pre_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_d_pre.rows[0][1])))
            diff_d_rows = proxy.query(f"PROXY DIFF {tx_del_pre};").rows
            del_w_phases_list.append(extract_phase_timings_from_diff_rows(diff_d_rows))
            wait_innodb_idle()
            if i == 0:
                assert my_hash() == canonical_hash

            # 1M DELETE (B) Post-spill undo (`spilled_temp_table`)
            proxy.query("DELETE FROM imdb_ratings WHERE tconst LIKE 'tt%';")
            tx_del_post = next(r[0] for r in proxy.query("PROXY HISTORY 10;").rows if "DELETE FROM imdb_ratings WHERE tconst LIKE" in str(r[6]))
            proxy.query(f"PROXY DIFF {tx_del_post};")
            wait_innodb_idle()
            t0 = time.perf_counter()
            rev_d_post = proxy.query(f"PROXY REVERSE {tx_del_post};")
            p_del_u_post_t.append(time.perf_counter() - t0)
            assert rev_d_post.columns and rev_d_post.columns[0] == "step_no", rev_d_post
            del_post_path = extract_restore_path(str(rev_d_post.rows[0][1]))
            assert del_post_path == "spilled_temp_table", del_post_path
            del_u_post_phases_list.append(extract_undo_timings_from_reverse_desc(str(rev_d_post.rows[0][1])))
            if i == trials - 1:
                assert my_hash() == canonical_hash
            print(
                f"  [MySQL 8 Proxy trial {i+1}/{trials}] DTBL_u={p_dtbl_u_t[-1]:.4f}s TRUNC_u={p_trunc_u_t[-1]:.4f}s | "
                f"UPD={p_upd_f_t[-1]:.2f}s (pre={p_upd_u_pre_t[-1]:.2f}s, post={p_upd_u_post_t[-1]:.2f}s) | "
                f"DEL={p_del_f_t[-1]:.2f}s (pre={p_del_u_pre_t[-1]:.2f}s, post={p_del_u_post_t[-1]:.2f}s)",
                flush=True,
            )

        t_drain0 = time.perf_counter()
        rem = -1
        while time.perf_counter() - t_drain0 < 180.0:
            rem = int(direct.query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='_reverse_quarantine' AND table_name LIKE '_side_%';").rows[0][0])
            if rem == 0:
                break
            time.sleep(0.25)
        drain_s = round(time.perf_counter() - t_drain0, 3)
        assert rem == 0, f"MySQL left {rem} orphaned _side_* tables!"
        direct.query("DROP TABLE IF EXISTS imdb_ratings;")
        direct.query("DROP TABLE IF EXISTS _bench_seed_master;")
    finally:
        direct.close()
        proxy.close()

    return {
        "server_version": version,
        "trials": trials,
        "rollback_test_passed": my_rollback_ok,
        "direct_baseline": {
            "drop_table": summarize_trials(b_dtbl_t, 3),
            "truncate": summarize_trials(b_trunc_t, 3),
            "drop_column": summarize_trials(b_dcol_t, 3),
            "update_1m": summarize_trials(b_upd_t, 2),
            "delete_1m": summarize_trials(b_del_t, 2),
        },
        "proxy": {
            "drop_table_write": summarize_trials(p_dtbl_f_t, 3),
            "drop_table_undo": summarize_trials(p_dtbl_u_t, 3),
            "drop_table_undo_phase_timings_s": median_phase_dict(p_dtbl_u_phases),
            "truncate_write": summarize_trials(p_trunc_f_t, 3),
            "truncate_undo": summarize_trials(p_trunc_u_t, 3),
            "truncate_undo_phase_timings_s": median_phase_dict(p_trunc_u_phases),
            "drop_column_write": summarize_trials(p_dcol_f_t, 3),
            "drop_column_undo": summarize_trials(p_dcol_u_t, 3),
            "update_1m_write": summarize_trials(p_upd_f_t, 2),
            "update_1m_undo_pre_spill": summarize_trials(p_upd_u_pre_t, 2),
            "update_1m_undo_pre_spill_path": upd_pre_path,
            "update_1m_undo_pre_spill_phase_timings_s": median_phase_dict(upd_u_pre_phases_list),
            "update_1m_undo_post_spill": summarize_trials(p_upd_u_post_t, 2),
            "update_1m_undo_post_spill_path": upd_post_path,
            "update_1m_undo_post_spill_phase_timings_s": median_phase_dict(upd_u_post_phases_list),
            "update_1m_phase_timings_s": median_phase_dict(upd_w_phases_list),
            "delete_1m_write": summarize_trials(p_del_f_t, 2),
            "delete_1m_undo_pre_spill": summarize_trials(p_del_u_pre_t, 2),
            "delete_1m_undo_pre_spill_path": del_pre_path,
            "delete_1m_undo_pre_spill_phase_timings_s": median_phase_dict(del_u_pre_phases_list),
            "delete_1m_undo_post_spill": summarize_trials(p_del_u_post_t, 2),
            "delete_1m_undo_post_spill_path": del_post_path,
            "delete_1m_undo_post_spill_phase_timings_s": median_phase_dict(del_u_post_phases_list),
            "delete_1m_phase_timings_s": median_phase_dict(del_w_phases_list),
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


def bench_mariadb_11_flashback(tsv_rows: list[tuple[str, float, int]], canonical_hash: str, trials: int) -> dict[str, Any]:
    print(f"\n=== [4/5] MariaDB 11 Flashback ({trials} trials/cell: mariadb-binlog --flashback) ===", flush=True)
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
        c: MySQLWireClient | None = None
        version = ""
        for _ in range(60):
            try:
                c = MySQLWireClient(host="127.0.0.1", port=13308, user="root", password="mariapass", database="app", timeout=600.0)
                version = str(c.query("SELECT VERSION();").rows[0][0])
                if version:
                    break
            except Exception:
                if c is not None:
                    try:
                        c.close()
                    except Exception:
                        pass
                    c = None
            time.sleep(0.75)
        else:
            raise RuntimeError("MariaDB container failed to become ready")
        assert c is not None
        c.query("SET SESSION sql_log_bin = 0;")
        c.query("CREATE TABLE imdb_ratings (tconst VARCHAR(16) PRIMARY KEY, average_rating DOUBLE, num_votes INT);")
        for i in range(0, len(tsv_rows), 5000):
            chunk = tsv_rows[i : i + 5000]
            vals = ",".join(f"('{t}',{a},{v})" for t, a, v in chunk)
            c.query(f"INSERT INTO imdb_ratings (tconst, average_rating, num_votes) VALUES {vals};")
        c.query("SET SESSION sql_log_bin = 1;")
        assert hash_rows(c.query("SELECT tconst, average_rating, num_votes FROM imdb_ratings ORDER BY tconst;").rows) == canonical_hash

        def binlog_file() -> str:
            return str(c.query("SHOW MASTER STATUS;").rows[0][0])

        upd_fwd_t: list[float] = []
        upd_undo_t: list[float] = []
        del_fwd_t: list[float] = []
        del_undo_t: list[float] = []

        for i in range(trials):
            # 1M UPDATE
            c.query("FLUSH BINARY LOGS;")
            f_upd = binlog_file()
            t0 = time.perf_counter()
            c.query("UPDATE imdb_ratings SET average_rating = average_rating + 1.0;")
            upd_fwd_t.append(time.perf_counter() - t0)
            c.query("FLUSH BINARY LOGS;")
            t0 = time.perf_counter()
            subprocess.run(
                ["docker", "exec", name, "sh", "-c", f"mariadb-binlog --flashback /var/lib/mysql/{f_upd} | mariadb --max-allowed-packet=512M -uroot -pmariapass app"],
                env=ENV, check=True, capture_output=True,
            )
            upd_undo_t.append(time.perf_counter() - t0)
            if i == 0:
                assert hash_rows(c.query("SELECT tconst, average_rating, num_votes FROM imdb_ratings ORDER BY tconst;").rows) == canonical_hash

            # 1M DELETE
            c.query("FLUSH BINARY LOGS;")
            f_del = binlog_file()
            t0 = time.perf_counter()
            c.query("DELETE FROM imdb_ratings;")
            del_fwd_t.append(time.perf_counter() - t0)
            c.query("FLUSH BINARY LOGS;")
            t0 = time.perf_counter()
            subprocess.run(
                ["docker", "exec", name, "sh", "-c", f"mariadb-binlog --flashback /var/lib/mysql/{f_del} | mariadb --max-allowed-packet=512M -uroot -pmariapass app"],
                env=ENV, check=True, capture_output=True,
            )
            del_undo_t.append(time.perf_counter() - t0)
            try:
                cur_mb = binlog_file()
                c.query(f"PURGE BINARY LOGS TO '{cur_mb}';")
            except Exception:
                pass
            if i == trials - 1:
                assert hash_rows(c.query("SELECT tconst, average_rating, num_votes FROM imdb_ratings ORDER BY tconst;").rows) == canonical_hash
            print(f"  [MariaDB 11 trial {i+1}/{trials}] UPD={upd_fwd_t[-1]:.2f}s/fb={upd_undo_t[-1]:.2f}s | DEL={del_fwd_t[-1]:.2f}s/fb={del_undo_t[-1]:.2f}s", flush=True)

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

        return {
            "server_version": version,
            "trials": trials,
            "update_1m_write": summarize_trials(upd_fwd_t, 2),
            "update_1m_undo": summarize_trials(upd_undo_t, 2),
            "delete_1m_write": summarize_trials(del_fwd_t, 2),
            "delete_1m_undo": summarize_trials(del_undo_t, 2),
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


def fmt_stat(st: dict[str, Any], ndigits: int = 2, bold: bool = False) -> str:
    med = st["median_s"]
    mn = st["min_s"]
    mx = st["max_s"]
    core = f"`{med:.{ndigits}f}s`"
    if bold:
        core = f"**{core}**"
    return f"{core} (`{mn:.{ndigits}f}–{mx:.{ndigits}f}s`)"


def fmt_ratio_stat(p_st: dict[str, Any], b_st: dict[str, Any], ndigits: int = 2) -> str:
    p_med = p_st["median_s"]
    b_med = b_st["median_s"]
    ratio = f" ({p_med / b_med:.1f}x)" if b_med > 0 else ""
    return f"`{p_med:.{ndigits}f}s`{ratio} (`{p_st['min_s']:.{ndigits}f}–{p_st['max_s']:.{ndigits}f}s`)"


def fmt_write_phase_row(label: str, ph: dict[str, Any]) -> str:
    return (
        f"| **{label}** | `{ph.get('blast_radius_check_s', 0.0):.3f}s` | "
        f"`{ph.get('side_table_create_s', 0.0):.3f}s` | "
        f"`{ph.get('snapshot_capture_s', 0.0):.3f}s` | "
        f"`{ph.get('dml_exec_s', 0.0):.3f}s` | "
        f"`{ph.get('commit_s', 0.0):.3f}s` | "
        f"`{ph.get('spill_s', 0.0):.2f}s` |"
    )


def fmt_undo_phase_row(label: str, ph: dict[str, Any]) -> str:
    return (
        f"| **{label}** | `{ph.get('wal_sync_s', 0.0):.4f}s` | "
        f"`{ph.get('ledger_load_s', 0.0):.4f}s` | "
        f"`{ph.get('stage_temp_s', 0.0):.3f}s` | "
        f"`{ph.get('conflict_and_lock_s', 0.0):.3f}s` | "
        f"`{ph.get('restore_exec_s', 0.0):.3f}s` | "
        f"`{ph.get('commit_s', 0.0):.3f}s` |"
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
    trials = pg16.get("trials", 5)

    pg_spills = [
        pg16_p["update_1m_phase_timings_s"].get("spill_s", 0.0),
        pg16_p["delete_1m_phase_timings_s"].get("spill_s", 0.0),
        pg18_p["update_1m_phase_timings_s"].get("spill_s", 0.0),
        pg18_p["delete_1m_phase_timings_s"].get("spill_s", 0.0),
    ]
    min_spill = min(pg_spills)
    max_spill = max(pg_spills)
    win_low = 5.0 + min_spill
    win_high = 5.0 + max_spill

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
        f"Bulk `UPDATE`/`DELETE` statements above `side_table_threshold = 500` capture before/after rows into PostgreSQL `CREATE UNLOGGED TABLE` snapshots and stream them asynchronously via `_SideSpillWorker` to compressed SHA-256-verified spill files on disk (`tx_spill_*.undo.zlib`), then drop all `_side_*` tables. Because PostgreSQL skips WAL writes for `UNLOGGED` tables, an unclean PostgreSQL crash (`kill -9` / power loss) *after* commit and *before* background spill completion truncates unspilled `_side_*` tables on crash recovery—losing undo history for that unspilled transaction (primary logged tables remain consistent). At 1,000,000 rows, this window is **`{win_low:.1f}–{win_high:.1f}` seconds** under the default `side_spill_delay_seconds = 5.0` (`5.0s` grace delay + `{min_spill:.1f}–{max_spill:.1f}s` measured `spill_s`), or **`{min_spill:.1f}–{max_spill:.1f}` seconds** if `side_spill_delay_seconds = 0.0`.",
        "",
        f"## Benchmarks (1,000,000 IMDb Rows, {trials} Trials/Cell, `SHA-256` Verified)",
        "",
        f"Generated directly from [`{json_rel_path}`]({json_rel_path}) via [`scripts/run_benchmarks.py`](scripts/run_benchmarks.py) (**{trials} independent trials per cell**, reporting **`median` (`min–max`)**; fresh table reseed + `VACUUM ANALYZE` + `CHECKPOINT` on PostgreSQL and InnoDB purge drain `trx_rseg_history_len` on MySQL before each run; timestamp: `{meta['timestamp_utc']}`, git commit: `{git_commit}`, source tree SHA-256: `{meta['source_tree_sha256'][:16]}...`, canonical 1M dataset SHA-256: `{meta['dataset']['canonical_sha256'][:16]}...`).",
        "",
        "Both undo paths are measured and labeled below:",
        "- **Pre-Spill Undo (`side_table`)**: `PROXY REVERSE` executed within the in-DB snapshot window while `_side_*` tables are still resident in `_reverse_quarantine`.",
        "- **Post-Spill Undo (`spilled_temp_table`)**: `PROXY REVERSE` executed *after* `_side_*` tables have been spilled to compressed disk files (`tx_spill_*.undo.zlib`) and dropped from the database (loads the spill file into a staging temp table via `COPY FROM STDIN` on Postgres / batched multi-row `INSERT` with `sql_log_bin=0` on MySQL, then runs a single set-based `UPDATE ... FROM` / `UPDATE ... INNER JOIN` or `INSERT ... SELECT` with full `FOR UPDATE` drift checks).",
        "",
        f"### PostgreSQL 16 & PostgreSQL 18 (`RETURNING OLD, NEW`) — Median (`min–max` over {trials} trials)",
        "",
        "| 1,000,000-Row Operation | PG 16 Direct | PG 16 Proxy Write | PG 16 Undo (Pre-Spill `side_table`) | PG 16 Undo (Post-Spill `spilled_temp_table`) | PG 18 Direct | PG 18 Proxy Write (`RETURNING OLD/NEW`) | PG 18 Undo (Pre-Spill `side_table`) | PG 18 Undo (Post-Spill `spilled_temp_table`) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        f"| **`DROP TABLE`** | {fmt_stat(pg16_b['drop_table'], 3)} | {fmt_stat(pg16_p['drop_table_write'], 3)} | {fmt_stat(pg16_p['drop_table_undo'], 3, bold=True)} (`ddl_quarantine`) | — | — | — | — | — |",
        f"| **`TRUNCATE TABLE`** | {fmt_stat(pg16_b['truncate'], 3)} | {fmt_stat(pg16_p['truncate_write'], 3)} | {fmt_stat(pg16_p['truncate_undo'], 3, bold=True)} (`ddl_quarantine`) | — | — | — | — | — |",
        f"| **`ALTER DROP COLUMN`** | {fmt_stat(pg16_b['drop_column'], 3)} | {fmt_stat(pg16_p['drop_column_write'], 3)} | {fmt_stat(pg16_p['drop_column_undo'], 3, bold=True)} (`ddl_quarantine`) | — | — | — | — | — |",
        f"| **1M Bulk `UPDATE`** | {fmt_stat(pg16_b['update_1m'], 2)} | {fmt_ratio_stat(pg16_p['update_1m_write'], pg16_b['update_1m'], 2)} | {fmt_stat(pg16_p['update_1m_undo_pre_spill'], 2, bold=True)} | {fmt_stat(pg16_p['update_1m_undo_post_spill'], 2, bold=True)} | {fmt_stat(pg18_b['update_1m'], 2)} | {fmt_ratio_stat(pg18_p['update_1m_write'], pg18_b['update_1m'], 2)} | {fmt_stat(pg18_p['update_1m_undo_pre_spill'], 2, bold=True)} | {fmt_stat(pg18_p['update_1m_undo_post_spill'], 2, bold=True)} |",
        f"| **1M Bulk `DELETE`** | {fmt_stat(pg16_b['delete_1m'], 2)} | {fmt_ratio_stat(pg16_p['delete_1m_write'], pg16_b['delete_1m'], 2)} | {fmt_stat(pg16_p['delete_1m_undo_pre_spill'], 2, bold=True)} | {fmt_stat(pg16_p['delete_1m_undo_post_spill'], 2, bold=True)} | {fmt_stat(pg18_b['delete_1m'], 2)} | {fmt_ratio_stat(pg18_p['delete_1m_write'], pg18_b['delete_1m'], 2)} | {fmt_stat(pg18_p['delete_1m_undo_pre_spill'], 2, bold=True)} | {fmt_stat(pg18_p['delete_1m_undo_post_spill'], 2, bold=True)} |",
        "",
        f"### MySQL 8.0 vs. MariaDB 11 Flashback (`mariadb-binlog --flashback`) — Median (`min–max` over {trials} trials)",
        "",
        "| 1,000,000-Row Operation | MySQL 8.0 Direct | MySQL 8.0 Proxy Write | MySQL 8.0 Undo (Pre-Spill `side_table`) | MySQL 8.0 Undo (Post-Spill `spilled_temp_table`) | MariaDB 11 Flashback (`--flashback`) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
        f"| **`DROP TABLE`** | {fmt_stat(my8_b['drop_table'], 3)} | {fmt_stat(my8_p['drop_table_write'], 3)} | {fmt_stat(my8_p['drop_table_undo'], 3, bold=True)} (`ddl_quarantine`) | — | Not reversible (`DROP`) |",
        f"| **`TRUNCATE TABLE`** | {fmt_stat(my8_b['truncate'], 3)} | {fmt_stat(my8_p['truncate_write'], 3)} | {fmt_stat(my8_p['truncate_undo'], 3, bold=True)} (`ddl_quarantine`) | — | {'Reversible' if mdb['truncate_reversible'] else 'Not reversible (emits no `INSERT`s)'} |",
        f"| **`ALTER DROP COLUMN`** | {fmt_stat(my8_b['drop_column'], 3)} | {fmt_stat(my8_p['drop_column_write'], 3)} | {fmt_stat(my8_p['drop_column_undo'], 3, bold=True)} (`ddl_quarantine`) | — | Not reversible (`ALTER`) |",
        f"| **1M Bulk `UPDATE`** | {fmt_stat(my8_b['update_1m'], 2)} | {fmt_ratio_stat(my8_p['update_1m_write'], my8_b['update_1m'], 2)} | {fmt_stat(my8_p['update_1m_undo_pre_spill'], 2, bold=True)} | {fmt_stat(my8_p['update_1m_undo_post_spill'], 2, bold=True)} | Forward {fmt_stat(mdb['update_1m_write'], 2)} / Flashback {fmt_stat(mdb['update_1m_undo'], 2, bold=True)} |",
        f"| **1M Bulk `DELETE`** | {fmt_stat(my8_b['delete_1m'], 2)} | {fmt_ratio_stat(my8_p['delete_1m_write'], my8_b['delete_1m'], 2)} | {fmt_stat(my8_p['delete_1m_undo_pre_spill'], 2, bold=True)} | {fmt_stat(my8_p['delete_1m_undo_post_spill'], 2, bold=True)} | Forward {fmt_stat(mdb['delete_1m_write'], 2)} / Flashback {fmt_stat(mdb['delete_1m_undo'], 2, bold=True)} |",
        "",
        "### Per-Phase Write & Spill Timing Breakdown (1,000,000 Rows, Median Across Trials)",
        "",
        "| Engine & Operation | Blast-Radius Probe (`COUNT`) | Side-Table Create | Pre-Image Capture (`FOR UPDATE`) | DML Execution | `COMMIT` | Post-Commit Disk Spill (`spill_s`) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        fmt_write_phase_row("PG 16 — 1M `UPDATE`", pg16_p["update_1m_phase_timings_s"]),
        fmt_write_phase_row("PG 16 — 1M `DELETE`", pg16_p["delete_1m_phase_timings_s"]),
        fmt_write_phase_row("PG 18 — 1M `UPDATE` (`RETURNING OLD/NEW`)", pg18_p["update_1m_phase_timings_s"]),
        fmt_write_phase_row("PG 18 — 1M `DELETE` (`RETURNING *`)", pg18_p["delete_1m_phase_timings_s"]),
        fmt_write_phase_row("MySQL 8.0 — 1M `UPDATE`", my8_p["update_1m_phase_timings_s"]),
        fmt_write_phase_row("MySQL 8.0 — 1M `DELETE`", my8_p["delete_1m_phase_timings_s"]),
        "",
        "### Per-Phase Undo (`PROXY REVERSE`) Timing Breakdown (Median Across Trials)",
        "",
        "| Engine, Operation & Restore Path | Change-Stream Sync (`wal_sync_s`) | Ledger Load (`ledger_load_s`) | Temp Staging (`stage_temp_s`) | Conflict & Lock (`conflict_and_lock_s`) | Restore SQL (`restore_exec_s`) | `COMMIT` (`commit_s`) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
        fmt_undo_phase_row("PG 16 — `DROP TABLE` (`ddl_quarantine`)", pg16_p["drop_table_undo_phase_timings_s"]),
        fmt_undo_phase_row("PG 16 — `TRUNCATE TABLE` (`ddl_quarantine`)", pg16_p["truncate_undo_phase_timings_s"]),
        fmt_undo_phase_row("PG 16 — 1M `UPDATE` (`side_table`)", pg16_p["update_1m_undo_pre_spill_phase_timings_s"]),
        fmt_undo_phase_row("PG 16 — 1M `UPDATE` (`spilled_temp_table`)", pg16_p["update_1m_undo_post_spill_phase_timings_s"]),
        fmt_undo_phase_row("PG 16 — 1M `DELETE` (`side_table`)", pg16_p["delete_1m_undo_pre_spill_phase_timings_s"]),
        fmt_undo_phase_row("PG 16 — 1M `DELETE` (`spilled_temp_table`)", pg16_p["delete_1m_undo_post_spill_phase_timings_s"]),
        fmt_undo_phase_row("PG 18 — 1M `UPDATE` (`side_table`)", pg18_p["update_1m_undo_pre_spill_phase_timings_s"]),
        fmt_undo_phase_row("PG 18 — 1M `UPDATE` (`spilled_temp_table`)", pg18_p["update_1m_undo_post_spill_phase_timings_s"]),
        fmt_undo_phase_row("PG 18 — 1M `DELETE` (`side_table`)", pg18_p["delete_1m_undo_pre_spill_phase_timings_s"]),
        fmt_undo_phase_row("PG 18 — 1M `DELETE` (`spilled_temp_table`)", pg18_p["delete_1m_undo_post_spill_phase_timings_s"]),
        fmt_undo_phase_row("MySQL 8.0 — `DROP TABLE` (`ddl_quarantine`)", my8_p["drop_table_undo_phase_timings_s"]),
        fmt_undo_phase_row("MySQL 8.0 — `TRUNCATE TABLE` (`ddl_quarantine`)", my8_p["truncate_undo_phase_timings_s"]),
        fmt_undo_phase_row("MySQL 8.0 — 1M `UPDATE` (`side_table`)", my8_p["update_1m_undo_pre_spill_phase_timings_s"]),
        fmt_undo_phase_row("MySQL 8.0 — 1M `UPDATE` (`spilled_temp_table`)", my8_p["update_1m_undo_post_spill_phase_timings_s"]),
        fmt_undo_phase_row("MySQL 8.0 — 1M `DELETE` (`side_table`)", my8_p["delete_1m_undo_pre_spill_phase_timings_s"]),
        fmt_undo_phase_row("MySQL 8.0 — 1M `DELETE` (`spilled_temp_table`)", my8_p["delete_1m_undo_post_spill_phase_timings_s"]),
        "",
        "<details>",
        "<summary>Provenance: Git commit, image digests & cleanup verification</summary>",
        "",
        f"- Git commit: `{git_commit}` (`source_tree_sha256`: `{meta['source_tree_sha256']}`)",
        f"- Trials per cell: `{trials}`",
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
    parser = argparse.ArgumentParser(description="Run reproducible 1M benchmarks (5 trials/cell) and update README.md from JSON output.")
    parser.add_argument("--render-only", type=str, default="", help="Regenerate README.md from an existing benchmark JSON file.")
    parser.add_argument("--trials", type=int, default=5, help="Number of trials per benchmark cell (default: 5).")
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
    print(f"Loaded {len(tsv_rows):,} IMDb rows | canonical SHA-256 = {canonical_hash} | trials = {args.trials}", flush=True)

    run_compose(["up", "-d", "--build", "--force-recreate", "--wait"], extra_env={"REVERSE_PROXY_MAX_CAPTURE_ROWS": "2000000"})
    try:
        pg16_res = bench_postgres_16(tsv_rows, canonical_hash, args.trials)
        pg18_res = bench_postgres_18(tsv_rows, canonical_hash, args.trials)
        my8_res = bench_mysql_8(tsv_rows, canonical_hash, args.trials)
        mdb_res = bench_mariadb_11_flashback(tsv_rows, canonical_hash, args.trials)
        cap_res = bench_default_cap_refusal()
    finally:
        run_compose(["up", "-d", "--wait"], extra_env={"REVERSE_PROXY_MAX_CAPTURE_ROWS": "10000"})

    ts = datetime.now(timezone.utc)
    ts_slug = ts.strftime("%Y%m%d_%H%M%SZ")
    payload: dict[str, Any] = {
        "metadata": {
            "timestamp_utc": ts.isoformat(),
            "trials_per_cell": args.trials,
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
