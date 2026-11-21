# Universal SQL Reverse Proxy

A zero-dependency pure-Python database reverse proxy providing a universal **"Ctrl+Z" (`PROXY REVERSE`)** for SQL mutations across **PostgreSQL**, **MySQL**, and **SQLite**—with wire-protocol frontends (`pgwire` v3 and MySQL 8 `caching_sha2_password` / `mysql_native_password`), WAL & binlog background trigger capture, causal cascade undo, drift detection, DDL quarantine, and a built-in Web Control Plane UI.

## Key Capabilities

- **Multi-Engine Wire Proxies**:
  - `PgWireServer` (`reverse_proxy/frontends/pgwire_server.py`) — PostgreSQL v3 wire protocol (`SimpleQuery` + `Parse/Bind/Describe/Execute`, TLS, MD5/SCRAM-SHA-256 auth, `NoticeResponse` `tx_id` notifications)
  - `MySQLServer` (`reverse_proxy/frontends/mysql_server.py`) — MySQL 8 wire protocol (`Handshake v10`, `caching_sha2_password` + `mysql_native_password`, `COM_QUERY`, `OK_Packet` `tx_id` info)
- **Complete DML, Join, Upsert & DDL Quarantine Symmetry**:
  - `INSERT` (including `ON CONFLICT` / `ON DUPLICATE KEY UPDATE` / `REPLACE INTO` / `INSERT OR REPLACE` mixed upserts)
  - `UPDATE` (including Postgres `UPDATE ... FROM` & MySQL `UPDATE ... JOIN`)
  - `DELETE` (including Postgres `DELETE ... USING`, MySQL `DELETE t FROM t JOIN ...`, and recursive `ON DELETE CASCADE` capture)
  - `MERGE INTO` (`UPDATE` + `DELETE` + `INSERT` snapshots)
  - `DROP TABLE` and `TRUNCATE TABLE` (including multi-table statements) quarantined safely into `_reverse_quarantine` (with owned sequence & index renaming on Postgres)
  - Reversible `ALTER TABLE`, `RENAME TABLE`, & index migrations: `ADD COLUMN`, `DROP COLUMN`, `ALTER COLUMN TYPE` / `MODIFY COLUMN` / `CHANGE COLUMN` (quarantines pre-alter values for lossless undo even after truncation), `SET/DROP DEFAULT`, `SET/DROP NOT NULL`, `RENAME COLUMN`, `RENAME TABLE`, `CREATE INDEX`, and `DROP INDEX`
- **Zero-Config Trigger Auto-Capture & Trigger-Safe Reversal (Optional Hybrid Mode)**:
  - `PostgresWALPoller` (`reverse_proxy/wal_poller.py`) — polls PostgreSQL's built-in `pgoutput` logical replication protocol (`--wal-slot`, with `test_decoding` backward compatibility), correlates triggers/procs via `pg_logical_emit_message`, monitors slot retention (`wal_status`, `retained_bytes`, `max_slot_wal_keep_size`) via `/api/status`, and reverses under `SET LOCAL session_replication_role = 'replica'`
  - `MySQLBinlogPoller` (`reverse_proxy/binlog_poller.py`) — polls MySQL `ROW` binlog via non-blocking `COM_BINLOG_DUMP` (`--binlog-poll`) and applies trigger-bypassing `BINLOG` RBR inverse events inside `BEGIN; ... COMMIT;`
- **Safety-First Guardrails, Atomic Locking & Ledger Integrity**:
  - **Safe default blast-radius cap (`--max-capture-rows 10000`)**: mutations (`UPDATE`, `DELETE`, `TRUNCATE`) affecting more than `10,000` rows are **refused before mutating** unless explicitly overridden (`--max-capture-rows 2000000` or `0` for unlimited).
  - **Atomic conflict check + lock**: conflict verification runs inside `BEGIN ... SELECT ... FOR UPDATE` (Postgres/MySQL) or `BEGIN IMMEDIATE` (SQLite) in the same transaction as the restore.
  - **Spill integrity & erasure**: compressed disk spill files record an atomic `SHA-256` checksum verified before restore, and support targeted erasure (`PROXY PURGE TX`, `PROXY PURGE TABLE`) and retention (`PROXY PURGE OLDER THAN N DAYS`, `--spill-retention-days`).
  - `ControlPlaneServer` (`reverse_proxy/web_ui.py`) — HTTP/HTTPS dashboard, SQL playground, side-by-side row diff viewer, search/filter, CSV/JSON audit export, webhooks, `/api/status` WAL telemetry, and CDC ingest API (`/api/cdc/event`)

## Installation & Quick Start

### 1. Install CLI (`sql-reverse-proxy`)

```bash
pip install .
sql-reverse-proxy --help
```

### 2. Live PostgreSQL 16 + MySQL 8.0 Stack (Docker Compose)

```bash
docker compose up -d --build
```

Services started:
- PostgreSQL 16 (`127.0.0.1:5432`, `wal_level=logical`, `max_slot_wal_keep_size=1024MB`) & Postgres Reverse Proxy (`127.0.0.1:5433`, Web UI `http://127.0.0.1:8080`)
- MySQL 8.0 (`127.0.0.1:3306`, `binlog_format=ROW`) & MySQL Reverse Proxy (`127.0.0.1:3307`, Web UI `http://127.0.0.1:8081`)

### 3. Local SQLite Mode

```bash
sql-reverse-proxy --engine sqlite --sqlite-path ./app.db --ledger-path ./undo_ledger.db
```

## Hybrid Mode Operational Notes

- **PostgreSQL (`--wal-slot`)**: Requires `wal_level = logical` (server restart) and a replication slot. Always configure **`max_slot_wal_keep_size`** (e.g., `1024MB` in `postgresql.conf`) so a stopped proxy/poller cannot cause unbounded WAL disk growth. Monitor slot retention live at `GET /api/status` (`wal_slot.retained_bytes`, `wal_slot.wal_status`).
- **MySQL (`--binlog-poll`)**: Requires `binlog_format=ROW` and `binlog_row_image=FULL` (default in MySQL 8.0).

## SQL-Native Control Commands

Works from `psql`, `mysql`, ORMs, or any SQL client connected through the proxy:

```sql
PROXY HISTORY LIMIT 25;
PROXY DIFF LAST;                  -- or PROXY DIFF <tx_id>
PROXY REVERSE;                    -- or PROXY REVERSE LAST (Ctrl+Z for the latest active mutation)
PROXY REVERSE LAST DRY RUN;
PROXY REVERSE <tx_id>;
PROXY REVERSE <tx_id> FORCE;      -- override drift / schema-drift checks
PROXY REVERSE <tx_id> CASCADE;    -- reverse causal dependent transactions cleanly
PROXY PURGE;                      -- permanently drop quarantined DROP/TRUNCATE snapshots
PROXY PURGE TX <tx_id>;           -- targeted erasure (removes ledger entry, spill file, quarantine)
PROXY PURGE TABLE <table_name>;   -- erase all history & spill files for a table
PROXY PURGE OLDER THAN 30 DAYS;   -- retention purge
PROXY PURGE LOG LIMIT 50;         -- inspect append-only audit log of who purged what and when
```

<!-- BENCHMARK_SECTION_START -->
## Concurrency & Locking During Large Undos

Conflict verification (`SELECT ... FOR UPDATE` on Postgres/MySQL, `BEGIN IMMEDIATE` on SQLite) runs in the **same transaction** as state restoration, while `ReverseProxyEngine.reverse()` releases the global Python engine lock when multi-session drivers are active (`scripts/run_benchmarks.py`):

- **PostgreSQL 16 (MVCC row locks):** During a 1,000,000-row `PROXY REVERSE` undo, 4 concurrent writer threads completed **80 disjoint `INSERT`s** (`zz_conc_<tid>_<i> (disjoint inserts)`) with **0 errors**, `max_wait = 0.019s`, `avg = 0.005s`.
- **MySQL 8.0 (InnoDB row/gap locks):** During a 1,000,000-row `PROXY REVERSE` undo, 4 concurrent writer threads completed **80 disjoint trailing-key `INSERT`s** (`zz_conc_<tid>_<i> (disjoint inserts)`) with **0 errors**, `max_wait = 0.023s`, `avg = 0.007s`. Under `REPEATABLE READ`, inserts falling *inside* locked primary-key ranges/gaps can block until commit.

### Durability Note: `UNLOGGED` Side Tables on PostgreSQL

Bulk `UPDATE`/`DELETE` statements above `side_table_threshold = 500` capture before/after rows into PostgreSQL `CREATE UNLOGGED TABLE` snapshots and stream them asynchronously via `_SideSpillWorker` to compressed SHA-256-verified spill files on disk (`tx_spill_*.undo.zlib`), then drop all `_side_*` tables. Because PostgreSQL skips WAL writes for `UNLOGGED` tables, an unclean PostgreSQL crash (`kill -9` / power loss) *after* commit and *before* background spill completion truncates unspilled `_side_*` tables on crash recovery—losing undo history for that unspilled transaction (primary logged tables remain consistent). At 1,000,000 rows, this window is **`8.8–12.9` seconds** under the default `side_spill_delay_seconds = 5.0` (`5.0s` grace delay + `3.8–7.9s` measured `spill_s`), or **`3.8–7.9` seconds** if `side_spill_delay_seconds = 0.0`.

## Benchmarks (1,000,000 IMDb Rows, 5 Trials/Cell, `SHA-256` Verified)

Generated directly from [`benchmarks/results_20261121_193251Z.json`](benchmarks/results_20261121_193251Z.json) via [`scripts/run_benchmarks.py`](scripts/run_benchmarks.py) (**5 independent trials per cell**, reporting **`median` (`min–max`)**; fresh table reseed + `VACUUM ANALYZE` + `CHECKPOINT` on PostgreSQL and InnoDB purge drain `trx_rseg_history_len` on MySQL before each run; timestamp: `2026-11-21T19:32:51.017558+00:00`, git commit: `b7c120371a4112fa8bacc7506c1a1e634aea96fa`, source tree SHA-256: `96621e036f5ef0ab...`, canonical 1M dataset SHA-256: `e14b2548e70a6575...`).

Both undo paths are measured and labeled below:
- **Pre-Spill Undo (`side_table`)**: `PROXY REVERSE` executed within the in-DB snapshot window while `_side_*` tables are still resident in `_reverse_quarantine`.
- **Post-Spill Undo (`spilled_temp_table`)**: `PROXY REVERSE` executed *after* `_side_*` tables have been spilled to compressed disk files (`tx_spill_*.undo.zlib`) and dropped from the database (loads the spill file into a staging temp table via `COPY FROM STDIN` on Postgres / batched multi-row `INSERT` with `sql_log_bin=0` on MySQL, then runs a single set-based `UPDATE ... FROM` / `UPDATE ... INNER JOIN` or `INSERT ... SELECT` with full `FOR UPDATE` drift checks).

### PostgreSQL 16 & PostgreSQL 18 (`RETURNING OLD, NEW`) — Median (`min–max` over 5 trials)

| 1,000,000-Row Operation | PG 16 Direct | PG 16 Proxy Write | PG 16 Undo (Pre-Spill `side_table`) | PG 16 Undo (Post-Spill `spilled_temp_table`) | PG 18 Direct | PG 18 Proxy Write (`RETURNING OLD/NEW`) | PG 18 Undo (Pre-Spill `side_table`) | PG 18 Undo (Post-Spill `spilled_temp_table`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`DROP TABLE`** | `0.006s` (`0.005–0.007s`) | `0.005s` (`0.005–0.006s`) | **`0.004s`** (`0.003–0.005s`) (`ddl_quarantine`) | — | — | — | — | — |
| **`TRUNCATE TABLE`** | `0.007s` (`0.007–0.007s`) | `0.004s` (`0.004–0.006s`) | **`0.003s`** (`0.003–0.004s`) (`ddl_quarantine`) | — | — | — | — | — |
| **`ALTER DROP COLUMN`** | `0.001s` (`0.001–0.001s`) | `0.281s` (`0.268–0.290s`) | **`5.580s`** (`5.576–6.492s`) (`ddl_quarantine`) | — | — | — | — | — |
| **1M Bulk `UPDATE`** | `3.85s` (`3.76–4.12s`) | `4.98s` (1.3x) (`4.36–5.15s`) | **`7.39s`** (`6.49–7.67s`) | **`8.84s`** (`8.23–9.90s`) | `3.18s` (`3.18–3.40s`) | `4.38s` (1.4x) (`4.37–4.51s`) | **`6.31s`** (`6.22–6.40s`) | **`8.79s`** (`7.90–9.56s`) |
| **1M Bulk `DELETE`** | `0.35s` (`0.34–0.35s`) | `0.88s` (2.5x) (`0.76–0.93s`) | **`4.01s`** (`3.46–4.54s`) | **`4.73s`** (`3.88–4.86s`) | `0.22s` (`0.22–0.22s`) | `0.74s` (3.4x) (`0.64–0.77s`) | **`2.99s`** (`2.62–3.04s`) | **`4.49s`** (`4.05–4.67s`) |

### MySQL 8.0 vs. MariaDB 11 Flashback (`mariadb-binlog --flashback`) — Median (`min–max` over 5 trials)

| 1,000,000-Row Operation | MySQL 8.0 Direct | MySQL 8.0 Proxy Write | MySQL 8.0 Undo (Pre-Spill `side_table`) | MySQL 8.0 Undo (Post-Spill `spilled_temp_table`) | MariaDB 11 Flashback (`--flashback`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`DROP TABLE`** | `0.011s` (`0.010–0.014s`) | `0.014s` (`0.010–0.629s`) | **`0.011s`** (`0.008–0.014s`) (`ddl_quarantine`) | — | Not reversible (`DROP`) |
| **`TRUNCATE TABLE`** | `0.022s` (`0.015–0.115s`) | `0.022s` (`0.013–0.125s`) | **`0.012s`** (`0.009–0.016s`) (`ddl_quarantine`) | — | Not reversible (emits no `INSERT`s) |
| **`ALTER DROP COLUMN`** | `0.007s` (`0.006–0.009s`) | `2.912s` (`2.579–3.294s`) | **`11.825s`** (`9.545–14.321s`) (`ddl_quarantine`) | — | Not reversible (`ALTER`) |
| **1M Bulk `UPDATE`** | `2.47s` (`2.42–2.98s`) | `10.61s` (4.3x) (`8.90–13.77s`) | **`13.14s`** (`8.63–18.82s`) | **`18.13s`** (`13.55–19.82s`) | Forward `1.33s` (`1.15–1.58s`) / Flashback **`2.87s`** (`2.73–3.28s`) |
| **1M Bulk `DELETE`** | `1.99s` (`1.61–2.13s`) | `5.54s` (2.8x) (`4.72–5.63s`) | **`6.67s`** (`4.98–6.92s`) | **`7.54s`** (`7.12–8.89s`) | Forward `1.05s` (`1.00–1.13s`) / Flashback **`1.73s`** (`1.65–1.98s`) |

### Per-Phase Write & Spill Timing Breakdown (1,000,000 Rows, Median Across Trials)

| Engine & Operation | Blast-Radius Probe (`COUNT`) | Side-Table Create | Pre-Image Capture (`FOR UPDATE`) | DML Execution | `COMMIT` | Post-Commit Disk Spill (`spill_s`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **PG 16 — 1M `UPDATE`** | `0.083s` | `0.002s` | `0.500s` | `4.407s` | `0.004s` | `7.67s` |
| **PG 16 — 1M `DELETE`** | `0.090s` | `0.002s` | `0.000s` | `0.780s` | `0.005s` | `3.77s` |
| **PG 18 — 1M `UPDATE` (`RETURNING OLD/NEW`)** | `0.028s` | `0.001s` | `0.000s` | `4.343s` | `0.001s` | `7.88s` |
| **PG 18 — 1M `DELETE` (`RETURNING *`)** | `0.062s` | `0.001s` | `0.000s` | `0.665s` | `0.007s` | `3.90s` |
| **MySQL 8.0 — 1M `UPDATE`** | `0.254s` | `0.030s` | `2.973s` | `7.251s` | `0.099s` | `6.94s` |
| **MySQL 8.0 — 1M `DELETE`** | `0.258s` | `0.009s` | `2.963s` | `2.234s` | `0.054s` | `3.52s` |

### Per-Phase Undo (`PROXY REVERSE`) Timing Breakdown (Median Across Trials)

| Engine, Operation & Restore Path | Change-Stream Sync (`wal_sync_s`) | Ledger Load (`ledger_load_s`) | Temp Staging (`stage_temp_s`) | Conflict & Lock (`conflict_and_lock_s`) | Restore SQL (`restore_exec_s`) | `COMMIT` (`commit_s`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **PG 16 — `DROP TABLE` (`ddl_quarantine`)** | `0.0005s` | `0.0000s` | `0.000s` | `0.001s` | `0.001s` | `0.000s` |
| **PG 16 — `TRUNCATE TABLE` (`ddl_quarantine`)** | `0.0006s` | `0.0000s` | `0.000s` | `0.001s` | `0.001s` | `0.000s` |
| **PG 16 — 1M `UPDATE` (`side_table`)** | `1.0512s` | `0.0001s` | `0.000s` | `1.307s` | `5.010s` | `0.006s` |
| **PG 16 — 1M `UPDATE` (`spilled_temp_table`)** | `0.0007s` | `1.5150s` | `1.741s` | `1.520s` | `3.932s` | `0.010s` |
| **PG 16 — 1M `DELETE` (`side_table`)** | `0.7856s` | `0.0001s` | `0.000s` | `0.061s` | `3.135s` | `0.004s` |
| **PG 16 — 1M `DELETE` (`spilled_temp_table`)** | `0.0006s` | `0.7350s` | `0.868s` | `0.051s` | `3.014s` | `0.006s` |
| **PG 18 — 1M `UPDATE` (`side_table`)** | `0.0000s` | `0.0000s` | `0.000s` | `1.331s` | `4.953s` | `0.003s` |
| **PG 18 — 1M `UPDATE` (`spilled_temp_table`)** | `0.0000s` | `1.2778s` | `1.932s` | `1.486s` | `4.093s` | `0.011s` |
| **PG 18 — 1M `DELETE` (`side_table`)** | `0.0000s` | `0.0001s` | `0.000s` | `0.043s` | `2.941s` | `0.004s` |
| **PG 18 — 1M `DELETE` (`spilled_temp_table`)** | `0.0000s` | `0.6104s` | `0.929s` | `0.036s` | `2.860s` | `0.009s` |
| **MySQL 8.0 — `DROP TABLE` (`ddl_quarantine`)** | `0.0014s` | `0.0001s` | `0.000s` | `0.001s` | `0.005s` | `0.000s` |
| **MySQL 8.0 — `TRUNCATE TABLE` (`ddl_quarantine`)** | `0.0014s` | `0.0001s` | `0.000s` | `0.001s` | `0.008s` | `0.000s` |
| **MySQL 8.0 — 1M `UPDATE` (`side_table`)** | `0.0024s` | `0.0001s` | `0.000s` | `5.560s` | `6.838s` | `0.074s` |
| **MySQL 8.0 — 1M `UPDATE` (`spilled_temp_table`)** | `0.0017s` | `1.4738s` | `7.103s` | `4.740s` | `3.922s` | `0.061s` |
| **MySQL 8.0 — 1M `DELETE` (`side_table`)** | `0.0020s` | `0.0001s` | `0.000s` | `0.086s` | `6.536s` | `0.029s` |
| **MySQL 8.0 — 1M `DELETE` (`spilled_temp_table`)** | `0.0015s` | `0.7533s` | `3.598s` | `0.002s` | `3.024s` | `0.034s` |

<details>
<summary>Provenance: Git commit, image digests & cleanup verification</summary>

- Git commit: `b7c120371a4112fa8bacc7506c1a1e634aea96fa` (`source_tree_sha256`: `96621e036f5ef0ab1d6ed521456e89893938c2f5ec53cef28846f639518fb009`)
- Trials per cell: `5`
- `postgres:16`: `postgres@sha256:3950ad7c3148ca2175ef1b6c36c9efbf78957ae8fbe8b3a5d7c35af50500382f`
- `postgres:18`: `postgres@sha256:eb63372c1e05c755f55fa30cbd07aecc443676fc6c0fa90b9002d01537841e1a`
- `mysql:8.0`: `mysql@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b`
- `mariadb:11`: `mariadb@sha256:e1d5495f445654134f226f55a41ce0da227116f6f27f283101f405c794d841fc`
- Remaining `_side_*` tables after spill drain: PG 16 = `0`, PG 18 = `0`, MySQL 8.0 = `0`.
- Live `BEGIN; UPDATE; ROLLBACK;` verified: PG 16 = `True`, MySQL 8.0 = `True`.

</details>
<!-- BENCHMARK_SECTION_END -->

## Verification

Run the full unit test suite (zero external dependencies):

```bash
PYTHONPATH=tests .venv/bin/python -m unittest discover -s tests -v
```

Reproduce the full 1,000,000-row cross-engine benchmark suite (PostgreSQL 16, PostgreSQL 18, MySQL 8.0, and MariaDB 11 Flashback), write a timestamped JSON artifact under `benchmarks/`, and regenerate the benchmark tables above from that JSON:

```bash
.venv/bin/python scripts/run_benchmarks.py
```
