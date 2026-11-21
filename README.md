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

- **PostgreSQL 16 (MVCC row locks):** During a 1,000,000-row `PROXY REVERSE` undo, 4 concurrent writer threads completed **80 disjoint `INSERT`s** (`zz_conc_<tid>_<i> (disjoint inserts)`) with **0 errors**, `max_wait = 0.022s`, `avg = 0.007s`.
- **MySQL 8.0 (InnoDB row/gap locks):** During a 1,000,000-row `PROXY REVERSE` undo, 4 concurrent writer threads completed **80 disjoint trailing-key `INSERT`s** (`zz_conc_<tid>_<i> (disjoint inserts)`) with **0 errors**, `max_wait = 0.035s`, `avg = 0.011s`. Under `REPEATABLE READ`, inserts falling *inside* locked primary-key ranges/gaps can block until commit.

### Durability Note: `UNLOGGED` Side Tables on PostgreSQL

Bulk `UPDATE`/`DELETE` statements above `side_table_threshold = 500` capture before/after rows into PostgreSQL `CREATE UNLOGGED TABLE` snapshots and stream them asynchronously via `_SideSpillWorker` to compressed SHA-256-verified spill files on disk (`tx_spill_*.undo.zlib`), then drop all `_side_*` tables. Because PostgreSQL skips WAL writes for `UNLOGGED` tables, an unclean PostgreSQL crash (`kill -9` / power loss) *after* commit and *before* background spill completion truncates unspilled `_side_*` tables on crash recovery—losing undo history for that unspilled transaction (primary logged tables remain consistent).

## Benchmarks (1,000,000 IMDb Rows, `SHA-256` Verified)

Generated directly from [`benchmarks/results_20261121_062223Z.json`](benchmarks/results_20261121_062223Z.json) via [`scripts/run_benchmarks.py`](scripts/run_benchmarks.py) (timestamp: `2026-11-21T06:22:23.425475+00:00`, git commit: `4640443956198e2f4d7c0e2d16075c82e6431334`, source tree SHA-256: `51503c17a10d15cf...`, canonical 1M dataset SHA-256: `e14b2548e70a6575...`).

Both undo paths are measured and labeled below:
- **Pre-Spill Undo (`side_table`)**: `PROXY REVERSE` executed within the in-DB snapshot window while `_side_*` tables are still resident in `_reverse_quarantine`.
- **Post-Spill Undo (`spilled_temp_table`)**: `PROXY REVERSE` executed *after* `_side_*` tables have been spilled to compressed disk files (`tx_spill_*.undo.zlib`) and dropped from the database (loads the spill file into a staging temp table via `COPY FROM STDIN` on Postgres / batched multi-row `INSERT` on MySQL, then runs a single set-based `UPDATE ... FROM` / `UPDATE ... INNER JOIN` or `INSERT ... SELECT` with full `FOR UPDATE` drift checks).

### PostgreSQL 16 & PostgreSQL 18 (`RETURNING OLD, NEW`)

| 1,000,000-Row Operation | PG 16 Direct | PG 16 Proxy Write | PG 16 Undo (Pre-Spill `side_table`) | PG 16 Undo (Post-Spill `spilled_temp_table`) | PG 18 Direct | PG 18 Proxy Write (`RETURNING OLD/NEW`) | PG 18 Undo (Pre-Spill `side_table`) | PG 18 Undo (Post-Spill `spilled_temp_table`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`DROP TABLE`** | `0.005s` | `0.006s` | **`1.485s`** (`ddl_quarantine`) | — | — | — | — | — |
| **`TRUNCATE TABLE`** | `0.006s` | `0.007s` | **`1.480s`** (`ddl_quarantine`) | — | — | — | — | — |
| **`ALTER DROP COLUMN`** | `0.001s` | `0.297s` | **`5.877s`** (`ddl_quarantine`) | — | — | — | — | — |
| **1M Bulk `UPDATE`** | `3.81s` | `6.11s` (1.6x) | **`12.87s`** | **`15.30s`** | `4.20s` | `5.71s` (1.4x) | **`12.32s`** | **`13.25s`** |
| **1M Bulk `DELETE`** | `0.39s` | `0.97s` (2.5x) | **`8.60s`** | **`5.37s`** | `0.36s` | `0.76s` (2.1x) | **`6.11s`** | **`6.22s`** |

### MySQL 8.0 vs. MariaDB 11 Flashback (`mariadb-binlog --flashback`)

| 1,000,000-Row Operation | MySQL 8.0 Direct | MySQL 8.0 Proxy Write | MySQL 8.0 Undo (Pre-Spill `side_table`) | MySQL 8.0 Undo (Post-Spill `spilled_temp_table`) | MariaDB 11 Flashback (`--flashback`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`DROP TABLE`** | `0.014s` | `0.024s` | **`0.016s`** (`ddl_quarantine`) | — | Not reversible (`DROP`) |
| **`TRUNCATE TABLE`** | `0.429s` | `0.030s` | **`0.016s`** (`ddl_quarantine`) | — | Not reversible (emits no `INSERT`s) |
| **`ALTER DROP COLUMN`** | `0.007s` | `3.045s` | **`14.470s`** (`ddl_quarantine`) | — | Not reversible (`ALTER`) |
| **1M Bulk `UPDATE`** | `3.53s` | `12.30s` (3.5x) | **`13.11s`** | **`23.30s`** | Forward `1.44s` / Flashback **`3.46s`** |
| **1M Bulk `DELETE`** | `5.06s` | `5.47s` (1.1x) | **`5.95s`** | **`9.07s`** | Forward `1.12s` / Flashback **`2.77s`** |

### Per-Phase Write & Spill Timing Breakdown (1,000,000 Rows)

| Engine & Operation | Blast-Radius Probe (`COUNT`) | Side-Table Create | Pre-Image Capture (`FOR UPDATE`) | DML Execution | `COMMIT` | Post-Commit Disk Spill (`spill_s`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **PG 16 — 1M `UPDATE`** | `0.126s` | `0.003s` | `0.609s` | `4.824s` | `0.006s` | `7.29s` |
| **PG 16 — 1M `DELETE`** | `0.115s` | `0.001s` | `0.000s` | `0.846s` | `0.003s` | `4.26s` |
| **PG 18 — 1M `UPDATE` (`RETURNING OLD/NEW`)** | `0.043s` | `0.001s` | `0.000s` | `5.663s` | `0.001s` | `8.21s` |
| **PG 18 — 1M `DELETE` (`RETURNING *`)** | `0.084s` | `0.001s` | `0.000s` | `0.665s` | `0.008s` | `4.08s` |
| **MySQL 8.0 — 1M `UPDATE`** | `0.272s` | `0.067s` | `3.231s` | `8.291s` | `0.416s` | `7.60s` |
| **MySQL 8.0 — 1M `DELETE`** | `0.252s` | `0.009s` | `2.936s` | `2.061s` | `0.198s` | `3.85s` |

<details>
<summary>Provenance: Git commit, image digests & cleanup verification</summary>

- Git commit: `4640443956198e2f4d7c0e2d16075c82e6431334` (`source_tree_sha256`: `51503c17a10d15cfdccd26dc6f9e9cd87f3f7e169bb80a6e725f70eefb4daac8`)
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
