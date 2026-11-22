# SQL Undo Proxy (`sql-undo-proxy`)

A SQL safety proxy for **PostgreSQL**, **MySQL**, and **SQLite** that captures supported mutations, quarantines destructive schema changes, and lets operators inspect and reverse selected committed operations with drift checks—**without rewinding everyone else's work**.

- **Restore quarantined `DROP TABLE` / `TRUNCATE` tables in milliseconds (`3–13ms`)**; reverse 1,000,000-row `UPDATE` and `DELETE` operations in seconds (`3.5–17.2s` in the published 5-trial benchmark environment).
- **Zero third-party runtime dependencies** (pure-Python `pgwire` v3 and MySQL 8 wire frontends, SQLite-backed compressed/spilled undo ledger, optional PostgreSQL `pgoutput` WAL & MySQL `ROW` binlog trigger capture, and an HTTP/HTTPS Control Plane UI).

---

## 30-Second Walkthrough: Surgical Undo While Other Traffic Continues

Point-in-time recovery (PITR) and storage snapshots rewind the *entire database*, erasing every unrelated write since the bad query. `sql-undo-proxy` reverses **one committed transaction** while leaving concurrent application writes intact—and refuses safely if a target row has drifted:

```sql
-- 1. An AI agent or admin session connected through the proxy deletes customer rows:
DELETE FROM customers WHERE tier = 'pro';
-- NOTICE: [reverse-proxy] tx_id=tx_a18f04c29b status=exact rows=2

-- 2. Meanwhile, the live application inserts new rows and updates unrelated rows:
INSERT INTO customers VALUES (4, 'Dave', 'enterprise');
UPDATE customers SET tier = 'plus' WHERE id = 2;

-- 3. Operator inspects the recorded before/after diff and durability state:
PROXY HISTORY LIMIT 5;
--  tx_id         | actor | status | rows_affected | raw_sql                                  | durability
-- ---------------+-------+--------+---------------+------------------------------------------+------------
--  tx_a18f04c29b | agent | exact  |             2 | DELETE FROM customers WHERE tier = 'pro' | durable

PROXY DIFF tx_a18f04c29b;
--  op_type | table     | pk       | before_json                                  | after_json
-- ---------+-----------+----------+----------------------------------------------+------------
--  DELETE  | customers | {"id":1} | {"id":1,"name":"Alice","tier":"pro"}         | null
--  DELETE  | customers | {"id":3} | {"id":3,"name":"Carol","tier":"pro"}         | null

-- 4. Reverse ONLY tx_a18f04c29b — Alice (1) and Carol (3) are restored;
--    Dave (4) and Bob's update (2) remain untouched:
PROXY REVERSE tx_a18f04c29b;
-- COMMAND TAG: PROXY REVERSE OK

-- 5. What if another writer modified a target row after the bad UPDATE?
UPDATE customers SET tier = 'gold' WHERE id = 2;      -- Proxy records tx_7c09e1120a (expected tier='gold')
-- (Direct app connection changes id=2 to tier='platinum')
PROXY REVERSE tx_7c09e1120a;
-- COMMAND TAG: PROXY REVERSE CONFLICT
--  conflict_table | pk       | column | expected_after | actual_current | reason
-- ----------------+----------+--------+----------------+----------------+---------------------------
--  customers      | {"id":2} | tier   | 'gold'         | 'platinum'     | Row modified since UPDATE.
-- (Use `PROXY REVERSE tx_7c09e1120a FORCE;` only if you explicitly want to overwrite the drift.)
```

---

## When to Use This (and When Not To)

**Do not** put `sql-undo-proxy` in front of a 50,000-TPS primary application connection pool. Put it in front of **high-risk human, migration, and AI-agent database connections** where write volume is moderate and mistakes are catastrophic:

- **AI Coding Agents & Text-to-SQL / MCP Database Servers**: Enforce a hard blast-radius breaker (`--max-capture-rows 10000` refuses runaway `DELETE`/`UPDATE`/`TRUNCATE` before mutating), quarantine `DROP TABLE` / `TRUNCATE` / `DROP COLUMN` non-destructively, and let an agent or operator run `PROXY REVERSE LAST;`.
- **Break-Glass Production SQL Consoles (`psql`, `mysql`, TablePlus, DBeaver, Retool)**: Route human/bastion sessions through the proxy while the main application talks directly to the database (0% app overhead). Every ad-hoc human query gets an actor tag, before/after row diff, and surgical `PROXY REVERSE <tx_id>` with `SELECT ... FOR UPDATE` drift detection.
- **CI/CD Migration Runners & Data Backfills**: Automatically quarantine dropped or altered columns so a failed canary deploy can roll back both schema and data (`PROXY REVERSE <tx_id>`).
- **Local Development, Staging & E2E Test Suites**: Roll back multi-connection test mutations (including DDL) across HTTP requests (`PROXY REVERSE ... CASCADE`) without re-seeding containers.

---

## Safety Contract, Durability States & Compatibility Boundaries

### 1. Per-Transaction Durability States (`PROXY HISTORY` / `/api/history`)
Every ledger entry exposes an explicit **`durability`** state so operators never have to guess whether an undo payload is crash-safe on disk:
- **`durable`**: Before/after rows are synchronously stored in `undo_ledger.db` (`<= 500` rows or DDL quarantine metadata), or `_SideSpillWorker` has finished streaming the DB-side snapshot to a compressed, `SHA-256`-verified spill file (`tx_spill_*.undo.zlib`) and dropped the `_side_*` tables.
- **`capture_pending`**: Bulk mutation (`> 500` rows on Postgres/MySQL) has committed its before/after snapshot into `_reverse_quarantine._side_*` and is queued for background disk spill. `PROXY REVERSE` works immediately from `_side_*`, or `PROXY DIFF` forces an immediate synchronous spill. On PostgreSQL, `_side_*` tables are `UNLOGGED` for speed; an unclean PostgreSQL crash (`kill -9` / power loss) during this `8.5–12.6s` window (at 1M rows) truncates `_side_*` on crash recovery.
- **`unavailable`**: If an unspilled `_side_*` table is missing or empty after an unclean database crash, `sql-undo-proxy` marks `durability = unavailable` and **fails closed** on `PROXY REVERSE` rather than executing a partial or empty restore.

### 2. What `PROXY REVERSE <tx_id> CASCADE` Tracks (and What It Cannot Track)
`build_causal_reverse_plan` (`reverse_proxy/causal.py`) builds a DAG over recorded transactions later than `<tx_id>` and reverses dependents in newest-first topological order based on **four recorded data edges**:
1. **Primary-Key Write Overlap (`same_row`)**: A later recorded transaction updated or deleted a `(schema, table, pk)` tuple inserted or modified by an earlier transaction.
2. **Foreign-Key Child-of-Insert (`fk_child_of_insert`)**: A later recorded transaction inserted or updated a child row whose FK references a parent row inserted by `<tx_id>`.
3. **Foreign-Key Parent-of-Delete (`fk_parent_of_delete`)**: A later recorded transaction deleted a parent row that `<tx_id>`'s deleted child row depends on for re-insertion.
4. **Table-Level DDL Shadow (`ddl_on_table`)**: A later recorded `DROP` / `TRUNCATE` / `ALTER` modified the schema of a table touched by `<tx_id>`.

**Explicit boundaries of `CASCADE`**:
- **Application-level read-then-write dependencies are invisible**: If Transaction A updates `accounts.balance`, and Transaction B `SELECT`s that balance, computes a decision in application code, and `INSERT`s into `approvals` (with no FK or PK overlap), `CASCADE` will not link B to A.
- **Unproxied connections**: Writes performed on direct database connections that bypass the proxy are invisible to `CASCADE` (unless hybrid `--wal-slot` / `--binlog-poll` capture is active), though `SELECT ... FOR UPDATE` drift detection still protects `<tx_id>` from silently clobbering direct edits to the same rows.

### 3. Trigger & Constraint Compatibility Matrix during `PROXY REVERSE`

| Mechanism | PostgreSQL (`apply_reverse`) | MySQL 8.0 (`apply_reverse`) | SQLite (`apply_reverse`) |
| :--- | :--- | :--- | :--- |
| **Standard User Triggers (`ENABLE` / `ORIGIN`)** | **Suppressed** when backend user can `SET LOCAL session_replication_role = 'replica'`; if unprivileged, falls back via savepoint and triggers fire | **Suppressed** in hybrid `--binlog-poll` mode via `BINLOG '...'` RBR replay (requires `BINLOG_ADMIN` / `SUPER`); falls back to SQL if unprivileged | **Fires** unless captured via hybrid session/CDC and reversed in topological order |
| **PostgreSQL `ENABLE REPLICA` / `ENABLE ALWAYS` Triggers** | **Fires** even under `session_replication_role = 'replica'` (per PostgreSQL specification) | N/A | N/A |
| **`ON DELETE CASCADE` Foreign Keys** | **Captured & restored**: recursive child discovery snapshots child tables before `DELETE` and restores parent -> child | **Captured & restored**: recursive child discovery snapshots child tables before `DELETE` and restores parent -> child | **Captured & restored**: recursive `PRAGMA foreign_key_list` discovery snapshots and restores parent -> child |
| **Primary-Key `UPDATE` (`SET id = ...`)** | **Supported** via row-captured `RETURNING` path (`_update_touches_pk` bypasses PK-join side-table path) | **Supported** via row-captured path (`_mysql_update_touches_pk` bypasses PK-join side-table path) | **Supported** via `rowid` / before-after PK mapping |
| **Concurrent Schema Drift (`ADD` / `DROP COLUMN` after DML)** | **Detected**: `ADD COLUMN` uses column-subset restore; `DROP COLUMN` raises `DriftConflict` unless `FORCE` is passed | **Detected**: `ADD COLUMN` uses column-subset restore; `DROP COLUMN` raises `DriftConflict` unless `FORCE` is passed | **Detected**: `ADD COLUMN` uses column-subset restore; `DROP COLUMN` raises `DriftConflict` unless `FORCE` is passed |

---

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

### 1. Install CLI (`sql-undo-proxy`)

```bash
pip install .
sql-undo-proxy --help
```

### 2. Live PostgreSQL 16 + MySQL 8.0 Stack (Docker Compose)

```bash
docker compose up -d --build
```

Services started:
- PostgreSQL 16 (`127.0.0.1:5432`, `wal_level=logical`, `max_slot_wal_keep_size=1024MB`) & Postgres Undo Proxy (`127.0.0.1:5433`, Web UI `http://127.0.0.1:8080`)
- MySQL 8.0 (`127.0.0.1:3306`, `binlog_format=ROW`) & MySQL Undo Proxy (`127.0.0.1:3307`, Web UI `http://127.0.0.1:8081`)

### 3. Local SQLite Mode

```bash
sql-undo-proxy --engine sqlite --sqlite-path ./app.db --ledger-path ./undo_ledger.db
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

- **PostgreSQL 16 (MVCC row locks):** During a 1,000,000-row `PROXY REVERSE` undo, 4 concurrent writer threads completed **80 disjoint `INSERT`s** (`zz_conc_<tid>_<i> (disjoint inserts)`) with **0 errors**, `max_wait = 0.014s`, `avg = 0.005s`.
- **MySQL 8.0 (InnoDB row/gap locks):** During a 1,000,000-row `PROXY REVERSE` undo, 4 concurrent writer threads completed **80 disjoint trailing-key `INSERT`s** (`zz_conc_<tid>_<i> (disjoint inserts)`) with **0 errors**, `max_wait = 0.017s`, `avg = 0.006s`. Under `REPEATABLE READ`, inserts falling *inside* locked primary-key ranges/gaps can block until commit.

### Durability Note: `UNLOGGED` Side Tables on PostgreSQL

Bulk `UPDATE`/`DELETE` statements above `side_table_threshold = 500` capture before/after rows into PostgreSQL `CREATE UNLOGGED TABLE` snapshots and stream them asynchronously via `_SideSpillWorker` to compressed SHA-256-verified spill files on disk (`tx_spill_*.undo.zlib`), then drop all `_side_*` tables. Because PostgreSQL skips WAL writes for `UNLOGGED` tables, an unclean PostgreSQL crash (`kill -9` / power loss) *after* commit and *before* background spill completion truncates unspilled `_side_*` tables on crash recovery—losing undo history for that unspilled transaction (primary logged tables remain consistent). At 1,000,000 rows, this window is **`8.5–12.6` seconds** under the default `side_spill_delay_seconds = 5.0` (`5.0s` grace delay + `3.5–7.6s` measured `spill_s`), or **`3.5–7.6` seconds** if `side_spill_delay_seconds = 0.0`.

## Benchmarks (1,000,000 IMDb Rows, 5 Trials/Cell, `SHA-256` Verified)

Generated directly from [`benchmarks/results_20261121_202212Z.json`](benchmarks/results_20261121_202212Z.json) via [`scripts/run_benchmarks.py`](scripts/run_benchmarks.py) (**5 independent trials per cell**, reporting **`median` (`min–max`)**; fresh table reseed + `VACUUM ANALYZE` + `CHECKPOINT` on PostgreSQL and InnoDB purge drain `trx_rseg_history_len` on MySQL before each run; timestamp: `2026-11-21T20:22:12.931106+00:00`, git commit: `3d9428352a7cb604a7f66e86166a5ca8bc2c8821`, source tree SHA-256: `b788d0fc88342294...`, canonical 1M dataset SHA-256: `e14b2548e70a6575...`).

Both undo paths are measured and labeled below:
- **Pre-Spill Undo (`side_table`)**: `PROXY REVERSE` executed within the in-DB snapshot window while `_side_*` tables are still resident in `_reverse_quarantine`.
- **Post-Spill Undo (`spilled_temp_table`)**: `PROXY REVERSE` executed *after* `_side_*` tables have been spilled to compressed disk files (`tx_spill_*.undo.zlib`) and dropped from the database (loads the spill file into a staging temp table via `COPY FROM STDIN` on Postgres / batched multi-row `INSERT` on MySQL, then runs a single set-based `UPDATE ... FROM` / `UPDATE ... INNER JOIN` or `INSERT ... SELECT` with full `FOR UPDATE` drift checks). On MySQL, `SET SESSION sql_log_bin = 0` is used around `_rev_*` temp staging only when `@@SESSION.binlog_format = 'ROW'` (falling back to logged staging under `STATEMENT`/`MIXED` or when the user lacks `SQL_LOG_BIN` privilege so attached replicas never break).
- **Both PostgreSQL 16 and PostgreSQL 18 run in identical hybrid mode (`wal_level=logical`, `--wal-slot reverse_proxy_slot`)**. Schema-change undos (`DROP TABLE`, `TRUNCATE TABLE`, `ALTER TABLE`) skip synchronous change-stream polling (`wal_sync_s = 0.0000s`), and `PostgresWALPoller` automatically advances `restart_lsn` to `confirmed_flush_lsn` when idle.

### PostgreSQL 16 & PostgreSQL 18 (`RETURNING OLD, NEW`) — Median (`min–max` over 5 trials)

| 1,000,000-Row Operation | PG 16 Direct | PG 16 Proxy Write | PG 16 Undo (Pre-Spill `side_table`) | PG 16 Undo (Post-Spill `spilled_temp_table`) | PG 18 Direct | PG 18 Proxy Write (`RETURNING OLD/NEW`) | PG 18 Undo (Pre-Spill `side_table`) | PG 18 Undo (Post-Spill `spilled_temp_table`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`DROP TABLE`** | `0.005s` (`0.005–0.007s`) | `0.005s` (`0.005–0.009s`) | **`0.004s`** (`0.003–0.008s`) (`ddl_quarantine`) | — | — | — | — | — |
| **`TRUNCATE TABLE`** | `0.007s` (`0.006–0.009s`) | `0.004s` (`0.004–0.016s`) | **`0.003s`** (`0.003–0.004s`) (`ddl_quarantine`) | — | — | — | — | — |
| **`ALTER DROP COLUMN`** | `0.001s` (`0.001–0.001s`) | `0.276s` (`0.252–0.286s`) | **`4.772s`** (`4.219–5.132s`) (`ddl_quarantine`) | — | — | — | — | — |
| **1M Bulk `UPDATE`** | `3.64s` (`3.33–4.22s`) | `4.93s` (1.4x) (`4.29–4.99s`) | **`6.99s`** (`6.78–9.36s`) | **`10.07s`** (`9.79–11.19s`) | `4.01s` (`3.75–4.11s`) | `3.96s` (1.0x) (`3.94–5.08s`) | **`7.07s`** (`6.96–8.52s`) | **`10.17s`** (`9.54–13.78s`) |
| **1M Bulk `DELETE`** | `0.34s` (`0.33–0.38s`) | `0.84s` (2.5x) (`0.78–0.92s`) | **`4.10s`** (`3.65–4.25s`) | **`5.06s`** (`4.83–5.42s`) | `0.32s` (`0.31–0.36s`) | `0.77s` (2.4x) (`0.76–0.92s`) | **`3.53s`** (`3.17–4.53s`) | **`5.02s`** (`4.83–6.94s`) |

### MySQL 8.0 vs. MariaDB 11 Flashback (`mariadb-binlog --flashback`) — Median (`min–max` over 5 trials)

| 1,000,000-Row Operation | MySQL 8.0 Direct | MySQL 8.0 Proxy Write | MySQL 8.0 Undo (Pre-Spill `side_table`) | MySQL 8.0 Undo (Post-Spill `spilled_temp_table`) | MariaDB 11 Flashback (`--flashback`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`DROP TABLE`** | `0.016s` (`0.013–0.054s`) | `0.111s` (`0.008–0.711s`) | **`0.013s`** (`0.006–0.274s`) (`ddl_quarantine`) | — | Not reversible (`DROP`) |
| **`TRUNCATE TABLE`** | `0.028s` (`0.020–0.226s`) | `0.015s` (`0.015–0.132s`) | **`0.010s`** (`0.008–0.012s`) (`ddl_quarantine`) | — | Not reversible (emits no `INSERT`s) |
| **`ALTER DROP COLUMN`** | `0.008s` (`0.006–0.014s`) | `3.150s` (`2.796–3.516s`) | **`12.558s`** (`11.802–14.548s`) (`ddl_quarantine`) | — | Not reversible (`ALTER`) |
| **1M Bulk `UPDATE`** | `3.06s` (`2.97–3.18s`) | `10.86s` (3.5x) (`9.99–11.42s`) | **`9.83s`** (`7.83–12.19s`) | **`17.24s`** (`16.07–18.06s`) | Forward `1.30s` (`1.29–1.42s`) / Flashback **`3.08s`** (`3.05–3.18s`) |
| **1M Bulk `DELETE`** | `2.27s` (`1.69–2.33s`) | `5.75s` (2.5x) (`5.13–5.87s`) | **`6.69s`** (`5.10–6.94s`) | **`8.54s`** (`8.47–8.86s`) | Forward `1.14s` (`1.11–1.20s`) / Flashback **`1.92s`** (`1.72–2.06s`) |

### Per-Phase Write & Spill Timing Breakdown (1,000,000 Rows, Median Across Trials)

| Engine & Operation | Blast-Radius Probe (`COUNT`) | Side-Table Create | Pre-Image Capture (`FOR UPDATE`) | DML Execution | `COMMIT` | Post-Commit Disk Spill (`spill_s`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **PG 16 — 1M `UPDATE`** | `0.079s` | `0.002s` | `0.481s` | `4.365s` | `0.005s` | `7.61s` |
| **PG 16 — 1M `DELETE`** | `0.093s` | `0.002s` | `0.000s` | `0.735s` | `0.005s` | `3.67s` |
| **PG 18 — 1M `UPDATE` (`RETURNING OLD/NEW`)** | `0.047s` | `0.002s` | `0.000s` | `3.914s` | `0.001s` | `7.22s` |
| **PG 18 — 1M `DELETE` (`RETURNING *`)** | `0.062s` | `0.001s` | `0.000s` | `0.693s` | `0.008s` | `3.55s` |
| **MySQL 8.0 — 1M `UPDATE`** | `0.284s` | `0.033s` | `3.166s` | `7.198s` | `0.179s` | `7.00s` |
| **MySQL 8.0 — 1M `DELETE`** | `0.318s` | `0.010s` | `2.970s` | `2.329s` | `0.096s` | `3.48s` |

### Per-Phase Undo (`PROXY REVERSE`) Timing Breakdown (Median Across Trials)

| Engine, Operation & Restore Path | Change-Stream Sync (`wal_sync_s`) | Ledger Load (`ledger_load_s`) | Temp Staging (`stage_temp_s`) | Conflict & Lock (`conflict_and_lock_s`) | Restore SQL (`restore_exec_s`) | `COMMIT` (`commit_s`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **PG 16 — `DROP TABLE` (`ddl_quarantine`)** | `0.0000s` | `0.0000s` | `0.000s` | `0.002s` | `0.001s` | `0.000s` |
| **PG 16 — `TRUNCATE TABLE` (`ddl_quarantine`)** | `0.0000s` | `0.0000s` | `0.000s` | `0.001s` | `0.001s` | `0.000s` |
| **PG 16 — 1M `UPDATE` (`side_table`)** | `1.3856s` | `0.0001s` | `0.000s` | `1.288s` | `4.524s` | `0.002s` |
| **PG 16 — 1M `UPDATE` (`spilled_temp_table`)** | `0.0024s` | `1.4932s` | `1.690s` | `1.450s` | `4.099s` | `0.010s` |
| **PG 16 — 1M `DELETE` (`side_table`)** | `0.8779s` | `0.0001s` | `0.000s` | `0.061s` | `3.203s` | `0.006s` |
| **PG 16 — 1M `DELETE` (`spilled_temp_table`)** | `0.0024s` | `0.7559s` | `0.856s` | `0.037s` | `2.661s` | `0.004s` |
| **PG 18 — 1M `UPDATE` (`side_table`)** | `1.1901s` | `0.0003s` | `0.000s` | `1.144s` | `4.758s` | `0.006s` |
| **PG 18 — 1M `UPDATE` (`spilled_temp_table`)** | `0.0058s` | `1.3853s` | `1.700s` | `1.531s` | `4.228s` | `0.014s` |
| **PG 18 — 1M `DELETE` (`side_table`)** | `0.7856s` | `0.0003s` | `0.000s` | `0.039s` | `2.713s` | `0.005s` |
| **PG 18 — 1M `DELETE` (`spilled_temp_table`)** | `0.0055s` | `0.5969s` | `0.803s` | `0.114s` | `2.839s` | `0.011s` |
| **MySQL 8.0 — `DROP TABLE` (`ddl_quarantine`)** | `0.0000s` | `0.0001s` | `0.000s` | `0.001s` | `0.005s` | `0.000s` |
| **MySQL 8.0 — `TRUNCATE TABLE` (`ddl_quarantine`)** | `0.0000s` | `0.0001s` | `0.000s` | `0.001s` | `0.007s` | `0.000s` |
| **MySQL 8.0 — 1M `UPDATE` (`side_table`)** | `0.0025s` | `0.0001s` | `0.000s` | `1.687s` | `7.841s` | `0.082s` |
| **MySQL 8.0 — 1M `UPDATE` (`spilled_temp_table`)** | `0.0022s` | `1.9184s` | `7.386s` | `1.960s` | `4.061s` | `0.090s` |
| **MySQL 8.0 — 1M `DELETE` (`side_table`)** | `0.0020s` | `0.0001s` | `0.000s` | `0.082s` | `6.561s` | `0.047s` |
| **MySQL 8.0 — 1M `DELETE` (`spilled_temp_table`)** | `0.0022s` | `0.8541s` | `3.669s` | `0.002s` | `3.014s` | `0.031s` |

<details>
<summary>Provenance: Git commit, image digests & cleanup verification</summary>

- Git commit: `3d9428352a7cb604a7f66e86166a5ca8bc2c8821` (`source_tree_sha256`: `b788d0fc883422949a4a031acce0c492a227e2553e14dec31c509a131cc5f4c5`)
- Trials per cell: `5`
- `postgres:16`: `postgres@sha256:3950ad7c3148ca2175ef1b6c36c9efbf78957ae8fbe8b3a5d7c35af50500382f`
- `postgres:18`: `postgres@sha256:eb63372c1e05c755f55fa30cbd07aecc443676fc6c0fa90b9002d01537841e1a`
- `mysql:8.0`: `mysql@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b`
- `mariadb:11`: `mariadb@sha256:e1d5495f445654134f226f55a41ce0da227116f6f27f283101f405c794d841fc`
- Remaining `_side_*` tables after spill drain: PG 16 = `0`, PG 18 = `0`, MySQL 8.0 = `0`.
- Live `BEGIN; UPDATE; ROLLBACK;` verified: PG 16 = `True`, MySQL 8.0 = `True`.
- Live MySQL 8.0 Primary -> Replica post-spill undo verified: formats = `['ROW', 'STATEMENT']`, `Replica_SQL_Running = Yes`.

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
