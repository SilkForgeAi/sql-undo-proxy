"""CLI entrypoint launching pgwire, MySQL wire, and Web Control Plane servers."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import ssl
import sys
import tomllib
from typing import Any

from .drivers import MySQLDriver, PostgresDriver, SQLiteDriver
from .engine import ReverseProxyEngine
from .frontends import MySQLServer, PgWireServer
from .ledger import UndoLedger
from .binlog_poller import MySQLBinlogPoller
from .wal_poller import PostgresWALPoller
from .web_ui import ControlPlaneServer


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sql-reverse-proxy",
        description="Universal multi-engine SQL Reverse Proxy (pgwire + MySQL + Web UI)",
    )
    p.add_argument("--config", default=None, help="Optional TOML config file path")
    p.add_argument(
        "--engine",
        choices=["sqlite", "postgres", "mysql"],
        default=os.environ.get("REVERSE_PROXY_ENGINE", "sqlite"),
    )
    p.add_argument(
        "--sqlite-path",
        default=os.environ.get("REVERSE_PROXY_SQLITE_PATH", ":memory:"),
        help="SQLite DB file path (default: :memory:)",
    )
    p.add_argument(
        "--backend-host",
        default=os.environ.get("REVERSE_PROXY_BACKEND_HOST", "127.0.0.1"),
    )
    p.add_argument(
        "--backend-port",
        type=int,
        default=int(os.environ.get("REVERSE_PROXY_BACKEND_PORT", "0")),
        help="0 uses engine default (5432/3306)",
    )
    p.add_argument(
        "--backend-user",
        default=os.environ.get("REVERSE_PROXY_BACKEND_USER", "postgres"),
    )
    p.add_argument(
        "--backend-password",
        default=os.environ.get("REVERSE_PROXY_BACKEND_PASSWORD", ""),
    )
    p.add_argument(
        "--backend-db",
        default=os.environ.get("REVERSE_PROXY_BACKEND_DB", "postgres"),
    )
    p.add_argument(
        "--ledger-path",
        default=os.environ.get("REVERSE_PROXY_LEDGER_PATH", "./undo_ledger.db"),
    )
    p.add_argument(
        "--listen-host",
        default=os.environ.get("REVERSE_PROXY_LISTEN_HOST", "127.0.0.1"),
        help="Bind host for proxy listeners",
    )
    p.add_argument(
        "--pg-port",
        type=int,
        default=int(os.environ.get("REVERSE_PROXY_PG_PORT", "5433")),
        help="pgwire listen port (0 disables)",
    )
    p.add_argument(
        "--mysql-port",
        type=int,
        default=int(os.environ.get("REVERSE_PROXY_MYSQL_PORT", "3307")),
        help="MySQL listen port (0 disables)",
    )
    p.add_argument(
        "--ui-port",
        type=int,
        default=int(os.environ.get("REVERSE_PROXY_UI_PORT", "8080")),
        help="Web UI listen port (0 disables)",
    )
    p.add_argument(
        "--max-capture-rows",
        type=int,
        default=int(os.environ.get("REVERSE_PROXY_MAX_CAPTURE_ROWS", "10000")),
        help="Refuse DML/TRUNCATE affecting more than N rows before mutating (default 10000; <= 0 disables guard)",
    )
    p.add_argument(
        "--spill-retention-days",
        type=float,
        default=(
            float(os.environ["REVERSE_PROXY_SPILL_RETENTION_DAYS"])
            if os.environ.get("REVERSE_PROXY_SPILL_RETENTION_DAYS")
            else None
        ),
        help="Optional retention window (days): purge older undo records & spill files on startup",
    )
    p.add_argument("--require-where-delete", action="store_true")
    p.add_argument("--require-where-update", action="store_true")
    p.add_argument(
        "--auth-user",
        action="append",
        default=[],
        metavar="USER:PASSWORD",
        help="Optional proxy client credential (repeatable). If omitted, trust auth is enabled.",
    )
    p.add_argument(
        "--tls-cert",
        default=os.environ.get("REVERSE_PROXY_TLS_CERT", None),
        help="Optional PEM certificate file enabling TLS on pgwire and HTTPS on Web UI",
    )
    p.add_argument(
        "--tls-key",
        default=os.environ.get("REVERSE_PROXY_TLS_KEY", None),
        help="Optional PEM private key file for --tls-cert",
    )
    p.add_argument(
        "--wal-slot",
        default=os.environ.get("REVERSE_PROXY_WAL_SLOT", None),
        help="Optional Postgres logical replication slot (test_decoding) for automatic trigger/WAL capture",
    )
    p.add_argument(
        "--binlog-poll",
        action="store_true",
        default=os.environ.get("REVERSE_PROXY_BINLOG_POLL", "").lower() in ("1", "true", "yes"),
        help="Enable MySQL ROW binlog polling for automatic trigger capture and RBR trigger-safe undo",
    )
    return p


def _parse_auth_users(entries: list[str]) -> dict[str, str] | None:
    if not entries:
        return None
    users: dict[str, str] = {}
    for item in entries:
        if ":" not in item:
            raise ValueError(f"Invalid --auth-user '{item}': expected USER:PASSWORD")
        user, pw = item.split(":", 1)
        users[user] = pw
    return users


def load_config_into_args(args: argparse.Namespace) -> argparse.Namespace:
    if not args.config:
        return args
    with open(args.config, "rb") as fh:
        cfg: dict[str, Any] = tomllib.load(fh)

    proxy_cfg = cfg.get("proxy", {})
    backend_cfg = cfg.get("backend", {})
    tls_cfg = cfg.get("tls", {})
    auth_cfg = cfg.get("auth", {})

    mapping = {
        "engine": backend_cfg.get("engine") or cfg.get("engine"),
        "sqlite_path": backend_cfg.get("sqlite_path"),
        "backend_host": backend_cfg.get("host"),
        "backend_port": backend_cfg.get("port"),
        "backend_user": backend_cfg.get("user"),
        "backend_password": backend_cfg.get("password"),
        "backend_db": backend_cfg.get("database"),
        "ledger_path": proxy_cfg.get("ledger_path"),
        "listen_host": proxy_cfg.get("listen_host"),
        "pg_port": proxy_cfg.get("pg_port"),
        "mysql_port": proxy_cfg.get("mysql_port"),
        "ui_port": proxy_cfg.get("ui_port"),
        "max_capture_rows": proxy_cfg.get("max_capture_rows"),
        "spill_retention_days": proxy_cfg.get("spill_retention_days"),
        "require_where_delete": proxy_cfg.get("require_where_delete"),
        "require_where_update": proxy_cfg.get("require_where_update"),
        "binlog_poll": proxy_cfg.get("binlog_poll"),
        "wal_slot": proxy_cfg.get("wal_slot"),
        "tls_cert": tls_cfg.get("cert"),
        "tls_key": tls_cfg.get("key"),
    }
    for attr, val in mapping.items():
        if val is not None:
            setattr(args, attr, val)

    if isinstance(auth_cfg.get("users"), dict):
        merged = list(args.auth_user)
        for u, pw in auth_cfg["users"].items():
            merged.append(f"{u}:{pw}")
        args.auth_user = merged

    return args


def _build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext | None:
    if not args.tls_cert:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
    return ctx


async def _run_servers(args: argparse.Namespace) -> None:
    args = load_config_into_args(args)
    max_cap: int | None = None if args.max_capture_rows <= 0 else args.max_capture_rows
    if args.engine == "sqlite":
        driver_or_factory = SQLiteDriver(
            args.sqlite_path, max_capture_rows=max_cap
        )
    elif args.engine == "postgres":
        port = args.backend_port or 5432
        emit_wal = bool(args.wal_slot)
        driver_or_factory = lambda: PostgresDriver(
            host=args.backend_host,
            port=port,
            user=args.backend_user,
            password=args.backend_password,
            database=args.backend_db,
            max_capture_rows=max_cap,
            emit_wal_marker=emit_wal,
        )
    else:
        port = args.backend_port or 3306
        enable_binlog = bool(args.binlog_poll)
        driver_or_factory = lambda: MySQLDriver(
            host=args.backend_host,
            port=port,
            user=args.backend_user,
            password=args.backend_password,
            database=args.backend_db,
            max_capture_rows=max_cap,
            binlog_marker_enabled=enable_binlog,
        )

    auth_users = _parse_auth_users(args.auth_user)
    ssl_ctx = _build_ssl_context(args)
    ledger = UndoLedger(args.ledger_path)
    engine = ReverseProxyEngine(
        driver_or_factory,
        ledger,
        require_where_on_delete=args.require_where_delete,
        require_where_on_update=args.require_where_update,
    )
    if args.spill_retention_days is not None and args.spill_retention_days >= 0:
        erased, qs = ledger.purge_older_than(args.spill_retention_days)
        for qname, sch in qs:
            try:
                engine.driver.purge_quarantine_table(qname, sch)
            except Exception:
                pass
        if erased:
            print(
                f"[reverse-proxy] retention purged {erased} record(s) older than {args.spill_retention_days}d",
                flush=True,
            )

    pg_srv = (
        PgWireServer(
            engine,
            host=args.listen_host,
            port=args.pg_port,
            auth_users=auth_users,
            ssl_context=ssl_ctx,
        )
        if args.pg_port > 0
        else None
    )
    mysql_srv = (
        MySQLServer(
            engine,
            host=args.listen_host,
            port=args.mysql_port,
            auth_users=auth_users,
        )
        if args.mysql_port > 0
        else None
    )
    ui_srv = (
        ControlPlaneServer(
            engine,
            host=args.listen_host,
            port=args.ui_port,
            pg_port=args.pg_port or None,
            mysql_port=args.mysql_port or None,
            ssl_context=ssl_ctx,
        )
        if args.ui_port > 0
        else None
    )

    wal_poller: PostgresWALPoller | None = None
    if args.engine == "postgres" and args.wal_slot:
        wal_driver = PostgresDriver(
            host=args.backend_host,
            port=args.backend_port or 5432,
            user=args.backend_user,
            password=args.backend_password,
            database=args.backend_db,
        )
        wal_poller = PostgresWALPoller(wal_driver, ledger, slot_name=args.wal_slot)
        wal_poller.start()
        engine.wal_sync_fn = wal_poller.poll_once
        if ui_srv is not None:
            ui_srv.wal_health_fn = wal_poller.get_slot_health

    binlog_poller: MySQLBinlogPoller | None = None
    if args.engine == "mysql" and args.binlog_poll:
        bl_driver = MySQLDriver(
            host=args.backend_host,
            port=args.backend_port or 3306,
            user=args.backend_user,
            password=args.backend_password,
            database=args.backend_db,
        )
        candidate = MySQLBinlogPoller(bl_driver, ledger)
        try:
            candidate.start()
            binlog_poller = candidate
            engine.wal_sync_fn = binlog_poller.poll_once
        except Exception as exc:
            print(f"[reverse-proxy] warning: binlog poller disabled ({exc})", file=sys.stderr, flush=True)
            bl_driver.close()

    if pg_srv:
        await pg_srv.start()
    if mysql_srv:
        await mysql_srv.start()
    if ui_srv:
        ui_srv.start()

    scheme = "https" if ssl_ctx else "http"
    print(f"[reverse-proxy] backend={args.engine} ledger={args.ledger_path} tls={ssl_ctx is not None} wal_slot={args.wal_slot} binlog_poll={binlog_poller is not None}", flush=True)
    if pg_srv:
        print(f"[reverse-proxy] pgwire listening on {args.listen_host}:{pg_srv.bound_port}", flush=True)
    if mysql_srv:
        print(f"[reverse-proxy] mysql  listening on {args.listen_host}:{mysql_srv.bound_port}", flush=True)
    if ui_srv:
        print(f"[reverse-proxy] web UI listening on {scheme}://{args.listen_host}:{ui_srv.bound_port}", flush=True)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    await stop_event.wait()
    if wal_poller:
        wal_poller.stop()
        wal_poller.driver.close()
    if binlog_poller:
        binlog_poller.stop()
        binlog_poller.driver.close()
    if ui_srv:
        ui_srv.stop()
    if pg_srv:
        await pg_srv.stop()
    if mysql_srv:
        await mysql_srv.stop()
    engine.close()
    if isinstance(driver_or_factory, SQLiteDriver):
        driver_or_factory.close()
    ledger.close()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        asyncio.run(_run_servers(args))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
