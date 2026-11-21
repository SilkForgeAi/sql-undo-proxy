"""Session probe & introspection compatibility layer for real psql/mysql/ORM clients on SQLite backends."""

from __future__ import annotations

import re

from .engine import ReverseProxyEngine
from .models import QueryResult


def maybe_handle_pg_probe(
    engine: ReverseProxyEngine, sql: str
) -> list[QueryResult] | None:
    """
    Emulate common PostgreSQL client startup/introspection probes (psql, psycopg,
    SQLAlchemy, DBeaver) when running against a SQLite backend.
    """
    s = sql.strip().rstrip(";").strip()
    if not s:
        return None
    upper = s.upper()

    # SET <var> = ... / SET NAMES ... / SET TIME ZONE ...
    if upper.startswith("SET "):
        return [QueryResult(command_tag="SET")]

    # RESET ALL / DISCARD ALL
    if upper in ("RESET ALL", "DISCARD ALL"):
        return [QueryResult(command_tag=upper)]

    # SHOW <param>
    if upper.startswith("SHOW "):
        param = s[5:].strip().lower()
        defaults = {
            "standard_conforming_strings": ("standard_conforming_strings", "on"),
            "server_version": ("server_version", "16.0 (sql-reverse-proxy)"),
            "client_encoding": ("client_encoding", "UTF8"),
            "server_encoding": ("server_encoding", "UTF8"),
            "datestyle": ("DateStyle", "ISO, MDY"),
            "transaction isolation level": ("transaction_isolation", "read committed"),
            "transaction_isolation": ("transaction_isolation", "read committed"),
        }
        if param in defaults:
            col, val = defaults[param]
            return [QueryResult(columns=[col], rows=[(val,)], rowcount=1, command_tag="SELECT 1")]
        return [QueryResult(columns=[param or "setting"], rows=[("",)], rowcount=1, command_tag="SELECT 1")]

    # SELECT version() / current_database() / current_schema()
    if re.fullmatch(r"SELECT\s+VERSION\s*\(\s*\)", s, re.I):
        return [
            QueryResult(
                columns=["version"],
                rows=[("PostgreSQL 16.0 (sql-reverse-proxy on SQLite)",)],
                rowcount=1,
                command_tag="SELECT 1",
            )
        ]
    if re.fullmatch(r"SELECT\s+CURRENT_DATABASE\s*\(\s*\)", s, re.I):
        return [
            QueryResult(
                columns=["current_database"],
                rows=[("app",)],
                rowcount=1,
                command_tag="SELECT 1",
            )
        ]
    if re.fullmatch(r"SELECT\s+CURRENT_SCHEMA\s*\(\s*\)", s, re.I):
        return [
            QueryResult(
                columns=["current_schema"],
                rows=[("public",)],
                rowcount=1,
                command_tag="SELECT 1",
            )
        ]

    return None


def maybe_handle_mysql_probe(
    engine: ReverseProxyEngine, sql: str, *, database: str = "app"
) -> list[QueryResult] | None:
    """
    Emulate common MySQL client startup/introspection probes (mysql CLI, PyMySQL,
    SQLAlchemy, DBeaver) when running against a SQLite backend.
    """
    s = sql.strip().rstrip(";").strip()
    if not s:
        return None
    upper = s.upper()

    if upper.startswith("SET "):
        return [QueryResult(command_tag="OK")]

    if upper.startswith("USE "):
        return [QueryResult(command_tag="OK")]

    # SELECT @@... probes (mysql client / SQLAlchemy / PyMySQL)
    if re.match(r"^SELECT\s+@@", s, re.I):
        if "VERSION_COMMENT" in upper:
            return [
                QueryResult(
                    columns=["@@version_comment"],
                    rows=[("sql-reverse-proxy (SQLite)",)],
                    rowcount=1,
                    command_tag="SELECT 1",
                )
            ]
        if "MAX_ALLOWED_PACKET" in upper:
            return [
                QueryResult(
                    columns=["@@max_allowed_packet"],
                    rows=[(67108864,)],
                    rowcount=1,
                    command_tag="SELECT 1",
                )
            ]
        if "ISOLATION" in upper:
            return [
                QueryResult(
                    columns=["@@transaction_isolation"],
                    rows=[("REPEATABLE-READ",)],
                    rowcount=1,
                    command_tag="SELECT 1",
                )
            ]
        if "SQL_MODE" in upper:
            return [
                QueryResult(
                    columns=["@@sql_mode"],
                    rows=[("STRICT_TRANS_TABLES",)],
                    rowcount=1,
                    command_tag="SELECT 1",
                )
            ]
        return [QueryResult(columns=["value"], rows=[("",)], rowcount=1, command_tag="SELECT 1")]

    if re.fullmatch(r"SELECT\s+DATABASE\s*\(\s*\)", s, re.I):
        return [
            QueryResult(
                columns=["DATABASE()"],
                rows=[(database or "app",)],
                rowcount=1,
                command_tag="SELECT 1",
            )
        ]

    if re.fullmatch(r"SELECT\s+VERSION\s*\(\s*\)", s, re.I):
        return [
            QueryResult(
                columns=["VERSION()"],
                rows=[("8.0.36-reverse-proxy",)],
                rowcount=1,
                command_tag="SELECT 1",
            )
        ]

    if upper == "SHOW TABLES":
        res = engine.driver.execute_read(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_reverse_quarantine%' ORDER BY name;"
        )
        col = f"Tables_in_{database or 'app'}"
        return [
            QueryResult(
                columns=[col],
                rows=res.rows,
                rowcount=len(res.rows),
                command_tag=f"SELECT {len(res.rows)}",
            )
        ]

    if upper == "SHOW DATABASES":
        return [
            QueryResult(
                columns=["Database"],
                rows=[(database or "app",)],
                rowcount=1,
                command_tag="SELECT 1",
            )
        ]

    m_desc = re.match(
        r"^(?:DESCRIBE|DESC|SHOW\s+COLUMNS\s+FROM)\s+`?([A-Za-z_0-9 ]+)`?$", s, re.I
    )
    if m_desc:
        tbl = m_desc.group(1)
        schema = engine.driver.inspect_table(tbl)
        rows = [
            (
                col,
                schema.column_types.get(col, "TEXT"),
                "YES" if col not in schema.pk_columns else "NO",
                "PRI" if (col in schema.pk_columns and not schema.using_rowid_fallback) else "",
                None,
                "",
            )
            for col in schema.columns
        ]
        return [
            QueryResult(
                columns=["Field", "Type", "Null", "Key", "Default", "Extra"],
                rows=rows,
                rowcount=len(rows),
                command_tag=f"SELECT {len(rows)}",
            )
        ]

    if upper.startswith("SHOW VARIABLES") or upper.startswith("SHOW COLLATION") or upper.startswith("SHOW WARNINGS"):
        return [
            QueryResult(
                columns=["Variable_name", "Value"],
                rows=[],
                rowcount=0,
                command_tag="SELECT 0",
            )
        ]

    return None
