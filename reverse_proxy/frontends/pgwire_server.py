"""Asynchronous PostgreSQL v3 wire protocol (pgwire) TCP server frontend."""

from __future__ import annotations

import asyncio
import hashlib
import os
import ssl
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..compat import maybe_handle_pg_probe
from ..engine import ReverseProxyEngine
from ..models import EngineType, QueryResult
from ..protocols.pgwire_codec import (
    CANCEL_REQUEST_CODE,
    OID_TEXT,
    PG_PROTOCOL_V3,
    SSL_REQUEST_CODE,
    PgColumnDesc,
    decode_pg_text_value,
    encode_auth_md5,
    encode_auth_ok,
    encode_backend_key_data,
    encode_bind_complete,
    encode_close_complete,
    encode_command_complete,
    encode_data_row,
    encode_empty_query_response,
    encode_error_response,
    encode_no_data,
    encode_notice_response,
    encode_parameter_description,
    encode_parameter_status,
    encode_parse_complete,
    encode_ready_for_query,
    encode_row_description,
    infer_pg_oid,
    parse_bind_payload,
    parse_close_or_describe_payload,
    parse_execute_payload,
    parse_parse_payload,
    parse_startup_params,
    pg_placeholders_to_sqlite,
)


@dataclass
class _PreparedStmt:
    name: str
    sql: str
    param_oids: list[int] = field(default_factory=list)


@dataclass
class _Portal:
    name: str
    sql: str
    params: list[Any]
    result_formats: list[int]
    cached_result: QueryResult | None = None


class PgWireServer:
    """TCP server speaking pgwire v3 in front of any ReverseProxyEngine."""

    def __init__(
        self,
        engine: ReverseProxyEngine,
        host: str = "127.0.0.1",
        port: int = 5433,
        auth_users: dict[str, str] | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.engine = engine
        self.host = host
        self.port = port
        self.auth_users = auth_users
        self.ssl_context = ssl_context
        self._server: asyncio.AbstractServer | None = None
        self._bound_port: int = port

    @property
    def bound_port(self) -> int:
        return self._bound_port

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        sockets = self._server.sockets
        if sockets:
            self._bound_port = sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def _read_startup(
        self, reader: asyncio.StreamReader
    ) -> dict[str, str] | None:
        while True:
            raw_len = await reader.readexactly(4)
            length = struct.unpack("!I", raw_len)[0]
            if length < 8 or length > 65536:
                raise ValueError(f"Invalid pgwire startup length: {length}")
            body = await reader.readexactly(length - 4)
            code = struct.unpack("!I", body[:4])[0]
            if code == SSL_REQUEST_CODE:
                return None  # caller handles SSL decline and loops
            if code == CANCEL_REQUEST_CODE:
                return None
            if code == PG_PROTOCOL_V3:
                return parse_startup_params(body[4:])
            raise ValueError(f"Unsupported pgwire protocol code: {code}")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        session_id = f"pg_{uuid.uuid4().hex[:8]}"
        prepared: dict[str, _PreparedStmt] = {}
        portals: dict[str, _Portal] = {}

        try:
            # Startup / optional SSL negotiation loop
            startup_params: dict[str, str] | None = None
            while startup_params is None:
                raw_len = await reader.readexactly(4)
                length = struct.unpack("!I", raw_len)[0]
                body = await reader.readexactly(length - 4)
                code = struct.unpack("!I", body[:4])[0]
                if code == SSL_REQUEST_CODE:
                    if self.ssl_context is not None:
                        writer.write(b"S")
                        await writer.drain()
                        await writer.start_tls(self.ssl_context)
                    else:
                        writer.write(b"N")
                        await writer.drain()
                    continue
                if code == CANCEL_REQUEST_CODE:
                    writer.close()
                    return
                if code == PG_PROTOCOL_V3:
                    startup_params = parse_startup_params(body[4:])
                else:
                    writer.write(encode_error_response("Unsupported protocol version", sqlstate="0A000"))
                    await writer.drain()
                    return

            user = startup_params.get("user") or "anonymous"

            if self.auth_users is not None:
                expected_pw = self.auth_users.get(user)
                salt = os.urandom(4)
                writer.write(encode_auth_md5(salt))
                await writer.drain()
                p_header = await reader.readexactly(5)
                if chr(p_header[0]) != "p":
                    writer.write(encode_error_response("Expected password message", sqlstate="28P01"))
                    await writer.drain()
                    return
                p_len = struct.unpack("!I", p_header[1:5])[0] - 4
                pw_payload = (await reader.readexactly(p_len)).rstrip(b"\x00").decode("utf-8", errors="replace")
                if expected_pw is None:
                    writer.write(
                        encode_error_response(f'password authentication failed for user "{user}"', sqlstate="28P01")
                    )
                    await writer.drain()
                    return
                inner = hashlib.md5((expected_pw + user).encode("utf-8")).hexdigest()
                expected_md5 = "md5" + hashlib.md5(inner.encode("ascii") + salt).hexdigest()
                if pw_payload != expected_md5 and pw_payload != expected_pw:
                    writer.write(
                        encode_error_response(f'password authentication failed for user "{user}"', sqlstate="28P01")
                    )
                    await writer.drain()
                    return

            self.engine.set_session_actor(session_id, user)

            # Send handshake
            writer.write(encode_auth_ok())
            writer.write(encode_parameter_status("server_version", "16.0 (reverse-proxy)"))
            writer.write(encode_parameter_status("client_encoding", "UTF8"))
            writer.write(encode_parameter_status("server_encoding", "UTF8"))
            writer.write(encode_parameter_status("DateStyle", "ISO, MDY"))
            writer.write(encode_parameter_status("integer_datetimes", "on"))
            writer.write(encode_parameter_status("standard_conforming_strings", "on"))
            writer.write(encode_backend_key_data(os.getpid() & 0xFFFFFFFF, 1))
            writer.write(encode_ready_for_query("I"))
            await writer.drain()

            # Main message loop
            while True:
                try:
                    header = await reader.readexactly(5)
                except asyncio.IncompleteReadError:
                    break
                msg_type = chr(header[0])
                length = struct.unpack("!I", header[1:5])[0]
                payload = await reader.readexactly(length - 4) if length > 4 else b""

                if msg_type == "X":  # Terminate
                    break

                if msg_type == "Q":  # Simple Query
                    sql = payload.rstrip(b"\x00").decode("utf-8", errors="replace")
                    await self._handle_simple_query(writer, session_id, sql)
                    await writer.drain()
                    continue

                if msg_type == "P":  # Parse
                    stmt_name, query, param_oids = parse_parse_payload(payload)
                    prepared[stmt_name] = _PreparedStmt(stmt_name, query, param_oids)
                    writer.write(encode_parse_complete())
                    continue

                if msg_type == "B":  # Bind
                    portal_name, stmt_name, param_fmts, param_vals, res_fmts = (
                        parse_bind_payload(payload)
                    )
                    stmt = prepared.get(stmt_name)
                    if stmt is None:
                        writer.write(
                            encode_error_response(
                                f"Prepared statement '{stmt_name}' does not exist.",
                                sqlstate="26000",
                            )
                        )
                        continue
                    decoded_params: list[Any] = []
                    for idx, raw_val in enumerate(param_vals):
                        oid = stmt.param_oids[idx] if idx < len(stmt.param_oids) else OID_TEXT
                        fmt = (
                            param_fmts[idx]
                            if idx < len(param_fmts)
                            else (param_fmts[0] if len(param_fmts) == 1 else 0)
                        )
                        if raw_val is None:
                            decoded_params.append(None)
                        elif fmt == 0:
                            # If client didn't specify OID (0), keep string (or numeric if needed)
                            decoded_params.append(
                                decode_pg_text_value(raw_val, oid if oid else OID_TEXT)
                            )
                        else:
                            decoded_params.append(raw_val)
                    portals[portal_name] = _Portal(
                        name=portal_name,
                        sql=stmt.sql,
                        params=decoded_params,
                        result_formats=res_fmts,
                    )
                    writer.write(encode_bind_complete())
                    continue

                if msg_type == "D":  # Describe
                    target_type, name = parse_close_or_describe_payload(payload)
                    if target_type == "S":
                        stmt = prepared.get(name)
                        if stmt is None:
                            writer.write(
                                encode_error_response(
                                    f"Prepared statement '{name}' does not exist.",
                                    sqlstate="26000",
                                )
                            )
                        else:
                            writer.write(encode_parameter_description(stmt.param_oids))
                            writer.write(encode_no_data())
                    elif target_type == "P":
                        portal = portals.get(name)
                        if portal is None:
                            writer.write(
                                encode_error_response(
                                    f"Portal '{name}' does not exist.", sqlstate="34000"
                                )
                            )
                        else:
                            try:
                                res = await self._run_portal(portal, session_id)
                                if res.columns:
                                    writer.write(
                                        encode_row_description(
                                            self._build_col_descs(res)
                                        )
                                    )
                                else:
                                    writer.write(encode_no_data())
                            except Exception as exc:
                                writer.write(encode_error_response(str(exc)))
                    continue

                if msg_type == "E":  # Execute
                    portal_name, _max_rows = parse_execute_payload(payload)
                    portal = portals.get(portal_name)
                    if portal is None:
                        writer.write(
                            encode_error_response(
                                f"Portal '{portal_name}' does not exist.", sqlstate="34000"
                            )
                        )
                        continue
                    try:
                        res = await self._run_portal(portal, session_id)
                        self._write_notices(writer, res)
                        if res.columns:
                            for row in res.rows:
                                writer.write(encode_data_row(row))
                        writer.write(encode_command_complete(res.command_tag or "OK"))
                    except Exception as exc:
                        writer.write(encode_error_response(str(exc)))
                    continue

                if msg_type == "C":  # Close
                    target_type, name = parse_close_or_describe_payload(payload)
                    if target_type == "S":
                        prepared.pop(name, None)
                    elif target_type == "P":
                        portals.pop(name, None)
                    writer.write(encode_close_complete())
                    continue

                if msg_type == "H":  # Flush
                    await writer.drain()
                    continue

                if msg_type == "S":  # Sync
                    writer.write(encode_ready_for_query(self._tx_indicator(session_id)))
                    await writer.drain()
                    continue

        except (asyncio.IncompleteReadError, ConnectionResetError, EOFError):
            pass
        finally:
            self.engine.close_session(session_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _tx_indicator(self, session_id: str) -> str:
        sess = self.engine._get_session(session_id)
        return "T" if sess.in_tx else "I"

    def _translate_sql_for_backend(self, sql: str) -> str:
        if self.engine.driver.engine_type == EngineType.SQLITE:
            return pg_placeholders_to_sqlite(sql)
        return sql

    async def _run_portal(self, portal: _Portal, session_id: str) -> QueryResult:
        if portal.cached_result is not None:
            return portal.cached_result
        sql = self._translate_sql_for_backend(portal.sql)
        res = await asyncio.to_thread(
            self.engine.execute_one, sql, session_id=session_id, params=portal.params
        )
        portal.cached_result = res
        return res

    async def _handle_simple_query(
        self, writer: asyncio.StreamWriter, session_id: str, sql: str
    ) -> None:
        if not sql.strip():
            writer.write(encode_empty_query_response())
            writer.write(encode_ready_for_query(self._tx_indicator(session_id)))
            return

        try:
            results: list[QueryResult] | None = None
            if self.engine.driver.engine_type == EngineType.SQLITE:
                results = await asyncio.to_thread(maybe_handle_pg_probe, self.engine, sql)
            if results is None:
                results = await asyncio.to_thread(self.engine.execute, sql, session_id=session_id)
            if not results:
                writer.write(encode_empty_query_response())
            for res in results:
                self._write_notices(writer, res)
                if res.columns:
                    writer.write(encode_row_description(self._build_col_descs(res)))
                    for row in res.rows:
                        writer.write(encode_data_row(row))
                writer.write(encode_command_complete(res.command_tag or "OK"))
            writer.write(encode_ready_for_query(self._tx_indicator(session_id)))
        except Exception as exc:
            writer.write(encode_error_response(str(exc)))
            writer.write(encode_ready_for_query(self._tx_indicator(session_id)))

    @staticmethod
    def _build_col_descs(res: QueryResult) -> list[PgColumnDesc]:
        return [
            PgColumnDesc(name=col, type_oid=infer_pg_oid(res.rows, idx))
            for idx, col in enumerate(res.columns)
        ]

    @staticmethod
    def _write_notices(writer: asyncio.StreamWriter, res: QueryResult) -> None:
        if res.tx_id and res.reversibility is not None:
            writer.write(
                encode_notice_response(
                    f"[reverse-proxy] tx_id={res.tx_id} reversibility={res.reversibility.value}"
                )
            )
        for warning in res.warnings:
            writer.write(encode_notice_response(f"[reverse-proxy] {warning}", severity="WARNING"))
