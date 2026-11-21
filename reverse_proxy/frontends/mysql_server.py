"""Asynchronous MySQL wire protocol TCP server frontend."""

from __future__ import annotations

import asyncio
import os
import struct
import uuid
from typing import Any

from ..compat import maybe_handle_mysql_probe
from ..engine import ReverseProxyEngine
from ..models import EngineType, QueryResult
from ..parser import tokenize
from ..protocols.mysql_codec import (
    CLIENT_DEPRECATE_EOF,
    COM_INIT_DB,
    COM_PING,
    COM_QUERY,
    COM_QUIT,
    COM_STMT_CLOSE,
    COM_STMT_EXECUTE,
    COM_STMT_PREPARE,
    COM_STMT_RESET,
    SERVER_STATUS_AUTOCOMMIT,
    SERVER_STATUS_IN_TRANS,
    MySQLColumnDef,
    caching_sha2_password_scramble,
    encode_binary_row,
    encode_column_definition_41,
    encode_eof_packet,
    encode_err_packet,
    encode_handshake_v10,
    encode_lenenc_int,
    encode_ok_packet,
    encode_stmt_prepare_ok,
    encode_text_row,
    frame_mysql_packet,
    infer_mysql_field_type,
    mysql_native_password_scramble,
    parse_handshake_response_41,
    parse_stmt_execute,
)


class MySQLServer:
    """TCP server speaking the MySQL 8.0 wire protocol in front of any ReverseProxyEngine."""

    def __init__(
        self,
        engine: ReverseProxyEngine,
        host: str = "127.0.0.1",
        port: int = 3307,
        auth_users: dict[str, str] | None = None,
    ) -> None:
        self.engine = engine
        self.host = host
        self.port = port
        self.auth_users = auth_users
        self._server: asyncio.AbstractServer | None = None
        self._bound_port = port
        self._conn_counter = 0

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

    async def _read_packet(self, reader: asyncio.StreamReader) -> tuple[int, bytes]:
        header = await reader.readexactly(4)
        length = header[0] | (header[1] << 8) | (header[2] << 16)
        seq_id = header[3]
        payload = await reader.readexactly(length) if length > 0 else b""
        return seq_id, payload

    def _status_flags(self, session_id: str) -> int:
        sess = self.engine._get_session(session_id)
        if sess.in_tx:
            return SERVER_STATUS_IN_TRANS
        return SERVER_STATUS_AUTOCOMMIT

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        session_id = f"mysql_{uuid.uuid4().hex[:8]}"
        self._conn_counter += 1
        conn_id = self._conn_counter

        try:
            scramble = os.urandom(20)
            handshake = encode_handshake_v10(conn_id=conn_id, scramble=scramble)
            writer.write(frame_mysql_packet(handshake, seq_id=0))
            await writer.drain()

            seq, resp_payload = await self._read_packet(reader)
            hs_resp = parse_handshake_response_41(resp_payload)
            deprecate_eof = bool(hs_resp["client_flags"] & CLIENT_DEPRECATE_EOF)
            username = hs_resp.get("username") or "anonymous"

            if self.auth_users is not None:
                expected_pw = self.auth_users.get(username)
                client_plugin = hs_resp.get("auth_plugin") or "mysql_native_password"
                if expected_pw is None:
                    valid = False
                elif client_plugin == "caching_sha2_password":
                    valid = (
                        hs_resp["auth_response"]
                        == caching_sha2_password_scramble(expected_pw, scramble)
                    )
                else:
                    valid = (
                        hs_resp["auth_response"]
                        == mysql_native_password_scramble(expected_pw, scramble)
                    )
                if not valid:
                    writer.write(
                        frame_mysql_packet(
                            encode_err_packet(
                                f"Access denied for user '{username}'",
                                error_code=1045,
                                sqlstate="28000",
                            ),
                            seq_id=seq + 1,
                        )
                    )
                    await writer.drain()
                    return

            self.engine.set_session_actor(session_id, username)

            writer.write(
                frame_mysql_packet(
                    encode_ok_packet(status_flags=SERVER_STATUS_AUTOCOMMIT),
                    seq_id=seq + 1,
                )
            )
            await writer.drain()

            prepared_stmts: dict[int, list[Any]] = {}
            next_stmt_id = 1

            while True:
                try:
                    seq, payload = await self._read_packet(reader)
                except asyncio.IncompleteReadError:
                    break
                if not payload:
                    continue

                cmd = payload[0]
                next_seq = seq + 1

                if cmd == COM_QUIT:
                    break

                if cmd == COM_PING:
                    writer.write(
                        frame_mysql_packet(
                            encode_ok_packet(status_flags=self._status_flags(session_id)),
                            seq_id=next_seq,
                        )
                    )
                    await writer.drain()
                    continue

                if cmd == COM_INIT_DB:
                    writer.write(
                        frame_mysql_packet(
                            encode_ok_packet(status_flags=self._status_flags(session_id)),
                            seq_id=next_seq,
                        )
                    )
                    await writer.drain()
                    continue

                if cmd == COM_QUERY:
                    sql = payload[1:].decode("utf-8", errors="replace")
                    await self._handle_com_query(
                        writer, session_id, sql, next_seq, deprecate_eof=deprecate_eof
                    )
                    await writer.drain()
                    continue

                if cmd == COM_STMT_PREPARE:
                    sql = payload[1:].decode("utf-8", errors="replace")
                    num_params = sum(1 for t in tokenize(sql) if t.kind == "OP" and t.text == "?")
                    stmt_id = next_stmt_id
                    next_stmt_id += 1
                    prepared_stmts[stmt_id] = [sql, num_params, []]
                    writer.write(
                        frame_mysql_packet(
                            encode_stmt_prepare_ok(stmt_id, 0, num_params),
                            seq_id=next_seq,
                        )
                    )
                    cur_seq = next_seq + 1
                    if num_params > 0:
                        for pidx in range(num_params):
                            writer.write(
                                frame_mysql_packet(
                                    encode_column_definition_41(MySQLColumnDef(name=f"?{pidx}")),
                                    seq_id=cur_seq,
                                )
                            )
                            cur_seq += 1
                        writer.write(
                            frame_mysql_packet(
                                encode_eof_packet(status_flags=self._status_flags(session_id)),
                                seq_id=cur_seq,
                            )
                        )
                    await writer.drain()
                    continue

                if cmd == COM_STMT_EXECUTE:
                    stmt_id = struct.unpack_from("<I", payload, 1)[0]
                    entry = prepared_stmts.get(stmt_id)
                    if entry is None:
                        writer.write(
                            frame_mysql_packet(
                                encode_err_packet(f"Unknown prepared statement handler ({stmt_id})", error_code=1243),
                                seq_id=next_seq,
                            )
                        )
                        await writer.drain()
                        continue
                    sql, num_params, saved_types = entry
                    _, params, new_types = parse_stmt_execute(payload, num_params, saved_types)
                    entry[2] = new_types
                    await self._handle_stmt_execute(
                        writer,
                        session_id,
                        sql,
                        params,
                        next_seq,
                        deprecate_eof=deprecate_eof,
                    )
                    await writer.drain()
                    continue

                if cmd == COM_STMT_CLOSE:
                    if len(payload) >= 5:
                        stmt_id = struct.unpack_from("<I", payload, 1)[0]
                        prepared_stmts.pop(stmt_id, None)
                    continue

                if cmd == COM_STMT_RESET:
                    writer.write(
                        frame_mysql_packet(
                            encode_ok_packet(status_flags=self._status_flags(session_id)),
                            seq_id=next_seq,
                        )
                    )
                    await writer.drain()
                    continue

                writer.write(
                    frame_mysql_packet(
                        encode_err_packet(f"Unsupported MySQL command: 0x{cmd:02x}", error_code=1047),
                        seq_id=next_seq,
                    )
                )
                await writer.drain()

        except (asyncio.IncompleteReadError, ConnectionResetError, EOFError):
            pass
        finally:
            self.engine.close_session(session_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_com_query(
        self,
        writer: asyncio.StreamWriter,
        session_id: str,
        sql: str,
        seq: int,
        *,
        deprecate_eof: bool,
    ) -> None:
        try:
            results: list[QueryResult] | None = None
            if self.engine.driver.engine_type == EngineType.SQLITE:
                results = await asyncio.to_thread(maybe_handle_mysql_probe, self.engine, sql)
            if results is None:
                results = await asyncio.to_thread(self.engine.execute, sql, session_id=session_id)
        except Exception as exc:
            writer.write(frame_mysql_packet(encode_err_packet(str(exc)), seq_id=seq))
            return
        self._write_results(writer, session_id, results, seq, deprecate_eof=deprecate_eof, binary=False)

    async def _handle_stmt_execute(
        self,
        writer: asyncio.StreamWriter,
        session_id: str,
        sql: str,
        params: list[Any],
        seq: int,
        *,
        deprecate_eof: bool,
    ) -> None:
        try:
            results = await asyncio.to_thread(
                self.engine.execute, sql, session_id=session_id, params=params
            )
        except Exception as exc:
            writer.write(frame_mysql_packet(encode_err_packet(str(exc)), seq_id=seq))
            return
        self._write_results(writer, session_id, results, seq, deprecate_eof=deprecate_eof, binary=True)

    def _write_results(
        self,
        writer: asyncio.StreamWriter,
        session_id: str,
        results: list[QueryResult],
        seq: int,
        *,
        deprecate_eof: bool,
        binary: bool,
    ) -> None:
        if not results:
            writer.write(
                frame_mysql_packet(
                    encode_ok_packet(status_flags=self._status_flags(session_id)),
                    seq_id=seq,
                )
            )
            return

        res = results[-1]
        status_flags = self._status_flags(session_id)

        if not res.columns:
            info_parts: list[str] = []
            if res.tx_id and res.reversibility is not None:
                info_parts.append(
                    f"[reverse-proxy] tx_id={res.tx_id} reversibility={res.reversibility.value}"
                )
            info_parts.extend(res.warnings)
            ok = encode_ok_packet(
                affected_rows=res.rowcount,
                status_flags=status_flags,
                warnings=len(res.warnings),
                info=" | ".join(info_parts),
            )
            writer.write(frame_mysql_packet(ok, seq_id=seq))
            return

        writer.write(frame_mysql_packet(encode_lenenc_int(len(res.columns)), seq_id=seq))
        seq += 1

        col_defs: list[MySQLColumnDef] = []
        for idx, col_name in enumerate(res.columns):
            col_def = MySQLColumnDef(
                name=col_name,
                field_type=infer_mysql_field_type(res.rows, idx),
            )
            col_defs.append(col_def)
            writer.write(frame_mysql_packet(encode_column_definition_41(col_def), seq_id=seq))
            seq += 1

        if not deprecate_eof:
            writer.write(
                frame_mysql_packet(encode_eof_packet(status_flags=status_flags), seq_id=seq)
            )
            seq += 1

        for row in res.rows:
            row_bytes = encode_binary_row(row, col_defs) if binary else encode_text_row(row)
            writer.write(frame_mysql_packet(row_bytes, seq_id=seq))
            seq += 1

        if deprecate_eof:
            eof_ok = encode_ok_packet(
                status_flags=status_flags,
                warnings=len(res.warnings),
                header_byte=0xFE,
            )
            writer.write(frame_mysql_packet(eof_ok, seq_id=seq))
        else:
            writer.write(
                frame_mysql_packet(encode_eof_packet(status_flags=status_flags), seq_id=seq)
            )
