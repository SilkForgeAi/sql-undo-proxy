"""Pure-Python MySQL wire protocol TCP client."""

from __future__ import annotations

import socket
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from ..protocols.mysql_codec import (
    CLIENT_DEPRECATE_EOF,
    COM_INIT_DB,
    COM_PING,
    COM_QUERY,
    COM_QUIT,
    SERVER_STATUS_IN_TRANS,
    MySQLColumnDef,
    bind_mysql_params,
    caching_sha2_full_auth_encrypt,
    caching_sha2_password_scramble,
    decode_lenenc_int,
    decode_mysql_text_row,
    encode_handshake_response_41,
    frame_mysql_packet,
    mysql_native_password_scramble,
    parse_auth_switch_request,
    parse_column_definition_41,
    parse_err_packet,
    parse_handshake_v10,
    parse_ok_packet,
    read_mysql_packet_sync,
)


class MySQLError(RuntimeError):
    def __init__(self, message: str, code: int = 0, sqlstate: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.sqlstate = sqlstate


@dataclass
class MySQLResult:
    columns: list[str] = field(default_factory=list)
    field_types: list[int] = field(default_factory=list)
    rows: list[tuple[Any, ...]] = field(default_factory=list)
    affected_rows: int = 0
    last_insert_id: int = 0
    info: str = ""
    server_status: int = 0

    @property
    def in_transaction(self) -> bool:
        return bool(self.server_status & SERVER_STATUS_IN_TRANS)


class MySQLWireClient:
    """Synchronous MySQL wire client using mysql_native_password."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3306,
        user: str = "root",
        password: str = "",
        database: str = "",
        timeout: float = 120.0,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self.server_version = ""
        self.server_status = 0
        self._deprecate_eof = True
        self.connect()

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock = sock
        try:
            pkt = read_mysql_packet_sync(sock)
            if pkt.payload[:1] == b"\xff":
                code, state, msg = parse_err_packet(pkt.payload)
                raise MySQLError(msg, code=code, sqlstate=state)
            hs = parse_handshake_v10(pkt.payload)
            self.server_version = hs["server_version"]
            self._deprecate_eof = bool(hs["capabilities"] & CLIENT_DEPRECATE_EOF)

            plugin = hs.get("auth_plugin") or "mysql_native_password"
            nonce = hs["scramble"]
            if plugin == "caching_sha2_password":
                scramble = caching_sha2_password_scramble(self.password, nonce)
            else:
                plugin = "mysql_native_password"
                scramble = mysql_native_password_scramble(self.password, nonce)

            resp = encode_handshake_response_41(
                username=self.user,
                auth_response=scramble,
                database=self.database,
                auth_plugin=plugin,
            )
            sock.sendall(frame_mysql_packet(resp, seq_id=pkt.seq_id + 1))

            while True:
                auth_res = read_mysql_packet_sync(sock)
                hdr = auth_res.payload[:1]
                if hdr == b"\xff":
                    code, state, msg = parse_err_packet(auth_res.payload)
                    raise MySQLError(msg, code=code, sqlstate=state)
                if hdr == b"\x00":
                    ok = parse_ok_packet(auth_res.payload)
                    self.server_status = ok["status_flags"]
                    break
                if hdr == b"\xfe":
                    plugin, nonce = parse_auth_switch_request(auth_res.payload)
                    if plugin == "caching_sha2_password":
                        sw_resp = caching_sha2_password_scramble(self.password, nonce)
                    else:
                        sw_resp = mysql_native_password_scramble(self.password, nonce)
                    sock.sendall(frame_mysql_packet(sw_resp, seq_id=auth_res.seq_id + 1))
                    continue
                if hdr == b"\x01":
                    # AuthMoreData for caching_sha2_password
                    sub = auth_res.payload[1:2]
                    if sub == b"\x03":
                        # Fast auth succeeded; next packet is OK_Packet
                        continue
                    if sub == b"\x04":
                        # Full auth required: request RSA public key
                        sock.sendall(frame_mysql_packet(b"\x02", seq_id=auth_res.seq_id + 1))
                        key_pkt = read_mysql_packet_sync(sock)
                        if key_pkt.payload[:1] == b"\xff":
                            code, state, msg = parse_err_packet(key_pkt.payload)
                            raise MySQLError(msg, code=code, sqlstate=state)
                        pem = key_pkt.payload[1:]
                        encrypted = caching_sha2_full_auth_encrypt(self.password, nonce, pem)
                        sock.sendall(frame_mysql_packet(encrypted, seq_id=key_pkt.seq_id + 1))
                        continue
                break
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.sendall(frame_mysql_packet(bytes([COM_QUIT]), seq_id=0))
            except OSError:
                pass
            try:
                self._sock.close()
            finally:
                self._sock = None

    def ping(self) -> None:
        assert self._sock is not None
        self._sock.sendall(frame_mysql_packet(bytes([COM_PING]), seq_id=0))
        pkt = read_mysql_packet_sync(self._sock)
        if pkt.payload[:1] == b"\xff":
            code, state, msg = parse_err_packet(pkt.payload)
            raise MySQLError(msg, code=code, sqlstate=state)

    def select_db(self, database: str) -> None:
        assert self._sock is not None
        payload = bytes([COM_INIT_DB]) + database.encode("utf-8")
        self._sock.sendall(frame_mysql_packet(payload, seq_id=0))
        pkt = read_mysql_packet_sync(self._sock)
        if pkt.payload[:1] == b"\xff":
            code, state, msg = parse_err_packet(pkt.payload)
            raise MySQLError(msg, code=code, sqlstate=state)
        self.database = database

    def query(self, sql: str) -> MySQLResult:
        assert self._sock is not None
        payload = bytes([COM_QUERY]) + sql.encode("utf-8")
        self._sock.sendall(frame_mysql_packet(payload, seq_id=0))
        return self._read_query_response()

    def execute(self, sql: str, params: Sequence[Any] = ()) -> MySQLResult:
        bound_sql = bind_mysql_params(sql, params) if params else sql
        return self.query(bound_sql)

    def _read_query_response(self) -> MySQLResult:
        assert self._sock is not None
        first = read_mysql_packet_sync(self._sock)
        header = first.payload[0]

        if header == 0xFF:
            code, state, msg = parse_err_packet(first.payload)
            raise MySQLError(msg, code=code, sqlstate=state)

        if header == 0x00:
            ok = parse_ok_packet(first.payload)
            self.server_status = ok["status_flags"]
            return MySQLResult(
                affected_rows=ok["affected_rows"],
                last_insert_id=ok["last_insert_id"],
                info=ok["info"],
                server_status=ok["status_flags"],
            )

        # Resultset
        col_count, _ = decode_lenenc_int(first.payload, 0)
        assert col_count is not None
        col_defs: list[MySQLColumnDef] = []
        for _ in range(col_count):
            pkt = read_mysql_packet_sync(self._sock)
            col_defs.append(parse_column_definition_41(pkt.payload))

        if not self._deprecate_eof:
            eof_pkt = read_mysql_packet_sync(self._sock)
            if eof_pkt.payload[0] == 0xFF:
                code, state, msg = parse_err_packet(eof_pkt.payload)
                raise MySQLError(msg, code=code, sqlstate=state)

        rows: list[tuple[Any, ...]] = []
        while True:
            pkt = read_mysql_packet_sync(self._sock)
            if pkt.payload[0] == 0xFF:
                code, state, msg = parse_err_packet(pkt.payload)
                raise MySQLError(msg, code=code, sqlstate=state)
            if pkt.payload[0] == 0xFE and len(pkt.payload) < 9:
                # Classic EOF or CLIENT_DEPRECATE_EOF OK packet
                if self._deprecate_eof and len(pkt.payload) >= 5:
                    ok = parse_ok_packet(pkt.payload)
                    self.server_status = ok["status_flags"]
                break
            rows.append(decode_mysql_text_row(pkt.payload, col_defs))

        return MySQLResult(
            columns=[c.name for c in col_defs],
            field_types=[c.field_type for c in col_defs],
            rows=rows,
            affected_rows=len(rows),
            server_status=self.server_status,
        )
