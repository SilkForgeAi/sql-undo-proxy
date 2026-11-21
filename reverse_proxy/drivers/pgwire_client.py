"""Pure-Python PostgreSQL v3 wire protocol (pgwire) TCP client."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import socket
import ssl
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..protocols.pgwire_codec import (
    OID_TEXT,
    SSL_REQUEST_CODE,
    PgColumnDesc,
    decode_pg_text_value,
    encode_pg_text_value,
    encode_startup_message,
    frame_message,
    read_cstring,
    read_typed_message_sync,
)


class PgError(RuntimeError):
    def __init__(self, message: str, sqlstate: str = "") -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


@dataclass
class PgWireResult:
    columns: list[str] = field(default_factory=list)
    column_oids: list[int] = field(default_factory=list)
    rows: list[tuple[Any, ...]] = field(default_factory=list)
    command_tag: str = ""
    notices: list[str] = field(default_factory=list)


class PgWireClient:
    """Synchronous pgwire v3 client supporting Trust, Cleartext, MD5, and SCRAM-SHA-256."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5432,
        user: str = "postgres",
        password: str = "",
        database: str = "postgres",
        timeout: float = 120.0,
        ssl_mode: str = "disable",
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.timeout = timeout
        self.ssl_mode = ssl_mode
        self.ssl_context = ssl_context
        self._sock: socket.socket | None = None
        self.server_params: dict[str, str] = {}
        self.tx_status: str = "I"
        self.connect()

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock = sock
        try:
            if self.ssl_mode in ("prefer", "require"):
                ssl_req = struct.pack("!II", 8, SSL_REQUEST_CODE)
                sock.sendall(ssl_req)
                reply = sock.recv(1)
                if reply == b"S":
                    ctx = self.ssl_context or ssl.create_default_context()
                    sock = ctx.wrap_socket(sock, server_hostname=self.host)
                    self._sock = sock
                elif self.ssl_mode == "require":
                    raise PgError("Server refused TLS/SSL upgrade (ssl_mode=require)")
            startup = encode_startup_message({"user": self.user, "database": self.database})
            sock.sendall(startup)
            self._authenticate()
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.sendall(frame_message("X", b""))
            except OSError:
                pass
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _authenticate(self) -> None:
        assert self._sock is not None
        scram_state: dict[str, Any] = {}

        while True:
            msg = read_typed_message_sync(self._sock)
            if msg.msg_type == "R":
                auth_type = struct.unpack("!I", msg.payload[:4])[0]
                if auth_type == 0:  # AuthOK
                    continue
                if auth_type == 3:  # Cleartext
                    self._sock.sendall(
                        frame_message("p", self.password.encode("utf-8") + b"\x00")
                    )
                    continue
                if auth_type == 5:  # MD5
                    salt = msg.payload[4:8]
                    inner = hashlib.md5(
                        (self.password + self.user).encode("utf-8")
                    ).hexdigest()
                    outer = hashlib.md5(inner.encode("ascii") + salt).hexdigest()
                    self._sock.sendall(
                        frame_message("p", ("md5" + outer).encode("ascii") + b"\x00")
                    )
                    continue
                if auth_type == 10:  # SASL
                    nonce = base64.b64encode(os.urandom(18)).decode("ascii")
                    client_first_bare = f"n={self.user},r={nonce}"
                    client_first = "n,," + client_first_bare
                    scram_state["nonce"] = nonce
                    scram_state["client_first_bare"] = client_first_bare
                    mech = b"SCRAM-SHA-256\x00"
                    initial_bytes = client_first.encode("utf-8")
                    body = mech + struct.pack("!i", len(initial_bytes)) + initial_bytes
                    self._sock.sendall(frame_message("p", body))
                    continue
                if auth_type == 11:  # SASLContinue
                    server_first = msg.payload[4:].decode("utf-8")
                    parts = dict(p.split("=", 1) for p in server_first.split(","))
                    srv_nonce = parts["r"]
                    if not srv_nonce.startswith(scram_state["nonce"]):
                        raise PgError("SCRAM server nonce mismatch")
                    salt = base64.b64decode(parts["s"])
                    iterations = int(parts["i"])
                    salted_pw = hashlib.pbkdf2_hmac(
                        "sha256", self.password.encode("utf-8"), salt, iterations
                    )
                    client_key = hmac.new(salted_pw, b"Client Key", hashlib.sha256).digest()
                    stored_key = hashlib.sha256(client_key).digest()
                    client_final_no_proof = f"c=biws,r={srv_nonce}"
                    auth_msg = (
                        f"{scram_state['client_first_bare']},{server_first},{client_final_no_proof}"
                    ).encode("utf-8")
                    client_sig = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
                    proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
                    client_final = (
                        f"{client_final_no_proof},p={base64.b64encode(proof).decode('ascii')}"
                    )
                    server_key = hmac.new(salted_pw, b"Server Key", hashlib.sha256).digest()
                    scram_state["expected_srv_sig"] = hmac.new(
                        server_key, auth_msg, hashlib.sha256
                    ).digest()
                    self._sock.sendall(
                        frame_message("p", client_final.encode("utf-8"))
                    )
                    continue
                if auth_type == 12:  # SASLFinal
                    server_final = msg.payload[4:].decode("utf-8")
                    parts = dict(p.split("=", 1) for p in server_final.split(","))
                    if "v" in parts:
                        sig = base64.b64decode(parts["v"])
                        if not hmac.compare_digest(sig, scram_state["expected_srv_sig"]):
                            raise PgError("SCRAM server signature verification failed")
                    continue
                raise PgError(f"Unsupported pgwire auth type: {auth_type}")

            if msg.msg_type == "S":
                k, off = read_cstring(msg.payload, 0)
                v, _ = read_cstring(msg.payload, off)
                self.server_params[k] = v
                continue
            if msg.msg_type == "K":
                continue
            if msg.msg_type == "N":
                continue
            if msg.msg_type == "E":
                raise self._parse_error(msg.payload)
            if msg.msg_type == "Z":
                self.tx_status = chr(msg.payload[0])
                return

    @staticmethod
    def _parse_error(payload: bytes) -> PgError:
        fields: dict[str, str] = {}
        off = 0
        while off < len(payload):
            code = chr(payload[off])
            off += 1
            if code == "\x00":
                break
            val, off = read_cstring(payload, off)
            fields[code] = val
        return PgError(fields.get("M", "Unknown PostgreSQL error"), sqlstate=fields.get("C", ""))

    @staticmethod
    def _parse_notice(payload: bytes) -> str:
        fields: dict[str, str] = {}
        off = 0
        while off < len(payload):
            code = chr(payload[off])
            off += 1
            if code == "\x00":
                break
            val, off = read_cstring(payload, off)
            fields[code] = val
        return fields.get("M", "")

    @staticmethod
    def _parse_row_desc(payload: bytes) -> list[PgColumnDesc]:
        num_cols = struct.unpack_from("!H", payload, 0)[0]
        off = 2
        cols: list[PgColumnDesc] = []
        for _ in range(num_cols):
            name, off = read_cstring(payload, off)
            table_oid, col_attr, type_oid, type_size, type_mod, fmt = struct.unpack_from(
                "!IhIhih", payload, off
            )
            off += 18
            cols.append(
                PgColumnDesc(
                    name=name,
                    table_oid=table_oid,
                    column_attr=col_attr,
                    type_oid=type_oid,
                    type_size=type_size,
                    type_mod=type_mod,
                    format_code=fmt,
                )
            )
        return cols

    @staticmethod
    def _parse_data_row(payload: bytes, col_descs: list[PgColumnDesc]) -> tuple[Any, ...]:
        num_cols = struct.unpack_from("!H", payload, 0)[0]
        off = 2
        vals: list[Any] = []
        for i in range(num_cols):
            length = struct.unpack_from("!i", payload, off)[0]
            off += 4
            if length == -1:
                vals.append(None)
            else:
                raw = payload[off : off + length]
                off += length
                oid = col_descs[i].type_oid if i < len(col_descs) else OID_TEXT
                vals.append(decode_pg_text_value(raw, oid))
        return tuple(vals)

    def query(self, sql: str) -> list[PgWireResult]:
        """Execute one or more SQL statements via Simple Query protocol."""
        assert self._sock is not None
        self._sock.sendall(frame_message("Q", sql.encode("utf-8") + b"\x00"))
        return self._collect_results()

    def copy_from_stdin(self, copy_sql: str, chunks: Iterable[bytes]) -> PgWireResult:
        """Stream tab-delimited COPY data into PostgreSQL via CopyInResponse/CopyData/CopyDone."""
        assert self._sock is not None
        self._sock.sendall(frame_message("Q", copy_sql.encode("utf-8") + b"\x00"))
        err: PgError | None = None
        while True:
            msg = read_typed_message_sync(self._sock)
            t = msg.msg_type
            if t == "G":
                for chunk in chunks:
                    if chunk:
                        self._sock.sendall(frame_message("d", chunk))
                self._sock.sendall(frame_message("c", b""))
                results = self._collect_results()
                return results[-1] if results else PgWireResult(command_tag="COPY 0")
            if t == "N":
                continue
            if t == "E":
                err = self._parse_error(msg.payload)
            elif t == "Z":
                self.tx_status = chr(msg.payload[0])
                if err is not None:
                    raise err
                return PgWireResult(command_tag="EMPTY")

    @staticmethod
    def _build_bind_body(params: Sequence[Any]) -> bytes:
        bind_buf = bytearray(b"\x00\x00")  # portal="", stmt=""
        bind_buf.extend(struct.pack("!H", 0))  # all params text format
        bind_buf.extend(struct.pack("!H", len(params)))
        for p in params:
            encoded = encode_pg_text_value(p)
            if encoded is None:
                bind_buf.extend(struct.pack("!i", -1))
            else:
                bind_buf.extend(struct.pack("!i", len(encoded)))
                bind_buf.extend(encoded)
        bind_buf.extend(struct.pack("!H", 0))  # all result cols text format
        return bytes(bind_buf)

    def execute(self, sql: str, params: Sequence[Any] = ()) -> PgWireResult:
        """Execute a single SQL statement (uses Extended Query when params are provided)."""
        if not params:
            results = self.query(sql)
            return results[-1] if results else PgWireResult(command_tag="EMPTY")

        assert self._sock is not None
        parse_body = b"\x00" + sql.encode("utf-8") + b"\x00" + struct.pack("!H", 0)
        describe_body = b"P\x00"
        execute_body = b"\x00" + struct.pack("!I", 0)

        wire = (
            frame_message("P", parse_body)
            + frame_message("B", self._build_bind_body(params))
            + frame_message("D", describe_body)
            + frame_message("E", execute_body)
            + frame_message("S", b"")
        )
        self._sock.sendall(wire)
        results = self._collect_results()
        return results[-1] if results else PgWireResult(command_tag="EMPTY")

    def executemany(
        self, sql: str, params_seq: Sequence[Sequence[Any]], batch_size: int = 500
    ) -> None:
        """Execute a parameterized DML statement across many parameter rows via pgwire pipelining."""
        if not params_seq:
            return
        assert self._sock is not None
        parse_frame = frame_message(
            "P", b"\x00" + sql.encode("utf-8") + b"\x00" + struct.pack("!H", 0)
        )
        execute_frame = frame_message("E", b"\x00" + struct.pack("!I", 0))
        sync_frame = frame_message("S", b"")

        for i in range(0, len(params_seq), batch_size):
            chunk = params_seq[i : i + batch_size]
            wire = bytearray(parse_frame)
            for params in chunk:
                wire.extend(frame_message("B", self._build_bind_body(params)))
                wire.extend(execute_frame)
            wire.extend(sync_frame)
            self._sock.sendall(bytes(wire))
            self._collect_results()

    def _collect_results(self) -> list[PgWireResult]:
        assert self._sock is not None
        results: list[PgWireResult] = []
        current_cols: list[PgColumnDesc] = []
        current_rows: list[tuple[Any, ...]] = []
        notices: list[str] = []
        err: PgError | None = None

        while True:
            msg = read_typed_message_sync(self._sock)
            t = msg.msg_type
            if t in ("1", "2", "3", "t", "n"):
                continue
            if t == "T":
                current_cols = self._parse_row_desc(msg.payload)
                current_rows = []
            elif t == "D":
                current_rows.append(self._parse_data_row(msg.payload, current_cols))
            elif t == "C":
                tag = msg.payload.rstrip(b"\x00").decode("utf-8", errors="replace")
                results.append(
                    PgWireResult(
                        columns=[c.name for c in current_cols],
                        column_oids=[c.type_oid for c in current_cols],
                        rows=current_rows,
                        command_tag=tag,
                        notices=notices,
                    )
                )
                current_cols = []
                current_rows = []
                notices = []
            elif t == "I":
                results.append(PgWireResult(command_tag="EMPTY", notices=notices))
                notices = []
            elif t == "N":
                notices.append(self._parse_notice(msg.payload))
            elif t == "E":
                err = self._parse_error(msg.payload)
            elif t == "Z":
                self.tx_status = chr(msg.payload[0])
                if err is not None:
                    raise err
                return results
