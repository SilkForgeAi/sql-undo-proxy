"""PostgreSQL v3 wire protocol (pgwire) binary framing, type codecs, and packet helpers."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Any

from ..parser import tokenize

PG_PROTOCOL_V3 = 196608  # (3 << 16) | 0
SSL_REQUEST_CODE = 80877103
CANCEL_REQUEST_CODE = 80877102

# Common PostgreSQL type OIDs
OID_BOOL = 16
OID_BYTEA = 17
OID_INT8 = 20
OID_INT2 = 21
OID_INT4 = 23
OID_TEXT = 25
OID_OID = 26
OID_JSON = 114
OID_FLOAT4 = 700
OID_FLOAT8 = 701
OID_VARCHAR = 1043
OID_NUMERIC = 1700
OID_UUID = 2950
OID_JSONB = 3802


@dataclass
class PgColumnDesc:
    name: str
    table_oid: int = 0
    column_attr: int = 0
    type_oid: int = OID_TEXT
    type_size: int = -1
    type_mod: int = -1
    format_code: int = 0  # 0 = text, 1 = binary


@dataclass
class PgMessage:
    msg_type: str
    payload: bytes


def read_cstring(buf: bytes, offset: int = 0) -> tuple[str, int]:
    end = buf.find(b"\x00", offset)
    if end == -1:
        return buf[offset:].decode("utf-8", errors="replace"), len(buf)
    return buf[offset:end].decode("utf-8", errors="replace"), end + 1


def frame_message(msg_type: str, payload: bytes = b"") -> bytes:
    assert len(msg_type) == 1
    return msg_type.encode("ascii") + struct.pack("!I", 4 + len(payload)) + payload


# --- Startup & Auth ---

def encode_startup_message(params: dict[str, str]) -> bytes:
    body = bytearray(struct.pack("!I", PG_PROTOCOL_V3))
    for k, v in params.items():
        body.extend(k.encode("utf-8") + b"\x00" + v.encode("utf-8") + b"\x00")
    body.append(0)
    return struct.pack("!I", 4 + len(body)) + bytes(body)


def parse_startup_params(payload: bytes) -> dict[str, str]:
    params: dict[str, str] = {}
    offset = 0
    while offset < len(payload):
        if payload[offset : offset + 1] == b"\x00":
            break
        key, offset = read_cstring(payload, offset)
        val, offset = read_cstring(payload, offset)
        params[key] = val
    return params


def encode_auth_ok() -> bytes:
    return frame_message("R", struct.pack("!I", 0))


def encode_auth_cleartext() -> bytes:
    return frame_message("R", struct.pack("!I", 3))


def encode_auth_md5(salt: bytes) -> bytes:
    assert len(salt) == 4
    return frame_message("R", struct.pack("!I", 5) + salt)


def encode_auth_sasl(mechanisms: list[str]) -> bytes:
    body = bytearray(struct.pack("!I", 10))
    for mech in mechanisms:
        body.extend(mech.encode("utf-8") + b"\x00")
    body.append(0)
    return frame_message("R", bytes(body))


def encode_auth_sasl_continue(data: bytes) -> bytes:
    return frame_message("R", struct.pack("!I", 11) + data)


def encode_auth_sasl_final(data: bytes) -> bytes:
    return frame_message("R", struct.pack("!I", 12) + data)


def encode_parameter_status(name: str, value: str) -> bytes:
    payload = name.encode("utf-8") + b"\x00" + value.encode("utf-8") + b"\x00"
    return frame_message("S", payload)


def encode_backend_key_data(pid: int, secret_key: int) -> bytes:
    return frame_message("K", struct.pack("!II", pid, secret_key))


def encode_ready_for_query(tx_status: str = "I") -> bytes:
    assert tx_status in ("I", "T", "E")
    return frame_message("Z", tx_status.encode("ascii"))


# --- Query Responses ---

def infer_pg_oid(rows: list[tuple[Any, ...]], col_idx: int) -> int:
    for row in rows:
        val = row[col_idx]
        if val is None:
            continue
        if isinstance(val, bool):
            return OID_BOOL
        if isinstance(val, int):
            return OID_INT8 if (val < -2147483648 or val > 2147483647) else OID_INT4
        if isinstance(val, float):
            return OID_FLOAT8
        if isinstance(val, (bytes, bytearray, memoryview)):
            return OID_BYTEA
        return OID_TEXT
    return OID_TEXT


def encode_pg_text_value(val: Any) -> bytes | None:
    if val is None:
        return None
    if isinstance(val, bool):
        return b"t" if val else b"f"
    if isinstance(val, (bytes, bytearray, memoryview)):
        return b"\\x" + bytes(val).hex().encode("ascii")
    return str(val).encode("utf-8")


def decode_pg_text_value(raw: bytes | None, type_oid: int) -> Any:
    if raw is None:
        return None
    if type_oid == OID_BYTEA:
        if raw.startswith(b"\\x"):
            return bytes.fromhex(raw[2:].decode("ascii"))
        return raw
    text = raw.decode("utf-8")
    if type_oid == OID_BOOL:
        return text in ("t", "true", "TRUE", "1", "y", "yes")
    if type_oid in (OID_INT2, OID_INT4, OID_INT8, OID_OID):
        return int(text)
    if type_oid in (OID_FLOAT4, OID_FLOAT8):
        return float(text)
    return text


def encode_row_description(columns: list[PgColumnDesc]) -> bytes:
    body = bytearray(struct.pack("!H", len(columns)))
    for col in columns:
        body.extend(col.name.encode("utf-8") + b"\x00")
        body.extend(
            struct.pack(
                "!IhIhih",
                col.table_oid,
                col.column_attr,
                col.type_oid,
                col.type_size,
                col.type_mod,
                col.format_code,
            )
        )
    return frame_message("T", bytes(body))


def encode_data_row(values: list[Any] | tuple[Any, ...]) -> bytes:
    body = bytearray(struct.pack("!H", len(values)))
    for val in values:
        encoded = encode_pg_text_value(val)
        if encoded is None:
            body.extend(struct.pack("!i", -1))
        else:
            body.extend(struct.pack("!i", len(encoded)))
            body.extend(encoded)
    return frame_message("D", bytes(body))


def encode_command_complete(tag: str) -> bytes:
    return frame_message("C", tag.encode("utf-8") + b"\x00")


def encode_empty_query_response() -> bytes:
    return frame_message("I", b"")


def encode_notice_response(message: str, severity: str = "NOTICE") -> bytes:
    body = bytearray()
    body.extend(b"S" + severity.encode("utf-8") + b"\x00")
    body.extend(b"M" + message.encode("utf-8") + b"\x00")
    body.append(0)
    return frame_message("N", bytes(body))


def encode_error_response(
    message: str, *, sqlstate: str = "42000", severity: str = "ERROR"
) -> bytes:
    body = bytearray()
    body.extend(b"S" + severity.encode("utf-8") + b"\x00")
    body.extend(b"V" + severity.encode("utf-8") + b"\x00")
    body.extend(b"C" + sqlstate.encode("ascii") + b"\x00")
    body.extend(b"M" + message.encode("utf-8") + b"\x00")
    body.append(0)
    return frame_message("E", bytes(body))


# --- Extended Query Protocol Messages ---

def encode_parse_complete() -> bytes:
    return frame_message("1", b"")


def encode_bind_complete() -> bytes:
    return frame_message("2", b"")


def encode_close_complete() -> bytes:
    return frame_message("3", b"")


def encode_no_data() -> bytes:
    return frame_message("n", b"")


def encode_parameter_description(param_oids: list[int]) -> bytes:
    body = bytearray(struct.pack("!H", len(param_oids)))
    for oid in param_oids:
        body.extend(struct.pack("!I", oid))
    return frame_message("t", bytes(body))


def parse_parse_payload(payload: bytes) -> tuple[str, str, list[int]]:
    stmt_name, offset = read_cstring(payload, 0)
    query, offset = read_cstring(payload, offset)
    num_params = struct.unpack_from("!H", payload, offset)[0]
    offset += 2
    oids: list[int] = []
    for _ in range(num_params):
        oids.append(struct.unpack_from("!I", payload, offset)[0])
        offset += 4
    return stmt_name, query, oids


def parse_bind_payload(payload: bytes) -> tuple[str, str, list[int], list[bytes | None], list[int]]:
    portal, offset = read_cstring(payload, 0)
    stmt_name, offset = read_cstring(payload, offset)
    num_fmt = struct.unpack_from("!H", payload, offset)[0]
    offset += 2
    param_fmts = [struct.unpack_from("!H", payload, offset + 2 * i)[0] for i in range(num_fmt)]
    offset += 2 * num_fmt

    num_params = struct.unpack_from("!H", payload, offset)[0]
    offset += 2
    param_vals: list[bytes | None] = []
    for _ in range(num_params):
        length = struct.unpack_from("!i", payload, offset)[0]
        offset += 4
        if length == -1:
            param_vals.append(None)
        else:
            param_vals.append(payload[offset : offset + length])
            offset += length

    num_res_fmt = struct.unpack_from("!H", payload, offset)[0]
    offset += 2
    res_fmts = [struct.unpack_from("!H", payload, offset + 2 * i)[0] for i in range(num_res_fmt)]
    return portal, stmt_name, param_fmts, param_vals, res_fmts


def parse_close_or_describe_payload(payload: bytes) -> tuple[str, str]:
    target_type = chr(payload[0])
    name, _ = read_cstring(payload, 1)
    return target_type, name


def parse_execute_payload(payload: bytes) -> tuple[str, int]:
    portal, offset = read_cstring(payload, 0)
    max_rows = struct.unpack_from("!I", payload, offset)[0]
    return portal, max_rows


# --- Synchronous Socket Readers ---

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("Unexpected EOF on pgwire socket")
        buf.extend(chunk)
    return bytes(buf)


def read_startup_packet_sync(sock: socket.socket) -> tuple[int, bytes]:
    length = struct.unpack("!I", _recv_exact(sock, 4))[0]
    if length < 8 or length > 65536:
        raise ValueError(f"Invalid startup packet length: {length}")
    body = _recv_exact(sock, length - 4)
    code = struct.unpack("!I", body[:4])[0]
    return code, body[4:]


def read_typed_message_sync(sock: socket.socket) -> PgMessage:
    header = _recv_exact(sock, 5)
    msg_type = chr(header[0])
    length = struct.unpack("!I", header[1:5])[0]
    if length < 4:
        raise ValueError(f"Invalid pgwire message length: {length}")
    payload = _recv_exact(sock, length - 4) if length > 4 else b""
    return PgMessage(msg_type=msg_type, payload=payload)


# --- Dialect Helper ---

def pg_placeholders_to_sqlite(sql: str) -> str:
    """Convert PostgreSQL `$1, $2` positional parameters to SQLite `?1, ?2` outside literals/comments."""
    tokens = tokenize(sql)
    out: list[str] = []
    last = 0
    for tok in tokens:
        if tok.kind == "WORD" and tok.text.startswith("$") and tok.text[1:].isdigit():
            out.append(sql[last : tok.start])
            out.append("?" + tok.text[1:])
            last = tok.end
    out.append(sql[last:])
    return "".join(out)
