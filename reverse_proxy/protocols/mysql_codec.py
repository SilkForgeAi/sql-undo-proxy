"""MySQL wire protocol binary framing, authentication scramble, and text resultset codecs."""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..parser import tokenize

# Capability flags
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_FOUND_ROWS = 0x00000002
CLIENT_LONG_FLAG = 0x00000004
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_TRANSACTIONS = 0x00002000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_DEPRECATE_EOF = 0x01000000

# Server status flags
SERVER_STATUS_IN_TRANS = 0x0001
SERVER_STATUS_AUTOCOMMIT = 0x0002

# Commands
COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_PING = 0x0E
COM_STMT_PREPARE = 0x16
COM_STMT_EXECUTE = 0x17
COM_STMT_CLOSE = 0x19
COM_STMT_RESET = 0x1A

# Field types
FIELD_TYPE_DECIMAL = 0x00
FIELD_TYPE_TINY = 0x01
FIELD_TYPE_SHORT = 0x02
FIELD_TYPE_LONG = 0x03
FIELD_TYPE_FLOAT = 0x04
FIELD_TYPE_DOUBLE = 0x05
FIELD_TYPE_NULL = 0x06
FIELD_TYPE_LONGLONG = 0x08
FIELD_TYPE_INT24 = 0x09
FIELD_TYPE_NEWDECIMAL = 0xF6
FIELD_TYPE_BLOB = 0xFC
FIELD_TYPE_VAR_STRING = 0xFD
FIELD_TYPE_STRING = 0xFE

UTF8MB4_CHARSET = 45


@dataclass
class MySQLPacket:
    seq_id: int
    payload: bytes


@dataclass
class MySQLColumnDef:
    name: str
    field_type: int = FIELD_TYPE_VAR_STRING
    schema: str = ""
    table: str = ""
    column_length: int = 255
    decimals: int = 0
    charset: int = UTF8MB4_CHARSET


# --- Length-Encoded Primitives ---

def encode_lenenc_int(val: int) -> bytes:
    if val < 0xFB:
        return bytes([val])
    if val < (1 << 16):
        return b"\xfc" + struct.pack("<H", val)
    if val < (1 << 24):
        return b"\xfd" + struct.pack("<I", val)[:3]
    return b"\xfe" + struct.pack("<Q", val)


def decode_lenenc_int(buf: bytes, offset: int = 0) -> tuple[int | None, int]:
    first = buf[offset]
    if first < 0xFB:
        return first, offset + 1
    if first == 0xFB:
        return None, offset + 1
    if first == 0xFC:
        return struct.unpack_from("<H", buf, offset + 1)[0], offset + 3
    if first == 0xFD:
        raw = buf[offset + 1 : offset + 4] + b"\x00"
        return struct.unpack("<I", raw)[0], offset + 4
    return struct.unpack_from("<Q", buf, offset + 1)[0], offset + 9


def encode_lenenc_str(data: bytes | str | None) -> bytes:
    if data is None:
        return b"\xfb"
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return encode_lenenc_int(len(raw)) + raw


def decode_lenenc_str(buf: bytes, offset: int = 0) -> tuple[bytes | None, int]:
    length, offset = decode_lenenc_int(buf, offset)
    if length is None:
        return None, offset
    end = offset + length
    return buf[offset:end], end


def frame_mysql_packet(payload: bytes, seq_id: int) -> bytes:
    length = len(payload)
    header = struct.pack("<I", length)[:3] + bytes([seq_id & 0xFF])
    return header + payload


# --- Auth & Handshake ---

def mysql_native_password_scramble(password: str, auth_plugin_data: bytes) -> bytes:
    if not password:
        return b""
    pw_bytes = password.encode("utf-8")
    stage1 = hashlib.sha1(pw_bytes).digest()
    stage2 = hashlib.sha1(stage1).digest()
    challenge = hashlib.sha1(auth_plugin_data[:20] + stage2).digest()
    return bytes(a ^ b for a, b in zip(stage1, challenge))


def caching_sha2_password_scramble(password: str, auth_plugin_data: bytes) -> bytes:
    """MySQL 8 `caching_sha2_password` scramble: XOR(SHA256(pw), SHA256(SHA256(SHA256(pw)) + nonce))."""
    if not password:
        return b""
    pw_bytes = password.encode("utf-8")
    stage1 = hashlib.sha256(pw_bytes).digest()
    stage2 = hashlib.sha256(stage1).digest()
    stage3 = hashlib.sha256(stage2 + auth_plugin_data[:20]).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def _read_der_tl(buf: bytes, offset: int) -> tuple[int, int, int]:
    tag = buf[offset]
    offset += 1
    length = buf[offset]
    offset += 1
    if length & 0x80:
        num_bytes = length & 0x7F
        length = int.from_bytes(buf[offset : offset + num_bytes], "big")
        offset += num_bytes
    return tag, length, offset


def _parse_rsa_spki_pem(pem_bytes: bytes) -> tuple[int, int]:
    """Parse X.509 SubjectPublicKeyInfo PEM into RSA `(n, e)` without external crypto deps."""
    lines = [
        line.strip()
        for line in pem_bytes.decode("ascii", errors="ignore").splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    der = base64.b64decode("".join(lines))
    _, _, off = _read_der_tl(der, 0)  # outer SEQUENCE
    _, alg_len, off = _read_der_tl(der, off)  # AlgorithmIdentifier SEQUENCE
    off += alg_len
    tag, bit_len, off = _read_der_tl(der, off)  # BIT STRING
    assert tag == 0x03
    bit_body = der[off + 1 : off + bit_len]  # skip unused-bits byte (0x00)
    _, _, key_off = _read_der_tl(bit_body, 0)  # RSAPublicKey SEQUENCE
    _, n_len, key_off = _read_der_tl(bit_body, key_off)
    n = int.from_bytes(bit_body[key_off : key_off + n_len], "big")
    key_off += n_len
    _, e_len, key_off = _read_der_tl(bit_body, key_off)
    e = int.from_bytes(bit_body[key_off : key_off + e_len], "big")
    return n, e


def _mgf1_sha1(seed: bytes, mask_len: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < mask_len:
        out.extend(hashlib.sha1(seed + struct.pack(">I", counter)).digest())
        counter += 1
    return bytes(out[:mask_len])


def rsa_oaep_sha1_encrypt_pem(pem_bytes: bytes, plaintext: bytes) -> bytes:
    """RFC 8017 RSAES-OAEP-ENCRYPT (SHA-1) matching MySQL 8 `RSA_PKCS1_OAEP_PADDING`."""
    n, e = _parse_rsa_spki_pem(pem_bytes)
    k = (n.bit_length() + 7) // 8
    hlen = 20  # SHA-1
    if len(plaintext) > k - 2 * hlen - 2:
        raise ValueError("Password too long for RSA key")
    lhash = hashlib.sha1(b"").digest()
    ps = b"\x00" * (k - len(plaintext) - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + plaintext
    seed = os.urandom(hlen)
    db_mask = _mgf1_sha1(seed, k - hlen - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = _mgf1_sha1(masked_db, hlen)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    em = b"\x00" + masked_seed + masked_db
    c = pow(int.from_bytes(em, "big"), e, n)
    return c.to_bytes(k, "big")


def caching_sha2_full_auth_encrypt(
    password: str, nonce: bytes, pem_pubkey: bytes
) -> bytes:
    plain = password.encode("utf-8") + b"\x00"
    xored = bytes(plain[i] ^ nonce[i % len(nonce)] for i in range(len(plain)))
    return rsa_oaep_sha1_encrypt_pem(pem_pubkey, xored)


def encode_handshake_v10(
    *,
    conn_id: int,
    scramble: bytes,
    server_version: str = "8.0.36-reverse-proxy",
    capabilities: int = (
        CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_DEPRECATE_EOF
    ),
) -> bytes:
    assert len(scramble) == 20
    part1 = scramble[:8]
    part2 = scramble[8:20]
    cap_lower = capabilities & 0xFFFF
    cap_upper = (capabilities >> 16) & 0xFFFF

    buf = bytearray()
    buf.append(10)  # protocol version
    buf.extend(server_version.encode("utf-8") + b"\x00")
    buf.extend(struct.pack("<I", conn_id))
    buf.extend(part1)
    buf.append(0)  # filler
    buf.extend(struct.pack("<H", cap_lower))
    buf.append(UTF8MB4_CHARSET)
    buf.extend(struct.pack("<H", SERVER_STATUS_AUTOCOMMIT))
    buf.extend(struct.pack("<H", cap_upper))
    buf.append(21)  # auth_plugin_data_len (20 + NUL)
    buf.extend(b"\x00" * 10)  # reserved
    buf.extend(part2 + b"\x00")
    buf.extend(b"mysql_native_password\x00")
    return bytes(buf)


def parse_handshake_v10(payload: bytes) -> dict[str, Any]:
    proto = payload[0]
    nul = payload.find(b"\x00", 1)
    server_version = payload[1:nul].decode("utf-8", errors="replace")
    off = nul + 1
    conn_id = struct.unpack_from("<I", payload, off)[0]
    off += 4
    part1 = payload[off : off + 8]
    off += 9  # 8 + 1 filler
    cap_low = struct.unpack_from("<H", payload, off)[0]
    off += 2
    charset = payload[off]
    off += 1
    status = struct.unpack_from("<H", payload, off)[0]
    off += 2
    cap_high = struct.unpack_from("<H", payload, off)[0]
    off += 2
    capabilities = cap_low | (cap_high << 16)
    auth_len = payload[off]
    off += 11  # 1 + 10 reserved
    part2_len = max(13, auth_len - 8)
    part2 = payload[off : off + part2_len].rstrip(b"\x00")
    off += part2_len
    plugin = ""
    if capabilities & CLIENT_PLUGIN_AUTH and off < len(payload):
        end = payload.find(b"\x00", off)
        plugin = (payload[off:end] if end != -1 else payload[off:]).decode("utf-8", errors="replace")
    return {
        "protocol": proto,
        "server_version": server_version,
        "conn_id": conn_id,
        "capabilities": capabilities,
        "charset": charset,
        "status": status,
        "scramble": (part1 + part2)[:20],
        "auth_plugin": plugin,
    }


def encode_handshake_response_41(
    *,
    username: str,
    auth_response: bytes,
    database: str = "",
    auth_plugin: str = "mysql_native_password",
    capabilities: int = (
        CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_DEPRECATE_EOF
    ),
) -> bytes:
    if not database:
        capabilities &= ~CLIENT_CONNECT_WITH_DB
    buf = bytearray()
    buf.extend(struct.pack("<I", capabilities))
    buf.extend(struct.pack("<I", 16 * 1024 * 1024))  # max packet size
    buf.append(UTF8MB4_CHARSET)
    buf.extend(b"\x00" * 23)
    buf.extend(username.encode("utf-8") + b"\x00")
    buf.append(len(auth_response))
    buf.extend(auth_response)
    if capabilities & CLIENT_CONNECT_WITH_DB:
        buf.extend(database.encode("utf-8") + b"\x00")
    if capabilities & CLIENT_PLUGIN_AUTH:
        buf.extend(auth_plugin.encode("utf-8") + b"\x00")
    return bytes(buf)


def parse_auth_switch_request(payload: bytes) -> tuple[str, bytes]:
    assert payload[0] == 0xFE
    nul = payload.find(b"\x00", 1)
    plugin = payload[1:nul].decode("utf-8", errors="replace")
    nonce = payload[nul + 1 :].rstrip(b"\x00")
    return plugin, nonce


def parse_handshake_response_41(payload: bytes) -> dict[str, Any]:
    client_flags, max_pkt = struct.unpack_from("<II", payload, 0)
    charset = payload[8]
    off = 32  # 4 + 4 + 1 + 23 reserved
    nul = payload.find(b"\x00", off)
    username = payload[off:nul].decode("utf-8", errors="replace")
    off = nul + 1
    if client_flags & CLIENT_SECURE_CONNECTION:
        auth_len = payload[off]
        off += 1
        auth_resp = payload[off : off + auth_len]
        off += auth_len
    else:
        nul = payload.find(b"\x00", off)
        auth_resp = payload[off:nul]
        off = nul + 1
    database = ""
    if (client_flags & CLIENT_CONNECT_WITH_DB) and off < len(payload):
        nul = payload.find(b"\x00", off)
        database = payload[off:nul].decode("utf-8", errors="replace")
        off = nul + 1
    auth_plugin = ""
    if (client_flags & CLIENT_PLUGIN_AUTH) and off < len(payload):
        nul = payload.find(b"\x00", off)
        auth_plugin = (payload[off:nul] if nul != -1 else payload[off:]).decode("utf-8", errors="replace")
    return {
        "client_flags": client_flags,
        "max_packet_size": max_pkt,
        "charset": charset,
        "username": username,
        "auth_response": auth_resp,
        "database": database,
        "auth_plugin": auth_plugin,
    }


# --- OK / ERR / EOF / Resultset Packets ---

def encode_ok_packet(
    *,
    affected_rows: int = 0,
    last_insert_id: int = 0,
    status_flags: int = SERVER_STATUS_AUTOCOMMIT,
    warnings: int = 0,
    info: str = "",
    header_byte: int = 0x00,
) -> bytes:
    buf = bytearray([header_byte])
    buf.extend(encode_lenenc_int(affected_rows))
    buf.extend(encode_lenenc_int(last_insert_id))
    buf.extend(struct.pack("<HH", status_flags, warnings))
    if info:
        buf.extend(info.encode("utf-8"))
    return bytes(buf)


def parse_ok_packet(payload: bytes) -> dict[str, Any]:
    off = 1  # skip 0x00 or 0xFE header
    affected_rows, off = decode_lenenc_int(payload, off)
    last_insert_id, off = decode_lenenc_int(payload, off)
    status_flags, warnings = struct.unpack_from("<HH", payload, off)
    off += 4
    info = payload[off:].decode("utf-8", errors="replace") if off < len(payload) else ""
    return {
        "affected_rows": affected_rows or 0,
        "last_insert_id": last_insert_id or 0,
        "status_flags": status_flags,
        "warnings": warnings,
        "info": info,
    }


def encode_err_packet(
    message: str, *, error_code: int = 1064, sqlstate: str = "42000"
) -> bytes:
    buf = bytearray([0xFF])
    buf.extend(struct.pack("<H", error_code))
    buf.extend(b"#" + sqlstate[:5].ljust(5, "0").encode("ascii"))
    buf.extend(message.encode("utf-8"))
    return bytes(buf)


def parse_err_packet(payload: bytes) -> tuple[int, str, str]:
    code = struct.unpack_from("<H", payload, 1)[0]
    sqlstate = payload[4:9].decode("ascii", errors="replace") if payload[3:4] == b"#" else ""
    msg_off = 9 if payload[3:4] == b"#" else 3
    msg = payload[msg_off:].decode("utf-8", errors="replace")
    return code, sqlstate, msg


def encode_eof_packet(*, warnings: int = 0, status_flags: int = SERVER_STATUS_AUTOCOMMIT) -> bytes:
    return b"\xfe" + struct.pack("<HH", warnings, status_flags)


def infer_mysql_field_type(rows: list[tuple[Any, ...]], col_idx: int) -> int:
    for row in rows:
        val = row[col_idx]
        if val is None:
            continue
        if isinstance(val, bool):
            return FIELD_TYPE_TINY
        if isinstance(val, int):
            return FIELD_TYPE_LONGLONG
        if isinstance(val, float):
            return FIELD_TYPE_DOUBLE
        if isinstance(val, (bytes, bytearray, memoryview)):
            return FIELD_TYPE_BLOB
        return FIELD_TYPE_VAR_STRING
    return FIELD_TYPE_VAR_STRING


def encode_column_definition_41(col: MySQLColumnDef) -> bytes:
    buf = bytearray()
    buf.extend(encode_lenenc_str("def"))
    buf.extend(encode_lenenc_str(col.schema))
    buf.extend(encode_lenenc_str(col.table))
    buf.extend(encode_lenenc_str(col.table))
    buf.extend(encode_lenenc_str(col.name))
    buf.extend(encode_lenenc_str(col.name))
    buf.append(0x0C)  # fixed-length fields length
    buf.extend(struct.pack("<H", col.charset))
    buf.extend(struct.pack("<I", col.column_length))
    buf.append(col.field_type)
    buf.extend(struct.pack("<H", 0))  # flags
    buf.append(col.decimals)
    buf.extend(b"\x00\x00")  # filler
    return bytes(buf)


def parse_column_definition_41(payload: bytes) -> MySQLColumnDef:
    off = 0
    _cat, off = decode_lenenc_str(payload, off)
    schema_b, off = decode_lenenc_str(payload, off)
    table_b, off = decode_lenenc_str(payload, off)
    _org_table, off = decode_lenenc_str(payload, off)
    name_b, off = decode_lenenc_str(payload, off)
    _org_name, off = decode_lenenc_str(payload, off)
    off += 1  # 0x0C
    charset, col_len, field_type, _flags, decimals = struct.unpack_from("<HIBHB", payload, off)
    return MySQLColumnDef(
        name=(name_b or b"").decode("utf-8", errors="replace"),
        field_type=field_type,
        schema=(schema_b or b"").decode("utf-8", errors="replace"),
        table=(table_b or b"").decode("utf-8", errors="replace"),
        column_length=col_len,
        decimals=decimals,
        charset=charset,
    )


def encode_text_row(values: Sequence[Any] | tuple[Any, ...]) -> bytes:
    buf = bytearray()
    for val in values:
        if val is None:
            buf.append(0xFB)
        elif isinstance(val, bool):
            buf.extend(encode_lenenc_str(b"1" if val else b"0"))
        elif isinstance(val, (bytes, bytearray, memoryview)):
            buf.extend(encode_lenenc_str(bytes(val)))
        else:
            buf.extend(encode_lenenc_str(str(val).encode("utf-8")))
    return bytes(buf)


def decode_mysql_text_row(payload: bytes, col_defs: list[MySQLColumnDef]) -> tuple[Any, ...]:
    off = 0
    vals: list[Any] = []
    for col in col_defs:
        raw, off = decode_lenenc_str(payload, off)
        if raw is None:
            vals.append(None)
            continue
        ft = col.field_type
        if ft == FIELD_TYPE_BLOB:
            vals.append(raw)
        elif ft in (FIELD_TYPE_TINY, FIELD_TYPE_SHORT, FIELD_TYPE_LONG, FIELD_TYPE_LONGLONG, FIELD_TYPE_INT24):
            vals.append(int(raw.decode("ascii")))
        elif ft in (FIELD_TYPE_FLOAT, FIELD_TYPE_DOUBLE):
            vals.append(float(raw.decode("ascii")))
        else:
            vals.append(raw.decode("utf-8"))
    return tuple(vals)


# --- Sync Socket Helpers ---

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("Unexpected EOF on MySQL socket")
        buf.extend(chunk)
    return bytes(buf)


def read_mysql_packet_sync(sock: socket.socket) -> MySQLPacket:
    header = _recv_exact(sock, 4)
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    seq_id = header[3]
    payload = _recv_exact(sock, length) if length > 0 else b""
    return MySQLPacket(seq_id=seq_id, payload=payload)


# --- Safe SQL Literal Escaping for `?` Param Interpolation ---

def format_mysql_literal(val: Any) -> str:
    if val is None:
        return "NULL"
    if isinstance(val, bool):
        return "1" if val else "0"
    if isinstance(val, (int, float)):
        return repr(val)
    if isinstance(val, (bytes, bytearray, memoryview)):
        return "X'" + bytes(val).hex() + "'"
    text = str(val)
    escaped = (
        text.replace("\\", "\\\\")
        .replace("\x00", "\\0")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("'", "\\'")
        .replace('"', '\\"')
    )
    return f"'{escaped}'"


def bind_mysql_params(sql: str, params: Sequence[Any]) -> str:
    """Safely bind `?` positional placeholders outside string literals/comments."""
    if not params:
        return sql
    tokens = tokenize(sql)
    out: list[str] = []
    last = 0
    param_idx = 0
    for tok in tokens:
        if tok.kind == "OP" and tok.text == "?":
            if param_idx >= len(params):
                raise ValueError("Too few parameters supplied for MySQL query.")
            out.append(sql[last : tok.start])
            out.append(format_mysql_literal(params[param_idx]))
            last = tok.end
            param_idx += 1
    out.append(sql[last:])
    if param_idx != len(params):
        raise ValueError(
            f"Expected {param_idx} parameter(s) for MySQL query, got {len(params)}."
        )
    return "".join(out)


# --- Binary Prepared Statement Protocol (COM_STMT_PREPARE / COM_STMT_EXECUTE) ---

def encode_stmt_prepare_ok(stmt_id: int, num_columns: int, num_params: int) -> bytes:
    return struct.pack("<BIHHBH", 0x00, stmt_id, num_columns, num_params, 0, 0)


def parse_stmt_execute(
    payload: bytes,
    num_params: int,
    saved_types: list[tuple[int, int]],
) -> tuple[int, list[Any], list[tuple[int, int]]]:
    stmt_id, _flags, _iter_count = struct.unpack_from("<IBI", payload, 1)
    off = 10
    params: list[Any] = []
    if num_params == 0:
        return stmt_id, params, saved_types

    null_bm_len = (num_params + 7) // 8
    null_bm = payload[off : off + null_bm_len]
    off += null_bm_len
    new_params_flag = payload[off]
    off += 1
    types = list(saved_types)
    if new_params_flag == 1:
        types = []
        for _ in range(num_params):
            ft, uf = struct.unpack_from("<BB", payload, off)
            off += 2
            types.append((ft, uf))

    for i in range(num_params):
        if (null_bm[i // 8] >> (i % 8)) & 1:
            params.append(None)
            continue
        ft, uf = types[i] if i < len(types) else (FIELD_TYPE_VAR_STRING, 0)
        unsigned = bool(uf & 0x80)
        if ft == FIELD_TYPE_NULL:
            params.append(None)
        elif ft == FIELD_TYPE_TINY:
            params.append(struct.unpack_from("<B" if unsigned else "<b", payload, off)[0])
            off += 1
        elif ft == FIELD_TYPE_SHORT:
            params.append(struct.unpack_from("<H" if unsigned else "<h", payload, off)[0])
            off += 2
        elif ft in (FIELD_TYPE_LONG, FIELD_TYPE_INT24):
            params.append(struct.unpack_from("<I" if unsigned else "<i", payload, off)[0])
            off += 4
        elif ft == FIELD_TYPE_LONGLONG:
            params.append(struct.unpack_from("<Q" if unsigned else "<q", payload, off)[0])
            off += 8
        elif ft == FIELD_TYPE_FLOAT:
            params.append(struct.unpack_from("<f", payload, off)[0])
            off += 4
        elif ft == FIELD_TYPE_DOUBLE:
            params.append(struct.unpack_from("<d", payload, off)[0])
            off += 8
        elif ft in (7, 10, 12):  # TIMESTAMP, DATE, DATETIME
            slen = payload[off]
            off += 1
            if slen == 0:
                params.append("0000-00-00 00:00:00" if ft != 10 else "0000-00-00")
            elif slen == 4:
                yr, mo, dy = struct.unpack_from("<HBB", payload, off)
                params.append(f"{yr:04d}-{mo:02d}-{dy:02d}")
            elif slen == 7:
                yr, mo, dy, hr, mn, sc = struct.unpack_from("<HBBBBB", payload, off)
                params.append(f"{yr:04d}-{mo:02d}-{dy:02d} {hr:02d}:{mn:02d}:{sc:02d}")
            else:
                yr, mo, dy, hr, mn, sc, us = struct.unpack_from("<HBBBBBI", payload, off)
                params.append(f"{yr:04d}-{mo:02d}-{dy:02d} {hr:02d}:{mn:02d}:{sc:02d}.{us:06d}")
            off += slen
        elif ft == 11:  # TIME
            slen = payload[off]
            off += 1
            if slen == 0:
                params.append("00:00:00")
            else:
                neg = payload[off]
                days, hr, mn, sc = struct.unpack_from("<IBBB", payload, off + 1)
                tot_hr = days * 24 + hr
                params.append(f"{'-' if neg else ''}{tot_hr:02d}:{mn:02d}:{sc:02d}")
            off += slen
        elif ft in (FIELD_TYPE_BLOB, 0xF9, 0xFA, 0xFB):
            raw, off = decode_lenenc_str(payload, off)
            params.append(raw if raw is not None else b"")
        else:
            raw, off = decode_lenenc_str(payload, off)
            params.append(raw.decode("utf-8", errors="replace") if raw is not None else "")

    return stmt_id, params, types


def encode_binary_row(row: Sequence[Any], col_defs: list[MySQLColumnDef]) -> bytes:
    nbm_len = (len(col_defs) + 7 + 2) // 8
    null_bm = bytearray(nbm_len)
    vals_buf = bytearray()
    for i, (val, col) in enumerate(zip(row, col_defs)):
        if val is None:
            byte_pos = (i + 2) // 8
            bit_pos = (i + 2) % 8
            null_bm[byte_pos] |= 1 << bit_pos
            continue
        ft = col.field_type
        if ft == FIELD_TYPE_LONGLONG:
            vals_buf.extend(struct.pack("<q", int(val)))
        elif ft == FIELD_TYPE_DOUBLE:
            vals_buf.extend(struct.pack("<d", float(val)))
        elif ft == FIELD_TYPE_BLOB:
            vals_buf.extend(encode_lenenc_str(bytes(val)))
        elif isinstance(val, bool):
            vals_buf.extend(encode_lenenc_str(b"1" if val else b"0"))
        else:
            vals_buf.extend(encode_lenenc_str(str(val).encode("utf-8")))
    return bytes([0x00]) + bytes(null_bm) + bytes(vals_buf)
