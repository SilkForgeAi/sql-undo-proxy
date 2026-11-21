"""Pure-Python MySQL Row-Based Binary Log (binlog) poller for trigger/proc auto-capture and RBR undo."""

from __future__ import annotations

import base64
import datetime as dt
import decimal
import json
import struct
import threading
import zlib
from dataclasses import dataclass, field
from typing import Any

from .cdc import CDCIngestor
from .drivers.mysql_client import MySQLError, MySQLWireClient
from .drivers.mysql_driver import MySQLDriver, QUARANTINE_DB
from .ledger import UndoLedger, new_tx_id
from .models import EngineType, MutationOp
from .protocols.mysql_codec import frame_mysql_packet, read_mysql_packet_sync

MARKER_TABLE = "_proxy_wal_marker"

# Binlog Event Type codes
ROTATE_EVENT = 4
FORMAT_DESCRIPTION_EVENT = 15
XID_EVENT = 16
QUERY_EVENT = 2
TABLE_MAP_EVENT = 19
WRITE_ROWS_EVENT_V1 = 23
UPDATE_ROWS_EVENT_V1 = 24
DELETE_ROWS_EVENT_V1 = 25
WRITE_ROWS_EVENT_V2 = 30
UPDATE_ROWS_EVENT_V2 = 31
DELETE_ROWS_EVENT_V2 = 32

# MySQL Field Type constants
MYSQL_TYPE_DECIMAL = 0
MYSQL_TYPE_TINY = 1
MYSQL_TYPE_SHORT = 2
MYSQL_TYPE_LONG = 3
MYSQL_TYPE_FLOAT = 4
MYSQL_TYPE_DOUBLE = 5
MYSQL_TYPE_NULL = 6
MYSQL_TYPE_TIMESTAMP = 7
MYSQL_TYPE_LONGLONG = 8
MYSQL_TYPE_INT24 = 9
MYSQL_TYPE_DATE = 10
MYSQL_TYPE_TIME = 11
MYSQL_TYPE_DATETIME = 12
MYSQL_TYPE_YEAR = 13
MYSQL_TYPE_NEWDATE = 14
MYSQL_TYPE_VARCHAR = 15
MYSQL_TYPE_BIT = 16
MYSQL_TYPE_TIMESTAMP2 = 17
MYSQL_TYPE_DATETIME2 = 18
MYSQL_TYPE_TIME2 = 19
MYSQL_TYPE_JSON = 245
MYSQL_TYPE_NEWDECIMAL = 246
MYSQL_TYPE_ENUM = 247
MYSQL_TYPE_SET = 248
MYSQL_TYPE_TINY_BLOB = 249
MYSQL_TYPE_MEDIUM_BLOB = 250
MYSQL_TYPE_LONG_BLOB = 251
MYSQL_TYPE_BLOB = 252
MYSQL_TYPE_VAR_STRING = 253
MYSQL_TYPE_STRING = 254
MYSQL_TYPE_GEOMETRY = 255

_TEXT_LIKE_TYPES = {"text", "tinytext", "mediumtext", "longtext"}


@dataclass
class BinlogTableMap:
    table_id: int
    db: str
    table: str
    col_count: int
    col_types: list[int]
    col_metas: list[Any]
    null_bitmap: bytes
    unsigned_flags: list[bool]
    raw_event: bytes


def _read_lenenc_int(buf: bytes, offset: int) -> tuple[int, int]:
    first = buf[offset]
    if first < 0xFB:
        return first, offset + 1
    if first == 0xFC:
        return struct.unpack_from("<H", buf, offset + 1)[0], offset + 3
    if first == 0xFD:
        val = int.from_bytes(buf[offset + 1 : offset + 4], "little")
        return val, offset + 4
    if first == 0xFE:
        return struct.unpack_from("<Q", buf, offset + 1)[0], offset + 9
    raise ValueError(f"Unexpected lenenc marker: 0x{first:02x}")


def _decode_newdecimal(buf: bytes, offset: int, precision: int, scale: int) -> tuple[str, int]:
    """Decode MySQL binary NEWDECIMAL(precision, scale) into decimal string."""
    dig_per_dec = 9
    comp_bytes = (0, 1, 1, 2, 2, 3, 3, 4, 4)
    intg = precision - scale
    intg0 = intg // dig_per_dec
    frac0 = scale // dig_per_dec
    intg0x = intg - intg0 * dig_per_dec
    frac0x = scale - frac0 * dig_per_dec
    total_bytes = intg0 * 4 + comp_bytes[intg0x] + frac0 * 4 + comp_bytes[frac0x]
    raw = bytearray(buf[offset : offset + total_bytes])
    pos = offset + total_bytes

    neg = (raw[0] & 0x80) == 0
    raw[0] ^= 0x80
    if neg:
        for i in range(len(raw)):
            raw[i] ^= 0xFF

    idx = 0
    int_parts: list[str] = []
    if intg0x > 0:
        nbytes = comp_bytes[intg0x]
        val = int.from_bytes(raw[idx : idx + nbytes], "big", signed=False)
        idx += nbytes
        if val != 0:
            int_parts.append(str(val))
    for _ in range(intg0):
        val = int.from_bytes(raw[idx : idx + 4], "big", signed=False)
        idx += 4
        if int_parts or val != 0:
            int_parts.append(f"{val:09d}" if int_parts else str(val))
    int_str = "".join(int_parts) or "0"

    frac_parts: list[str] = []
    for _ in range(frac0):
        val = int.from_bytes(raw[idx : idx + 4], "big", signed=False)
        idx += 4
        frac_parts.append(f"{val:09d}")
    if frac0x > 0:
        nbytes = comp_bytes[frac0x]
        val = int.from_bytes(raw[idx : idx + nbytes], "big", signed=False)
        frac_parts.append(f"{val:0{frac0x}d}")

    frac_str = "".join(frac_parts)
    sign = "-" if neg else ""
    if frac_str:
        return f"{sign}{int_str}.{frac_str}", pos
    return f"{sign}{int_str}", pos


def _decode_json_value(buf: bytes, val_type: int, offset: int, root_buf: bytes) -> Any:
    if val_type == 0x04:  # literal
        lit = buf[offset]
        if lit == 0x00:
            return None
        if lit == 0x01:
            return True
        if lit == 0x02:
            return False
        return None
    if val_type == 0x05:  # int16
        return struct.unpack_from("<h", buf, offset)[0]
    if val_type == 0x06:  # uint16
        return struct.unpack_from("<H", buf, offset)[0]
    if val_type == 0x07:  # int32
        return struct.unpack_from("<i", buf, offset)[0]
    if val_type == 0x08:  # uint32
        return struct.unpack_from("<I", buf, offset)[0]
    if val_type == 0x09:  # int64
        return struct.unpack_from("<q", buf, offset)[0]
    if val_type == 0x0A:  # uint64
        return struct.unpack_from("<Q", buf, offset)[0]
    if val_type == 0x0B:  # double
        return struct.unpack_from("<d", buf, offset)[0]
    if val_type == 0x0C:  # utf8mb4 string (varint len)
        slen = 0
        shift = 0
        p = offset
        while True:
            b = buf[p]
            p += 1
            slen |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return buf[p : p + slen].decode("utf-8", errors="replace")
    if val_type in (0x00, 0x01, 0x02, 0x03):  # small/large object/array
        is_large = val_type in (0x01, 0x03)
        is_obj = val_type in (0x00, 0x01)
        hdr_fmt = "<II" if is_large else "<HH"
        step = 4 if is_large else 2
        count, _byte_size = struct.unpack_from(hdr_fmt, buf, offset)
        sub = buf[offset:]
        p = step * 2
        if is_obj:
            keys: list[str] = []
            key_off_fmt = "<IH" if is_large else "<HH"
            key_entry_size = 6 if is_large else 4
            for i in range(count):
                k_off, k_len = struct.unpack_from(key_off_fmt, sub, p + i * key_entry_size)
                keys.append(sub[k_off : k_off + k_len].decode("utf-8", errors="replace"))
            val_entry_base = p + count * key_entry_size
            out_obj: dict[str, Any] = {}
            val_fmt = "<BI" if is_large else "<BH"
            val_entry_size = 5 if is_large else 3
            for i in range(count):
                vt, v_or_off = struct.unpack_from(val_fmt, sub, val_entry_base + i * val_entry_size)
                if vt in (0x04, 0x05, 0x06) or (is_large and vt in (0x07, 0x08)):
                    # Inlined scalar inside the offset field
                    inline_raw = sub[val_entry_base + i * val_entry_size + 1 : val_entry_base + (i + 1) * val_entry_size]
                    out_obj[keys[i]] = _decode_json_value(inline_raw, vt, 0, root_buf)
                else:
                    out_obj[keys[i]] = _decode_json_value(sub, vt, v_or_off, root_buf)
            return out_obj
        else:
            out_arr: list[Any] = []
            val_fmt = "<BI" if is_large else "<BH"
            val_entry_size = 5 if is_large else 3
            for i in range(count):
                vt, v_or_off = struct.unpack_from(val_fmt, sub, p + i * val_entry_size)
                if vt in (0x04, 0x05, 0x06) or (is_large and vt in (0x07, 0x08)):
                    inline_raw = sub[p + i * val_entry_size + 1 : p + (i + 1) * val_entry_size]
                    out_arr.append(_decode_json_value(inline_raw, vt, 0, root_buf))
                else:
                    out_arr.append(_decode_json_value(sub, vt, v_or_off, root_buf))
            return out_arr
    return buf[offset:].hex()


def decode_json_binary(raw: bytes) -> str:
    if not raw:
        return "null"
    val = _decode_json_value(raw, raw[0], 1, raw)
    return json.dumps(val, ensure_ascii=False)


def parse_table_map_event(raw_event: bytes, *, has_checksum: bool) -> BinlogTableMap:
    body = raw_event[19:-4] if has_checksum else raw_event[19:]
    table_id = int.from_bytes(body[0:6], "little")
    # flags = struct.unpack_from("<H", body, 6)[0]
    pos = 8
    db_len = body[pos]
    pos += 1
    db = body[pos : pos + db_len].decode("utf-8", errors="replace")
    pos += db_len + 1  # NUL
    tbl_len = body[pos]
    pos += 1
    table = body[pos : pos + tbl_len].decode("utf-8", errors="replace")
    pos += tbl_len + 1  # NUL

    col_count, pos = _read_lenenc_int(body, pos)
    col_types = list(body[pos : pos + col_count])
    pos += col_count

    meta_len, pos = _read_lenenc_int(body, pos)
    meta_end = pos + meta_len
    col_metas: list[Any] = []
    mpos = pos
    for i, ctype in enumerate(col_types):
        if ctype in (
            MYSQL_TYPE_FLOAT,
            MYSQL_TYPE_DOUBLE,
            MYSQL_TYPE_BLOB,
            MYSQL_TYPE_TINY_BLOB,
            MYSQL_TYPE_MEDIUM_BLOB,
            MYSQL_TYPE_LONG_BLOB,
            MYSQL_TYPE_JSON,
            MYSQL_TYPE_GEOMETRY,
            MYSQL_TYPE_TIMESTAMP2,
            MYSQL_TYPE_DATETIME2,
            MYSQL_TYPE_TIME2,
        ):
            col_metas.append(body[mpos])
            mpos += 1
        elif ctype in (MYSQL_TYPE_VARCHAR, MYSQL_TYPE_VAR_STRING):
            col_metas.append(struct.unpack_from("<H", body, mpos)[0])
            mpos += 2
        elif ctype == MYSQL_TYPE_NEWDECIMAL:
            col_metas.append((body[mpos], body[mpos + 1]))
            mpos += 2
        elif ctype == MYSQL_TYPE_BIT:
            col_metas.append((body[mpos], body[mpos + 1]))
            mpos += 2
        elif ctype == MYSQL_TYPE_STRING:
            b0, b1 = body[mpos], body[mpos + 1]
            mpos += 2
            if b0 in (MYSQL_TYPE_ENUM, MYSQL_TYPE_SET):
                col_types[i] = b0
                col_metas.append(b1)
            else:
                max_len = (((b0 & 0x30) ^ 0x30) << 4) | b1
                col_metas.append(max_len)
        elif ctype in (MYSQL_TYPE_ENUM, MYSQL_TYPE_SET):
            col_metas.append(body[mpos + 1])
            mpos += 2
        else:
            col_metas.append(None)

    pos = meta_end
    null_bm_len = (col_count + 7) // 8
    null_bitmap = body[pos : pos + null_bm_len]
    pos += null_bm_len

    # Parse optional metadata (MySQL 8.0+) for SIGNEDNESS (type=1)
    int_types = {
        MYSQL_TYPE_TINY,
        MYSQL_TYPE_SHORT,
        MYSQL_TYPE_INT24,
        MYSQL_TYPE_LONG,
        MYSQL_TYPE_LONGLONG,
    }
    unsigned_flags = [False] * col_count
    while pos < len(body):
        opt_type = body[pos]
        pos += 1
        opt_len, pos = _read_lenenc_int(body, pos)
        opt_val = body[pos : pos + opt_len]
        pos += opt_len
        if opt_type == 1:  # SIGNEDNESS
            bit_idx = 0
            for ci, ct in enumerate(col_types):
                if ct in int_types:
                    byte_i = bit_idx // 8
                    bit_in_byte = 7 - (bit_idx % 8)
                    if byte_i < len(opt_val):
                        unsigned_flags[ci] = bool((opt_val[byte_i] >> bit_in_byte) & 1)
                    bit_idx += 1

    return BinlogTableMap(
        table_id=table_id,
        db=db,
        table=table,
        col_count=col_count,
        col_types=col_types,
        col_metas=col_metas,
        null_bitmap=null_bitmap,
        unsigned_flags=unsigned_flags,
        raw_event=raw_event,
    )


def _decode_col_value(
    buf: bytes,
    offset: int,
    ctype: int,
    meta: Any,
    unsigned: bool,
    sql_type_hint: str = "",
) -> tuple[Any, int]:
    if ctype == MYSQL_TYPE_TINY:
        val = struct.unpack_from("<B" if unsigned else "<b", buf, offset)[0]
        return val, offset + 1
    if ctype == MYSQL_TYPE_SHORT:
        val = struct.unpack_from("<H" if unsigned else "<h", buf, offset)[0]
        return val, offset + 2
    if ctype == MYSQL_TYPE_INT24:
        val = int.from_bytes(buf[offset : offset + 3], "little", signed=not unsigned)
        return val, offset + 3
    if ctype == MYSQL_TYPE_LONG:
        val = struct.unpack_from("<I" if unsigned else "<i", buf, offset)[0]
        return val, offset + 4
    if ctype == MYSQL_TYPE_LONGLONG:
        val = struct.unpack_from("<Q" if unsigned else "<q", buf, offset)[0]
        return val, offset + 8
    if ctype == MYSQL_TYPE_FLOAT:
        val = struct.unpack_from("<f", buf, offset)[0]
        return val, offset + 4
    if ctype == MYSQL_TYPE_DOUBLE:
        val = struct.unpack_from("<d", buf, offset)[0]
        return val, offset + 8
    if ctype == MYSQL_TYPE_YEAR:
        y = buf[offset]
        return (0 if y == 0 else 1900 + y), offset + 1
    if ctype == MYSQL_TYPE_NEWDECIMAL:
        prec, scale = meta
        return _decode_newdecimal(buf, offset, prec, scale)
    if ctype in (MYSQL_TYPE_VARCHAR, MYSQL_TYPE_VAR_STRING):
        max_len = int(meta)
        if max_len < 256:
            slen = buf[offset]
            offset += 1
        else:
            slen = struct.unpack_from("<H", buf, offset)[0]
            offset += 2
        raw = buf[offset : offset + slen]
        offset += slen
        if "binary" in sql_type_hint.lower():
            return raw, offset
        return raw.decode("utf-8", errors="replace"), offset
    if ctype == MYSQL_TYPE_STRING:
        max_len = int(meta)
        if max_len < 256:
            slen = buf[offset]
            offset += 1
        else:
            slen = struct.unpack_from("<H", buf, offset)[0]
            offset += 2
        raw = buf[offset : offset + slen]
        offset += slen
        if "binary" in sql_type_hint.lower():
            return raw, offset
        return raw.decode("utf-8", errors="replace"), offset
    if ctype in (
        MYSQL_TYPE_BLOB,
        MYSQL_TYPE_TINY_BLOB,
        MYSQL_TYPE_MEDIUM_BLOB,
        MYSQL_TYPE_LONG_BLOB,
        MYSQL_TYPE_GEOMETRY,
    ):
        pack_len = int(meta)
        slen = int.from_bytes(buf[offset : offset + pack_len], "little")
        offset += pack_len
        raw = buf[offset : offset + slen]
        offset += slen
        if sql_type_hint.lower() in _TEXT_LIKE_TYPES:
            return raw.decode("utf-8", errors="replace"), offset
        return raw, offset
    if ctype == MYSQL_TYPE_JSON:
        pack_len = int(meta)
        slen = int.from_bytes(buf[offset : offset + pack_len], "little")
        offset += pack_len
        raw = buf[offset : offset + slen]
        offset += slen
        return decode_json_binary(raw), offset
    if ctype == MYSQL_TYPE_NEWDATE:
        val = int.from_bytes(buf[offset : offset + 3], "little")
        day = val & 0x1F
        month = (val >> 5) & 0x0F
        year = val >> 9
        return f"{year:04d}-{month:02d}-{day:02d}", offset + 3
    if ctype == MYSQL_TYPE_DATETIME2:
        fsp = int(meta)
        fsp_bytes = (fsp + 1) // 2
        packed = int.from_bytes(buf[offset : offset + 5], "big")
        offset += 5
        frac = 0
        if fsp_bytes:
            frac = int.from_bytes(buf[offset : offset + fsp_bytes], "big")
            offset += fsp_bytes
        if packed == 0:
            return "0000-00-00 00:00:00", offset
        # Top bit (bit 39) is sign (always 1 for positive)
        ym = (packed >> 22) & 0x1FFFF
        year = ym // 13
        month = ym % 13
        day = (packed >> 17) & 0x1F
        hour = (packed >> 12) & 0x1F
        minute = (packed >> 6) & 0x3F
        second = packed & 0x3F
        base_str = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
        if fsp > 0:
            frac_digits = frac * (10 ** (6 - fsp_bytes * 2))
            return f"{base_str}.{frac_digits:06d}"[: 19 + 1 + fsp], offset
        return base_str, offset
    if ctype == MYSQL_TYPE_TIMESTAMP2:
        fsp = int(meta)
        fsp_bytes = (fsp + 1) // 2
        sec = struct.unpack_from(">I", buf, offset)[0]
        offset += 4
        frac = 0
        if fsp_bytes:
            frac = int.from_bytes(buf[offset : offset + fsp_bytes], "big")
            offset += fsp_bytes
        ts_dt = dt.datetime.fromtimestamp(sec, tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        if fsp > 0:
            frac_digits = frac * (10 ** (6 - fsp_bytes * 2))
            return f"{ts_dt}.{frac_digits:06d}"[: 19 + 1 + fsp], offset
        return ts_dt, offset
    if ctype == MYSQL_TYPE_TIME2:
        fsp = int(meta)
        fsp_bytes = (fsp + 1) // 2
        packed = int.from_bytes(buf[offset : offset + 3], "big")
        offset += 3
        if fsp_bytes:
            offset += fsp_bytes
        neg = not bool((packed >> 23) & 1)
        val = (packed ^ 0xFFFFFF) + 1 if neg else (packed & 0x7FFFFF)
        hour = (val >> 12) & 0x3FF
        minute = (val >> 6) & 0x3F
        second = val & 0x3F
        return f"{'-' if neg else ''}{hour:02d}:{minute:02d}:{second:02d}", offset
    if ctype in (MYSQL_TYPE_ENUM, MYSQL_TYPE_SET):
        size = int(meta)
        val = int.from_bytes(buf[offset : offset + size], "little")
        return val, offset + size
    if ctype == MYSQL_TYPE_BIT:
        bits, bytes_len = meta
        total = bytes_len + (1 if bits else 0)
        val = int.from_bytes(buf[offset : offset + total], "big")
        return val, offset + total
    raise ValueError(f"Unsupported MySQL binlog field type: {ctype}")


def _decode_row_image(
    buf: bytes,
    offset: int,
    tmap: BinlogTableMap,
    cols_present: bytes,
    col_names: list[str],
    col_type_hints: dict[str, str],
) -> tuple[dict[str, Any], int]:
    present_indices = [
        i for i in range(tmap.col_count) if (cols_present[i // 8] >> (i % 8)) & 1
    ]
    nbm_len = (len(present_indices) + 7) // 8
    null_bm = buf[offset : offset + nbm_len]
    offset += nbm_len

    row: dict[str, Any] = {}
    for p_idx, col_idx in enumerate(present_indices):
        cname = col_names[col_idx] if col_idx < len(col_names) else f"col_{col_idx}"
        is_null = bool((null_bm[p_idx // 8] >> (p_idx % 8)) & 1)
        if is_null:
            row[cname] = None
            continue
        val, offset = _decode_col_value(
            buf,
            offset,
            tmap.col_types[col_idx],
            tmap.col_metas[col_idx],
            tmap.unsigned_flags[col_idx],
            col_type_hints.get(cname, ""),
        )
        row[cname] = val
    return row, offset


def parse_and_invert_rows_event(
    raw_event: bytes,
    tmap: BinlogTableMap,
    col_names: list[str],
    col_type_hints: dict[str, str],
    *,
    has_checksum: bool,
) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], bytes]:
    """Decode WRITE/UPDATE/DELETE_ROWS_EVENT (v1/v2) and construct the exact inverted RBR event."""
    ev_type = raw_event[4]
    is_v2 = ev_type in (WRITE_ROWS_EVENT_V2, UPDATE_ROWS_EVENT_V2, DELETE_ROWS_EVENT_V2)
    is_update = ev_type in (UPDATE_ROWS_EVENT_V1, UPDATE_ROWS_EVENT_V2)

    body = raw_event[19:-4] if has_checksum else raw_event[19:]
    pos = 8  # table_id (6) + flags (2)
    if is_v2:
        extra_len = struct.unpack_from("<H", body, pos)[0]
        pos += 2 + max(0, extra_len - 2)
    col_count, pos = _read_lenenc_int(body, pos)
    bm_len = (col_count + 7) // 8
    bm1 = body[pos : pos + bm_len]
    pos += bm_len
    if is_update:
        bm2 = body[pos : pos + bm_len]
        pos += bm_len
    else:
        bm2 = b""

    rows_header_end = 19 + pos
    before_rows: list[dict[str, Any]] = []
    after_rows: list[dict[str, Any]] = []
    swapped_chunks: list[bytes] = []

    while pos < len(body):
        if is_update:
            b_start = pos
            b_dict, pos = _decode_row_image(body, pos, tmap, bm1, col_names, col_type_hints)
            b_slice = body[b_start:pos]
            a_start = pos
            a_dict, pos = _decode_row_image(body, pos, tmap, bm2, col_names, col_type_hints)
            a_slice = body[a_start:pos]
            before_rows.append(b_dict)
            after_rows.append(a_dict)
            # Prepend in reverse pair order when multiple rows were updated
            swapped_chunks.append(a_slice + b_slice)
        else:
            r_dict, pos = _decode_row_image(body, pos, tmap, bm1, col_names, col_type_hints)
            if ev_type in (WRITE_ROWS_EVENT_V1, WRITE_ROWS_EVENT_V2):
                after_rows.append(r_dict)
            else:
                before_rows.append(r_dict)

    base_no_crc = raw_event[:-4] if has_checksum else raw_event
    if ev_type in (WRITE_ROWS_EVENT_V1, WRITE_ROWS_EVENT_V2):
        inv_type = DELETE_ROWS_EVENT_V1 if ev_type == WRITE_ROWS_EVENT_V1 else DELETE_ROWS_EVENT_V2
        inv_buf = bytearray(base_no_crc)
        inv_buf[4] = inv_type
        op_name = "INSERT"
    elif ev_type in (DELETE_ROWS_EVENT_V1, DELETE_ROWS_EVENT_V2):
        inv_type = WRITE_ROWS_EVENT_V1 if ev_type == DELETE_ROWS_EVENT_V1 else WRITE_ROWS_EVENT_V2
        inv_buf = bytearray(base_no_crc)
        inv_buf[4] = inv_type
        op_name = "DELETE"
    else:
        # Swap bm1 <-> bm2 if needed and reverse row pairs
        inv_buf = bytearray(base_no_crc[:rows_header_end])
        # Fix bm1/bm2 order inside header if partial row images were used
        if bm1 != bm2:
            bm1_off = rows_header_end - 2 * bm_len
            inv_buf[bm1_off : bm1_off + bm_len] = bm2
            inv_buf[bm1_off + bm_len : rows_header_end] = bm1
        for chunk in reversed(swapped_chunks):
            inv_buf.extend(chunk)
        op_name = "UPDATE"

    if has_checksum:
        crc = zlib.crc32(inv_buf) & 0xFFFFFFFF
        inv_buf.extend(struct.pack("<I", crc))

    return op_name, before_rows, after_rows, bytes(inv_buf)


class MySQLBinlogPoller:
    """Polls MySQL row-based binlog via non-blocking COM_BINLOG_DUMP to capture triggers & RBR undo."""

    def __init__(
        self,
        driver: MySQLDriver,
        ledger: UndoLedger,
        *,
        poll_interval_sec: float = 0.25,
        server_id: int = 9901,
    ) -> None:
        self.driver = driver
        self.ledger = ledger
        self.poll_interval_sec = poll_interval_sec
        self.server_id = server_id
        self._dump_client: MySQLWireClient | None = None
        self._current_file: str | None = None
        self._current_pos: int = 4
        self._has_checksum: bool = True
        self._fde_raw: bytes | None = None
        self._table_maps: dict[int, BinlogTableMap] = {}
        self._schema_cache: dict[tuple[str, str], tuple[list[str], list[str], dict[str, str]]] = {}
        self._tx_events: list[dict[str, Any]] = []
        self._tx_meta: dict[str, Any] | None = None
        self._in_tx: bool = False
        self._poll_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def _ensure_dump_client(self) -> MySQLWireClient:
        if self._dump_client is not None:
            return self._dump_client
        src = self.driver._client
        client = MySQLWireClient(
            host=src.host,
            port=src.port,
            user=src.user,
            password=src.password,
            database=src.database,
            timeout=src.timeout,
        )
        client.connect()
        try:
            res = client.query("SHOW VARIABLES LIKE 'binlog_checksum';")
            if res.rows:
                self._has_checksum = str(res.rows[0][1]).upper() != "NONE"
        except Exception:
            self._has_checksum = True
        try:
            client.query("SET @master_binlog_checksum = @@global.binlog_checksum;")
        except Exception:
            try:
                client.query("SET @source_binlog_checksum = @@global.binlog_checksum;")
            except Exception:
                pass
        if self._current_file is None:
            for sql in ("SHOW MASTER STATUS;", "SHOW BINARY LOG STATUS;"):
                try:
                    st = client.query(sql)
                    if st.rows:
                        self._current_file = str(st.rows[0][0])
                        self._current_pos = int(st.rows[0][1])
                        break
                except Exception:
                    continue
            if self._current_file is None:
                raise RuntimeError("MySQL binary logging is not enabled or accessible.")
            # Fetch initial FORMAT_DESCRIPTION_EVENT from byte 4 if starting mid-log
            if self._current_pos > 4 and self._fde_raw is None:
                self._bootstrap_fde(client, self._current_file)
                client.close()
                client = MySQLWireClient(
                    host=src.host,
                    port=src.port,
                    user=src.user,
                    password=src.password,
                    database=src.database,
                    timeout=src.timeout,
                )
                client.connect()
                try:
                    client.query("SET @master_binlog_checksum = @@global.binlog_checksum;")
                except Exception:
                    try:
                        client.query("SET @source_binlog_checksum = @@global.binlog_checksum;")
                    except Exception:
                        pass
        self._dump_client = client
        return client

    def _bootstrap_fde(self, client: MySQLWireClient, log_file: str) -> None:
        payload = (
            bytes([0x12])
            + struct.pack("<IHI", 4, 0x01, self.server_id + 1)
            + log_file.encode("utf-8")
        )
        assert client._sock is not None
        client._sock.sendall(frame_mysql_packet(payload, seq_id=0))
        while True:
            pkt = read_mysql_packet_sync(client._sock).payload
            if pkt[0] == 0xFE and len(pkt) < 9:
                break
            if pkt[0] == 0xFF:
                break
            ev = pkt[1:]
            if ev[4] == FORMAT_DESCRIPTION_EVENT:
                self._fde_raw = ev

    def ensure_ready(self) -> None:
        self.driver._ensure_marker_table()
        self._ensure_dump_client()

    def _get_table_info(self, db: str, table: str) -> tuple[list[str], list[str], dict[str, str]]:
        key = (db, table)
        if key not in self._schema_cache:
            try:
                ts = self.driver.inspect_table(table, db)
                self._schema_cache[key] = (
                    list(ts.columns),
                    list(ts.pk_columns),
                    dict(ts.column_types),
                )
            except Exception:
                self._schema_cache[key] = ([], [], {})
        return self._schema_cache[key]

    def poll_once(self) -> int:
        """Fetch pending MySQL binlog events non-blockingly. Returns committed tx count."""
        with self._poll_lock:
            return self._poll_once_locked()

    def _poll_once_locked(self) -> int:
        committed = 0
        rec_tables_cache: dict[str, set[tuple[str, str]]] = {}
        trig_cache: dict[tuple[str, str], bool] = {}
        for _ in range(16):  # follow binlog file rotations safely
            client = self._ensure_dump_client()
            assert self._current_file is not None
            assert client._sock is not None
            start_file = self._current_file
            rotated = False

            payload = (
                bytes([0x12])
                + struct.pack("<IHI", self._current_pos, 0x01, self.server_id)
                + self._current_file.encode("utf-8")
            )
            try:
                try:
                    client._sock.sendall(frame_mysql_packet(payload, seq_id=0))
                except Exception:
                    self._reset_dump_client()
                    client = self._ensure_dump_client()
                    assert client._sock is not None
                    client._sock.sendall(frame_mysql_packet(payload, seq_id=0))

                while True:
                    pkt = read_mysql_packet_sync(client._sock).payload
                    if pkt[0] == 0xFE and len(pkt) < 9:
                        break
                    if pkt[0] == 0xFF:
                        break
                    ev = pkt[1:]
                    ev_type = ev[4]
                    next_pos = struct.unpack_from("<I", ev, 13)[0]

                    if ev_type == ROTATE_EVENT:
                        rbody = ev[19:-4] if self._has_checksum else ev[19:]
                        rot_pos = struct.unpack_from("<Q", rbody, 0)[0]
                        rot_file = rbody[8:].decode("utf-8", errors="replace").rstrip("\x00")
                        if rot_file and rot_pos >= 4 and (
                            rot_file != self._current_file or rot_pos > self._current_pos
                        ):
                            if rot_file != start_file:
                                rotated = True
                            self._current_file = rot_file
                            self._current_pos = int(rot_pos)
                        continue

                    if ev_type == FORMAT_DESCRIPTION_EVENT:
                        self._fde_raw = ev
                        if next_pos > self._current_pos:
                            self._current_pos = next_pos
                        continue

                    if next_pos > 0:
                        self._current_pos = next_pos

                    if ev_type == QUERY_EVENT:
                        qbody = ev[19:-4] if self._has_checksum else ev[19:]
                        db_len = qbody[8]
                        sv_len = struct.unpack_from("<H", qbody, 11)[0]
                        q_off = 13 + sv_len + db_len + 1
                        query = qbody[q_off:].decode("utf-8", errors="replace").strip().upper()
                        if query == "BEGIN":
                            self._in_tx = True
                            self._tx_events = []
                            self._tx_meta = None
                        elif query in ("COMMIT", "END") and self._in_tx:
                            if self._flush_tx():
                                committed += 1
                        elif query.startswith("ROLLBACK"):
                            self._in_tx = False
                            self._tx_events = []
                            self._tx_meta = None
                        elif query.startswith(("ALTER ", "CREATE ", "DROP ", "TRUNCATE ")):
                            self._schema_cache.clear()
                        continue

                    if ev_type == TABLE_MAP_EVENT:
                        tmap = parse_table_map_event(ev, has_checksum=self._has_checksum)
                        self._table_maps[tmap.table_id] = tmap
                        continue

                    if ev_type in (
                        WRITE_ROWS_EVENT_V1,
                        UPDATE_ROWS_EVENT_V1,
                        DELETE_ROWS_EVENT_V1,
                        WRITE_ROWS_EVENT_V2,
                        UPDATE_ROWS_EVENT_V2,
                        DELETE_ROWS_EVENT_V2,
                    ):
                        ebody = ev[19:-4] if self._has_checksum else ev[19:]
                        tid = int.from_bytes(ebody[0:6], "little")
                        tmap = self._table_maps.get(tid)
                        if tmap is None:
                            continue
                        if tmap.db == QUARANTINE_DB and tmap.table == MARKER_TABLE:
                            cols, _pks, hints = self._get_table_info(tmap.db, tmap.table)
                            if not cols:
                                cols = ["id", "payload"]
                            try:
                                _op, _b, a_rows, _inv = parse_and_invert_rows_event(
                                    ev, tmap, cols, hints, has_checksum=self._has_checksum
                                )
                                if a_rows and "payload" in a_rows[-1]:
                                    self._tx_meta = json.loads(str(a_rows[-1]["payload"]))
                            except Exception:
                                pass
                            continue
                        if tmap.db == QUARANTINE_DB:
                            continue
                        if self._tx_meta and (
                            self._tx_meta.get("is_reverse") or self._tx_meta.get("skip_binlog_dml")
                        ):
                            continue
                        corr_id = self._tx_meta.get("tx_id") if self._tx_meta else None
                        if corr_id:
                            cid = str(corr_id)
                            tbls = rec_tables_cache.get(cid)
                            if tbls is None:
                                rec = self.ledger.get_record(cid)
                                tbls = (
                                    {(op.schema or self.driver._default_db, op.table) for op in rec.ops}
                                    if rec is not None
                                    else set()
                                )
                                rec_tables_cache[cid] = tbls
                            tkey = (tmap.db, tmap.table)
                            if tkey in tbls:
                                has_trigs = trig_cache.get(tkey)
                                if has_trigs is None:
                                    has_trigs = self.driver._table_has_triggers(tmap.table, tmap.db)
                                    trig_cache[tkey] = has_trigs
                                if not has_trigs:
                                    continue

                        cols, pks, hints = self._get_table_info(tmap.db, tmap.table)
                        try:
                            op_name, b_rows, a_rows, inv_ev = parse_and_invert_rows_event(
                                ev, tmap, cols, hints, has_checksum=self._has_checksum
                            )
                        except Exception:
                            continue
                        rbr_blob = base64.b64encode(tmap.raw_event + inv_ev).decode("ascii")
                        self._tx_events.append(
                            {
                                "op": op_name,
                                "db": tmap.db,
                                "table": tmap.table,
                                "pks": pks,
                                "hints": hints,
                                "before_rows": b_rows,
                                "after_rows": a_rows,
                                "rbr_blob": rbr_blob,
                            }
                        )
                        continue

                    if ev_type == XID_EVENT:
                        if self._flush_tx():
                            committed += 1
            finally:
                # MySQL closes/ends the dump session after BINLOG_DUMP_NON_BLOCK EOF
                self._reset_dump_client()

            if not rotated:
                break

        return committed

    def _reset_dump_client(self) -> None:
        if self._dump_client is not None:
            try:
                self._dump_client.close()
            except Exception:
                pass
            self._dump_client = None

    def _flush_tx(self) -> bool:
        events = self._tx_events
        meta = self._tx_meta
        self._tx_events = []
        self._tx_meta = None
        self._in_tx = False

        if not events:
            return False
        if meta and meta.get("is_reverse"):
            return False

        corr_tx_id = str(meta["tx_id"]) if meta and "tx_id" in meta else None
        existing_rec = self.ledger.get_record(corr_tx_id) if corr_tx_id else None
        existing_tables = (
            {(op.schema or self.driver._default_db, op.table) for op in existing_rec.ops}
            if existing_rec is not None
            else set()
        )
        fde_b64 = base64.b64encode(self._fde_raw).decode("ascii") if self._fde_raw else None

        attach_rbr: dict[tuple[str, str], tuple[str, list[str]]] = {}
        extra_ops: list[MutationOp] = []

        if existing_rec is not None:
            for ev in events:
                tkey = (ev["db"], ev["table"])
                if tkey in existing_tables:
                    if fde_b64:
                        attach_rbr.setdefault(tkey, (fde_b64, []))[1].append(ev["rbr_blob"])
                    continue
                extra_ops.append(
                    MutationOp(
                        op_type=ev["op"],
                        table=ev["table"],
                        schema=ev["db"],
                        pk_columns=ev["pks"] or list((ev["before_rows"] or ev["after_rows"])[0].keys()),
                        column_types=ev["hints"],
                        before_rows=ev["before_rows"],
                        after_rows=ev["after_rows"],
                        rbr_fde_b64=fde_b64,
                        rbr_undo_events=[ev["rbr_blob"]] if fde_b64 else [],
                    )
                )
            if extra_ops or attach_rbr:
                self.ledger.append_ops(
                    corr_tx_id,  # type: ignore[arg-type]
                    extra_ops,
                    warning="Captured trigger/binlog side effects." if extra_ops else None,
                    attach_rbr=attach_rbr or None,
                )
                return bool(extra_ops)
            return False

        # External direct-DB mutation (not executed through the SQL proxy)
        tx_id = corr_tx_id or new_tx_id()
        cdc = CDCIngestor(self.ledger, EngineType.MYSQL)
        cdc.begin_marker(tx_id, session_id="binlog_poller", raw_sql="/* MySQL binlog tx */")
        for ev in events:
            cdc.ingest_row_event(
                tx_id,
                op_type=ev["op"],
                table=ev["table"],
                schema=ev["db"],
                pk_columns=ev["pks"],
                before_row=ev["before_rows"][0] if len(ev["before_rows"]) == 1 else None,
                after_row=ev["after_rows"][0] if len(ev["after_rows"]) == 1 else None,
            )
            if ev["op"] == "INSERT" and len(ev["after_rows"]) > 1:
                for ar in ev["after_rows"][1:]:
                    cdc.ingest_row_event(
                        tx_id,
                        op_type="INSERT",
                        table=ev["table"],
                        schema=ev["db"],
                        pk_columns=ev["pks"],
                        after_row=ar,
                    )
            elif ev["op"] == "DELETE" and len(ev["before_rows"]) > 1:
                for br in ev["before_rows"][1:]:
                    cdc.ingest_row_event(
                        tx_id,
                        op_type="DELETE",
                        table=ev["table"],
                        schema=ev["db"],
                        pk_columns=ev["pks"],
                        before_row=br,
                    )
            elif ev["op"] == "UPDATE" and len(ev["after_rows"]) > 1:
                for br, ar in zip(ev["before_rows"][1:], ev["after_rows"][1:]):
                    cdc.ingest_row_event(
                        tx_id,
                        op_type="UPDATE",
                        table=ev["table"],
                        schema=ev["db"],
                        pk_columns=ev["pks"],
                        before_row=br,
                        after_row=ar,
                    )
        rec = cdc.commit_marker(tx_id)
        if fde_b64 and rec is not None:
            for ev in events:
                attach_rbr.setdefault((ev["db"], ev["table"]), (fde_b64, []))[1].append(
                    ev["rbr_blob"]
                )
            self.ledger.append_ops(tx_id, [], attach_rbr=attach_rbr)
        return True

    def start(self) -> None:
        if self._thread is not None:
            return
        self.ensure_ready()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name="mysql-binlog-poller", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._reset_dump_client()

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception:
                pass
            self._stop_event.wait(self.poll_interval_sec)
