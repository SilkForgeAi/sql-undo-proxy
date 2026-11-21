"""Stage 15 tests: MySQL binlog RBR parser/inverter, attach_rbr ledger persistence, and Ctrl+Z shorthand."""

from __future__ import annotations

import struct
import unittest
import zlib

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.binlog_poller import (
    DELETE_ROWS_EVENT_V2,
    MYSQL_TYPE_LONG,
    MYSQL_TYPE_NEWDECIMAL,
    MYSQL_TYPE_VARCHAR,
    TABLE_MAP_EVENT,
    UPDATE_ROWS_EVENT_V2,
    WRITE_ROWS_EVENT_V2,
    parse_and_invert_rows_event,
    parse_table_map_event,
)
from reverse_proxy.drivers import SQLiteDriver
from reverse_proxy.models import EngineType, MutationOp, ReversibilityStatus, StatementKind
from reverse_proxy.parser import parse_statement


def _wrap_binlog_event(ev_type: int, body: bytes) -> bytes:
    total_len = 19 + len(body) + 4
    header = struct.pack("<IBIIIH", 0, ev_type, 1, total_len, 100 + total_len, 0)
    raw = bytearray(header + body)
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    raw.extend(struct.pack("<I", crc))
    return bytes(raw)


def _encode_newdecimal_10_2(int_part: int, frac_part: int) -> bytes:
    # NEWDECIMAL(10, 2): intg=8 -> 4 bytes with sign bit 0x80 flipped; frac=2 -> 1 byte
    return struct.pack(">IB", int_part ^ 0x80000000, frac_part)


class TestStage15MySQLBinlogAndShorthand(unittest.TestCase):
    def test_table_map_and_rows_decode_plus_rbr_inversion(self) -> None:
        # Table: (id INT UNSIGNED, name VARCHAR(80), bal DECIMAL(10,2))
        table_id = (42).to_bytes(6, "little")
        tmap_body = (
            table_id
            + struct.pack("<H", 1)
            + b"\x03app\x00"
            + b"\x06m_acct\x00"
            + bytes([3, MYSQL_TYPE_LONG, MYSQL_TYPE_VARCHAR, MYSQL_TYPE_NEWDECIMAL])
            + bytes([4])
            + struct.pack("<H", 320)  # max_len=320 (>255 -> 2-byte varchar length prefix)
            + bytes([10, 2])
            + bytes([0b00000110])  # nullable cols 1, 2
            + bytes([1, 1, 0x80])  # optional metadata SIGNEDNESS: bit0=1 (id UNSIGNED)
        )
        tmap_raw = _wrap_binlog_event(TABLE_MAP_EVENT, tmap_body)
        tmap = parse_table_map_event(tmap_raw, has_checksum=True)
        self.assertEqual(tmap.db, "app")
        self.assertEqual(tmap.table, "m_acct")
        self.assertEqual(tmap.unsigned_flags, [True, False, False])

        cols = ["id", "name", "bal"]
        hints = {"id": "int", "name": "varchar", "bal": "decimal"}

        # 1. WRITE_ROWS_EVENT_V2 -> inverts to DELETE_ROWS_EVENT_V2 with valid CRC32
        row1 = (
            bytes([0])
            + struct.pack("<I", 3000000001)
            + struct.pack("<H", 5)
            + b"Alice"
            + _encode_newdecimal_10_2(100, 50)
        )
        wr_body = table_id + struct.pack("<HH", 0, 2) + bytes([3, 0xFF]) + row1
        wr_raw = _wrap_binlog_event(WRITE_ROWS_EVENT_V2, wr_body)
        op, before_rows, after_rows, inv_wr = parse_and_invert_rows_event(
            wr_raw, tmap, cols, hints, has_checksum=True
        )
        self.assertEqual(op, "INSERT")
        self.assertEqual(before_rows, [])
        self.assertEqual(after_rows, [{"id": 3000000001, "name": "Alice", "bal": "100.50"}])
        self.assertEqual(inv_wr[4], DELETE_ROWS_EVENT_V2)
        self.assertEqual(struct.pack("<I", zlib.crc32(inv_wr[:-4]) & 0xFFFFFFFF), inv_wr[-4:])

        # Re-parsing inverted DELETE_ROWS_EVENT_V2 -> before_rows matches & inverts back to WRITE_ROWS_EVENT_V2
        op_d, b_d, a_d, inv_d = parse_and_invert_rows_event(
            inv_wr, tmap, cols, hints, has_checksum=True
        )
        self.assertEqual(op_d, "DELETE")
        self.assertEqual(b_d, after_rows)
        self.assertEqual(a_d, [])
        self.assertEqual(inv_d[4], WRITE_ROWS_EVENT_V2)

        # 2. UPDATE_ROWS_EVENT_V2 with different-sized VARCHAR values ('Alice' -> 'Alice Long Updated Name')
        row2 = (
            bytes([0])
            + struct.pack("<I", 3000000001)
            + struct.pack("<H", 23)
            + b"Alice Long Updated Name"
            + _encode_newdecimal_10_2(500, 75)
        )
        upd_body = table_id + struct.pack("<HH", 0, 2) + bytes([3, 0xFF, 0xFF]) + row1 + row2
        upd_raw = _wrap_binlog_event(UPDATE_ROWS_EVENT_V2, upd_body)
        op_u, b_u, a_u, inv_u = parse_and_invert_rows_event(
            upd_raw, tmap, cols, hints, has_checksum=True
        )
        self.assertEqual(op_u, "UPDATE")
        self.assertEqual(b_u[0]["name"], "Alice")
        self.assertEqual(a_u[0]["name"], "Alice Long Updated Name")
        self.assertEqual(a_u[0]["bal"], "500.75")

        # Parse inverted UPDATE_ROWS_EVENT_V2 to confirm clean byte swap!
        op_u2, b_u2, a_u2, _ = parse_and_invert_rows_event(
            inv_u, tmap, cols, hints, has_checksum=True
        )
        self.assertEqual(op_u2, "UPDATE")
        self.assertEqual(b_u2, a_u)
        self.assertEqual(a_u2, b_u)
        self.assertEqual(struct.pack("<I", zlib.crc32(inv_u[:-4]) & 0xFFFFFFFF), inv_u[-4:])

    def test_ledger_attach_rbr_and_ctrl_z_shorthand(self) -> None:
        p1 = parse_statement("PROXY REVERSE;")
        self.assertEqual(p1.kind, StatementKind.PROXY_REVERSE)
        self.assertEqual(p1.proxy_tx_id, "LAST")
        p2 = parse_statement("PROXY REVERSE LAST DRY RUN;")
        self.assertEqual(p2.proxy_tx_id, "LAST")
        self.assertTrue(p2.proxy_dry_run)
        p3 = parse_statement("PROXY REVERSE FORCE;")
        self.assertEqual(p3.proxy_tx_id, "LAST")
        self.assertTrue(p3.proxy_force)
        p4 = parse_statement("PROXY DIFF;")
        self.assertEqual(p4.kind, StatementKind.PROXY_DIFF)
        self.assertEqual(p4.proxy_tx_id, "LAST")

        drv = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        eng = ReverseProxyEngine(drv, ledger)
        drv._conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);")

        r1 = eng.execute_one("INSERT INTO items VALUES (1, 'one');")
        r2 = eng.execute_one("UPDATE items SET name = 'two' WHERE id = 1;")
        assert r1.tx_id and r2.tx_id

        updated = ledger.append_ops(
            r2.tx_id,
            [],
            attach_rbr={(None or "", "items"): ("ZmRl", ["YmxvYjE="])},
        )
        assert updated is not None
        fetched = ledger.get_record(r2.tx_id)
        assert fetched is not None
        self.assertEqual(fetched.ops[0].rbr_fde_b64, "ZmRl")
        self.assertEqual(fetched.ops[0].rbr_undo_events, ["YmxvYjE="])

        # Shorthand PROXY REVERSE LAST skips nothing and undoes r2 -> r1
        rev1 = eng.execute_one("PROXY REVERSE;")
        self.assertEqual(rev1.command_tag, "PROXY REVERSE OK")
        self.assertEqual(drv._conn.execute("SELECT name FROM items WHERE id = 1;").fetchone()[0], "one")

        rev2 = eng.execute_one("PROXY REVERSE LAST;")
        self.assertEqual(rev2.command_tag, "PROXY REVERSE OK")
        self.assertEqual(drv._conn.execute("SELECT COUNT(*) FROM items;").fetchone()[0], 0)
        eng.close()
        ledger.close()


if __name__ == "__main__":
    unittest.main()
