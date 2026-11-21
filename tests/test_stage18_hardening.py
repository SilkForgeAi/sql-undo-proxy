"""Stage 18 tests: Spill SHA-256 integrity, erasure/TTL purge, pgoutput binary decoding, CLI safety defaults."""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.cli import build_parser
from reverse_proxy.drivers import SQLiteDriver
from reverse_proxy.models import EngineType, MutationOp, ReversibilityStatus
from reverse_proxy.parser import parse_statement
from reverse_proxy.wal_poller import parse_pgoutput_message


def _pack_pgoutput_text_tuple(values: list[str | None]) -> bytes:
    buf = bytearray(struct.pack("!H", len(values)))
    for v in values:
        if v is None:
            buf.extend(b"n")
        else:
            raw = v.encode("utf-8")
            buf.extend(b"t" + struct.pack("!i", len(raw)) + raw)
    return bytes(buf)


class TestStage18Hardening(unittest.TestCase):
    def test_spill_sha256_integrity_check_and_erasure_purge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "app.db")
            ledger_path = os.path.join(tmp, "ledger.db")
            drv = SQLiteDriver(db_path)
            ledger = UndoLedger(
                ledger_path, compress_threshold_bytes=128, spill_threshold_bytes=256
            )
            eng = ReverseProxyEngine(drv, ledger)
            try:
                eng.execute_one("CREATE TABLE gdpr_users (id INTEGER PRIMARY KEY, email TEXT);")
                big_ops = [
                    MutationOp(
                        op_type="INSERT",
                        table="gdpr_users",
                        schema="main",
                        pk_columns=["id"],
                        column_types={"id": "INTEGER", "email": "TEXT"},
                        before_rows=[],
                        after_rows=[{"id": i, "email": f"user_{i}_" + ("x" * 60)} for i in range(1, 80)],
                    )
                ]
                rec = ledger.record_transaction(
                    tx_id="tx_spill_1",
                    engine=EngineType.SQLITE,
                    session_id="s1",
                    raw_sql="INSERT INTO gdpr_users ...",
                    status=ReversibilityStatus.EXACT,
                    ops=big_ops,
                )
                row = ledger._conn.execute(
                    "SELECT spill_path, spill_sha256 FROM undo_records WHERE tx_id = ?",
                    (rec.tx_id,),
                ).fetchone()
                self.assertIsNotNone(row["spill_path"])
                self.assertIsNotNone(row["spill_sha256"])
                spill_path = row["spill_path"]
                self.assertTrue(os.path.exists(spill_path))

                # Corrupt 1 byte in spill file -> must catch SHA-256 mismatch before restore
                orig_bytes = open(spill_path, "rb").read()
                corrupted = bytes([orig_bytes[0] ^ 0xFF]) + orig_bytes[1:]
                with open(spill_path, "wb") as fh:
                    fh.write(corrupted)
                with self.assertRaises(ValueError) as ctx:
                    ledger.get_record(rec.tx_id)
                self.assertIn("SHA-256 mismatch", str(ctx.exception))

                # Restore intact bytes, verify PROXY PURGE TX removes both record and spill file
                with open(spill_path, "wb") as fh:
                    fh.write(orig_bytes)
                self.assertEqual(len(ledger.get_record(rec.tx_id).ops[0].after_rows), 79)
                res_tx = eng.execute_one(f"PROXY PURGE TX {rec.tx_id};")
                self.assertEqual(res_tx.rowcount, 1)
                self.assertFalse(os.path.exists(spill_path))
                self.assertIsNone(ledger.get_record(rec.tx_id))

                # Targeted table purge & older-than retention purge
                eng.execute_one("INSERT INTO gdpr_users VALUES (1, 'a@b.com');")
                eng.execute_one("CREATE TABLE keep_tbl (id INTEGER PRIMARY KEY, v TEXT);")
                eng.execute_one("INSERT INTO keep_tbl VALUES (1, 'stay');")
                old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
                ledger._conn.execute(
                    "UPDATE undo_records SET created_at = ? WHERE raw_sql LIKE '%keep_tbl%';",
                    (old_ts,),
                )
                ledger._conn.commit()

                p_tbl = eng.execute_one("PROXY PURGE TABLE gdpr_users;", actor="sec_admin")
                self.assertGreaterEqual(p_tbl.rowcount, 1)
                p_old = eng.execute_one("PROXY PURGE OLDER THAN 5 DAYS;", actor="cron_bot")
                self.assertEqual(p_old.rowcount, 1)

                # Verify purge audit log records who purged what and when!
                p_log = eng.execute_one("PROXY PURGE LOG LIMIT 10;")
                self.assertEqual(p_log.command_tag, "PROXY PURGE LOG")
                actors_modes = [(r[2], r[3]) for r in p_log.rows]
                self.assertIn(("sec_admin", "table"), actors_modes)
                self.assertIn(("cron_bot", "older_than"), actors_modes)
                self.assertIn(("anonymous", "tx"), actors_modes)
            finally:
                eng.close()
                ledger.close()

    def test_pgoutput_binary_protocol_decoding(self) -> None:
        relations: dict[int, dict] = {}
        # 1. Begin (lsn, ts, xid=899)
        b_pkt = b"B" + struct.pack("!QQI", 100, 200, 899)
        self.assertEqual(parse_pgoutput_message(b_pkt, relations), {"kind": "begin", "xid": "899"})

        # 2. Message ('M', flags=1, lsn, prefix='reverse_proxy\0', len, content)
        content = b'{"tx_id":"tx_demo"}'
        m_pkt = b"M\x01" + struct.pack("!Q", 100) + b"reverse_proxy\x00" + struct.pack("!I", len(content)) + content
        self.assertEqual(
            parse_pgoutput_message(m_pkt, relations),
            {"kind": "message", "prefix": "reverse_proxy", "content": '{"tx_id":"tx_demo"}'},
        )

        # 3. Relation (rel_id=16385, public.items, cols: id int4, name text, active bool)
        r_pkt = (
            b"R"
            + struct.pack("!I", 16385)
            + b"public\x00items\x00\x64"
            + struct.pack("!H", 3)
            + b"\x01id\x00" + struct.pack("!Ii", 23, -1)
            + b"\x00name\x00" + struct.pack("!Ii", 25, -1)
            + b"\x00active\x00" + struct.pack("!Ii", 16, -1)
        )
        self.assertEqual(parse_pgoutput_message(r_pkt, relations), {"kind": "relation", "rel_id": 16385})

        # 4. Insert + Update + Delete
        i_pkt = b"I" + struct.pack("!I", 16385) + b"N" + _pack_pgoutput_text_tuple(["1", "widget", "t"])
        self.assertEqual(
            parse_pgoutput_message(i_pkt, relations),
            {
                "kind": "dml",
                "op": "c",
                "schema": "public",
                "table": "items",
                "before": None,
                "after": {"id": 1, "name": "widget", "active": True},
            },
        )
        u_pkt = (
            b"U"
            + struct.pack("!I", 16385)
            + b"O"
            + _pack_pgoutput_text_tuple(["1", "widget", "t"])
            + b"N"
            + _pack_pgoutput_text_tuple(["1", "widget2", "f"])
        )
        u_parsed = parse_pgoutput_message(u_pkt, relations)
        assert u_parsed is not None
        self.assertEqual(u_parsed["before"], {"id": 1, "name": "widget", "active": True})
        self.assertEqual(u_parsed["after"], {"id": 1, "name": "widget2", "active": False})

        d_pkt = b"D" + struct.pack("!I", 16385) + b"K" + _pack_pgoutput_text_tuple(["1", None, None])
        d_parsed = parse_pgoutput_message(d_pkt, relations)
        assert d_parsed is not None
        self.assertEqual(d_parsed["op"], "d")
        self.assertEqual(d_parsed["before"]["id"], 1)

        c_pkt = b"C\x00" + struct.pack("!QQQ", 1, 2, 3)
        self.assertEqual(parse_pgoutput_message(c_pkt, relations), {"kind": "commit"})

    def test_cli_defaults_and_purge_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args([])
        self.assertEqual(args.max_capture_rows, 10000)
        self.assertIsNone(args.spill_retention_days)

        p1 = parse_statement("PROXY PURGE TX tx_123;")
        self.assertEqual((p1.purge_mode, p1.purge_target), ("tx", "tx_123"))
        p2 = parse_statement("PROXY PURGE TABLE users;")
        self.assertEqual((p2.purge_mode, p2.purge_target), ("table", "users"))
        p3 = parse_statement("PROXY PURGE OLDER THAN 30 DAYS;")
        self.assertEqual((p3.purge_mode, p3.purge_days), ("older_than", 30.0))


if __name__ == "__main__":
    unittest.main()
