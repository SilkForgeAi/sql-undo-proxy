"""Stage 17 tests: Pipelined/batched Postgres & MySQL bulk reversal and quarantine-only purge index."""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from reverse_proxy import ReverseProxyEngine, UndoLedger
from reverse_proxy.drivers import MySQLDriver, MySQLWireClient, PostgresDriver, SQLiteDriver
from reverse_proxy.models import EngineType, MutationOp, ReversibilityStatus
from reverse_proxy.protocols.mysql_codec import (
    COM_STMT_CLOSE,
    COM_STMT_EXECUTE,
    COM_STMT_PREPARE,
    COM_STMT_RESET,
    FIELD_TYPE_LONG,
    FIELD_TYPE_VAR_STRING,
    decode_lenenc_int,
    encode_lenenc_str,
    frame_mysql_packet,
    read_mysql_packet_sync,
)
from test_stage2_pgwire import _SimulatedPostgresBackend
from test_stage3_mysql import _SimulatedMySQLBackend
from test_stage10_isolation_auth import _DualProtocolServer


class TestStage17BulkBatchingAndScale(unittest.TestCase):
    def test_postgres_pipelined_executemany_and_bulk_reverse_1200_rows(self) -> None:
        backend = _SimulatedPostgresBackend()
        backend.start()
        ledger = UndoLedger(":memory:")
        drv = PostgresDriver(host="127.0.0.1", port=backend.port, user="postgres")
        eng = ReverseProxyEngine(drv, ledger)
        try:
            eng.execute("CREATE TABLE public.bulk_items (id INTEGER PRIMARY KEY, val INTEGER, note TEXT);")
            params = [(i, i * 10, f"r{i}") for i in range(1, 1201)]
            drv._client.executemany(
                'INSERT INTO "public"."bulk_items" ("id", "val", "note") VALUES ($1, $2, $3);',
                params,
                batch_size=500,
            )
            self.assertEqual(drv._client.query('SELECT COUNT(*) FROM "public"."bulk_items";')[0].rows[0][0], 1200)

            # Bulk UPDATE 1,200 rows -> batched pipelined reverse
            upd = eng.execute_one("UPDATE public.bulk_items SET val = val + 1, note = 'changed';")
            self.assertEqual(upd.rowcount, 1200)
            rev_u = eng.execute_one("PROXY REVERSE LAST;")
            self.assertEqual(rev_u.command_tag, "PROXY REVERSE OK")
            self.assertEqual(
                drv._client.query('SELECT val, note FROM "public"."bulk_items" WHERE id = 777;')[0].rows[0],
                (7770, "r777"),
            )

            # Bulk DELETE 1,200 rows -> batched pipelined INSERT reverse
            d = eng.execute_one("DELETE FROM public.bulk_items;")
            self.assertEqual(d.rowcount, 1200)
            self.assertEqual(drv._client.query('SELECT COUNT(*) FROM "public"."bulk_items";')[0].rows[0][0], 0)
            rev_d = eng.execute_one("PROXY REVERSE LAST;")
            self.assertEqual(rev_d.command_tag, "PROXY REVERSE OK")
            self.assertEqual(drv._client.query('SELECT COUNT(*) FROM "public"."bulk_items";')[0].rows[0][0], 1200)
        finally:
            eng.close()
            ledger.close()
            backend.stop()

    def test_mysql_batched_reverse_insert_update_case_delete_in_1200_rows(self) -> None:
        backend = _SimulatedMySQLBackend()
        backend.start()
        ledger = UndoLedger(":memory:")
        drv = MySQLDriver(host="127.0.0.1", port=backend.port, user="root", database="app")
        eng = ReverseProxyEngine(drv, ledger)
        try:
            drv._client.query("CREATE TABLE bulk_items (id INTEGER PRIMARY KEY, val INTEGER, note TEXT);")
            for start in range(1, 1201, 400):
                vals = ", ".join(f"({i}, {i * 10}, 'r{i}')" for i in range(start, min(start + 400, 1201)))
                drv._client.query(f"INSERT INTO bulk_items (id, val, note) VALUES {vals};")
            self.assertEqual(drv._client.query("SELECT COUNT(*) FROM bulk_items;").rows[0][0], 1200)

            # Bulk UPDATE 1,200 rows -> CASE batch reverse
            upd = eng.execute_one("UPDATE bulk_items SET val = val + 5, note = 'edited';")
            self.assertEqual(upd.rowcount, 1200)
            rev_u = eng.execute_one("PROXY REVERSE LAST;")
            self.assertEqual(rev_u.command_tag, "PROXY REVERSE OK")
            self.assertEqual(
                drv._client.query("SELECT val, note FROM bulk_items WHERE id = 999;").rows[0],
                (9990, "r999"),
            )

            # Bulk DELETE 1,200 rows -> multi-row INSERT batch reverse
            d = eng.execute_one("DELETE FROM bulk_items;")
            self.assertEqual(d.rowcount, 1200)
            rev_d = eng.execute_one("PROXY REVERSE LAST;")
            self.assertEqual(rev_d.command_tag, "PROXY REVERSE OK")
            self.assertEqual(drv._client.query("SELECT COUNT(*) FROM bulk_items;").rows[0][0], 1200)

            # Bulk INSERT capture via explicit values -> DELETE IN (...) batch reverse
            ins_vals = ", ".join(f"({i}, {i}, 'new')" for i in range(2001, 2051))
            eng.execute_one(f"INSERT INTO bulk_items (id, val, note) VALUES {ins_vals};")
            self.assertEqual(drv._client.query("SELECT COUNT(*) FROM bulk_items;").rows[0][0], 1250)
            rev_i = eng.execute_one("PROXY REVERSE LAST;")
            self.assertEqual(rev_i.command_tag, "PROXY REVERSE OK")
            self.assertEqual(drv._client.query("SELECT COUNT(*) FROM bulk_items;").rows[0][0], 1200)
        finally:
            eng.close()
            ledger.close()
            backend.stop()

    def test_list_quarantine_records_skips_spilled_dml_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = UndoLedger(os.path.join(tmp, "l.db"), spill_dir=os.path.join(tmp, "spill"), compress_threshold_bytes=100, spill_threshold_bytes=50)
            try:
                ledger.record_transaction(
                    tx_id="tx_big_dml",
                    engine=EngineType.POSTGRES,
                    session_id="s1",
                    raw_sql="UPDATE t SET x=1",
                    status=ReversibilityStatus.EXACT,
                    ops=[MutationOp(op_type="UPDATE", table="t", schema="public", pk_columns=["id"], column_types={"id": "int"}, before_rows=[{"id": i, "x": "abcdef" * 20} for i in range(200)], after_rows=[{"id": i, "x": "1"} for i in range(200)])],
                )
                ledger.record_transaction(
                    tx_id="tx_q1",
                    engine=EngineType.POSTGRES,
                    session_id="s1",
                    raw_sql="DROP TABLE t",
                    status=ReversibilityStatus.QUARANTINE,
                    ops=[MutationOp(op_type="QUARANTINE_DROP", table="t", schema="public", pk_columns=["id"], column_types={}, quarantine_name="t__tx_q1")],
                )
                q_recs = ledger.list_quarantine_records()
                self.assertEqual([r.tx_id for r in q_recs], ["tx_q1"])
            finally:
                ledger.close()

    def test_mysql_binary_prepared_statements_and_reverse(self) -> None:
        drv = SQLiteDriver(":memory:")
        ledger = UndoLedger(":memory:")
        eng = ReverseProxyEngine(drv, ledger)
        srv = _DualProtocolServer(eng)
        srv.start()
        my = MySQLWireClient(host="127.0.0.1", port=srv.mysql.bound_port, user="app")
        try:
            my.query("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);")
            assert my._sock is not None

            # 1. COM_STMT_PREPARE INSERT INTO items VALUES (?, ?)
            prep_sql = b"INSERT INTO items (id, name) VALUES (?, ?)"
            my._sock.sendall(frame_mysql_packet(bytes([COM_STMT_PREPARE]) + prep_sql, seq_id=0))
            ok_pkt = read_mysql_packet_sync(my._sock).payload
            self.assertEqual(ok_pkt[0], 0x00)
            stmt_id, num_cols, num_params = struct.unpack_from("<IHH", ok_pkt, 1)
            self.assertEqual((num_cols, num_params), (0, 2))
            # Drain 2 param defs + EOF
            for _ in range(3):
                read_mysql_packet_sync(my._sock)

            # 2. COM_STMT_EXECUTE (id=42, name='prepared-item')
            exec_body = (
                bytes([COM_STMT_EXECUTE])
                + struct.pack("<IBI", stmt_id, 0, 1)
                + bytes([0x00, 0x01])  # null bitmap=0, new_params_bind_flag=1
                + bytes([FIELD_TYPE_LONG, 0x00, FIELD_TYPE_VAR_STRING, 0x00])
                + struct.pack("<i", 42)
                + encode_lenenc_str(b"prepared-item")
            )
            my._sock.sendall(frame_mysql_packet(exec_body, seq_id=0))
            res_pkt = read_mysql_packet_sync(my._sock).payload
            self.assertEqual(res_pkt[0], 0x00)  # OK_Packet
            self.assertEqual(my.query("SELECT id, name FROM items WHERE id = 42;").rows, [(42, "prepared-item")])

            # 3. COM_STMT_PREPARE + EXECUTE SELECT binary resultset
            sel_sql = b"SELECT id, name FROM items WHERE id = ?"
            my._sock.sendall(frame_mysql_packet(bytes([COM_STMT_PREPARE]) + sel_sql, seq_id=0))
            ok2 = read_mysql_packet_sync(my._sock).payload
            sel_id, _, sel_np = struct.unpack_from("<IHH", ok2, 1)
            self.assertEqual(sel_np, 1)
            for _ in range(2):  # 1 param def + EOF
                read_mysql_packet_sync(my._sock)

            my._sock.sendall(
                frame_mysql_packet(
                    bytes([COM_STMT_EXECUTE])
                    + struct.pack("<IBI", sel_id, 0, 1)
                    + bytes([0x00, 0x01, FIELD_TYPE_LONG, 0x00])
                    + struct.pack("<i", 42),
                    seq_id=0,
                )
            )
            cnt_pkt = read_mysql_packet_sync(my._sock).payload
            col_cnt, _ = decode_lenenc_int(cnt_pkt, 0)
            self.assertEqual(col_cnt, 2)
            for _ in range(col_cnt):
                read_mysql_packet_sync(my._sock)  # ColumnDefinitions
            row_pkt = read_mysql_packet_sync(my._sock).payload
            self.assertEqual(row_pkt[0], 0x00)  # binary row header
            end_pkt = read_mysql_packet_sync(my._sock).payload
            self.assertEqual(end_pkt[0], 0xFE)

            # 4. COM_STMT_RESET & COM_STMT_CLOSE
            my._sock.sendall(frame_mysql_packet(bytes([COM_STMT_RESET]) + struct.pack("<I", stmt_id), seq_id=0))
            self.assertEqual(read_mysql_packet_sync(my._sock).payload[0], 0x00)
            my._sock.sendall(frame_mysql_packet(bytes([COM_STMT_CLOSE]) + struct.pack("<I", stmt_id), seq_id=0))

            # 5. PROXY REVERSE LAST undoes the prepared statement INSERT!
            my.query("PROXY REVERSE LAST;")
            self.assertEqual(my.query("SELECT COUNT(*) FROM items;").rows, [(0,)])
        finally:
            my.close()
            srv.stop()
            drv.close()
            ledger.close()


if __name__ == "__main__":
    unittest.main()
