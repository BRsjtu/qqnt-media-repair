"""Synthetic WAL, source-lock and encrypted publication tests only."""
import importlib.util
from io import BytesIO
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "skills/qqnt-media-repair/scripts/database_backend.py"
SPEC = importlib.util.spec_from_file_location("database_backend", MODULE)
backend = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = backend
SPEC.loader.exec_module(backend)


def synthetic_wal(endian="<", commits=(2, 0, 3)):
    magic = 0x377f0682 if endian == "<" else 0x377f0683
    header = struct.pack(">6I", magic, 3007000, 4096, 0, 19, 27)
    state = backend.checksum(header, endian=endian)
    result = header + struct.pack(">2I", *state)
    for index, commit in enumerate(commits):
        page = bytes([index + 1]) * 4096
        first = struct.pack(">2I", index + 1, commit)
        state = backend.checksum(first + page, state, endian)
        result += first + struct.pack(">4I", 19, 27, *state) + page
    return result


class WalTests(unittest.TestCase):
    def test_both_checksum_orders(self):
        for endian in ("<", ">"):
            data = synthetic_wal(endian)
            result = backend.validate_wal(data)
            self.assertEqual(result["frames"], 3)
            self.assertEqual(result["last_commit_pages"], 3)
            self.assertEqual(result["unused_tail_bytes"], 0)

    def test_partial_tail_and_uncommitted_frames_trimmed(self):
        data = synthetic_wal(commits=(2, 0)) + b"partial"
        result = backend.validate_wal(data)
        self.assertEqual(result["frames"], 1)
        self.assertEqual(result["valid_frames"], 2)
        self.assertEqual(result["unused_tail_bytes"], 4120 + 7)
        self.assertEqual(backend.committed_wal(data)[0], data[:32 + 4120])

    def test_reused_stale_salt_tail_is_not_replayed(self):
        data = bytearray(synthetic_wal())
        data[32 + 2 * 4120 + 8] ^= 1
        result = backend.validate_wal(bytes(data))
        self.assertEqual(result["frames"], 1)
        self.assertEqual(result["valid_frames"], 2)

    def test_bad_checksum_tail_keeps_last_good_commit(self):
        data = bytearray(synthetic_wal())
        data[-1] ^= 1
        self.assertEqual(backend.validate_wal(bytes(data))["frames"], 1)

    def test_corrupt_header_and_no_commit_fail_closed(self):
        data = bytearray(synthetic_wal())
        data[16] ^= 1
        with self.assertRaisesRegex(backend.BackendError, "wal_header_checksum_failed"):
            backend.validate_wal(bytes(data))
        with self.assertRaisesRegex(backend.BackendError, "no_valid_committed"):
            backend.validate_wal(synthetic_wal(commits=(0, 0)))

    def test_prefix_copy_and_alignment(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "stage.db"
            self.assertEqual(backend.copy_snapshot(BytesIO(b"p" * 1024 + b"d" * 4096), path), b"p" * 1024)
            self.assertEqual(path.read_bytes(), b"d" * 4096)
            with self.assertRaisesRegex(backend.BackendError, "page_alignment"):
                backend.copy_snapshot(BytesIO(b"p" * 1024 + b"bad"), Path(temp) / "bad.db")


HAS_CIPHER = os.name == "nt" and importlib.util.find_spec("sqlcipher3") is not None


@unittest.skipUnless(HAS_CIPHER, "requires reviewed Windows SQLCipher wheel")
class CipherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-ntqq-backend-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.work = self.root / "work"
        self.key = self.root / "synthetic.key"
        self.key.write_text("fixture-key-1234", encoding="ascii")
        # Sixteen characters, intentionally unrelated to any real account.
        self.db = self.source / "synthetic.db"
        self.make_source()

    def make_source(self):
        with backend.sqlcipher_runtime() as sql:
            source = sql.connect(str(self.root / "builder.db"), isolation_level=None)
            try:
                backend.configure(source, backend.load_key(self.key))
                source.execute("PRAGMA journal_mode=WAL")
                source.execute("PRAGMA wal_autocheckpoint=0")
                source.execute('CREATE TABLE c2c_msg_table ("40001" INTEGER PRIMARY KEY,"40800" BLOB,"40050" INTEGER, metadata TEXT)')
                source.execute('CREATE TABLE group_msg_table ("40001" INTEGER PRIMARY KEY,"40800" BLOB, metadata TEXT)')
                source.execute('INSERT INTO c2c_msg_table VALUES (1,?,?,?)', (b"before-one", 123, "unchanged-one"))
                source.execute('INSERT INTO group_msg_table VALUES (3,?,?)', (b"before-group", "unchanged-group"))
                source.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                source.execute('INSERT INTO c2c_msg_table VALUES (2,?,?,?)', (b"before-two", 456, "unchanged-two"))
                self.db.write_bytes(b"synthetic-prefix".ljust(1024, b"\0") + (self.root / "builder.db").read_bytes())
                # Deliberately include stale invalid tail and a partial frame.
                wal = (self.root / "builder.db-wal").read_bytes()
                self.wal = wal + b"\xff" * 4120 + b"partial-tail"
                Path(str(self.db) + "-wal").write_bytes(self.wal)
                Path(str(self.db) + "-shm").write_bytes(b"synthetic-stale-shm")
                self.main = self.db.read_bytes()
            finally:
                source.close()

    def update(self, old=b"before-one", new=b"after-one"):
        return {"table": "c2c_msg_table", "msg_id": 1, "old_body": old, "new_body": new}

    def test_insufficient_space_refuses_before_copy(self):
        from unittest import mock
        with mock.patch.object(backend.shutil, "disk_usage") as usage:
            usage.return_value.free = 0
            with self.assertRaisesRegex(backend.BackendError, "insufficient_working_drive_space"):
                with backend.staged_database(self.db, self.key, self.work):
                    self.fail("insufficient disk space must refuse the snapshot")
        self.assertEqual(self.db.read_bytes(), self.main)
        self.assertFalse(list(self.work.glob("ntqq-stage-*")))

    def test_scan_lock_readonly_and_cleanup(self):
        with backend.staged_database(self.db, self.key, self.work) as stage:
            stage_path = stage.path
            self.assertEqual(stage.connection.execute('SELECT count(*) FROM c2c_msg_table').fetchone()[0], 2)
            with self.assertRaises(Exception):
                stage.connection.execute('UPDATE c2c_msg_table SET "40800"=x\'00\'')
            with self.assertRaises(PermissionError):
                self.db.read_bytes()
        self.assertFalse(stage_path.exists())
        self.assertEqual(self.db.read_bytes(), self.main)
        self.assertEqual(Path(str(self.db) + "-wal").read_bytes(), self.wal)

    def test_publish_and_inverse_preserve_main_and_metadata(self):
        with backend.staged_database(self.db, self.key, self.work) as stage:
            result = stage.publish([self.update(), {"table": "group_msg_table", "msg_id": 3,
                                   "old_body": b"before-group", "new_body": b"after-group"}])
            self.assertTrue(result["published"])
            self.assertEqual(result["updated_rows"], 2)
            self.assertTrue(Path(result["shm_backup"]).is_file())
        self.assertEqual(self.db.read_bytes(), self.main)
        self.assertFalse(Path(str(self.db) + "-shm").exists())
        with backend.staged_database(self.db, self.key, self.work) as stage:
            row = stage.connection.execute('SELECT * FROM c2c_msg_table WHERE "40001"=1').fetchone()
            self.assertEqual(row, (1, b"after-one", 123, "unchanged-one"))
            self.assertEqual(stage.connection.execute('SELECT "40800" FROM group_msg_table').fetchone()[0], b"after-group")
            stage.publish([self.update(b"after-one", b"before-one")])
        self.assertEqual(self.db.read_bytes(), self.main)
        with backend.staged_database(self.db, self.key, self.work) as stage:
            self.assertEqual(stage.connection.execute('SELECT "40800" FROM c2c_msg_table WHERE "40001"=1').fetchone()[0], b"before-one")

    def test_stale_original_refused_and_source_untouched(self):
        with backend.staged_database(self.db, self.key, self.work) as stage:
            with self.assertRaisesRegex(backend.BackendError, "message_original_changed"):
                stage.publish([self.update(b"wrong-original")])
        self.assertEqual(self.db.read_bytes(), self.main)
        self.assertEqual(Path(str(self.db) + "-wal").read_bytes(), self.wal)

    def test_source_without_wal_can_publish(self):
        # The initial snapshot must already have committed pages in its main
        # file. Build that case by checkpointing only a disposable fixture.
        with backend.sqlcipher_runtime() as sql:
            fixture = self.root / "checkpoint.db"
            fixture.write_bytes(self.main[1024:])
            Path(str(fixture) + "-wal").write_bytes(backend.committed_wal(self.wal)[0])
            conn = backend._connect(sql, fixture, backend.load_key(self.key))
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()
            self.db.write_bytes(self.main[:1024] + fixture.read_bytes())
        Path(str(self.db) + "-wal").unlink()
        Path(str(self.db) + "-shm").unlink()
        main_before = self.db.read_bytes()
        with backend.staged_database(self.db, self.key, self.work) as stage:
            stage.publish([self.update()])
        self.assertEqual(self.db.read_bytes(), main_before)
        with backend.staged_database(self.db, self.key, self.work) as stage:
            self.assertEqual(stage.connection.execute('SELECT "40800" FROM c2c_msg_table WHERE "40001"=1').fetchone()[0], b"after-one")

    def test_source_sidefile_changes_refuse_publication(self):
        with backend.staged_database(self.db, self.key, self.work) as stage:
            Path(str(self.db) + "-wal").write_bytes(self.wal + b"changed")
            with self.assertRaisesRegex(backend.BackendError, "source_wal_changed"):
                stage.publish([self.update()])
        self.assertEqual(self.db.read_bytes(), self.main)

    def test_archive_nested_and_pending_byte_restored(self):
        archive = self.root / "rows.db"
        with backend.staged_database(self.db, self.key, self.work):
            with backend.encrypted_archive(archive, self.key) as conn:
                conn.execute("CREATE TABLE records(old_body BLOB, new_body BLOB)")
                conn.execute("INSERT INTO records VALUES (?,?)", (b"before-one", b"after-one"))
            self.assertEqual(backend._runtime_state["cell"].value, backend.PENDING_NTQQ)
        self.assertIsNone(backend._runtime_state)
        self.assertNotIn(b"before-one", archive.read_bytes())
        with backend.encrypted_archive(archive, self.key, readonly=True) as conn:
            self.assertEqual(conn.execute("SELECT * FROM records").fetchone(), (b"before-one", b"after-one"))
        with mock.patch.object(backend.importlib.metadata, "version", return_value="0.0"):
            with self.assertRaisesRegex(backend.BackendError, "version_not_reviewed"):
                with backend.sqlcipher_runtime():
                    self.fail("unreviewed SQLCipher accepted")


if __name__ == "__main__":
    unittest.main()
