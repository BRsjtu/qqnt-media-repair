"""End-to-end encrypted CLI workflow using disposable, invented account data."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/qqnt-media-repair/scripts"
sys.path.insert(0, str(SCRIPTS))
import database_backend as backend
import qqnt_repair as cli
sys.path.remove(str(SCRIPTS))


def varint(value):
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    return bytes(output + bytes([value]))


def integer(number, value):
    return varint(number << 3) + varint(value)


def string(number, value):
    value = value.encode("utf-8") if isinstance(value, str) else value
    return varint((number << 3) | 2) + varint(len(value)) + value


def file_segment(content, subtype=1):
    return (integer(45001, 101) + integer(45002, 3) + integer(45003, subtype)
            + string(45402, "fixture.dat") + string(45403, r"C:\Example\old.dat")
            + integer(45405, len(content)) + string(45407, hashlib.md5(content).hexdigest())
            + string(45503, "opaque-fixture") + integer(45507, (1 << 64) - 7003)
            + integer(45509, 1) + string(45554, "传输失败，请稍后重试"))


HAS_CIPHER = os.name == "nt" and importlib.util.find_spec("sqlcipher3") is not None


@unittest.skipUnless(HAS_CIPHER, "requires reviewed Windows SQLCipher wheel")
class CliWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-ntqq-cli-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.account = self.root / "accounts" / "fixture-account"
        self.db = self.account / "nt_qq" / "nt_db" / "nt_msg.db"
        self.db.parent.mkdir(parents=True)
        self.media = self.account / "FileRecv"
        self.media.mkdir()
        self.content = b"fixture original content"
        (self.media / "fixture.dat").write_bytes(self.content)
        self.key = self.root / "fixture.key"
        self.key.write_text("fixture-key-1234", encoding="ascii")
        self.run = self.root / "private-run"
        self.read_work = self.root / "read-only-verification"
        text = string(40800, integer(45002, 1) + string(45101, "untouched caption"))
        good = string(40800, file_segment(self.content))
        unsupported = string(40800, file_segment(self.content, subtype=2))
        missing = string(40800, file_segment(b"missing original content"))
        self.original = {
            "c2c_msg_table": [(1, text + good + unsupported, 11, "keep-a"),
                              (2, good, 12, "keep-b"), (3, missing, 13, "keep-missing"),
                              (4, unsupported, 14, "keep-unsupported")],
            "group_msg_table": [(10, good + text, 20, "keep-group")],
        }
        builder = self.root / "builder.db"
        with backend.sqlcipher_runtime() as sql:
            conn = sql.connect(str(builder), isolation_level=None)
            try:
                backend.configure(conn, backend.load_key(self.key))
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA wal_autocheckpoint=0")
                for table, rows in self.original.items():
                    conn.execute(f'CREATE TABLE "{table}" ("40001" INTEGER PRIMARY KEY, "40800" BLOB, "40050" INTEGER, metadata TEXT)')
                    conn.executemany(f'INSERT INTO "{table}" VALUES (?,?,?,?)', rows)
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                # Leave one unplanned message in the source WAL as well.
                row = (11, text, 21, "keep-wal-only")
                conn.execute('INSERT INTO group_msg_table VALUES (?,?,?,?)', row)
                self.original["group_msg_table"].append(row)
                self.db.write_bytes(b"invented-prefix".ljust(1024, b"\0") + builder.read_bytes())
                Path(str(self.db) + "-wal").write_bytes(Path(str(builder) + "-wal").read_bytes())
            finally:
                conn.close()
        self.main_before = self.db.read_bytes()

    def args(self, **values):
        args = dict(account=self.account, db=self.db, run=self.run, key_file=self.key,
                    qq_build="synthetic-build", extra_root=[], existing_index=None, sample=None)
        args.update(values)
        return SimpleNamespace(**args)

    def invoke(self, function, **values):
        output = StringIO()
        with redirect_stdout(output):
            function(self.args(**values))
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def rows(self):
        with backend.staged_database(self.db, self.key, self.read_work) as stage:
            return {table: stage.connection.execute(f'SELECT * FROM "{table}" ORDER BY "40001"').fetchall()
                    for table in self.original}

    def test_scan_sample_confirmation_bulk_rollback_and_idempotence(self):
        wal_before = Path(str(self.db) + "-wal").read_bytes()
        summary = self.invoke(cli.scan)[-1]
        self.assertEqual(summary["counts"]["planned_rows"], 3)
        self.assertEqual(summary["counts"]["unsupported_file_profile"], 2)
        self.assertEqual(summary["counts"]["original_not_matched_in_authorized_roots"], 1)
        self.assertEqual(self.rows(), self.original)
        self.assertEqual(Path(str(self.db) + "-wal").read_bytes(), wal_before)
        with backend.encrypted_archive(self.run / "plan.sqlite", self.key, readonly=True) as plan:
            self.assertEqual(plan.execute("SELECT table_name,count(*) FROM repairs GROUP BY table_name ORDER BY table_name").fetchall(),
                             [("c2c_msg_table", 2), ("group_msg_table", 1)])
        with self.assertRaisesRegex(ValueError, "sample validation"):
            self.invoke(cli.apply)
        sample = self.invoke(cli.apply, sample=1)[-1]
        self.assertEqual(sample["counts"]["updated_rows"], 1)
        sample_rows = self.rows()
        self.assertNotEqual(sample_rows["c2c_msg_table"][0][1], self.original["c2c_msg_table"][0][1])
        self.assertEqual(sample_rows["c2c_msg_table"][1:], self.original["c2c_msg_table"][1:])
        self.invoke(cli.confirm_ui, sample_count=1, evidence="Synthetic operator attestation only", existing_cases=False)
        bulk = self.invoke(cli.apply)[-1]
        self.assertEqual(bulk["counts"]["updated_rows"], 2)
        self.assertEqual(bulk["counts"]["already_in_desired_state"], 1)
        applied = self.rows()
        for table, rows in applied.items():
            for old, new in zip(self.original[table], rows):
                self.assertEqual((old[0], *old[2:]), (new[0], *new[2:]))
        self.assertEqual(applied["c2c_msg_table"][2:], self.original["c2c_msg_table"][2:])
        repeat = self.invoke(cli.apply)[-1]
        self.assertFalse(repeat["database_result"]["published"])
        self.assertEqual(repeat["counts"]["already_in_desired_state"], 3)
        self.assertEqual(self.rows(), applied)
        output = StringIO()
        with redirect_stdout(output):
            cli.apply(self.args(), rollback=True)
        self.assertEqual(json.loads(output.getvalue().splitlines()[-1])["counts"]["updated_rows"], 3)
        self.assertEqual(self.rows(), self.original)
        with redirect_stdout(StringIO()):
            cli.apply(self.args(), rollback=True)
        self.assertEqual(self.rows(), self.original)
        self.assertEqual(self.db.read_bytes(), self.main_before)
        self.assertNotIn(b"untouched caption", (self.run / "plan.sqlite").read_bytes())

    def test_changed_rows_are_preserved_during_bulk_and_rollback(self):
        self.invoke(cli.scan)
        self.invoke(cli.apply, sample=1)
        self.invoke(cli.confirm_ui, sample_count=1, evidence="Synthetic operator attestation only", existing_cases=False)
        changed = self.original["c2c_msg_table"][1][1] + string(40800, integer(45002, 1))
        with backend.staged_database(self.db, self.key, self.read_work) as stage:
            stage.publish([{"table": "c2c_msg_table", "msg_id": 2,
                            "old_body": self.original["c2c_msg_table"][1][1], "new_body": changed}])
        summary = self.invoke(cli.apply)[-1]
        self.assertEqual(summary["counts"]["changed_since_plan"], 1)
        self.assertEqual(summary["counts"]["updated_rows"], 1)
        with redirect_stdout(StringIO()):
            cli.apply(self.args(), rollback=True)
        expected = {table: list(rows) for table, rows in self.original.items()}
        old = expected["c2c_msg_table"][1]
        expected["c2c_msg_table"][1] = (old[0], changed, *old[2:])
        self.assertEqual(self.rows(), expected)
        self.assertEqual(self.db.read_bytes(), self.main_before)

    def test_changed_source_aborts_before_publication(self):
        self.invoke(cli.scan)
        wal_before = Path(str(self.db) + "-wal").read_bytes()
        (self.media / "fixture.dat").write_bytes(b"x" * len(self.content))
        with self.assertRaises(ValueError):
            self.invoke(cli.apply, sample=1)
        self.assertEqual(self.rows(), self.original)
        self.assertEqual(Path(str(self.db) + "-wal").read_bytes(), wal_before)
        self.assertEqual(self.db.read_bytes(), self.main_before)


if __name__ == "__main__":
    unittest.main()
