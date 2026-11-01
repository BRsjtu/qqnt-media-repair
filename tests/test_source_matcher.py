"""Synthetic source trees only; never open real account files."""
import hashlib
from contextlib import closing
import importlib.util
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "skills/qqnt-media-repair/scripts/source_matcher.py"
SPEC = importlib.util.spec_from_file_location("source_matcher", MODULE)
matcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matcher)


class SourceMatcherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.account = self.base / "accounts" / "example-account"
        self.media = self.account / "FileRecv"
        self.media.mkdir(parents=True)
        self.work = self.base / "private-work"

    def record(self, data=b"correct", **kwargs):
        return dict(filename="message.bin", size=len(data), legacy_md5=hashlib.md5(data).hexdigest(),
                    md5=None, local_path=None, **kwargs)

    def source(self, path, data=b"correct"):
        return dict(path=str(path), size=len(data), md5=hashlib.md5(data).hexdigest(),
                    sha256=hashlib.sha256(data).hexdigest())

    def index(self, entries):
        path = self.base / "old-index.sqlite3"
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE files (rel_path TEXT, media_root TEXT, basename TEXT, "
                       "size INTEGER, mtime_ns INTEGER, md5_from_name TEXT)")
            db.executemany("INSERT INTO files VALUES (?,?,?,?,?,?)", entries)
            db.commit()
        return path

    def test_filename_hint_cannot_substitute_for_content(self):
        digest = hashlib.md5(b"correct").hexdigest()
        (self.media / (digest + ".bin")).write_bytes(b"WRONG!!")
        (self.media / "message.bin").write_bytes(b"WRONG!!")
        with matcher.SourceMatcher(self.account, self.work) as source:
            self.assertIsNone(source.match(self.record()))
            self.assertEqual(source.stats["hashes"], 2)

    def test_public_verifier_rehashes_and_refuses_changed_source(self):
        file = self.media / "message.bin"
        file.write_bytes(b"correct")
        with matcher.SourceMatcher(self.account, self.work) as source:
            planned = source.match(self.record())
        with mock.patch.object(matcher.hashlib, "md5", wraps=hashlib.md5) as hasher:
            self.assertEqual(matcher.verify_source(planned, [self.account]), planned)
            self.assertEqual(hasher.call_count, 1)
        file.write_bytes(b"WRONG!!")
        with self.assertRaises(ValueError):
            matcher.verify_source(planned, [self.account])

    def test_same_size_fallback_returns_actual_hashes_even_thumbnail_name(self):
        expected = self.media / "thumb_unrelated-name.bin"
        expected.write_bytes(b"correct")
        (self.media / "message.bin").write_bytes(b"WRONG!!")
        with matcher.SourceMatcher(self.account, self.work) as source:
            result = source.match(self.record())
            self.assertEqual(Path(result["path"]), expected)
            self.assertEqual(result["sha256"], hashlib.sha256(b"correct").hexdigest())
            self.assertEqual(result["md5"], hashlib.md5(b"correct").hexdigest())

    def test_cache_revalidates_changed_file_even_same_size_and_mtime(self):
        file = self.media / "message.bin"
        file.write_bytes(b"correct")
        with matcher.SourceMatcher(self.account, self.work) as source:
            self.assertIsNotNone(source.match(self.record()))
            self.assertIsNotNone(source.match(self.record()))
            self.assertEqual(source.stats["hash_cache_hits"], 1)
            old = file.stat()
            file.write_bytes(b"WRONG!!")
            os.utime(file, ns=(old.st_atime_ns, old.st_mtime_ns))
            self.assertIsNone(source.match(self.record()))
            self.assertEqual(source.stats["hashes"], 2)

    def test_existing_index_is_reused_without_scanning_and_other_account_rejected(self):
        good = self.media / "renamed.bin"
        good.write_bytes(b"correct")
        other = self.account.parent / "other-account" / "FileRecv"
        other.mkdir(parents=True)
        (other / "message.bin").write_bytes(b"correct")
        index = self.index([
            ("other-account/FileRecv/message.bin", str(other), "message.bin", 7, 0, None),
            ("example-account/FileRecv/renamed.bin", "ignored", "renamed.bin", 7, 0, None),
        ])
        with mock.patch.object(matcher.os, "walk", side_effect=AssertionError("must not scan")):
            with matcher.SourceMatcher(self.account, self.work, existing_index=index) as source:
                result = source.match(self.record())
                self.assertEqual(Path(result["path"]), good)
                self.assertEqual(source.stats["index_reused"], 1)
                self.assertGreaterEqual(source.stats["rejected"], 1)

    def test_existing_size_is_only_hint(self):
        file = self.media / "message.bin"
        file.write_bytes(b"too small")
        index = self.index([("example-account/FileRecv/message.bin", "ignored", "message.bin", 7, 0, None)])
        with matcher.SourceMatcher(self.account, self.work, existing_index=index) as source:
            self.assertIsNone(source.match(self.record()))
            self.assertEqual(source.stats["hashes"], 0)

    def test_direct_path_cannot_escape_or_read_excluded_database_tree(self):
        outside = self.base / "outside.bin"
        outside.write_bytes(b"correct")
        excluded = self.account / "nt_db"
        excluded.mkdir()
        (excluded / "message.bin").write_bytes(b"correct")
        with matcher.SourceMatcher(self.account, self.work) as source:
            for path in (outside, excluded / "message.bin", self.media / ".." / "nt_db" / "message.bin",
                         r"\\server\share\message.bin", str(self.media / "message.bin") + ":stream"):
                record = self.record()
                record["local_path"] = str(path)
                self.assertIsNone(source.match(record))
            self.assertEqual(source.stats["hashes"], 0)

    def test_symlink_file_and_ancestor_are_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "message.bin").write_bytes(b"correct")
        try:
            (self.media / "file-link.bin").symlink_to(outside / "message.bin")
            (self.media / "dir-link").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with matcher.SourceMatcher(self.account, self.work) as source:
            for file in (self.media / "file-link.bin", self.media / "dir-link" / "message.bin"):
                record = self.record()
                record["local_path"] = str(file)
                self.assertIsNone(source.match(record))

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_windows_junction_ancestor_is_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "message.bin").write_bytes(b"correct")
        junction = self.media / "directory-junction"
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                                capture_output=True, timeout=10)
        if result.returncode:
            self.skipTest("junction creation unavailable")
        self.addCleanup(os.rmdir, junction)
        with matcher.SourceMatcher(self.account, self.work) as source:
            record = self.record()
            record["local_path"] = str(junction / "message.bin")
            self.assertIsNone(source.match(record))
            self.assertEqual(source.stats["hashes"], 0)
        with self.assertRaises(ValueError):
            matcher.verify_source(self.source(junction / "message.bin"), [self.account])

    def test_hardlink_sources_are_rejected(self):
        outside = self.base / "outside.bin"
        outside.write_bytes(b"correct")
        linked = self.media / "message.bin"
        try:
            os.link(outside, linked)
        except OSError:
            self.skipTest("hardlink creation unavailable")
        with matcher.SourceMatcher(self.account, self.work) as source:
            record = self.record()
            record["local_path"] = str(linked)
            self.assertIsNone(source.match(record))
            self.assertEqual(source.stats["hashes"], 0)
        with self.assertRaises(ValueError):
            matcher.verify_source(self.source(linked), [self.account])

    def test_file_changed_during_hashing_is_rejected(self):
        file = self.media / "message.bin"
        file.write_bytes(b"correct")
        original = hashlib.md5
        class MutatingDigest:
            def __init__(self):
                self.digest = original()
            def update(self, data):
                self.digest.update(data)
                file.write_bytes(b"WRONG!!")
            def hexdigest(self):
                return self.digest.hexdigest()
        record = self.record()
        with matcher.SourceMatcher(self.account, self.work) as source:
            with mock.patch.object(matcher.hashlib, "md5", MutatingDigest):
                self.assertIsNone(source.match(record))
            self.assertEqual(source.stats["hashes"], 0)

    def test_explicit_downloads_mapping_only(self):
        downloads = self.base / "Downloads"
        downloads.mkdir()
        file = downloads / "message.bin"
        file.write_bytes(b"correct")
        index = self.index([("__C_Downloads__/message.bin", "ignored", "message.bin", 7, 0, None)])
        with matcher.SourceMatcher(self.account, self.work, existing_index=index) as source:
            self.assertIsNone(source.match(self.record()))
        with matcher.SourceMatcher(self.account, self.work, extra_roots=[downloads], existing_index=index) as source:
            self.assertEqual(Path(source.match(self.record())["path"]), file)

    def test_conflicting_or_missing_record_hashes_never_match(self):
        (self.media / "message.bin").write_bytes(b"correct")
        with matcher.SourceMatcher(self.account, self.work) as source:
            record = self.record()
            record["md5"] = "f" * 32
            self.assertIsNone(source.match(record))
            record["legacy_md5"] = record["md5"] = None
            self.assertIsNone(source.match(record))
            self.assertEqual(source.stats["hashes"], 0)


if __name__ == "__main__":
    unittest.main()
