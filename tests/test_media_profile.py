"""Synthetic fixtures only: no account databases, media, or key files."""
import importlib.util
from pathlib import Path
import sys
import unittest

MODULE = Path(__file__).resolve().parents[1] / "skills/qqnt-media-repair/scripts/media_profile.py"
SPEC = importlib.util.spec_from_file_location("media_profile", MODULE)
profile = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = profile
SPEC.loader.exec_module(profile)


def varint(n):
    result = bytearray()
    while n > 127:
        result.append((n & 127) | 128)
        n >>= 7
    return bytes(result + bytes([n]))


def integer(n, value):
    return varint(n << 3) + varint(value)


def string(n, value):
    value = value.encode("utf-8") if isinstance(value, str) else value
    return varint((n << 3) | 2) + varint(len(value)) + value


DIGEST = "0123456789abcdef0123456789abcdef"
PATH = r"C:\Example\实际文件.png"


def segment(extra=b"", subtype=1, old=DIGEST):
    return (integer(45001, 1234567) + integer(45002, 3) + integer(45003, subtype)
            + string(45402, "图片.png") + string(45403, r"C:\Example\old.png")
            + integer(45405, 42) + string(45407, old)
            + integer(45411, 10) + integer(45411, 20)
            + integer(45412, 30) + integer(45412, 40)
            + string(45503, b"opaque-uuid") + integer(45507, (1 << 64) - 7003)
            + integer(45509, 1) + string(45554, profile.FAILURE_TEXT) + extra)


def replacement(**kwargs):
    return dict(source_path=PATH, md5=DIGEST, size=42, **kwargs)


class ProfileTests(unittest.TestCase):
    def test_multisegment_byte_preservation_and_idempotence(self):
        secret = string(45888, b"https://cdn.invalid/token=SECRET")
        unknown = string(45900, b"\x00\x01opaque")
        text = integer(45002, 1) + string(45101, "caption SECRET")
        untouched = segment(string(45999, "untouched"))
        target = segment(secret + unknown)
        prefix, suffix = integer(1, 2), string(2, b"outer-opaque")
        original = bytearray(prefix + string(40800, text) + string(40800, target)
                             + string(40800, untouched) + suffix)
        snapshot = bytes(original)
        info = profile.inspect_body(original)
        self.assertEqual(info["stats"]["segment_count"], 3)
        self.assertEqual(info["records"][1]["filename"], "图片.png")
        self.assertEqual(info["records"][1]["error_code"], -7003)
        self.assertTrue(info["records"][1]["failure_pattern_eligible"])
        self.assertNotIn("SECRET", repr(info))
        self.assertNotIn("cdn.invalid", repr(info))
        fixed, metadata = profile.normalize_body(original, {1: replacement()})
        expected = target.replace(string(45403, r"C:\Example\old.png"), string(45403, PATH))
        expected = expected.replace(integer(45507, (1 << 64) - 7003), b"")
        expected = expected.replace(integer(45509, 1), b"")
        expected = expected.replace(string(45554, profile.FAILURE_TEXT), b"")
        expected += string(45406, bytes.fromhex(DIGEST)) + string(45419, ".png")
        self.assertEqual(fixed, prefix + string(40800, text) + string(40800, expected)
                         + string(40800, untouched) + suffix)
        self.assertEqual(bytes(original), snapshot)
        self.assertEqual(metadata["changed_segments"], [1])
        self.assertEqual(profile.normalize_body(fixed, {1: replacement()})[0], fixed)
        self.assertEqual(profile.normalize_body(fixed, {1: replacement()})[1]["changes"], [])
        self.assertIn(integer(45001, 1234567), fixed)
        for raw in (secret, unknown, integer(45411, 10), integer(45411, 20),
                    integer(45412, 30), integer(45412, 40), string(45503, b"opaque-uuid")):
            self.assertIn(raw, fixed)

    def test_canonical_hash_conflict_and_equivalent_encodings(self):
        for canonical in (bytes.fromhex(DIGEST), DIGEST.upper()):
            blob = string(40800, segment(string(45406, canonical)))
            self.assertFalse(profile.inspect_body(blob)["records"][0]["md5_conflict"])
            profile.normalize_body(blob, {0: replacement()})
        blob = string(40800, segment(string(45406, b"\xff" * 16)))
        self.assertTrue(profile.inspect_body(blob)["records"][0]["md5_conflict"])
        with self.assertRaises(profile.ProfileError):
            profile.normalize_body(blob, {0: replacement()})

    def test_unknown_conflicting_duplicates_block_selected_segment(self):
        blob = string(40800, segment(string(45900, b"a") + string(45900, b"b")))
        self.assertTrue(profile.inspect_body(blob)["records"][0]["duplicate_conflict"])
        with self.assertRaises(profile.ProfileError):
            profile.normalize_body(blob, {0: replacement()})
        self.assertEqual(profile.normalize_body(blob, {})[0], blob)

    def test_no_remote_paths_or_nonfile_payloads_exported(self):
        url = "https://cdn.invalid/SECRET"
        remote = segment().replace(string(45403, r"C:\Example\old.png"), string(45403, url))
        bad_filename = segment().replace(string(45402, "图片.png"), string(45402, url))
        text = integer(45002, 1) + string(45402, "caption SECRET") + string(45403, url)
        blob = string(40800, remote) + string(40800, bad_filename) + string(40800, text)
        info = profile.inspect_body(blob)
        self.assertNotIn("SECRET", repr(info))
        self.assertIsNone(info["records"][0]["local_path"])
        self.assertIsNone(info["records"][1]["filename"])
        self.assertIsNone(info["records"][2]["filename"])

    def test_unsupported_profiles_and_semantic_source_checks(self):
        for content in (segment(subtype=2), segment(old=b"\x00" * 16),
                        segment().replace(integer(45002, 3), integer(45002, 2)),
                        segment().replace(integer(45509, 1), integer(45509, 2))):
            with self.subTest(content=content):
                with self.assertRaises(profile.ProfileError):
                    profile.normalize_body(string(40800, content), {0: replacement()})
        for key, value in (("md5", "f" * 32), ("size", 43), ("size", True)):
            selected = replacement()
            selected[key] = value
            with self.assertRaises(profile.ProfileError):
                profile.normalize_body(string(40800, segment()), {0: selected})

    def test_marker_or_known_error(self):
        for remove in (integer(45507, (1 << 64) - 7003), integer(45509, 1)):
            blob = string(40800, segment().replace(remove, b""))
            self.assertTrue(profile.inspect_body(blob)["records"][0]["failure_pattern_eligible"])
            profile.normalize_body(blob, {0: replacement()})

    def test_unknown_failure_codes_are_ineligible_even_with_marker(self):
        cases = [
            segment().replace(integer(45507, (1 << 64) - 7003), integer(45507, 999)),
            segment().replace(string(45554, profile.FAILURE_TEXT), string(45554, "unknown")),
            segment().replace(integer(45507, (1 << 64) - 7003), b"")
                     .replace(integer(45509, 1), b""),
        ]
        for content in cases:
            blob = string(40800, content)
            self.assertFalse(profile.inspect_body(blob)["records"][0]["failure_pattern_eligible"])
            with self.assertRaises(profile.ProfileError):
                profile.normalize_body(blob, {0: replacement()})

    def test_all_repeated_segments_and_atomic_rejection(self):
        original = bytearray(string(40800, segment()) + string(40800, segment(subtype=9)))
        snapshot = bytes(original)
        with self.assertRaises(profile.ProfileError):
            profile.normalize_body(original, {0: replacement(), 1: replacement()})
        self.assertEqual(bytes(original), snapshot)
        with self.assertRaises(profile.ProfileError):
            profile.normalize_body(snapshot, {2: replacement()})

    def test_extension_uses_message_filename(self):
        selected = replacement()
        selected["source_path"] = r"C:\Example\renamed.jpg"
        fixed, _ = profile.normalize_body(string(40800, segment()), {0: selected})
        self.assertIn(string(45419, ".png"), fixed)
        self.assertNotIn(string(45419, "png"), fixed)
        self.assertNotIn(string(45419, ".jpg"), fixed)

    def test_unsafe_paths(self):
        paths = [r"\\server\share\x.png", r"\\?\C:\x.png", "https://example.invalid/x",
                 r"relative\x.png", r"C:x.png", r"C:\Example\..\x.png",
                 r"C:\Example\x.png:stream", r"C:\Example\NUL.png", "C:\\Example\\x\x00.png",
                 "C:\\Example\\x.png.", "C:\\Example\\"]
        for path in paths:
            with self.subTest(path=path):
                selected = replacement()
                selected["source_path"] = path
                with self.assertRaises(profile.ProfileError):
                    profile.normalize_body(string(40800, segment()), {0: selected})

    def test_malformed_and_bounds(self):
        malformed = [b"\x00", b"\x80", b"\xff" * 10 + b"\x00", b"\x0a\xff" * 10,
                     b"\x0a\x02x", b"\x09abc", b"\x0dabc", b"\x0b", integer(40800, 1),
                     string(40800, b"\x80")]
        for blob in malformed:
            with self.subTest(blob=blob):
                with self.assertRaises(profile.ProfileError):
                    profile.inspect_body(blob)
        for blob in (b"x" * (profile.MAX_BLOB + 1),
                     integer(1, 0) * (profile.MAX_FIELDS + 1),
                     string(40800, integer(1, 0) * 10000) * 2,
                     string(40800, b"") * (profile.MAX_SEGMENTS + 1)):
            with self.assertRaises(profile.ProfileError):
                profile.inspect_body(blob)

    def test_noncanonical_unknown_wire_bytes_are_preserved(self):
        # Overlong but uint64-valid varint is deliberately retained byte-for-byte.
        raw = varint(45901 << 3) + b"\x81\x00"
        blob = string(40800, segment(raw))
        fixed, _ = profile.normalize_body(blob, {0: replacement()})
        self.assertIn(raw, fixed)


if __name__ == "__main__":
    unittest.main()
