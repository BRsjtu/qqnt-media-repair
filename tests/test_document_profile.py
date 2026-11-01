"""Synthetic byte-level checks for the opt-in FILE subtype-7 profile."""
import hashlib
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/qqnt-media-repair/scripts"
sys.path.insert(0, str(SCRIPTS))
import document_profile as profile
sys.path.remove(str(SCRIPTS))


def varint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    return bytes(out + bytes([value]))


def integer(number, value):
    return varint(number << 3) + varint(value)


def string(number, value):
    value = value.encode("utf-8") if isinstance(value, str) else value
    return varint((number << 3) | 2) + varint(len(value)) + value


def segment(content=b"original", *, filename="fixture.pdf", subtype=7,
            canonical=None, uri="::NTOSFull::C:\\old\\fixture.pdf", flags=True,
            extension=True, extra=b""):
    data = (integer(45002, 3) + integer(45003, subtype) + string(45402, filename)
            + string(45403, uri) + integer(45405, len(content))
            + string(45407, hashlib.md5(content).hexdigest()))
    if canonical is not None:
        data += string(45406, canonical)
    if extension:
        data += string(45419, Path(filename).suffix)
    if flags:
        data += integer(45507, (1 << 64) - 7003) + integer(45509, 1)
        data += string(45554, "传输失败，请稍后重试")
    return data + extra


class DocumentProfileTests(unittest.TestCase):
    content = b"original"
    digest = hashlib.md5(content).hexdigest()

    def inspect(self, **kwargs):
        return profile.inspect_body(string(40800, segment(self.content, **kwargs)))['records'][0]

    def test_accepts_known_subtype7_and_preserves_ntos_wrapper_and_opaque_fields(self):
        old = string(40800, segment(self.content, extra=string(45503, b"opaque")))
        new, changes = profile.normalize_body(old, {0: {
            "source_path": r"D:\Verified\fixture.pdf", "md5": self.digest,
            "size": len(self.content)}})
        record = profile.inspect_body(new)['records'][0]
        self.assertEqual(changes['changed_segments'], [0])
        self.assertEqual(record['local_path'], r"D:\Verified\fixture.pdf")
        self.assertTrue(record['path_prefix'])
        self.assertEqual(record['md5'], self.digest)
        self.assertFalse(record['known_failure'])
        self.assertIn(string(45503, b"opaque"), new)

    def test_missing_canonical_and_extension_are_repaired(self):
        old = string(40800, segment(self.content, flags=False, extension=False,
                                    uri=r"C:\old\fixture.pdf"))
        new, _ = profile.normalize_body(old, {0: {
            "source_path": r"D:\Verified\fixture.pdf", "md5": self.digest,
            "size": len(self.content)}})
        row = profile.inspect_body(new)['records'][0]
        self.assertEqual(row['canonical_encoding'], 'raw16')
        self.assertEqual(row['local_path'], r"D:\Verified\fixture.pdf")
        self.assertEqual(row['extension'], '.pdf')

    def test_generic_file_extension_and_exact_failure_are_supported(self):
        row = self.inspect(filename="fixture.docx")
        self.assertTrue(row['repair_eligible'])
        self.assertEqual(row['extension'], '.docx')

    def test_normalized_no_flags_is_not_eligible(self):
        row = self.inspect(canonical=bytes.fromhex(self.digest), flags=False)
        self.assertTrue(row['supported_profile'])
        self.assertFalse(row['repair_eligible'])

    def test_rejects_wrong_hash_unknown_flags_and_partial_known_signature(self):
        self.assertFalse(self.inspect(canonical="0" * 32)['supported_profile'])
        wrong = string(40800, segment(self.content, flags=False) + integer(45509, 8))
        self.assertFalse(profile.inspect_body(wrong)['records'][0]['supported_profile'])
        partial = string(40800, segment(self.content, flags=False) + integer(45509, 1))
        self.assertFalse(profile.inspect_body(partial)['records'][0]['supported_profile'])

    def test_wrong_source_identity_and_noncanonical_other_hash_rejected(self):
        blob = string(40800, segment(self.content))
        with self.assertRaises(profile.ProfileError):
            profile.normalize_body(blob, {0: {"source_path": r"D:\x.pdf", "md5": "0" * 32,
                                               "size": len(self.content)}})
        mismatched = string(40800, segment(self.content, canonical=bytes.fromhex("0" * 32)))
        self.assertFalse(profile.inspect_body(mismatched)['records'][0]['supported_profile'])

    def test_rejects_unknown_uri_namespace_and_wrong_type(self):
        self.assertFalse(self.inspect(uri="::Remote::C:\\x.pdf")['supported_profile'])
        self.assertFalse(self.inspect(subtype=1)['supported_profile'])

    def test_rejects_invalid_utf8_extension_and_windows_invalid_filename_tail(self):
        bad_extension = string(40800, segment(self.content, flags=False, extension=False)
                               + string(45419, b"\xff.pdf"))
        self.assertFalse(profile.inspect_body(bad_extension)['records'][0]['supported_profile'])
        trailing_space = self.inspect(filename="fixture.pdf ")
        trailing_dot = self.inspect(filename="fixture.pdf.")
        self.assertFalse(trailing_space['supported_profile'])
        self.assertFalse(trailing_dot['supported_profile'])


if __name__ == "__main__":
    unittest.main()
