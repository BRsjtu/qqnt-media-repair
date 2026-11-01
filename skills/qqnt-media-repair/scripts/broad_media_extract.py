"""Local metadata-only QQNT 40800 decoder; no database or filesystem access.

Schema sources (read 2026-11-01):
https://github.com/QQBackup/nt_msg_db_util/blob/master/msgdb/proto/c2c_40800.proto
https://github.com/QQBackup/nt_msg_db_util/blob/master/db_docs/c2c_msg_table/40800.md
Legacy 45407 ASCII32 and failure states also follow the locally observed profile:
media_profile.py (the separately named, locally validated legacy FILE profile)

Only known MsgBody.40800 and MsgContent.47710 boundaries are traversed.
Unknown length-delimited values are never guessed to be messages or paths.
45813 is not in the primary schema and is counted, not interpreted.
45408 may be a 20-byte thumbnail/checksum hash, NOT necessarily MD5.
45424 (image hash) and MediaRef.md5 are independent evidence, not authoritative
FILE-original hashes. No returned value proves media is missing or repairable.
"""
from __future__ import annotations

from collections import Counter
import ntpath
import re

MAX_BLOB = 16 * 1024 * 1024
MAX_FIELDS = 20_000
MAX_SEGMENTS = 2_000
MAX_DEPTH = 8
MAX_TEXT = 4096
MEDIA_TYPES = {2: "image", 3: "file", 4: "voice", 5: "video"}
FAILURE_TEXT = "传输失败，请稍后重试".encode("utf-8")
_HEX32 = re.compile(rb"[0-9a-fA-F]{32}\Z")
_ALLOW = {45002, 45003, 45402, 45403, 45405, 45406, 45407, 45408,
          45418, 45422, 45424, 45507, 45509, 45526, 45554,
          45812, 45814, 45862, 47710}


class DecodeError(ValueError):
    pass


class BoundExceeded(DecodeError):
    pass


def _varint(buf, pos):
    value = 0
    for index in range(10):
        if pos >= len(buf):
            raise DecodeError("truncated_varint")
        b = buf[pos]
        pos += 1
        if index == 9 and b > 1:
            raise DecodeError("varint_overflow")
        value |= (b & 127) << (index * 7)
        if b < 128:
            return value, pos
    raise DecodeError("unterminated_varint")


def _fields(data, budget):
    """Yield number, wire, int-or-memoryview, charging one global field budget."""
    buf = memoryview(data)
    pos = 0
    while pos < len(buf):
        budget[0] += 1
        if budget[0] > MAX_FIELDS:
            raise BoundExceeded("field_bound")
        key, pos = _varint(buf, pos)
        number, wire = key >> 3, key & 7
        if not 1 <= number <= 0x1fffffff:
            raise DecodeError("invalid_field_number")
        if wire == 0:
            value, pos = _varint(buf, pos)
        elif wire in (1, 5):
            end = pos + (8 if wire == 1 else 4)
            if end > len(buf):
                raise DecodeError("truncated_fixed")
            value, pos = buf[pos:end], end
        elif wire == 2:
            length, pos = _varint(buf, pos)
            end = pos + length
            if end > len(buf):
                raise DecodeError("truncated_length")
            value, pos = buf[pos:end], end
        else:
            raise DecodeError("unsupported_wire")
        yield number, wire, value


def _text(value):
    if len(value) > MAX_TEXT:
        return None
    try:
        text = bytes(value).decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if text and not any(ord(c) < 32 for c in text) else None


def _path(value):
    text = _text(value)
    if not text:
        return None
    if text.startswith("::NTOSFull::"):
        text = text[len("::NTOSFull::"):].lstrip("\\/")
    # Do not return arbitrary strings, remote URLs, UNC, devices, or ADS.
    if not re.match(r"^[A-Za-z]:[\\/]", text) or any(c in text[2:] for c in ':*?"<>|'):
        return None
    tail = text[3:].replace("/", "\\").split("\\")
    if any(part in ("", ".", "..") for part in tail):
        return None
    return ntpath.normpath(text)


def _filename(value):
    text = _text(value)
    if not text or any(c in text for c in '\\/:*?"<>|'):
        return None
    return text


def _md5(value):
    raw = bytes(value)
    if len(raw) == 16:
        return raw.hex()
    if len(raw) == 32 and _HEX32.fullmatch(raw):
        return raw.decode("ascii").lower()
    return None


def _thumbnail_hash(value):
    raw = bytes(value)
    if len(raw) == 16:
        return {"hex": raw.hex(), "bytes": 16, "encoding": "raw"}
    if len(raw) == 20:
        return {"hex": raw.hex(), "bytes": 20, "encoding": "raw"}
    if len(raw) == 32 and _HEX32.fullmatch(raw):
        return {"hex": raw.decode("ascii").lower(), "bytes": 16, "encoding": "ascii_hex"}
    return None


def _legacy_md5(value):
    # Only the observed ASCII32 legacy form is established for 45407.
    raw = bytes(value)
    return raw.decode("ascii").lower() if _HEX32.fullmatch(raw) else None


def _signed64(value):
    return value - (1 << 64) if value >= 1 << 63 else value


def extract_media(blob):
    """Return (records, stats), retaining every repeated media segment and hash.

    `segment_path` is [outer_ordinal, ref_ordinal, ...], where nested ordinals
    count occurrences of 47710. `nested_reference` distinguishes quoted media.
    Metadata is for LOCAL use. Never publish private filenames, paths, or content hashes.
    `local_path` prefers 45403, then 45812, then 45814; inspect `local_paths` to
    distinguish sent originals from cached thumbs. No existence checks occur.
    """
    stats = {"status": "null" if blob is None else "ok", "message_segments": 0,
             "media_segments": 0, "parse_failed": 0, "bounded_out": 0,
             "ignored_non_media_segments": 0, "unsafe_path_fields": 0,
             "md5_conflicts": 0, "unknown_fields": {}, "fields_parsed": 0}
    if blob is None:
        return [], stats
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        stats.update(status="parse_failed", parse_failed=1)
        return [], stats
    view = memoryview(blob)
    if view.nbytes > MAX_BLOB:
        stats.update(status="bounded_out", bounded_out=1)
        return [], stats
    records, unknown, budget = [], Counter(), [0]

    def decode_content(data, path, depth):
        if depth > MAX_DEPTH:
            raise BoundExceeded("depth_bound")
        stats["message_segments"] += 1
        if stats["message_segments"] > MAX_SEGMENTS:
            raise BoundExceeded("segment_bound")
        fields = {}
        for number, wire, value in _fields(data, budget):
            if number in _ALLOW:
                fields.setdefault(number, []).append((wire, value))
            else:
                unknown[f"content:{number}"] += 1

        def ints(number):
            return [v for w, v in fields.get(number, []) if w == 0]

        def vals(number, transform):
            output = []
            for wire, value in fields.get(number, []):
                if wire == 2:
                    result = transform(value)
                    if result is not None and result not in output:
                        output.append(result)
            return output

        types = ints(45002)
        media_types = list(dict.fromkeys(t for t in types if t in MEDIA_TYPES))
        if media_types:
            content_type = media_types[-1]
            hashes = {str(n): vals(n, _legacy_md5 if n == 45407 else _md5)
                      for n in (45406, 45407, 45424)}
            canonical_legacy = set(hashes["45406"] + hashes["45407"])
            conflict = len(canonical_legacy) > 1
            paths = {}
            for number in (45403, 45812, 45814):
                paths[str(number)] = vals(number, _path)
                stats["unsafe_path_fields"] += sum(
                    w == 2 and _path(v) is None for w, v in fields.get(number, []))
            primary = hashes["45406"] or hashes["45407"]
            # 45424 is documented as IMAGE hash; do not use it as FILE MD5.
            if not primary and content_type == 2:
                primary = hashes["45424"]
            names = vals(45402, _filename)
            sizes = ints(45405)
            subtype = ints(45003)
            errors = [_signed64(v) for v in ints(45507)]
            markers = ints(45509)
            failure_fields = fields.get(45554, [])
            all_paths = [p for n in ("45403", "45812", "45814") for p in paths[n]]
            ref_md5 = []
            for wire, value in fields.get(45526, []):
                if wire != 2:
                    continue
                try:
                    for n, w, v in _fields(value, budget):
                        if n == 45530 and w == 2:
                            h = _md5(v)
                            if h and h not in ref_md5:
                                ref_md5.append(h)
                except BoundExceeded:
                    raise
                except DecodeError:
                    stats["parse_failed"] += 1
            stats["media_segments"] += 1
            stats["md5_conflicts"] += int(conflict)
            records.append({
                "segment_ordinal": path[0], "segment_path": path,
                "nested_reference": len(path) > 1,
                "element_type": content_type, "media_type": MEDIA_TYPES[content_type],
                "content_types": list(dict.fromkeys(types)), "type_conflict": len(set(types)) > 1,
                "subtype": subtype[-1] if subtype else None, "subtypes": subtype,
                "filename": names[-1] if names else None, "filenames": names,
                "size": sizes[-1] if sizes else None, "size_bytes": sizes[-1] if sizes else None,
                "sizes": sizes, "size_conflict": len(set(sizes)) > 1,
                "md5": primary[-1] if primary else None,
                "legacy_md5": hashes["45407"][-1] if hashes["45407"] else None,
                "alt_md5": hashes["45424"][-1] if hashes["45424"] else None,
                "md5_fields": hashes, "md5_conflict": conflict,
                "invalid_md5_fields": {
                    str(n): sum(w != 2 or (w == 2 and
                        (_legacy_md5(v) if n == 45407 else _md5(v)) is None)
                        for w, v in fields.get(n, []))
                    for n in (45406, 45407, 45424)},
                "alt_md5_differs": bool(canonical_legacy and hashes["45424"] and
                                         canonical_legacy != set(hashes["45424"])),
                "reference_md5s": ref_md5,
                "local_path": all_paths[0] if all_paths else None, "local_paths": paths,
                "thumbnail_hashes": vals(45408, _thumbnail_hash),
                "video_thumbnail_hashes": vals(45862, _md5),
                "cover_names": vals(45422, lambda v: _filename(v) or
                                    (ntpath.basename(_path(v)) if _path(v) else None)),
                "original_flags": ints(45418), "error_codes": errors, "markers": markers,
                "known_failure_text_present": any(w == 2 and bytes(v) == FAILURE_TEXT
                                                 for w, v in failure_fields),
                "other_failure_text_present": any(w != 2 or bytes(v) != FAILURE_TEXT
                                                 for w, v in failure_fields),
                "known_failure_signal": -7003 in errors or 1 in markers,
            })
        else:
            stats["ignored_non_media_segments"] += 1
        # Only the primary schema's recursive MsgContent boundary is followed.
        for ordinal, (wire, value) in enumerate(fields.get(47710, [])):
            if wire == 2:
                try:
                    decode_content(value, path + [ordinal], depth + 1)
                except BoundExceeded:
                    raise
                except DecodeError:
                    stats["parse_failed"] += 1

    try:
        ordinal = 0
        for number, wire, value in _fields(view, budget):
            if number == 40800 and wire == 2:
                try:
                    decode_content(value, [ordinal], 1)
                except BoundExceeded:
                    raise
                except DecodeError:
                    stats["parse_failed"] += 1
                ordinal += 1
            else:
                unknown[f"outer:{number}:{wire}"] += 1
        if not ordinal and len(view):
            stats["status"] = "unsupported_outer_shape"
    except BoundExceeded:
        stats["bounded_out"] += 1
        stats["status"] = "bounded_out"
    except DecodeError:
        stats["parse_failed"] += 1
        stats["status"] = "partial" if records else "parse_failed"
    if stats["parse_failed"] and stats["status"] == "ok":
        stats["status"] = "partial"
    stats["unknown_fields"] = dict(unknown)
    stats["fields_parsed"] = budget[0]
    return records, stats


def _self_test():
    def vi(n):
        out = bytearray()
        while n > 127:
            out.append((n & 127) | 128)
            n >>= 7
        return bytes(out + bytes([n]))
    def scalar(n, v):
        return vi(n << 3) + vi(v)
    def raw(n, v):
        return vi((n << 3) | 2) + vi(len(v)) + v
    token = bytes.fromhex("1234567890abcdef1234567890abcdef")
    image = scalar(45002, 2) + raw(45424, token.hex().encode())
    image += raw(45812, b"C:\\QQ\\Pic\\Thumb\\sample.png") + raw(45101, b"PRIVATE_CHAT_TEXT")
    file = scalar(45002, 3) + scalar(45003, 1) + scalar(45405, 42)
    file += raw(45406, token) + raw(45407, token.hex().encode()) + raw(45402, b"sample.dat")
    file += raw(45403, b"C:\\QQ\\FileRecv\\sample.dat") + raw(45510, b"SECRET_CDN_TOKEN")
    file += scalar(45507, (1 << 64) - 7003) + raw(45554, FAILURE_TEXT)
    video = scalar(45002, 5) + raw(45406, token) + raw(45862, token)
    quoted = scalar(45002, 7) + raw(47710, image) + raw(47710, video)
    blob = raw(40800, file) + raw(40800, image) + raw(40800, quoted)
    records, stats = extract_media(blob)
    assert stats["status"] == "ok" and len(records) == 4
    assert records[0]["legacy_md5"] == token.hex() and not records[0]["md5_conflict"]
    assert records[0]["known_failure_signal"] and records[0]["known_failure_text_present"]
    assert records[1]["md5"] == token.hex() and records[1]["local_paths"]["45812"]
    assert records[2]["segment_path"] == [2, 0] and records[3]["segment_path"] == [2, 1]
    assert "PRIVATE_CHAT_TEXT" not in repr((records, stats))
    assert "SECRET_CDN_TOKEN" not in repr((records, stats))
    bad = raw(40800, scalar(45002, 2) + raw(45812, b"https://invalid/token"))
    r, s = extract_media(bad)
    assert r[0]["local_path"] is None and s["unsafe_path_fields"] == 1
    duplicate = raw(40800, scalar(45002, 3) + raw(45406, token) + raw(45406, b"x" * 16))
    r, _ = extract_media(duplicate)
    assert len(r[0]["md5_fields"]["45406"]) == 2 and r[0]["md5_conflict"]
    assert extract_media(b"\xff")[1]["parse_failed"]
    print("metadata-only synthetic self-test passed (no QQ files opened)")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        _self_test()
