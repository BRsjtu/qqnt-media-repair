"""Bounded, byte-preserving parser for one observed QQNT legacy FILE profile.

This module never opens files or emits text/URL fields outside the allowlist.
Segment ordinals count outer field 40800 occurrences, starting at zero.
"""

from dataclasses import dataclass
import ntpath
import re

MAX_BLOB = 16 * 1024 * 1024
MAX_FIELDS = 20_000
MAX_SEGMENTS = 2_000
MAX_DEPTH = 2
EXPIRED_ERROR = -7003
FAILURE_TEXT = "传输失败，请稍后重试".encode("utf-8")
_HEX = re.compile(r"[0-9a-fA-F]{32}\Z")


class ProfileError(ValueError):
    """Malformed protobuf, exceeded bound, or unsafe/unsupported replacement."""


@dataclass(frozen=True)
class _Field:
    number: int
    wire: int
    raw: bytes
    value: object


def _varint(data, offset):
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise ProfileError("truncated varint")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ProfileError("varint exceeds uint64")
        value |= (byte & 127) << (7 * index)
        if byte < 128:
            return value, offset
    raise ProfileError("unterminated varint")


def _encode_varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _encode_bytes(number, value):
    return _encode_varint((number << 3) | 2) + _encode_varint(len(value)) + value


def _parse(data, budget, depth):
    if depth > MAX_DEPTH:
        raise ProfileError("protobuf depth bound exceeded")
    fields = []
    offset = 0
    while offset < len(data):
        budget[0] += 1
        if budget[0] > MAX_FIELDS:
            raise ProfileError("protobuf field bound exceeded")
        start = offset
        tag, offset = _varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number <= 0x1FFFFFFF:
            raise ProfileError("invalid protobuf field number")
        if wire == 0:
            value, offset = _varint(data, offset)
        elif wire in (1, 5):
            end = offset + (8 if wire == 1 else 4)
            if end > len(data):
                raise ProfileError("truncated fixed-width field")
            value, offset = data[offset:end], end
        elif wire == 2:
            size, offset = _varint(data, offset)
            if size > len(data) - offset:
                raise ProfileError("truncated length-delimited field")
            end = offset + size
            value, offset = data[offset:end], end
        else:
            raise ProfileError("unsupported protobuf wire type")
        fields.append(_Field(number, wire, data[start:offset], value))
    return fields


def _body(blob):
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise ProfileError("body must be bytes")
    if (blob.nbytes if isinstance(blob, memoryview) else len(blob)) > MAX_BLOB:
        raise ProfileError("body size bound exceeded")
    data = bytes(blob)
    budget = [0]
    outer = _parse(data, budget, 0)
    segments = []
    for field in outer:
        if field.number != 40800:
            continue
        if field.wire != 2:
            raise ProfileError("MsgContent requires length-delimited encoding")
        if len(segments) >= MAX_SEGMENTS:
            raise ProfileError("segment bound exceeded")
        segments.append(_parse(field.value, budget, 1))
    stats = {"blob_bytes": len(data), "outer_fields": len(outer),
             "segment_count": len(segments),
             "segment_fields": budget[0] - len(outer)}
    return data, outer, segments, stats


def _hash(value):
    if isinstance(value, str):
        return value.lower() if _HEX.fullmatch(value) else None
    if isinstance(value, bytes):
        if len(value) == 16:
            return value.hex()
        if len(value) == 32:
            try:
                return _hash(value.decode("ascii"))
            except UnicodeDecodeError:
                pass
    return None


def _text(field):
    if field is None or field.wire != 2 or len(field.value) > 32767:
        return None
    try:
        return field.value.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _signed(value):
    return value - (1 << 64) if value >= (1 << 63) else value


def _record(fields, ordinal):
    by_number = {}
    for field in fields:
        by_number.setdefault(field.number, []).append(field)

    def first(number):
        return by_number.get(number, [None])[0]

    def scalar(number):
        field = first(number)
        return field.value if field is not None and field.wire == 0 else None

    duplicate_conflict = False
    for number, values in by_number.items():
        # Dimensions are observed repeated fields; their bytes remain opaque.
        if number in (45411, 45412):
            continue
        if len({(field.wire, field.value) for field in values}) > 1:
            duplicate_conflict = True

    hashes = []
    invalid_hash = False
    for number in (45406, 45407):
        for field in by_number.get(number, []):
            digest = _hash(field.value) if field.wire == 2 else None
            if digest is None:
                invalid_hash = True
            else:
                hashes.append(digest)
    md5_conflict = len(set(hashes)) > 1
    old = first(45407)
    legacy = (_hash(old.value) if old and old.wire == 2 and len(old.value) == 32
              else None)
    canonical = first(45406)
    canonical_hash = _hash(canonical.value) if canonical and canonical.wire == 2 else None
    error = scalar(45507)
    error = _signed(error) if error is not None else None
    marker = scalar(45509)
    filename, path = _text(first(45402)), _text(first(45403))
    # These numbers are meaningful only for this exact observed FILE profile.
    # Never export a remote URL merely because it occupies a path-like field.
    is_file = scalar(45002) == 3 and scalar(45003) == 1
    if (not is_file or filename is None or not filename
            or any(ord(c) < 32 or c in '\\/:*?"<>|' for c in filename)):
        filename = None
    if is_file and path is not None:
        try:
            path = _safe_path(path)
        except ProfileError:
            path = None
    else:
        path = None
    size = scalar(45405)
    known_wires = {45002: 0, 45003: 0, 45402: 2, 45403: 2, 45405: 0,
                   45406: 2, 45407: 2, 45507: 0, 45509: 0, 45554: 2, 45419: 2}
    invalid_wire = any(field.wire != known_wires[number]
                       for number, values in by_number.items() if number in known_wires
                       for field in values)
    supported = (scalar(45002) == 3 and scalar(45003) == 1 and legacy is not None
                 and filename is not None and size is not None and not invalid_hash
                 and not invalid_wire and not md5_conflict and not duplicate_conflict)
    eligible = (supported and (marker == 1 or error == EXPIRED_ERROR)
                and marker in (None, 1) and error in (None, EXPIRED_ERROR)
                and all(field.wire == 2 and field.value == FAILURE_TEXT
                        for field in by_number.get(45554, [])))
    return {"segment_ordinal": ordinal, "element_type": scalar(45002),
            "subtype": scalar(45003), "filename": filename, "size": size,
            "md5": canonical_hash if is_file else None,
            "legacy_md5": legacy if is_file else None, "md5_conflict": md5_conflict,
            "local_path": path, "failure_pattern_eligible": eligible,
            "marker": marker, "error_code": error,
            "duplicate_conflict": duplicate_conflict, "supported_profile": supported}


def inspect_body(blob):
    """Return allowlisted metadata for every segment and bounded parse stats.

    md5 is field 45406 normalized to lowercase hex; legacy_md5 is ASCII32
    field 45407. Neither arbitrary message text nor remote fields are returned.
    """
    _, _, segments, stats = _body(blob)
    return {"records": [_record(fields, i) for i, fields in enumerate(segments)],
            "stats": stats}


def _safe_path(path):
    if not isinstance(path, str) or not path or len(path) > 32767:
        raise ProfileError("source_path must be a bounded local absolute path")
    if not re.match(r"^[A-Za-z]:[\\/]", path):
        raise ProfileError("source_path must use a local absolute drive path")
    if any(ord(character) < 32 for character in path) or any(c in path[2:] for c in ':*?"<>|'):
        raise ProfileError("source_path contains unsafe path characters")
    parts = re.split(r"[\\/]", path[3:])
    if not parts or any(not part or part in (".", "..") or part.endswith((" ", "."))
                        for part in parts):
        raise ProfileError("source_path contains unsafe path components")
    reserved = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)", re.I)
    if any(reserved.match(part) for part in parts):
        raise ProfileError("source_path contains a device name")
    return path


def normalize_body(blob, replacements):
    """Repair only explicitly selected, eligible legacy FILE subtype 1 segments.

    replacements maps 0-based ordinals to source_path, md5 (hex32 or bytes16),
    and size. The caller must hash the source file; this pure module checks the
    supplied digest and size against the message. Unsupported selections raise
    ProfileError atomically. An already-normalized matching selection is a no-op.
    """
    data, outer, segments, stats = _body(blob)
    if not isinstance(replacements, dict):
        raise ProfileError("replacements must be a dictionary")
    changed = {}
    changes = []
    for ordinal, replacement in replacements.items():
        if type(ordinal) is not int or not 0 <= ordinal < len(segments):
            raise ProfileError("invalid segment ordinal")
        if not isinstance(replacement, dict) or set(replacement) != {"source_path", "md5", "size"}:
            raise ProfileError("replacement requires source_path, md5 and size")
        path = _safe_path(replacement["source_path"])
        digest = _hash(replacement["md5"])
        size = replacement["size"]
        if digest is None or type(size) is not int or not 0 <= size < (1 << 64):
            raise ProfileError("invalid replacement MD5 or size")
        fields = segments[ordinal]
        record = _record(fields, ordinal)
        if not record["supported_profile"]:
            raise ProfileError("selected segment is unsupported or conflicting")
        if size != record["size"] or digest != record["legacy_md5"]:
            raise ProfileError("replacement size or MD5 does not match the message")
        extension = ntpath.splitext(record["filename"])[1].encode("utf-8")
        target_path = path.encode("utf-8")
        target_hash = bytes.fromhex(digest)
        desired = {45403: target_path, 45406: target_hash, 45419: extension}
        already = (not any(field.number in (45507, 45509, 45554) for field in fields)
                   and all(any(field.number == number and field.wire == 2 and field.value == value
                               for field in fields) for number, value in desired.items()))
        if not record["failure_pattern_eligible"]:
            if already:
                continue
            raise ProfileError("selected segment lacks the validated failure pattern")
        result = []
        emitted = set()
        for field in fields:
            if field.number in (45507, 45509, 45554):
                continue
            if field.number in desired:
                if field.number not in emitted:
                    value = desired[field.number]
                    result.append(field.raw if field.wire == 2 and field.value == value
                                  else _encode_bytes(field.number, value))
                    emitted.add(field.number)
                continue
            result.append(field.raw)
        for number, value in desired.items():
            if number not in emitted:
                result.append(_encode_bytes(number, value))
        changed[ordinal] = b"".join(result)
        changes.append({"segment_ordinal": ordinal, "source_path": path,
                        "md5": digest, "size": size})
    result = []
    ordinal = 0
    for field in outer:
        if field.number == 40800:
            result.append(_encode_bytes(40800, changed[ordinal]) if ordinal in changed else field.raw)
            ordinal += 1
        else:
            result.append(field.raw)
    output = b"".join(result) if changed else data
    if len(output) > MAX_BLOB:
        raise ProfileError("normalized body size bound exceeded")
    # Include added fields in the same global budget as the input.
    _body(output)
    return output, {"changed_segments": sorted(changed), "changes": changes, "stats": stats}
