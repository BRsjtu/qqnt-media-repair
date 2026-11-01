"""Fail-closed Windows NTQQ SQLCipher staging and WAL-only publication.

The source main file is held through an exclusive, read-only Windows handle.
Only one large snapshot is created, with NTQQ's 1024-byte prefix removed. The
caller must keep the context alive until it has finished using the snapshot.
No SQL connection ever opens the source database. This module prints nothing.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import hashlib
import importlib
import importlib.metadata
import os
from pathlib import Path
import shutil
import struct
import tempfile
import threading
import uuid

HEADER_SIZE = 1024
PAGE_SIZE = 4096
SQLCIPHER_VERSION = "0.6.4"
MODULE_SHA256 = "48CBB04DE252A5F7E7D57DF402C5029A21D7C912D497704F2829A39F660612F7"
PENDING_RVA = 0x588468
PENDING_DEFAULT = 0x40000000
PENDING_NTQQ = 0x3FFFFC00
_runtime_lock = threading.RLock()
_runtime_state = None


class BackendError(RuntimeError):
    """A fixed, non-content-bearing failure description."""


def load_key(path):
    try:
        key = Path(path).read_bytes().decode("ascii").rstrip("\r\n")
    except (UnicodeError, OSError):
        raise BackendError("key_file_unreadable") from None
    if len(key) != 16 or any(not 32 <= ord(c) <= 126 for c in key):
        raise BackendError("key_must_be_16_printable_ascii_characters")
    return key


def qident(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise BackendError("invalid_sql_identifier")
    return '"' + value.replace('"', '""') + '"'


def stat_signature(path):
    try:
        s = Path(path).stat()
    except FileNotFoundError:
        return None
    return {"size": s.st_size, "mtime_ns": s.st_mtime_ns, "file_id": s.st_ino}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def checksum(data, state=(0, 0), endian="<"):
    if len(data) % 8:
        raise BackendError("wal_checksum_alignment")
    words = struct.unpack(endian + str(len(data) // 4) + "I", data)
    a, b = state
    for i in range(0, len(words), 2):
        a = (a + words[i] + b) & 0xffffffff
        b = (b + words[i + 1] + a) & 0xffffffff
    return a, b


def validate_wal(data):
    """Describe only the valid committed prefix; tolerate stale/partial tails.

    A malformed header or nonempty WAL without any valid commit is refused.
    Bytes after the last complete valid commit are never replayed/published.
    """
    if len(data) < 32:
        raise BackendError("wal_header_incomplete")
    h = struct.unpack(">8I", data[:32])
    if h[0] not in (0x377f0682, 0x377f0683) or h[1] != 3007000 or h[2] != PAGE_SIZE:
        raise BackendError("wal_format_unsupported")
    endian = "<" if h[0] == 0x377f0682 else ">"
    state = checksum(data[:24], endian=endian)
    if state != h[6:8]:
        raise BackendError("wal_header_checksum_failed")
    frame_size = 24 + PAGE_SIZE
    physical = (len(data) - 32) // frame_size
    commit_frame = commit_pages = valid = 0
    seen = set()
    committed_seen = set()
    for i in range(physical):
        offset = 32 + i * frame_size
        frame = struct.unpack(">6I", data[offset:offset + 24])
        if not frame[0] or frame[0] > 0xfffffffe or frame[2:4] != h[4:6]:
            break
        next_state = checksum(data[offset:offset + 8] + data[offset + 24:offset + frame_size], state, endian)
        if next_state != frame[4:6]:
            break
        state = next_state
        valid += 1
        seen.add(frame[0])
        if frame[1]:
            if frame[1] > 0xfffffffe:
                break
            commit_frame, commit_pages = i + 1, frame[1]
            committed_seen = set(seen)
    if not commit_frame:
        raise BackendError("wal_has_no_valid_committed_prefix")
    committed_bytes = 32 + commit_frame * frame_size
    return {"physical_frames": physical, "valid_frames": valid, "frames": commit_frame,
            "last_commit_pages": commit_pages, "unique_pages": len(committed_seen),
            "committed_bytes": committed_bytes, "bytes": len(data),
            "unused_tail_bytes": len(data) - committed_bytes,
            "sha256": sha256(data), "committed_sha256": sha256(data[:committed_bytes])}


def committed_wal(data):
    if not data:
        return b"", None
    info = validate_wal(data)
    return data[:info["committed_bytes"]], info


@contextmanager
def exclusive_reader(path):
    if os.name != "nt":
        raise BackendError("windows_required")
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                  ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise BackendError("database_not_exclusively_available")
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle(handle)
        raise
    with os.fdopen(fd, "rb") as stream:
        yield stream


def _install_pending_patch():
    if os.name != "nt":
        raise BackendError("windows_required")
    try:
        version = importlib.metadata.version("sqlcipher3")
    except importlib.metadata.PackageNotFoundError:
        raise BackendError("pinned_sqlcipher3_not_installed") from None
    if version != SQLCIPHER_VERSION:
        raise BackendError("sqlcipher3_version_not_reviewed")
    module = importlib.import_module("sqlcipher3._sqlite3")
    pyd = Path(module.__file__).resolve(strict=True)
    pe = pyd.read_bytes()
    if sha256(pe).upper() != MODULE_SHA256:
        raise BackendError("sqlcipher3_binary_not_reviewed")
    offset = int.from_bytes(pe[0x3c:0x40], "little")
    if pe[offset:offset + 4] != b"PE\0\0":
        raise BackendError("sqlcipher3_pe_invalid")
    sections = int.from_bytes(pe[offset + 6:offset + 8], "little")
    optional = int.from_bytes(pe[offset + 20:offset + 22], "little")
    writable = False
    for i in range(sections):
        start = offset + 24 + optional + i * 40
        section = pe[start:start + 40]
        size = int.from_bytes(section[8:12], "little")
        rva = int.from_bytes(section[12:16], "little")
        flags = int.from_bytes(section[36:40], "little")
        if section[:8].rstrip(b"\0") == b".data" and rva <= PENDING_RVA < rva + size:
            writable = bool(flags & 0x80000000)
    if not writable:
        raise BackendError("pending_byte_not_in_writable_data")
    library = ctypes.CDLL(str(pyd))
    cell = ctypes.c_uint32.from_address(int(library._handle) + PENDING_RVA)
    if cell.value != PENDING_DEFAULT:
        raise BackendError("pending_byte_initial_value_unexpected")
    cell.value = PENDING_NTQQ
    if cell.value != PENDING_NTQQ:
        cell.value = PENDING_DEFAULT
        raise BackendError("pending_byte_patch_not_verified")
    return {"library": library, "cell": cell}


@contextmanager
def sqlcipher_runtime():
    """Serialize the process-global adapter; nested archive contexts are safe."""
    global _runtime_state
    with _runtime_lock:
        first = _runtime_state is None
        if first:
            _runtime_state = _install_pending_patch()
        try:
            yield importlib.import_module("sqlcipher3.dbapi2")
        finally:
            if first:
                _runtime_state["cell"].value = PENDING_DEFAULT
                _runtime_state = None


def configure(connection, key):
    connection.execute(f"PRAGMA cipher_page_size={PAGE_SIZE}")
    connection.execute("PRAGMA key='" + key.replace("'", "''") + "'")
    connection.execute("PRAGMA kdf_iter=4000")
    connection.execute("PRAGMA cipher_hmac_algorithm=HMAC_SHA1")
    connection.execute("PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512")
    version = connection.execute("PRAGMA cipher_version").fetchone()
    if not version or not version[0]:
        raise BackendError("sqlcipher_not_active")
    connection.execute("SELECT count(*) FROM sqlite_master").fetchone()


def _connect(sql, path, key, readonly=False):
    conn = sql.connect(Path(path).as_uri() + "?mode=ro" if readonly else str(path),
                       uri=readonly, isolation_level=None)
    try:
        configure(conn, key)
        if readonly:
            conn.execute("PRAGMA query_only=ON")
        return conn
    except Exception:
        conn.close()
        raise


def cipher_integrity_errors(rows):
    return [row for row in rows if not (row and str(row[0]).strip().lower() == "ok")]


@contextmanager
def encrypted_archive(path, key_file, readonly=False):
    """Open a small SQLCipher archive; schema and row serialization are caller-owned."""
    archive_path = Path(path).resolve()
    if readonly and not archive_path.is_file():
        raise BackendError("archive_missing")
    key = load_key(key_file)
    with sqlcipher_runtime() as sql:
        conn = _connect(sql, archive_path, key, readonly=readonly)
        try:
            yield conn
        finally:
            conn.close()


def _read_optional(path):
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        return b""


def copy_snapshot(source, destination):
    """Copy bytes after the fixed prefix from an already exclusively held stream."""
    source.seek(0)
    prefix = source.read(HEADER_SIZE)
    if len(prefix) != HEADER_SIZE:
        raise BackendError("database_prefix_incomplete")
    with Path(destination).open("xb") as dst:
        shutil.copyfileobj(source, dst, 8 * 1024 * 1024)
        dst.flush()
        os.fsync(dst.fileno())
    if Path(destination).stat().st_size == 0 or Path(destination).stat().st_size % PAGE_SIZE:
        raise BackendError("database_page_alignment_invalid")
    return prefix


class StagedDatabase:
    """A single-use source-locked stage, with a read-only scanning connection."""

    def __init__(self, sql, db_path, path, key, original_wal, original_shm, source, prefix):
        self.path = path
        self.source = source
        self.connection = _connect(sql, path, key, readonly=True)
        self._sql, self._db, self._key = sql, db_path, key
        self._wal, self._shm, self._prefix = original_wal, original_shm, prefix
        self._used = False

    def _check_source(self):
        if stat_signature(self._db) != self.source["main"]:
            raise BackendError("source_main_changed")
        if _read_optional(str(self._db) + "-wal") != self._wal:
            raise BackendError("source_wal_changed")
        if _read_optional(str(self._db) + "-shm") != self._shm:
            raise BackendError("source_shm_changed")

    def publish(self, updates):
        """Conditionally replace 40800 BLOBs and publish only a verified WAL.

        Each update has table, msg_id, old_body, new_body. Duplicate identities,
        triggers, unrelated row changes and stale originals are refused. The
        caller should commit an encrypted before/new archive before calling.
        """
        if self._used:
            raise BackendError("stage_publish_already_attempted")
        self._used = True
        updates = list(updates)
        if not updates:
            raise BackendError("no_updates")
        identities = set()
        for item in updates:
            if set(item) != {"table", "msg_id", "old_body", "new_body"}:
                raise BackendError("update_fields_invalid")
            if item["table"] not in ("c2c_msg_table", "group_msg_table"):
                raise BackendError("message_table_not_allowed")
            if isinstance(item["msg_id"], bool) or not isinstance(item["msg_id"], int):
                raise BackendError("message_id_must_be_integer")
            if not all(isinstance(item[k], bytes) for k in ("old_body", "new_body")):
                raise BackendError("message_body_must_be_bytes")
            if item["old_body"] == item["new_body"]:
                raise BackendError("unchanged_message_body")
            identity = item["table"], item["msg_id"]
            if identity in identities:
                raise BackendError("duplicate_update_identity")
            identities.add(identity)
        self._check_source()
        # The public scan handle cannot be used to write, and is closed before
        # opening the writer so a caller's outstanding scan cannot hide changes.
        self.connection.close()
        self.connection = None
        stage_signature = stat_signature(self.path)
        writer = guard = verifier = None
        try:
            guard = _connect(self._sql, self.path, self._key, readonly=True)
            guard.execute("BEGIN")
            guard.execute("SELECT count(*) FROM sqlite_master").fetchone()
            writer = _connect(self._sql, self.path, self._key)
            if writer.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                raise BackendError("source_is_not_in_wal_mode")
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("PRAGMA synchronous=FULL")
            if writer.execute("PRAGMA wal_autocheckpoint").fetchone()[0] != 0 or writer.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise BackendError("writer_settings_not_verified")
            tables = sorted({item["table"] for item in updates})
            columns, counts = {}, {}
            for table in tables:
                columns[table] = [row[1] for row in writer.execute("PRAGMA table_info(" + qident(table) + ")")]
                if not {"40001", "40800"}.issubset(columns[table]):
                    raise BackendError("message_columns_missing")
                if writer.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)).fetchone():
                    raise BackendError("message_table_has_triggers")
                counts[table] = writer.execute("SELECT count(*) FROM " + qident(table)).fetchone()[0]
            before_rows = []
            writer.execute("BEGIN IMMEDIATE")
            for item in updates:
                table = qident(item["table"])
                rows = writer.execute('SELECT * FROM ' + table + ' WHERE "40001"=?', (item["msg_id"],)).fetchall()
                if len(rows) != 1:
                    raise BackendError("message_identity_not_unique")
                before = dict(zip(columns[item["table"]], rows[0]))
                if before["40800"] != item["old_body"]:
                    raise BackendError("message_original_changed")
                cursor = writer.execute('UPDATE ' + table + ' SET "40800"=? WHERE "40001"=? AND "40800"=?',
                                        (item["new_body"], item["msg_id"], item["old_body"]))
                if cursor.rowcount != 1:
                    raise BackendError("message_update_count_invalid")
                after = writer.execute('SELECT * FROM ' + table + ' WHERE "40001"=?', (item["msg_id"],)).fetchall()
                expected = tuple(item["new_body"] if column == "40800" else before[column]
                                 for column in columns[item["table"]])
                if after != [expected]:
                    raise BackendError("unrelated_columns_changed")
                before_rows.append(expected)
            if writer.total_changes != len(updates):
                raise BackendError("unexpected_total_changes")
            for table in tables:
                if writer.execute("SELECT count(*) FROM " + qident(table)).fetchone()[0] != counts[table]:
                    raise BackendError("table_row_count_changed")
            writer.execute("COMMIT")
            wal_path = Path(str(self.path) + "-wal")
            full = wal_path.read_bytes()
            if wal_path.read_bytes() != full:
                raise BackendError("candidate_wal_unstable")
            candidate, wal_after = committed_wal(full)
            initial, _ = committed_wal(self._wal)
            if initial and not candidate.startswith(initial):
                raise BackendError("candidate_wal_reset_or_history_changed")
            if stat_signature(self.path) != stage_signature:
                raise BackendError("staged_main_changed")
            verifier = _connect(self._sql, self.path, self._key, readonly=True)
            if cipher_integrity_errors(verifier.execute("PRAGMA cipher_integrity_check").fetchall()):
                raise BackendError("candidate_cipher_integrity_failed")
            for table in tables:
                if verifier.execute("PRAGMA integrity_check(" + qident(table) + ")").fetchall() != [("ok",)]:
                    raise BackendError("candidate_table_integrity_failed")
            for item, expected in zip(updates, before_rows):
                actual = verifier.execute('SELECT * FROM ' + qident(item["table"]) + ' WHERE "40001"=?', (item["msg_id"],)).fetchall()
                if actual != [expected]:
                    raise BackendError("fresh_reader_row_verification_failed")
            # Writer closes while guard/verifier still prevent checkpoint.
            writer.close()
            writer = None
            if stat_signature(self.path) != stage_signature:
                raise BackendError("writer_close_changed_staged_main")
            self._check_source()
            result = self._publish_wal(candidate)
            result.update({"updated_rows": len(updates), "wal_after": wal_after,
                           "cipher_integrity": "ok", "table_integrity": "ok",
                           "original_main_written": False})
            return result
        finally:
            # Never close the guard before a live writer, even on failure.
            for conn in (writer, verifier, guard):
                if conn is not None:
                    conn.close()

    def _publish_wal(self, candidate):
        backup = self.path.parent / "publish-backup"
        backup.mkdir()
        # Small rollback material only; the large main snapshot is never copied.
        (backup / "source-wal.bin").write_bytes(self._wal)
        (backup / "source-prefix.bin").write_bytes(self._prefix)
        if self._shm:
            (backup / "source-shm.bin").write_bytes(self._shm)
        target = Path(str(self._db) + "-wal")
        shm = Path(str(self._db) + "-shm")
        temporary = target.with_name(target.name + ".repair-" + uuid.uuid4().hex + ".tmp")
        shm_aside = shm.with_name(shm.name + ".repair-" + uuid.uuid4().hex + ".backup")
        moved_shm = replaced = False
        try:
            with temporary.open("xb") as out:
                out.write(candidate)
                out.flush()
                os.fsync(out.fileno())
            if temporary.read_bytes() != candidate:
                raise BackendError("publication_preparation_failed")
            self._check_source()
            if shm.exists():
                # Same-directory move remains atomic even when work_dir is on
                # another volume. This small backup is kept beside the source.
                os.replace(shm, shm_aside)
                moved_shm = True
            os.replace(temporary, target)
            replaced = True
            if target.read_bytes() != candidate or stat_signature(self._db) != self.source["main"]:
                raise BackendError("publication_verification_failed")
            return {"published": True, "wal_sha256": sha256(candidate),
                    "shm_backup": str(shm_aside) if moved_shm else None}
        except Exception:
            # Before replacing the WAL, restoring a moved SHM is safe. After
            # replacement, retain the old SHM aside: it must never be replayed
            # as the index of the new WAL.
            if moved_shm and not replaced and not shm.exists():
                os.replace(shm_aside, shm)
            raise
        finally:
            if temporary.exists():
                temporary.unlink()

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None


@contextmanager
def staged_database(db_path, key_file, work_dir):
    """Yield a locked, read-only stage; cleanup the sole large copy on exit."""
    if os.name != "nt":
        raise BackendError("windows_required")
    db_path = Path(db_path).resolve(strict=True)
    work_dir = Path(work_dir).resolve()
    if work_dir == db_path.parent or work_dir.is_relative_to(db_path.parent) or db_path.parent.is_relative_to(work_dir):
        raise BackendError("work_directory_must_be_separate_from_source_tree")
    if not db_path.is_file():
        raise BackendError("database_missing")
    key = load_key(key_file)
    work_dir.mkdir(parents=True, exist_ok=True)
    with sqlcipher_runtime() as sql, exclusive_reader(db_path) as original:
        main_signature = stat_signature(db_path)
        if main_signature["size"] <= HEADER_SIZE:
            raise BackendError("database_too_short")
        wal = _read_optional(str(db_path) + "-wal")
        shm = _read_optional(str(db_path) + "-shm")
        reserve = max(1024 * 1024 * 1024, main_signature["size"] // 20)
        needed = main_signature["size"] - HEADER_SIZE + len(wal) + reserve
        if shutil.disk_usage(work_dir).free < needed:
            raise BackendError("insufficient_working_drive_space")
        prefix_wal, wal_info = committed_wal(wal)
        source = {"main": main_signature, "wal": stat_signature(str(db_path) + "-wal"),
                  "wal_sha256": sha256(wal), "wal_info": wal_info,
                  "shm_sha256": sha256(shm)}
        with tempfile.TemporaryDirectory(prefix="ntqq-stage-", dir=work_dir) as temp:
            path = Path(temp) / "stage.db"
            prefix = copy_snapshot(original, path)
            if prefix_wal:
                Path(str(path) + "-wal").write_bytes(prefix_wal)
            stage = StagedDatabase(sql, db_path, path, key, wal, shm, source, prefix)
            try:
                stage._check_source()
                yield stage
            finally:
                stage.close()
