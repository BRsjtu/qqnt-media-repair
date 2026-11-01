"""Read-only, account-scoped source inventory and content verification.

The inventory and digest cache live in the caller's private work directory.
An existing inventory is only a candidate list: every selected file is checked
against current filesystem metadata and its actual content before it is returned.
"""

import hashlib
import ntpath
import os
from pathlib import Path
import re
import sqlite3
import stat


_HEX = re.compile(r"[0-9a-fA-F]{32}\Z")
_NAME_HEX = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F])")
_EXCLUDED = {"nt_db", "msgbackup", "logs", "log", ".git"}
_MEDIA = {"filerecv", "image", "audio", "video", "nt_qq", "pic", "ptt",
          "file", "emoji", "dataline"}
_CHUNK = 1024 * 1024


def _md5(value):
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 16:
            return bytes(value).hex()
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return None
    return value.lower() if isinstance(value, str) and _HEX.fullmatch(value) else None


def _signature(info):
    # Windows file identifiers can exceed SQLite's signed 64-bit integer range.
    return (info.st_size, info.st_mtime_ns, str(info.st_ino), str(info.st_dev),
            info.st_ctime_ns)


def _is_link(info):
    return (stat.S_ISLNK(info.st_mode) or
            bool(getattr(info, "st_file_attributes", 0) & 0x400))


def _plain_path(value):
    """Reject Windows device/UNC and alternate-stream paths on every platform."""
    value = os.fspath(value)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("invalid source path")
    if value.startswith(("\\\\", "//")):
        raise ValueError("UNC and device paths are not supported")
    drive, rest = ntpath.splitdrive(value)
    if ":" in rest or (drive and (len(drive) != 2 or drive[1] != ":")):
        raise ValueError("alternate streams and device paths are not supported")
    if drive and os.name != "nt":
        raise ValueError("foreign drive path")
    return Path(value)


def _without_links(path):
    """Inspect all ancestors, including the authorized root itself."""
    for component in (path, *path.parents):
        info = component.lstat()
        if _is_link(info):
            raise ValueError("links and reparse points are not supported")
    return path.stat()


def _authorized_file(value, roots):
    path = _plain_path(value).absolute()
    if ".." in path.parts:
        raise ValueError("parent traversal is not supported")
    root = next((root for root in roots if path.is_relative_to(root)), None)
    if root is None:
        raise ValueError("source outside authorized roots")
    if any(part.casefold() in _EXCLUDED for part in path.relative_to(root).parts):
        raise ValueError("excluded source directory")
    info = _without_links(path)
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("source escapes authorized root")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("source must be a regular file with one link")
    if os.name == "nt":
        # Python path stat and descriptor stat can expose different ctime
        # semantics on Windows. Descriptor ctime carries the change time.
        fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            opened = os.fstat(fd)
            if _signature(opened)[:4] != _signature(info)[:4] or opened.st_nlink != 1:
                raise ValueError("source changed during authorization")
            info = opened
        finally:
            os.close(fd)
    return resolved, info


def _read_verified(path, before, expected_size, authorize):
    signature = _signature(before)
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if _signature(opened) != signature or opened.st_nlink != 1:
            raise ValueError("source changed before reading")
        count = 0
        while True:
            chunk = stream.read(_CHUNK)
            if not chunk:
                break
            count += len(chunk)
            if count > expected_size:
                raise ValueError("source grew during reading")
            md5.update(chunk)
            sha256.update(chunk)
        if count != expected_size or _signature(os.fstat(stream.fileno())) != signature:
            raise ValueError("source changed during reading")
    _, after = authorize(path)
    if _signature(after) != signature:
        raise ValueError("source changed after reading")
    return {"path": str(path), "size": count, "md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def verify_source(source, allowed_roots):
    """Rehash a planned source with the full source policy, without any cache.

    Return current {path,size,md5,sha256}; raise ValueError/OSError on mismatch.
    This needs no inventory, work directory, or matcher instance.
    """
    roots = []
    for value in allowed_roots:
        root = _plain_path(value).absolute()
        if not stat.S_ISDIR(_without_links(root).st_mode):
            raise ValueError("authorized roots must be real directories")
        roots.append(root.resolve(strict=True))
    size = source.get("size")
    expected_md5 = _md5(source.get("md5"))
    expected_sha = source.get("sha256")
    if (isinstance(size, bool) or not isinstance(size, int) or size < 0 or
            expected_md5 is None or not isinstance(expected_sha, str) or
            not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha)):
        raise ValueError("invalid planned source metadata")
    authorize = lambda value: _authorized_file(value, roots)
    path, before = authorize(source["path"])
    if before.st_size != size:
        raise ValueError("planned source size changed")
    result = _read_verified(path, before, size, authorize)
    if result["md5"] != expected_md5 or result["sha256"] != expected_sha.lower():
        raise ValueError("planned source content changed")
    return result


class SourceMatcher:
    """Find verified media without copying it or modifying account data."""

    def __init__(self, account_dir, work_dir, extra_roots=(), existing_index=None):
        account = _plain_path(account_dir).absolute()
        if not stat.S_ISDIR(_without_links(account).st_mode):
            raise ValueError("account_dir must be a real directory")
        self.account_dir = account.resolve(strict=True)
        self.extra_roots = []
        for value in extra_roots:
            root = _plain_path(value).absolute()
            if not stat.S_ISDIR(_without_links(root).st_mode):
                raise ValueError("extra roots must be real directories")
            root = root.resolve(strict=True)
            if root not in self.extra_roots:
                self.extra_roots.append(root)
        self.roots = (self.account_dir, *self.extra_roots)
        work = _plain_path(work_dir).absolute()
        # A private work directory must not add files to any source tree.
        if any(work.is_relative_to(root) for root in self.roots):
            raise ValueError("work_dir must be outside authorized source roots")
        work.mkdir(parents=True, exist_ok=True)
        _without_links(work)
        self.stats = {"indexed": 0, "candidates": 0, "hashes": 0,
                      "hash_cache_hits": 0, "rejected": 0, "errors": 0,
                      "index_reused": 0}
        cache_path = work / "source-matcher.sqlite3"
        if cache_path.exists():
            info = _without_links(cache_path)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("unsafe local index")
        self.db = sqlite3.connect(cache_path)
        self.db.execute("CREATE TABLE IF NOT EXISTS hashes (path TEXT PRIMARY KEY, "
                        "size INTEGER, mtime INTEGER, ino TEXT, dev TEXT, "
                        "ctime INTEGER, md5 TEXT, sha256 TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS inventory (path TEXT PRIMARY KEY, "
                        "basename TEXT, size INTEGER, md5_hint TEXT)")
        self.db.execute("CREATE INDEX IF NOT EXISTS inventory_size ON inventory(size)")
        self.existing = None
        if existing_index is not None:
            try:
                source = _plain_path(existing_index).absolute()
                if not stat.S_ISREG(_without_links(source).st_mode):
                    raise ValueError("existing_index must be a regular file")
                self.existing = sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)
                columns = {row[1] for row in self.existing.execute("PRAGMA table_info(files)")}
                required = {"rel_path", "media_root", "basename", "size", "mtime_ns", "md5_from_name"}
                if not required <= columns:
                    raise ValueError("existing index has an unsupported files schema")
            except Exception:
                self.close()
                raise
            self.stats["index_reused"] = 1
        else:
            self._inventory()

    def _authorized(self, value):
        return _authorized_file(value, self.roots)

    def _inventory(self):
        self.db.execute("DELETE FROM inventory")
        starts = [child for child in self.account_dir.iterdir()
                  if child.name.casefold() in _MEDIA]
        starts.extend(self.extra_roots)
        for start in starts:
            try:
                if _is_link(start.lstat()) or not start.is_dir():
                    continue
                for current, dirs, files in os.walk(start, followlinks=False):
                    safe_dirs = []
                    for name in dirs:
                        try:
                            if name.casefold() not in _EXCLUDED and not _is_link((Path(current) / name).lstat()):
                                safe_dirs.append(name)
                        except OSError:
                            self.stats["errors"] += 1
                    dirs[:] = safe_dirs
                    for name in files:
                        try:
                            path, info = self._authorized(Path(current) / name)
                            hint = _NAME_HEX.search(name)
                            self.db.execute("INSERT OR REPLACE INTO inventory VALUES (?, ?, ?, ?)",
                                            (str(path), name, info.st_size,
                                             hint[1].lower() if hint else None))
                            self.stats["indexed"] += 1
                        except (OSError, ValueError):
                            self.stats["rejected"] += 1
            except OSError:
                self.stats["errors"] += 1
        self.db.commit()

    def _existing_path(self, relative):
        # Old indexes are relative to the account's parent. Never honor a root
        # supplied by the index itself (including its media_root column).
        if not isinstance(relative, str):
            raise ValueError("invalid relative index path")
        parts = relative.replace("\\", "/").split("/")
        if any(part in {"", ".", ".."} or ":" in part for part in parts):
            raise ValueError("invalid relative index path")
        if parts[0].casefold() == self.account_dir.name.casefold():
            return self.account_dir.joinpath(*parts[1:])
        if parts[0] == "__C_Downloads__":
            downloads = [root for root in self.extra_roots if root.name.casefold() == "downloads"]
            if len(downloads) == 1:
                return downloads[0].joinpath(*parts[1:])
        raise ValueError("index row belongs to another source root")

    def _candidates(self, size, filename, digest):
        if self.existing is not None:
            rows = self.existing.execute(
                "SELECT rel_path FROM files WHERE size=? ORDER BY "
                "CASE WHEN lower(basename)=lower(?) THEN 0 "
                "WHEN lower(md5_from_name)=? THEN 1 ELSE 2 END, rel_path", (size, filename, digest))
            for (relative,) in rows:
                try:
                    yield self._existing_path(relative)
                except ValueError:
                    self.stats["rejected"] += 1
        else:
            rows = self.db.execute(
                "SELECT path FROM inventory WHERE size=? ORDER BY "
                "CASE WHEN lower(basename)=lower(?) THEN 0 "
                "WHEN md5_hint=? THEN 1 ELSE 2 END, path", (size, filename, digest))
            for (path,) in rows:
                yield Path(path)

    def _hash(self, value, expected_size):
        path, before = self._authorized(value)
        if before.st_size != expected_size:
            return None
        signature = _signature(before)
        key = str(path)
        row = self.db.execute("SELECT size,mtime,ino,dev,ctime,md5,sha256 FROM hashes WHERE path=?",
                              (key,)).fetchone()
        if row and tuple(row[:5]) == signature:
            # Recheck metadata and links even for cached bytes.
            _, after = self._authorized(path)
            if _signature(after) != signature:
                raise ValueError("source changed during verification")
            self.stats["hash_cache_hits"] += 1
            return {"path": key, "size": expected_size, "md5": row[5], "sha256": row[6]}
        result = _read_verified(path, before, expected_size, self._authorized)
        self.db.execute("INSERT OR REPLACE INTO hashes VALUES (?,?,?,?,?,?,?,?)",
                        (key, *signature, result["md5"], result["sha256"]))
        self.db.commit()
        self.stats["hashes"] += 1
        return result

    def match(self, record):
        """Return actual digests only when size and every recorded MD5 agree."""
        digests = []
        for field in ("legacy_md5", "md5"):
            value = record.get(field)
            if value not in (None, "", b""):
                digest = _md5(value)
                if digest is None:
                    return None
                digests.append(digest)
        if not digests or len(set(digests)) != 1:
            return None
        size = record.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= (1 << 63) - 1:
            return None
        digest = digests[0]
        filename = ntpath.basename(str(record.get("filename") or ""))
        direct = record.get("local_path")
        candidates = self._candidates(size, filename, digest)
        seen = set()
        def paths():
            if direct:
                yield direct
            yield from candidates
        for candidate in paths():
            key = os.path.normcase(os.fspath(candidate))
            if key in seen:
                continue
            seen.add(key)
            self.stats["candidates"] += 1
            try:
                result = self._hash(candidate, size)
                if result and result["md5"] == digest:
                    return result
            except (OSError, ValueError):
                self.stats["rejected"] += 1
        return None

    def close(self):
        if getattr(self, "existing", None) is not None:
            self.existing.close()
            self.existing = None
        if getattr(self, "db", None) is not None:
            self.db.close()
            self.db = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
