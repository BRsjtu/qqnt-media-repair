"""Bounded local media-index preselector; all selected bytes are verified.

Index hints, including old content hashes, are candidate signals only. Failure
to find a match is `not_in_fast_index`, never evidence of original-file loss.
The wrapped reviewed SourceMatcher performs path authorization and actual
MD5+SHA256 verification. No database body or key is accessed by this module.
"""
from __future__ import annotations

from collections import Counter
import ntpath
from pathlib import Path
import re
import sqlite3

MAX_HASH_HINT_ROWS = 100_000


class FastCandidates:
    def __init__(self, matcher, content_hashes=None, *, max_unhinted=128,
                 exhaustive_size_fallback=False, check_stop=None):
        self.matcher = matcher
        self.index_connection = matcher.existing if matcher.existing is not None else matcher.db
        self.table = "files" if matcher.existing is not None else "inventory"
        self.path_column = "rel_path" if matcher.existing is not None else "path"
        self.hash_column = "md5_from_name" if matcher.existing is not None else "md5_hint"
        columns = {r[1] for r in self.index_connection.execute(f"PRAGMA table_info({self.table})")}
        self.has_media_categories = {"category", "media_root"} <= columns
        self.max_unhinted = max_unhinted
        self.exhaustive = exhaustive_size_fallback
        self.check_stop = check_stop or (lambda: None)
        self.stats = Counter()
        self.last_status = "not_in_fast_index"
        self.hashes = None
        self.hash_hints = {}
        if content_hashes and Path(content_hashes).is_file():
            self.hashes = sqlite3.connect(Path(content_hashes).resolve().as_uri() + "?mode=ro", uri=True)
            self.hashes.execute("PRAGMA query_only=ON")
            columns = {r[1] for r in self.hashes.execute("PRAGMA table_info(content_hashes)")}
            if not {"rel_path", "md5", "size", "error"} <= columns:
                self.hashes.close()
                self.hashes = None
                self.stats["legacy_hash_schema_unsupported"] += 1
            else:
                rows = self.hashes.execute("SELECT rel_path,md5,size FROM content_hashes WHERE error IS NULL AND md5 IS NOT NULL LIMIT ?", (MAX_HASH_HINT_ROWS + 1,))
                for index, (relative, md5, size) in enumerate(rows):
                    if index == MAX_HASH_HINT_ROWS:
                        self.stats["legacy_hash_hint_limit_reached"] += 1
                        break
                    if (not isinstance(relative, str) or not isinstance(md5, str)
                            or not re.fullmatch(r"[0-9a-fA-F]{32}", md5)
                            or type(size) is not int or not 0 <= size <= (1 << 63) - 1):
                        self.stats["invalid_legacy_hash_hint"] += 1
                        continue
                    self.hash_hints.setdefault((size, md5.lower()), []).append(relative)

    def close(self):
        if self.hashes is not None:
            self.hashes.close()
            self.hashes = None

    def _rows(self, size, filename, md5):
        con = self.index_connection
        table, path, hint = self.table, self.path_column, self.hash_column
        # Names above come only from fixed schema constants. Existing input
        # indexes remain read-only; the automatic inventory belongs to the run.
        for (relative,) in con.execute(f"SELECT {path} FROM {table} WHERE {hint}=? AND size=?", (md5, size)):
            yield "filename_md5_size", relative
        if filename:
            for (relative,) in con.execute(f"SELECT {path} FROM {table} WHERE basename=? COLLATE NOCASE AND size=?", (filename, size)):
                yield "basename_size", relative
        if self.hashes is not None:
            for relative in self.hash_hints.get((size, md5.lower()), ()):
                yield "legacy_actual_md5_size", relative
        # Filename hashes different from the message's MD5 are deliberately
        # omitted here. They remain discoverable with explicit exhaustive mode.
        order = ("CASE WHEN lower(category)='ori' THEN 0 "
                 "WHEN lower(media_root) IN ('filerecv','nt_file','nt_ptt') THEN 1 ELSE 2 END," + path
                 if self.has_media_categories else path)
        rows = con.execute(f"SELECT {path} FROM {table} WHERE size=? AND ({hint} IS NULL OR {hint}='') "
                           f"ORDER BY {order} LIMIT ?", (size, self.max_unhinted + 1))
        for index, (relative,) in enumerate(rows):
            if index == self.max_unhinted:
                self.stats["unhinted_size_candidate_limit_reached"] += 1
                break
            yield "unhinted_filename_size", relative

    def match(self, record):
        self.check_stop()
        size, md5 = record.get("size"), record.get("md5")
        filename = ntpath.basename(record.get("filename") or "")
        direct = record.get("local_path")
        seen = set()
        self.stats["queries"] += 1
        self.last_status = "not_in_fast_index"

        def candidates():
            direct_paths = record.get("local_path_candidates") or ([direct] if direct else [])
            for direct_path in direct_paths:
                yield "direct_path", Path(direct_path)
            for method, relative in self._rows(size, filename, md5):
                try:
                    yield method, (self.matcher._existing_path(relative)
                                   if self.matcher.existing is not None else Path(relative))
                except ValueError:
                    self.stats["rejected_index_path"] += 1

        for method, path in candidates():
            self.check_stop()
            token = ntpath.normcase(str(path))
            if token in seen:
                continue
            seen.add(token)
            self.stats["candidate." + method] += 1
            self.matcher.stats["candidates"] += 1
            try:
                source = self.matcher._hash(path, size)
                if source and source["md5"] == md5:
                    self.stats["matched." + method] += 1
                    self.last_status = "verified_fast_candidate"
                    return source
                self.stats["candidate_content_mismatch"] += 1
            except (OSError, ValueError):
                self.matcher.stats["rejected"] += 1
                self.stats["candidate_rejected_or_unreadable"] += 1
        if self.exhaustive:
            self.check_stop()
            self.stats["exhaustive_size_fallback_calls"] += 1
            source = self.matcher.match(record)
            if source:
                self.last_status = "verified_exhaustive_size_fallback"
                self.stats["matched.exhaustive_size_fallback"] += 1
                return source
            self.last_status = "not_matched_in_authorized_size_inventory"
        self.stats[self.last_status] += 1
        return None
