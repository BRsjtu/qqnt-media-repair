"""Read-only QQNT media inventory. Requires QQ already stopped.

Run using the reviewed runtime:
uv run --python 3.13 --with sqlcipher3==0.6.4 -- python <this-file> --qq-stopped
Only one temporary encrypted snapshot is created by staged_database, then removed.
The script never publishes changes or saves raw message BLOBs/chat text.
"""
from __future__ import annotations

import argparse
from collections import Counter, OrderedDict
import datetime as dt
import json
import ntpath
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
from database_backend import staged_database, BackendError
from source_matcher import SourceMatcher
from broad_media_extract import extract_media
from fast_media_candidates import FastCandidates

PROFILE = "explicit-image-media-path-rehydration-v1"
TABLES = ("c2c_msg_table", "group_msg_table")
KINDS = {"image": 2, "file": 3, "voice": 4, "video": 5}
PREDICATE = ' OR '.join('instr("40800",?)>0' for _ in range(4))
TAGS = tuple(bytes.fromhex("d0fc15" + n) for n in ("02", "03", "04", "05"))


class ScanStopped(RuntimeError):
    pass


def emit(value):
    print(json.dumps(value, ensure_ascii=True, separators=(",", ":")), flush=True)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


class LRU:
    def __init__(self, limit):
        self.items, self.limit = OrderedDict(), limit

    def get(self, key):
        if key not in self.items:
            return False, None
        value = self.items.pop(key)
        self.items[key] = value
        return True, value

    def put(self, key, value):
        self.items.pop(key, None)
        self.items[key] = value
        if len(self.items) > self.limit:
            self.items.popitem(last=False)


def thumbnail_path(path):
    norm = str(path).replace("\\", "/").casefold()
    return any(p in {"thumb", "thumbs", "thumbnail", "thumbnails"} for p in norm.split("/")) or "_tmb" in Path(norm).name


class PathMapper:
    """Validate alias roots ONCE; per-media mapping is strictly lexical."""
    def __init__(self, roots, aliases=()):
        self.mappings = []
        account = roots[0]
        for root in roots:
            self.mappings.append((ntpath.normcase(str(root)).rstrip("\\"), str(root)))
        default_alias = Path.home() / "Documents/Tencent Files" / account.name
        for alias, explicit in [*((a, True) for a in aliases), (default_alias, False)]:
            alias = Path(alias).absolute()
            try:
                same_root = alias.resolve(strict=True) == account
            except (OSError, ValueError):
                same_root = False
            if not same_root:
                if explicit:
                    raise ValueError("explicit_path_alias_does_not_resolve_to_account")
                continue
            self.mappings.append((ntpath.normcase(ntpath.normpath(str(alias))).rstrip("\\"), str(account)))

    def map(self, raw):
        if not isinstance(raw, str) or not raw or ".." in raw.replace("/", "\\").split("\\"):
            return None
        normalized = ntpath.normpath(raw)
        key = ntpath.normcase(normalized)
        for prefix, physical in self.mappings:
            if key == prefix:
                return Path(physical)
            if key.startswith(prefix + "\\"):
                return Path(ntpath.join(physical, normalized[len(prefix) + 1:]))
        return None

    def direct_candidates(self, record):
        result = []
        for field in ("45403", "45814", "45812"):
            for raw in record.get("local_paths", {}).get(field, []):
                if not thumbnail_path(raw):
                    mapped = self.map(raw)
                    if mapped is not None and str(mapped) not in result:
                        result.append(str(mapped))
        return result


def unprobed_paths(record):
    return [{"field": field, "is_thumbnail_path": thumbnail_path(raw), "status": "unprobed"}
            for field, paths in record.get("local_paths", {}).items() for raw in paths]


def inspect_paths(record, mapper, cache):
    results = []
    for field, paths in record.get("local_paths", {}).items():
        for raw in paths:
            found, status = cache.get(raw)
            if not found:
                try:
                    resolved = mapper.map(raw)
                    if resolved is None:
                        status = {"status": "outside_authorized_roots"}
                    else:
                        try:
                            info = resolved.stat()
                            status = {"status": "exists" if stat.S_ISREG(info.st_mode) else "not_file",
                                      "resolved_path": str(resolved), "size": info.st_size}
                        except FileNotFoundError:
                            status = {"status": "missing", "resolved_path": str(resolved)}
                except (OSError, ValueError):
                    status = {"status": "path_probe_error"}
                cache.put(raw, status)
            results.append({"field": field, "is_thumbnail_path": thumbnail_path(raw), **status})
    return results


def metadata_key(record):
    if record.get("md5_conflict") or record.get("size_conflict") or record.get("type_conflict"):
        return None, "conflicting_metadata"
    invalid = record.get("invalid_md5_fields", {})
    if invalid.get("45406", 0) or invalid.get("45407", 0):
        return None, "invalid_primary_hash_metadata"
    digest = record.get("md5")
    size = record.get("size")
    if not digest:
        return None, "missing_metadata_md5"
    if type(size) is not int or not 0 <= size <= (1 << 63) - 1:
        return None, "missing_or_invalid_metadata_size"
    return (size, digest), None


def init_output(path):
    if path.exists():
        raise ValueError("output_exists_choose_new_run")
    con = sqlite3.connect(path)
    con.executescript('''
      PRAGMA journal_mode=DELETE;
      CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE verified_sources(source_id INTEGER PRIMARY KEY,size INTEGER NOT NULL,
        md5 TEXT NOT NULL,sha256 TEXT NOT NULL,path TEXT NOT NULL,
        UNIQUE(size,md5));
      CREATE TABLE verified_refs(table_code INTEGER NOT NULL,msg_id INTEGER NOT NULL,
        segment_path TEXT NOT NULL,source_id INTEGER NOT NULL,peer TEXT,ts INTEGER,
        kind INTEGER NOT NULL,category TEXT NOT NULL,nested INTEGER NOT NULL,
        failure_signal INTEGER NOT NULL,
        PRIMARY KEY(table_code,msg_id,segment_path));
      CREATE TABLE examples(category TEXT NOT NULL,ordinal INTEGER NOT NULL,
        details TEXT NOT NULL,PRIMARY KEY(category,ordinal));
      CREATE TABLE restore_targets(path TEXT PRIMARY KEY COLLATE NOCASE,source_id INTEGER NOT NULL,
        field INTEGER NOT NULL,table_code INTEGER NOT NULL,msg_id INTEGER NOT NULL,
        segment_path TEXT NOT NULL,kind INTEGER NOT NULL,expected_size INTEGER NOT NULL,
        expected_md5 TEXT NOT NULL,reference_count INTEGER NOT NULL DEFAULT 1);
      CREATE TABLE blocked_restore_paths(path TEXT PRIMARY KEY COLLATE NOCASE,reason TEXT NOT NULL);
      CREATE TABLE restore_target_conflicts(path TEXT NOT NULL,existing_source_id INTEGER NOT NULL,
        incoming_source_id INTEGER NOT NULL,table_code INTEGER NOT NULL,msg_id INTEGER NOT NULL,
        segment_path TEXT NOT NULL);
    ''')
    return con


def save_restore_targets(out, record, statuses, source_id, table_code, mid, account, counts):
    """Inventory explicit original paths only; this function NEVER copies bytes."""
    if record.get("nested_reference") or any(record.get(k) for k in ("md5_conflict", "size_conflict", "type_conflict")):
        counts["restore_targets.excluded_nested_or_conflicting_record"] += 1
        return
    base = account / "nt_qq/nt_data"
    for status in statuses:
        if status.get("field") != "45403" or status["status"] != "missing" or status["is_thumbnail_path"]:
            continue
        path = Path(status["resolved_path"])
        try:
            relative = path.relative_to(base)
        except ValueError:
            counts["restore_targets.excluded_outside_nt_media_originals"] += 1
            continue
        parts = relative.parts
        if len(parts) < 3 or parts[0].casefold() not in {"pic", "emoji", "ptt", "video", "file"} or not any(p.casefold() == "ori" for p in parts[1:-1]):
            counts["restore_targets.excluded_outside_nt_media_originals"] += 1
            continue
        target = str(path)
        if out.execute("SELECT 1 FROM blocked_restore_paths WHERE path=?", (target,)).fetchone():
            counts["restore_targets.blocked_conflict_references"] += 1
            continue
        existing = out.execute("SELECT source_id FROM restore_targets WHERE path=?", (target,)).fetchone()
        if existing and existing[0] != source_id:
            out.execute("INSERT INTO restore_target_conflicts VALUES (?,?,?,?,?,?)",
                        (target, existing[0], source_id, table_code, mid, compact(record["segment_path"])))
            out.execute("DELETE FROM restore_targets WHERE path=?", (target,))
            out.execute("INSERT INTO blocked_restore_paths VALUES (?,?)", (target, "conflicting_verified_source_ids"))
            counts["restore_targets.conflicting_paths"] += 1
            counts["restore_targets.active_unique_paths"] -= 1
            continue
        if existing:
            out.execute("UPDATE restore_targets SET reference_count=reference_count+1 WHERE path=?", (target,))
            counts["restore_targets.repeated_path_references"] += 1
        else:
            out.execute("INSERT INTO restore_targets VALUES (?,?,?,?,?,?,?,?,?,1)",
                        (target, source_id, 45403, table_code, mid, compact(record["segment_path"]),
                         KINDS[record["media_type"]], record["size"], record["md5"]))
            counts["restore_targets.active_unique_paths"] += 1


def scan(args):
    if not args.qq_stopped:
        raise ValueError("explicit_qq_stopped_attestation_required")
    args.account = args.account.resolve(strict=True)
    args.db = args.db or args.account / "nt_qq/nt_db/nt_msg.db"
    if args.db.resolve(strict=True) != (args.account / "nt_qq/nt_db/nt_msg.db").resolve(strict=True):
        raise ValueError("database_must_belong_to_selected_account")
    run = args.run.resolve()
    source_tree = Path(__file__).resolve().parents[3]
    if run == source_tree or source_tree in run.parents:
        raise ValueError("run_directory_must_be_outside_tool_repository")
    run.mkdir(parents=True, exist_ok=True)
    out_path, summary_path = run / "media-metadata.private.sqlite", run / "summary.json"
    counts, unknown, examples = Counter(), Counter(), Counter()
    match_cache, miss_cache, path_cache = (LRU(args.cache_entries) for _ in range(3))
    extra_roots = [args.downloads.resolve(strict=True)] if args.downloads else []
    roots = (args.account, *extra_roots)
    if any(run.is_relative_to(root) for root in roots):
        raise ValueError("run_directory_must_be_outside_authorized_source_roots")
    path_mapper = PathMapper(roots, getattr(args, "path_alias", []))
    out = init_output(out_path)
    started, last_progress = time.monotonic(), time.monotonic()
    stage_source, selector, stop_reason = None, None, None
    completed = False
    matcher_stats, fast_stats = {}, {}
    stop_file = getattr(args, "stop_file", None) or run / "STOP"
    last_stop_probe = 0.0

    def check_stop():
        nonlocal last_stop_probe
        now = time.monotonic()
        if now - last_stop_probe >= 0.5:
            last_stop_probe = now
            if stop_file.is_file():
                raise ScanStopped("stop_file")
            timeout = getattr(args, "timeout_seconds", 1800)
            if timeout and now - started >= timeout:
                raise ScanStopped("timeout")

    def progress(phase, table=None):
        nonlocal last_progress
        out.commit()
        last_progress = time.monotonic()
        emit({"phase": phase, "table": table,
              "candidate_rows": counts["candidate_rows"], "media_segments": counts["media_segments"],
              "verified_refs": counts["verified_refs"], "unique_verified_sources": counts["unique_verified_sources"],
              "matcher_calls": counts["matcher_calls"], "cache_hits": counts["match_cache_hits"],
              "elapsed_seconds": round(last_progress - started, 1)})

    try:
        with staged_database(args.db, args.key_file, run / "snapshot-work") as stage:
            stage_source = stage.source
            con = stage.connection
            con.execute("PRAGMA query_only=ON")
            with SourceMatcher(args.account, run / "source-work", extra_roots=extra_roots,
                               existing_index=args.index) as matcher:
                selector = FastCandidates(matcher, getattr(args, "content_hashes", None),
                                          max_unhinted=getattr(args, "max_unhinted_candidates", 128),
                                          exhaustive_size_fallback=getattr(args, "exhaustive_size_fallback", False),
                                          check_stop=check_stop)
                for table_code, table in enumerate(TABLES):
                    check_stop()
                    exists = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                    if not exists:
                        counts[table + ".absent"] += 1
                        continue
                    columns = {str(r[1]) for r in con.execute(f'PRAGMA table_info("{table}")')}
                    if not {"40001", "40800"} <= columns:
                        raise ValueError("required_message_columns_missing")
                    counts[table + ".total_rows"] = con.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                    peer = '"40030"' if "40030" in columns else "NULL"
                    timestamp = '"40050"' if "40050" in columns else "NULL"
                    emit({"phase": "table_start", "table": table, "total_rows": counts[table + ".total_rows"]})
                    # Four C-level byte predicates cover canonical media type
                    # encodings in mixed and nested messages. They are not a
                    # guarantee of coverage for unknown/noncanonical encodings.
                    cursor = con.execute(f'SELECT "40001",{peer},{timestamp},"40800" FROM "{table}" '
                                         f'WHERE typeof("40800")=\'blob\' AND ({PREDICATE})', TAGS)
                    for mid, peer_value, timestamp_value, blob in cursor:
                        check_stop()
                        counts["candidate_rows"] += 1
                        counts[table + ".candidate_rows"] += 1
                        records, stats = extract_media(blob)
                        counts["parse_status." + stats["status"]] += 1
                        counts["parse_failed_segments"] += stats["parse_failed"]
                        counts["bounded_out_rows"] += stats["bounded_out"]
                        counts["unsafe_path_fields"] += stats["unsafe_path_fields"]
                        counts["all_message_segments_in_candidates"] += stats["message_segments"]
                        unknown.update(stats["unknown_fields"])
                        for record in records:
                            kind = record["media_type"]
                            counts["media_segments"] += 1
                            counts[table + ".media_segments"] += 1
                            counts["kind." + kind] += 1
                            counts["nested_reference_segments"] += int(record["nested_reference"])
                            counts["md5_conflict_segments"] += int(record["md5_conflict"])
                            counts["alt_md5_differs_segments"] += int(record["alt_md5_differs"])
                            statuses = unprobed_paths(record)
                            cache_key, rejection = metadata_key(record)
                            source = None
                            lookup_status = "not_attempted_invalid_or_missing_metadata"
                            if rejection:
                                category = rejection
                            else:
                                direct_candidates = path_mapper.direct_candidates(record)
                                direct = direct_candidates[0] if direct_candidates else None
                                hit, source = match_cache.get(cache_key)
                                # A previously unseen direct original can be
                                # absent from the existing index. Never let a
                                # cached index miss suppress that direct path.
                                miss_key = (*cache_key, tuple(direct_candidates))
                                if not hit:
                                    hit, cached_miss = miss_cache.get(miss_key)
                                    if hit:
                                        lookup_status = cached_miss
                                if hit:
                                    counts["match_cache_hits"] += 1
                                    if source:
                                        lookup_status = "cached_verified_original"
                                else:
                                    matching_record = dict(record)
                                    # Normalize junction aliases before sending
                                    # a direct path through SourceMatcher policy.
                                    matching_record["local_path"] = direct
                                    matching_record["local_path_candidates"] = direct_candidates
                                    counts["matcher_calls"] += 1
                                    source = selector.match(matching_record)
                                    lookup_status = selector.last_status
                                    if source:
                                        match_cache.put(cache_key, source)
                                    else:
                                        miss_cache.put(miss_key, lookup_status)
                                if source:
                                    statuses = inspect_paths(record, path_mapper, path_cache)
                                missing = [s for s in statuses if s["status"] == "missing"]
                                if source:
                                    if record["known_failure_signal"]:
                                        category = "failure_signal_with_verified_original"
                                    elif missing and all(s["is_thumbnail_path"] for s in missing):
                                        category = "cache_missing_with_verified_original"
                                    elif missing:
                                        category = "local_reference_missing_with_verified_original"
                                    else:
                                        category = "verified_original_no_failure_signal"
                                elif record["known_failure_signal"]:
                                    category = "failure_signal_not_in_fast_index" if lookup_status == "not_in_fast_index" else "failure_signal_without_verified_original"
                                elif missing:
                                    category = "local_reference_missing_not_in_fast_index" if lookup_status == "not_in_fast_index" else "local_reference_missing_without_verified_original"
                                else:
                                    category = "not_in_fast_index" if lookup_status == "not_in_fast_index" else "original_not_matched_in_authorized_index"
                            record["source_lookup_status"] = lookup_status
                            counts["unprobed_media_records"] += int(source is None)
                            for status in statuses:
                                counts["path." + status["status"]] += 1
                            counts["source_lookup." + lookup_status] += 1
                            counts["category." + category] += 1
                            counts["kind_category." + kind + "." + category] += 1
                            if source:
                                cur = out.execute("INSERT OR IGNORE INTO verified_sources(size,md5,sha256,path) VALUES (?,?,?,?)",
                                                  (source["size"], source["md5"], source["sha256"], source["path"]))
                                counts["unique_verified_sources"] += int(cur.rowcount == 1)
                                sid = out.execute("SELECT source_id FROM verified_sources WHERE size=? AND md5=?", cache_key).fetchone()[0]
                                save_restore_targets(out, record, statuses, sid, table_code, mid, roots[0], counts)
                                out.execute("INSERT OR REPLACE INTO verified_refs VALUES (?,?,?,?,?,?,?,?,?,?)",
                                            (table_code, mid, compact(record["segment_path"]), sid,
                                             str(peer_value) if peer_value is not None else None,
                                             timestamp_value, KINDS[kind], category,
                                             int(record["nested_reference"]), int(record["known_failure_signal"])))
                                counts["verified_refs"] += 1
                            if examples[category] < args.examples_per_category:
                                example = {"table": table, "id": str(mid), "peer": peer_value,
                                           "ts": timestamp_value, "kind": kind, "metadata": record,
                                           "path_status": statuses, "source_verified": source}
                                out.execute("INSERT INTO examples VALUES (?,?,?)",
                                            (category, examples[category], compact(example)))
                                examples[category] += 1
                        if counts["candidate_rows"] % 25_000 == 0 or time.monotonic() - last_progress >= 30:
                            progress("scanning", table)
                            if out_path.stat().st_size > args.max_output_mib * 1024 * 1024:
                                raise ValueError("metadata_output_size_bound_exceeded")
                    progress("table_complete", table)
                matcher_stats = dict(matcher.stats)
                fast_stats = dict(selector.stats)
            # No writer or stage.publish calls exist in this script.
        completed = True
    except KeyboardInterrupt:
        stop_reason = "keyboard_interrupt"
        raise
    except ScanStopped as exc:
        stop_reason = str(exc)
        raise
    finally:
        if selector is not None:
            fast_stats = dict(selector.stats)
            matcher_stats = dict(selector.matcher.stats)
            selector.close()
        summary = {"profile": PROFILE, "completed": completed, "created": utc(), "elapsed_seconds": round(time.monotonic() - started, 1),
                   "scope": "canonical 40800 media types 2/3/4/5 in c2c/group; nested MsgContent.47710 included",
                   "counts": dict(counts), "unknown_fields": dict(unknown),
                   "example_counts": dict(examples), "matcher_stats": matcher_stats,
                   "fast_preselector_stats": fast_stats, "stop_reason": stop_reason,
                   "stop_file": str(stop_file), "exhaustive_size_fallback": getattr(args, "exhaustive_size_fallback", False),
                   "source_stage_metadata": stage_source, "metadata_database": str(out_path),
                   "no_database_changes": True, "raw_message_blobs_saved": False,
                   "limitations": ["no UI failure validation; categories are diagnostic signals",
                     "missing cached thumbnail is not missing original",
                     "not matched means not found by current authorized existing index, not proof of lost content",
                     "fast mode excludes nonmatching hash filenames and limits unhinted size candidates; not_in_fast_index is incomplete search",
                     "no metadata MD5 or conflicting metadata cannot establish original loss",
                     "canonical byte prefilter does not cover unknown/noncanonical protobuf encodings",
                     "nested references must not be automatically treated as repair targets"]}
        out.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", ("summary", compact(summary)))
        out.commit()
        out.close()
        summary["metadata_database_bytes"] = out_path.stat().st_size
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        emit({"phase": "scan_complete" if completed else "scan_incomplete", "summary": str(summary_path),
              "counts": dict(counts), "metadata_database_bytes": summary["metadata_database_bytes"]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qq-stopped", action="store_true", help="operator confirms QQ is stopped")
    parser.add_argument("--db", type=Path, help="default: <account>/nt_qq/nt_db/nt_msg.db")
    parser.add_argument("--account", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--index", type=Path, help="optional existing files index; otherwise build a local inventory")
    downloads = Path.home() / "Downloads"
    parser.add_argument("--downloads", type=Path, default=downloads if downloads.is_dir() else None)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--examples-per-category", type=int, default=200)
    parser.add_argument("--cache-entries", type=int, default=250_000)
    parser.add_argument("--max-output-mib", type=int, default=64)
    parser.add_argument("--content-hashes", type=Path, help="optional local legacy content-hash hints")
    parser.add_argument("--path-alias", type=Path, action="append", default=[], help="existing alias directory resolving exactly to account root")
    parser.add_argument("--timeout-seconds", type=int, default=1800, help="save partial results after this time; 0 disables")
    parser.add_argument("--max-unhinted-candidates", type=int, default=128)
    parser.add_argument("--exhaustive-size-fallback", action="store_true")
    parser.add_argument("--stop-file", type=Path, help="default: <run>/STOP; create this empty file to stop cleanly")
    args = parser.parse_args()
    if not 0 <= args.examples_per_category <= 200 or not 1 <= args.cache_entries <= 500_000 or not 1 <= args.max_output_mib <= 128 or not 0 <= args.max_unhinted_candidates <= 1024 or args.timeout_seconds < 0:
        parser.error("invalid bound")
    try:
        scan(args)
    except (KeyboardInterrupt, ScanStopped):
        emit({"phase": "stopped_cleanly", "message": "partial_metadata_saved_snapshot_context_cleaned"})
        raise SystemExit(130) from None
    except Exception as exc:
        # No exception message from SQLCipher/path APIs is printed: it could
        # contain content-bearing names or key material.
        emit({"error": type(exc).__name__, "message": str(exc) if isinstance(exc, (BackendError, ValueError)) else "private_scan_stopped"})
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
