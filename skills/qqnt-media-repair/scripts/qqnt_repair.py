"""Local-only inventory, encrypted repair plans, bulk apply and row-level rollback."""
from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys

from database_backend import BackendError, encrypted_archive, staged_database
from media_profile import ProfileError, inspect_body, normalize_body
from source_matcher import SourceMatcher, verify_source

PROFILE = "legacy-file-subtype1-ascii-md5-failed-v1"
TABLES = ("c2c_msg_table", "group_msg_table")


def emit(value):
    print(json.dumps(value, ensure_ascii=True), flush=True)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def identity(columns, row):
    values = []
    for column, value in zip(columns, row):
        if str(column) == "40800":
            continue
        if isinstance(value, bytes):
            value = {"bytes_sha256": digest(value), "size": len(value)}
        values.append([column, type(value).__name__, value])
    return digest(json.dumps(values, ensure_ascii=True, separators=(",", ":")).encode())


def meta_get(conn, key):
    result = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return json.loads(result[0]) if result else None


def meta_set(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value, ensure_ascii=True)))


def init_plan(conn):
    conn.executescript('''
      CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE repairs(table_name TEXT NOT NULL,msg_id TEXT NOT NULL,
        old_body BLOB NOT NULL,new_body BLOB NOT NULL,identity_hash TEXT NOT NULL,
        sources TEXT NOT NULL,changed_segments INTEGER NOT NULL,
        PRIMARY KEY(table_name,msg_id));
      CREATE TABLE events(time TEXT NOT NULL,event TEXT NOT NULL,details TEXT NOT NULL);
    ''')


def event(conn, name, details):
    conn.execute("INSERT INTO events VALUES (?,?,?)", (now(), name, json.dumps(details)))


def validate_layout(account, database):
    account, database = account.resolve(strict=True), database.resolve(strict=True)
    if database != account / "nt_qq" / "nt_db" / "nt_msg.db":
        raise ValueError("database must be the selected account's nt_qq/nt_db/nt_msg.db")
    return account, database


def scan(args):
    account, database = validate_layout(args.account, args.db)
    run = args.run.resolve()
    # Private runtime material must not be written into the source/skill tree.
    source_tree = Path(__file__).resolve().parents[3]
    if run == source_tree or source_tree in run.parents:
        raise ValueError("run directory must be outside the tool repository")
    run.mkdir(parents=True, exist_ok=True)
    plan = run / "plan.sqlite"
    if plan.exists():
        raise ValueError("a plan already exists; select a new run directory")
    counts = Counter()
    # Field 45002, varint value 3. This broad SQL byte filter includes mixed
    # messages; the bounded parser then checks every 40800 segment exactly.
    file_tag = bytes.fromhex("d0fc1503")
    with staged_database(database, args.key_file, run) as stage:
        with encrypted_archive(plan, args.key_file) as output:
            init_plan(output)
            meta_set(output, "profile", PROFILE)
            meta_set(output, "db", str(database))
            meta_set(output, "account", str(account))
            meta_set(output, "qq_build", args.qq_build)
            meta_set(output, "profile_sha256", digest((Path(__file__).parent / "media_profile.py").read_bytes()))
            meta_set(output, "source", stage.source)
            meta_set(output, "extra_roots", [str(p.resolve(strict=True)) for p in args.extra_root])
            meta_set(output, "created", now())
            with SourceMatcher(account, run, extra_roots=args.extra_root,
                               existing_index=args.existing_index) as matcher:
                for table in TABLES:
                    exists = stage.connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                    if not exists:
                        counts[table + ".absent"] += 1
                        continue
                    count = stage.connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                    counts[table + ".total_rows"] = count
                    emit({"phase": "scan_table", "table": table, "total_rows": count})
                    cur = stage.connection.execute(f'SELECT * FROM "{table}" WHERE instr("40800",?)>0', (file_tag,))
                    columns = [str(c[0]) for c in cur.description]
                    body_i, id_i = columns.index("40800"), columns.index("40001")
                    for row in cur:
                        counts[table + ".candidate_rows"] += 1
                        old = row[body_i]
                        if not isinstance(old, bytes):
                            counts["non_blob"] += 1
                            continue
                        try:
                            inspected = inspect_body(old)
                        except ProfileError:
                            counts["malformed_or_bounded_out"] += 1
                            continue
                        replacements, sources = {}, []
                        for record in inspected["records"]:
                            if not record["failure_pattern_eligible"]:
                                if record["supported_profile"]:
                                    counts["profile_without_validated_failure"] += 1
                                elif record["element_type"] == 3:
                                    counts["unsupported_file_profile"] += 1
                                else:
                                    counts["other_segments"] += 1
                                continue
                            counts["eligible_segments"] += 1
                            source = matcher.match(record)
                            if source is None:
                                counts["original_not_matched_in_authorized_roots"] += 1
                                continue
                            ordinal = record["segment_ordinal"]
                            replacements[ordinal] = {"source_path": source["path"], "size": source["size"], "md5": source["md5"]}
                            sources.append({**source, "ordinal": ordinal})
                        if not replacements:
                            continue
                        try:
                            new, changes = normalize_body(old, replacements)
                        except ProfileError:
                            counts["normalization_rejected"] += 1
                            continue
                        if new == old:
                            counts["already_normalized"] += 1
                            continue
                        output.execute("INSERT INTO repairs VALUES (?,?,?,?,?,?,?)", (
                            table, str(row[id_i]), old, new, identity(columns, row),
                            json.dumps(sources, ensure_ascii=True), len(changes["changed_segments"])))
                        counts["planned_rows"] += 1
                        counts["planned_segments"] += len(changes["changed_segments"])
                        counts[table + ".planned_rows"] += 1
                        if counts["planned_rows"] % 100 == 0:
                            emit({"phase": "planning", "planned_rows": counts["planned_rows"]})
                meta_set(output, "matcher_stats", matcher.stats)
            meta_set(output, "counts", dict(counts))
            event(output, "scan_complete", dict(counts))
            output.commit()
    summary = {"phase": "scan_complete", "profile": PROFILE, "counts": dict(counts)}
    (run / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    emit(summary)


def confirm_ui(args):
    if not 1 <= args.sample_count <= 2:
        raise ValueError("confirm one or two representative original chat cards")
    if not args.evidence:
        raise ValueError("record a short local-only native-UI evidence note")
    with encrypted_archive(args.run / "plan.sqlite", args.key_file) as plan:
        if not args.existing_cases and not meta_get(plan, "sample_applied"):
            raise ValueError("first apply samples, or explicitly attest previously verified cases")
        proof = {"time": now(), "sample_count": args.sample_count,
                 "qq_build": meta_get(plan, "qq_build"), "profile": PROFILE,
                 "profile_sha256": meta_get(plan, "profile_sha256"),
                 "evidence": args.evidence, "existing_cases": args.existing_cases}
        meta_set(plan, "ui_confirmation", proof)
        event(plan, "ui_confirmed", {"sample_count": args.sample_count})
        plan.commit()
    emit({"phase": "profile_confirmed", "sample_count": args.sample_count,
          "note": "operator attestation of native QQ UI, not an automated UI test"})


def source_unchanged(source, allowed_roots):
    verify_source(source, allowed_roots)


def apply(args, rollback=False):
    run = args.run.resolve(strict=True)
    with encrypted_archive(run / "plan.sqlite", args.key_file) as plan:
        if meta_get(plan, "profile") != PROFILE:
            raise ValueError("unknown plan profile")
        if meta_get(plan, "profile_sha256") != digest((Path(__file__).parent / "media_profile.py").read_bytes()):
            raise ValueError("profile changed after planning; rescan")
        database, account = Path(meta_get(plan, "db")), Path(meta_get(plan, "account"))
        validate_layout(account, database)
        if not rollback and not args.sample and not meta_get(plan, "ui_confirmation"):
            raise ValueError("native QQ sample validation is required before bulk apply")
        entries = plan.execute("SELECT table_name,msg_id,old_body,new_body,identity_hash,sources FROM repairs ORDER BY table_name,msg_id").fetchall()
        if args.sample and not rollback:
            entries = entries[:args.sample]
        allowed = [account.resolve(strict=True)] + [Path(p).resolve(strict=True) for p in meta_get(plan, "extra_roots")]
        updates, checked, counts = [], set(), Counter()
        with staged_database(database, args.key_file, run) as stage:
            for table, msg_id, old, new, ident, source_json in entries:
                if table not in TABLES:
                    raise ValueError("unknown target table")
                cur = stage.connection.execute(f'SELECT * FROM "{table}" WHERE "40001"=?', (int(msg_id),))
                columns = [str(c[0]) for c in cur.description]
                rows = cur.fetchall()
                if len(rows) != 1:
                    counts["missing_or_nonunique_rows"] += 1
                    continue
                row = rows[0]
                body = row[columns.index("40800")]
                expected, desired = (new, old) if rollback else (old, new)
                if body == desired:
                    counts["already_in_desired_state"] += 1
                    continue
                if body != expected or identity(columns, row) != ident:
                    counts["changed_since_plan"] += 1
                    continue
                if not rollback:
                    for source in json.loads(source_json):
                        token = (source["path"], source["sha256"])
                        if token not in checked:
                            source_unchanged(source, allowed)
                            checked.add(token)
                updates.append({"table": table, "msg_id": int(msg_id), "old_body": expected, "new_body": desired})
            # Plan is already a committed encrypted before/after-row rollback archive.
            if updates:
                result = stage.publish(updates)
                counts["updated_rows"] = len(updates)
            else:
                result = {"published": False, "reason": "no unchanged eligible rows"}
        action = "rollback" if rollback else ("sample" if args.sample else "bulk")
        meta_set(plan, "last_" + action, {"time": now(), "counts": dict(counts), "database_result": result})
        if action == "sample" and updates:
            meta_set(plan, "sample_applied", len(updates))
        event(plan, action, dict(counts))
        plan.commit()
    summary = {"phase": action + "_complete", "counts": dict(counts), "database_result": result}
    (run / (action + "-result.json")).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    emit(summary)


def status(args):
    with encrypted_archive(args.run / "plan.sqlite", args.key_file, readonly=True) as plan:
        emit({"profile": meta_get(plan, "profile"), "qq_build": meta_get(plan, "qq_build"),
              "counts": meta_get(plan, "counts"), "ui_confirmed": bool(meta_get(plan, "ui_confirmation")),
              "last_bulk": meta_get(plan, "last_bulk"), "last_rollback": meta_get(plan, "last_rollback")})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="read-only full-table inventory and encrypted dry-run plan")
    s.add_argument("--db", type=Path, required=True)
    s.add_argument("--account", type=Path, required=True)
    s.add_argument("--qq-build", required=True)
    s.add_argument("--existing-index", type=Path)
    s.add_argument("--extra-root", type=Path, action="append", default=[])
    for name in ("confirm-ui", "apply", "rollback", "status"):
        sub.add_parser(name)
    for p in sub.choices.values():
        p.add_argument("--run", type=Path, required=True)
        p.add_argument("--key-file", type=Path, required=True)
    c = sub.choices["confirm-ui"]
    c.add_argument("--sample-count", type=int, required=True)
    c.add_argument("--evidence", required=True)
    c.add_argument("--existing-cases", action="store_true", help="attest the same profile already verified on this database/build")
    sub.choices["apply"].add_argument("--sample", type=int, choices=(1, 2))
    sub.choices["rollback"].set_defaults(sample=None)
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("this database adapter currently supports Windows only")
    try:
        if args.command == "scan": scan(args)
        elif args.command == "confirm-ui": confirm_ui(args)
        elif args.command == "apply": apply(args)
        elif args.command == "rollback": apply(args, rollback=True)
        else: status(args)
    except Exception as exc:
        # Detailed exception strings can contain database paths or source names.
        emit({"error": type(exc).__name__, "message": str(exc) if isinstance(exc, BackendError) else "operation stopped; inspect the local environment and CLI requirements"})
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
