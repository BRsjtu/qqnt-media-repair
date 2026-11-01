"""Restore explicitly recorded QQNT image paths from byte-verified local sources.

Default mode is a dry run. This tool never opens the QQ main database and never
changes metadata. Apply mode creates only absent files and writes a private
manifest; it does not overwrite or delete anything.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import sys
import tempfile

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
from source_matcher import verify_source


def _safe_stat(path: Path):
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400):
        raise ValueError("reparse_point")
    return st


def _assert_tree(path: Path, root: Path, *, allow_missing: bool):
    """Reject links/reparse points in every existing component below root."""
    root = root.resolve(strict=True)
    path = Path(os.path.abspath(path))
    if not path.is_relative_to(root):
        raise ValueError("target_escape")
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        try:
            _safe_stat(current)
        except FileNotFoundError:
            if allow_missing:
                continue
            raise
    return path


def _validate_windows_components(raw: str):
    import ntpath
    if not isinstance(raw, str) or not raw or any(ord(ch) < 32 for ch in raw):
        raise ValueError("invalid_windows_path")
    if raw.startswith(("\\\\", "//")) or raw.startswith(("\\\\?\\", "\\\\.\\")):
        raise ValueError("device_or_unc_path")
    drive, tail = ntpath.splitdrive(raw)
    if not drive or len(drive) != 2 or drive[1] != ":" or ":" in tail:
        raise ValueError("device_or_ads_path")
    for part in raw[len(drive):].replace("/", "\\").split("\\"):
        if not part:
            continue
        if part in {".", ".."} or part[-1:] in {".", " "} or any(c in part for c in '<>"|?*'):
            raise ValueError("invalid_windows_component")
        stem = part.split(".", 1)[0].rstrip(" .").casefold()
        if stem in {"con", "prn", "aux", "nul"} or stem in {f"com{i}" for i in range(1,10)} or stem in {f"lpt{i}" for i in range(1,10)}:
            raise ValueError("reserved_windows_name")


MEDIA_KINDS={"image":2,"file":3,"video":5}
IMAGE_EXTS={".jpg",".jpeg",".png",".gif",".webp",".bmp"}
VIDEO_EXTS={".mp4",".mov",".m4v",".webm",".mkv",".avi",".wmv",".flv",".ts",".mts",".3gp"}


def _target_policy(raw: str, account: Path, *, kind="image", preview=False) -> Path:
    _validate_windows_components(raw)
    p = Path(raw)
    if not p.is_absolute() or ".." in p.parts or "\x00" in raw:
        raise ValueError("invalid_target_path")
    q = Path(os.path.abspath(p))
    if not q.is_relative_to(account):
        raise ValueError("target_escape")
    rel = q.relative_to(account)
    parts = [x.casefold() for x in rel.parts]
    if len(parts) < 6 or parts[:2] != ["nt_qq", "nt_data"]:
        raise ValueError("target_outside_nt_media")
    roots={"image":{"pic","emoji"},"video":{"video"},"file":{"file"}}
    if kind not in roots or parts[2] not in roots[kind]:
        raise ValueError("target_not_allowed_kind")
    expected_parent = "thumb" if preview else "ori"
    if expected_parent not in parts[3:-1]:
        raise ValueError("target_wrong_media_directory")
    suffix=Path(rel).suffix.casefold()
    if kind=="image" and not preview and suffix not in IMAGE_EXTS:
        raise ValueError("unsupported_image_extension")
    if kind=="video" and suffix not in VIDEO_EXTS:
        raise ValueError("unsupported_video_extension")
    if preview and (kind!="image" or suffix not in IMAGE_EXTS):
        raise ValueError("preview_extension_not_image")
    return _assert_tree(q, account, allow_missing=True)


def _source_roots(account: Path):
    roots = [account.resolve(strict=True)]
    downloads = Path.home() / "Downloads"
    try:
        if downloads.is_dir():
            resolved = downloads.resolve(strict=True)
            if resolved not in roots:
                roots.append(resolved)
    except OSError:
        pass
    return roots


def _canonical_source(value, roots, account, aliases=()):
    """Resolve only explicitly supplied aliases that point to the account root."""
    raw = Path(value).absolute()
    lexical_roots = list(roots)
    for alias in aliases:
        try:
            alias_path = Path(alias).absolute()
            if alias_path.resolve(strict=True) != account:
                raise ValueError("source_alias_must_resolve_to_account")
            lexical_roots.append(alias_path)
        except OSError:
            pass
    if not any(raw.is_relative_to(root) for root in lexical_roots):
        raise ValueError("source_outside_authorized_roots")
    resolved = raw.resolve(strict=True)
    if not any(resolved.is_relative_to(root) for root in roots):
        raise ValueError("source_resolves_outside_authorized_roots")
    return resolved


def _verify_source(plan, roots, account, aliases=()):
    source_path = _canonical_source(plan["source"], roots, account, aliases)
    return verify_source({"path": str(source_path), "size": plan["size"],
                          "md5": plan["md5"], "sha256": plan["sha256"]}, roots)


def _hash_file(path: Path):
    md5, sha = hashlib.md5(), hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            md5.update(block)
            sha.update(block)
    return {"size": size, "md5": md5.hexdigest(), "sha256": sha.hexdigest()}


def _matches_source_if_present(path: Path, source):
    """Allow a prior Ori restore only when its current bytes equal this source."""
    try:
        st=_safe_stat(path)
    except FileNotFoundError:
        return True
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        return False
    actual=_hash_file(path)
    return (actual["size"],actual["md5"],actual["sha256"]) == (source["size"],source["md5"].lower(),source["sha256"].lower())


def _existing_preview_status(path: Path):
    """Protect existing cache bytes; thumbnails need not equal their originals."""
    try:
        st=_safe_stat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return "protected_existing_preview", None
        actual=_hash_file(path)
        _image_decodes(path)
        return "preserved_existing_preview", actual
    except Exception:
        return "protected_existing_preview", None


def _image_decodes(path: Path):
    try:
        from PIL import Image
    except ImportError as exc:
        raise ValueError("pillow_unavailable") from exc
    with Image.open(path) as image:
        if image.format not in {"JPEG", "PNG", "GIF", "WEBP", "BMP"}:
            raise ValueError("not_decodable_image")
        image.verify()


def _read_plan(db_path: Path, account: Path, only_msg_id=None, include_previews=False, media_kinds=("image",)):
    uri = db_path.resolve(strict=True).as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    db.row_factory = sqlite3.Row
    required = {
        "restore_targets": {"path", "source_id", "field", "table_code", "msg_id", "segment_path", "kind", "expected_size", "expected_md5"},
        "verified_sources": {"source_id", "size", "md5", "sha256", "path"},
        "blocked_restore_paths": {"path", "reason"},
        "restore_target_conflicts": {"path", "existing_source_id", "incoming_source_id"},
        "verified_refs": {"table_code", "msg_id", "segment_path", "source_id", "kind", "nested"},
    }
    for table, columns in required.items():
        actual = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        if not columns <= actual:
            db.close()
            raise ValueError("metadata_schema_mismatch")
    selected=tuple(k for k in MEDIA_KINDS if k in media_kinds)
    if not selected:
        db.close()
        return [],0
    kind_ids=tuple(MEDIA_KINDS[k] for k in selected)
    query = """SELECT t.*,s.size AS source_size,s.md5 AS source_md5,
                      s.sha256 AS source_sha256,s.path AS source_path
                 FROM restore_targets t JOIN verified_sources s USING(source_id)
                 WHERE t.kind IN ({}) AND t.field=45403""".format(",".join("?" for _ in kind_ids))
    args = list(kind_ids)
    if only_msg_id is not None:
        query += " AND t.msg_id=?"
        args.append(only_msg_id)
    query += " ORDER BY t.path"
    targets = []
    for row in db.execute(query, args):
        kind_name=next(k for k,v in MEDIA_KINDS.items() if v==row["kind"])
        path = _target_policy(row["path"], account,kind=kind_name)
        if row["source_size"] != row["expected_size"] or row["source_md5"].lower() != row["expected_md5"].lower():
            continue
        if db.execute("SELECT 1 FROM blocked_restore_paths WHERE path=?", (row["path"],)).fetchone():
            continue
        if db.execute("SELECT 1 FROM restore_target_conflicts WHERE path=?", (row["path"],)).fetchone():
            continue
        ref = db.execute("""SELECT 1 FROM verified_refs WHERE table_code=? AND msg_id=?
                            AND segment_path=? AND source_id=? AND kind=? AND nested=0 LIMIT 1""",
                         (row["table_code"], row["msg_id"], row["segment_path"], row["source_id"],row["kind"])).fetchone()
        if not ref:
            continue
        targets.append({"target": str(path), "source": row["source_path"], "size": row["source_size"],
                        "md5": row["source_md5"].lower(), "sha256": row["source_sha256"].lower(),
                        "msg_id": row["msg_id"], "field": row["field"], "kind": row["kind"],
                        "table_code": row["table_code"], "segment_path": row["segment_path"],
                        "media_kind":kind_name,
                        "preview": False})
    if include_previews and "image" in selected:
        has_declared = "declared_restoration_previews" in {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if has_declared:
            pvcols={r[1] for r in db.execute("PRAGMA table_info(declared_restoration_previews)")}
            if not {"path","source_id","field","table_code","msg_id","segment_path"} <= pvcols:
                db.close()
                raise ValueError("declared_previews_schema_mismatch")
            pvq = """SELECT p.path,p.field,p.msg_id,p.table_code,p.segment_path,p.source_id,
                            s.path AS source_path,s.size,s.md5,s.sha256,t.path AS original_path
                     FROM declared_restoration_previews p
                     JOIN verified_sources s ON s.source_id=p.source_id
                     JOIN restore_targets t ON t.source_id=p.source_id AND t.table_code=p.table_code
                       AND t.msg_id=p.msg_id AND t.segment_path=p.segment_path
                       AND t.field=45403 AND t.kind=2 AND t.expected_size=s.size
                       AND lower(t.expected_md5)=lower(s.md5)
                     JOIN verified_refs r ON r.source_id=p.source_id AND r.table_code=p.table_code
                       AND r.msg_id=p.msg_id AND r.segment_path=p.segment_path AND r.kind=2 AND r.nested=0
                     WHERE p.field IN (45812,45814)
                       AND NOT EXISTS(SELECT 1 FROM blocked_restore_paths b WHERE b.path=p.path)
                       AND NOT EXISTS(SELECT 1 FROM restore_target_conflicts c WHERE c.path=p.path)"""
            pva=[]
            if only_msg_id is not None:
                pvq += " AND p.msg_id=?"; pva.append(only_msg_id)
            for row in db.execute(pvq, pva):
                try:
                    op = _target_policy(row["original_path"], account,kind="image")
                    if not _matches_source_if_present(op,row):
                        continue
                    path = _target_policy(row["path"], account,kind="image",preview=True)
                    targets.append({"target":str(path),"source":row["source_path"],"size":row["size"],
                                    "md5":row["md5"].lower(),"sha256":row["sha256"].lower(),
                                    "msg_id":row["msg_id"],"field":row["field"],"kind":2,
                                    "table_code":row["table_code"],"segment_path":row["segment_path"],
                                    "media_kind":"image","preview":True})
                except (OSError, ValueError):
                    continue
        else:
            cats=("cache_missing_with_verified_original","local_reference_missing_with_verified_original")
            for (details,) in db.execute("SELECT details FROM examples WHERE category IN (?,?)",cats):
                try:
                    item=json.loads(details); source=item.get("source_verified") or {}; meta=item.get("metadata",{})
                    if item.get("kind")!="image" or not source or not meta.get("segment_path"):
                        continue
                    orig_missing=any(x.get("field")=="45403" and not x.get("is_thumbnail_path") and x.get("status")=="missing" for x in item.get("path_status",[]))
                    if not orig_missing or (only_msg_id is not None and int(item.get("id"))!=only_msg_id):
                        continue
                    src=db.execute("SELECT source_id FROM verified_sources WHERE size=? AND lower(md5)=lower(?) AND lower(sha256)=lower(?) AND path=?",
                                   (source.get("size"),source.get("md5"),source.get("sha256"),source.get("path"))).fetchone()
                    if not src:
                        continue
                    refs=db.execute("""SELECT t.path,t.table_code,t.msg_id,t.segment_path FROM restore_targets t
                        JOIN verified_refs r ON r.source_id=t.source_id AND r.table_code=t.table_code AND r.msg_id=t.msg_id
                          AND r.segment_path=t.segment_path AND r.kind=2 AND r.nested=0
                        WHERE t.source_id=? AND t.msg_id=? AND t.segment_path=? AND t.field=45403 AND t.kind=2
                          AND t.expected_size=? AND lower(t.expected_md5)=lower(?)""",
                        (src[0],int(item["id"]),meta["segment_path"],source["size"],source["md5"])).fetchall()
                    for ref in refs:
                        if not _matches_source_if_present(_target_policy(ref["path"],account,kind="image"),source):
                            continue
                        for declared in item.get("path_status",[]):
                            if declared.get("field") not in {"45812","45814"} or not declared.get("is_thumbnail_path") or declared.get("status")!="missing" or not declared.get("resolved_path"):
                                continue
                            path=_target_policy(declared["resolved_path"],account,kind="image",preview=True)
                            targets.append({"target":str(path),"source":source["path"],"size":source["size"],"md5":source["md5"].lower(),"sha256":source["sha256"].lower(),"msg_id":int(item["id"]),"field":int(declared["field"]),"kind":2,"media_kind":"image","table_code":ref[1],"segment_path":ref[3],"preview":True})
                except (KeyError,TypeError,ValueError,json.JSONDecodeError):
                    continue
    db.close()
    # One destination with multiple identities is never chosen implicitly.
    grouped = {}
    conflicts = set()
    for t in targets:
        key = os.path.normcase(t["target"])
        old = grouped.get(key)
        if old and (old["size"], old["md5"], old["sha256"]) != (t["size"], t["md5"], t["sha256"]):
            conflicts.add(key)
        else:
            grouped[key] = t
    return [t for k, t in grouped.items() if k not in conflicts], len(conflicts)


def _copy_exclusive(plan, account, roots, aliases=()):
    target = Path(plan["target"])
    _assert_tree(target.parent, account, allow_missing=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_tree(target.parent, account, allow_missing=False)
    if target.exists():
        if plan["preview"]:
            return _existing_preview_status(target)
        st = _safe_stat(target)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise ValueError("target_not_single_link_regular_file")
        actual = _hash_file(target)
        if (actual["size"], actual["md5"], actual["sha256"]) == (plan["size"], plan["md5"], plan["sha256"]):
            return "already_present", actual
        raise FileExistsError("target_exists_with_different_bytes")
    proof = _verify_source(plan, roots, account, aliases)
    if plan["preview"]:
        _image_decodes(Path(proof["path"]))
    fd, tmp_name = tempfile.mkstemp(prefix=".qqnt-restore-", suffix=".tmp", dir=target.parent)
    tmp = Path(tmp_name)
    try:
        md5, sha, size = hashlib.md5(), hashlib.sha256(), 0
        with os.fdopen(fd, "wb") as out, open(proof["path"], "rb") as src:
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                out.write(block)
                size += len(block)
                md5.update(block)
                sha.update(block)
            out.flush()
            os.fsync(out.fileno())
        actual = {"size": size, "md5": md5.hexdigest(), "sha256": sha.hexdigest()}
        if (size, actual["md5"], actual["sha256"]) != (plan["size"], plan["md5"], plan["sha256"]):
            raise ValueError("copy_hash_mismatch")
        _verify_source(plan, roots, account, aliases)
        _assert_tree(target.parent, account, allow_missing=False)
        try:
            if os.name == "nt":
                os.rename(tmp, target)  # Windows rename fails if destination exists.
            else:
                os.link(tmp, target)  # Atomic no-clobber publish on POSIX.
                tmp.unlink()
        except FileExistsError:
            if plan["preview"]:
                return _existing_preview_status(target)
            raise FileExistsError("target_appeared_during_restore") from None
        try:
            dfd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
        if plan["preview"]:
            _image_decodes(target)
        final = _hash_file(target)
        if final != actual:
            raise ValueError("target_hash_mismatch_after_publish")
        return "created", final
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def run(args):
    account = args.account.resolve(strict=True)
    if not account.is_dir():
        raise ValueError("account_not_directory")
    roots = _source_roots(account)
    aliases = getattr(args, "source_alias", ())
    media_kinds=getattr(args,"media_kinds",("image",))
    plans, identity_conflicts = _read_plan(args.metadata_db, account, args.only_msg_id,
                                           args.include_declared_previews,media_kinds)
    outcomes = []
    bytes_to_add = 0
    for p in plans:
        target = Path(p["target"])
        if target.exists():
            if p["preview"]:
                status, actual = _existing_preview_status(target)
                outcomes.append({"plan":p,"status":status,**({"target_hash":actual} if actual else {})})
                continue
            try:
                st = _safe_stat(target)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise ValueError("target_not_single_link_regular_file")
                actual = _hash_file(target)
                status = "already_present" if (actual["size"], actual["md5"], actual["sha256"]) == (p["size"],p["md5"],p["sha256"]) else "exists_different"
                if status == "exists_different":
                    outcomes.append({"plan":p,"status":status})
                    continue
            except OSError:
                outcomes.append({"plan":p,"status":"target_unreadable"})
                continue
        else:
            status = "planned"
            bytes_to_add += p["size"]
        # Rehash selected source now even in dry-run; this proves current source bytes.
        try:
            proof = _verify_source(p, roots, account, aliases)
            if p["preview"]:
                _image_decodes(Path(proof["path"]))
            outcomes.append({"plan":p,"status":status,"source_proof":proof})
        except Exception as exc:
            outcomes.append({"plan":p,"status":"source_verification_failed","error":type(exc).__name__})
    cap = args.max_added_mib * 1024 * 1024
    verified_bytes_to_add = sum(x["plan"]["size"] for x in outcomes if x["status"] == "planned")
    budget_ok = verified_bytes_to_add <= cap and all(x["status"] in {"planned","already_present","preserved_existing_preview","protected_existing_preview"} for x in outcomes)
    if args.apply and budget_ok:
        for pos, item in enumerate(outcomes):
            if item["status"] != "planned":
                continue
            try:
                item["status"], item["target_hash"] = _copy_exclusive(item["plan"], account, roots, aliases)
            except Exception as exc:
                item["status"] = "apply_failed"
                item["error"] = type(exc).__name__
                for later in outcomes[pos+1:]:
                    if later["status"] == "planned":
                        later["status"] = "not_attempted"
                break
    elif args.apply and not budget_ok:
        for item in outcomes:
            if item["status"] == "planned":
                item["status"] = "blocked_all_or_nothing_preflight"
    # Private manifest retains source/target identities but stdout remains counts-only.
    manifest = {"mode":"apply" if args.apply else "dry_run","created_local":__import__('datetime').datetime.now().astimezone().isoformat(),
                "max_added_mib":args.max_added_mib,"planned_bytes":verified_bytes_to_add,
                "budget_ok":budget_ok,"identity_conflicts_excluded":identity_conflicts,
                "counts":{},"items":[],"ui_verified":0}
    for item in outcomes:
        manifest["counts"][item["status"]] = manifest["counts"].get(item["status"],0)+1
        ent = dict(item["plan"])
        ent.update(status=item["status"])
        if item.get("source_proof"):
            ent["source_proof"] = item["source_proof"]
        if item.get("target_hash"):
            ent["target_hash"] = item["target_hash"]
        if item.get("error"):
            ent["error"] = item["error"]
        manifest["items"].append(ent)
    manifest["counts_by_media_kind"]={}
    for item in outcomes:
        kind=item["plan"]["media_kind"]
        per=manifest["counts_by_media_kind"].setdefault(kind,{})
        per[item["status"]]=per.get(item["status"],0)+1
    manifest["source_original_paths"] = sum(1 for x in outcomes if not x["plan"]["preview"] and x["status"] == "created")
    manifest["source_originals_already_present"] = sum(1 for x in outcomes if not x["plan"]["preview"] and x["status"] == "already_present")
    manifest["cache_previews_filled"] = sum(1 for x in outcomes if x["plan"]["preview"] and x["status"] == "created")
    manifest["cache_previews_already_present"] = sum(1 for x in outcomes if x["plan"]["preview"] and x["status"] == "already_present")
    manifest["cache_previews_preserved"] = sum(1 for x in outcomes if x["plan"]["preview"] and x["status"] in {"preserved_existing_preview","protected_existing_preview"})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    temp_out = args.out.with_name(args.out.name + ".tmp")
    temp_out.write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
    os.replace(temp_out,args.out)
    print(json.dumps({"mode":manifest["mode"],"counts":manifest["counts"],"bytes_to_add":verified_bytes_to_add,
                      "source_original_paths":manifest["source_original_paths"],"cache_previews_filled":manifest["cache_previews_filled"],
                      "cache_previews_preserved":manifest["cache_previews_preserved"],"ui_verified":0,
                      "counts_by_media_kind":manifest["counts_by_media_kind"],"budget_ok":budget_ok,
                      "identity_conflicts_excluded":identity_conflicts},separators=(",",":")))
    failed = any(x["status"] in {"apply_failed","not_attempted","source_verification_failed","exists_different","target_unreadable"} for x in outcomes)
    return 3 if failed else (0 if budget_ok else 2)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--metadata-db",type=Path,required=True)
    p.add_argument("--account",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--apply",action="store_true",help="create absent targets; default is dry-run")
    p.add_argument("--max-added-mib",type=int,default=2048)
    p.add_argument("--only-msg-id",type=int)
    p.add_argument("--include-declared-previews",action="store_true")
    p.add_argument("--media-kinds",default="image",help="experimental opt-in: comma-separated image,video,file; default: image; no UI compatibility is implied")
    p.add_argument("--source-alias",action="append",default=[],help="optional path alias; must resolve exactly to --account")
    a=p.parse_args()
    if a.max_added_mib < 0:
        p.error("--max-added-mib must be nonnegative")
    a.media_kinds=tuple(dict.fromkeys(x.strip().lower() for x in a.media_kinds.split(",") if x.strip()))
    if not a.media_kinds or any(k not in MEDIA_KINDS for k in a.media_kinds):
        p.error("--media-kinds must contain image, video, and/or file")
    if a.include_declared_previews and "image" not in a.media_kinds:
        p.error("--include-declared-previews requires image in --media-kinds")
    try:
        return run(a)
    except Exception as exc:
        print(json.dumps({"error":type(exc).__name__,"message":str(exc) if isinstance(exc,ValueError) else "restore_preflight_failed"},separators=(",",":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
