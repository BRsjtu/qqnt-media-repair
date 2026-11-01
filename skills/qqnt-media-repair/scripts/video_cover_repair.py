"""Experimental, local-only derivation of explicitly named QQNT video covers.

Dry-run is the default. The tool reads metadata and original videos only; it
never writes QQ databases, changes flags, opens media players, or overwrites a
cover. Generated PNGs are derived previews, not recovered original covers.
"""
from __future__ import annotations

import argparse
from datetime import datetime
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile

SCRIPTS=Path(__file__).parent
sys.path.insert(0,str(SCRIPTS))
from source_matcher import verify_source, _authorized_file, _signature

_MD5=re.compile(r"[0-9a-f]{32}\Z",re.I)
_MONTH=re.compile(r"\d{4}-(?:0[1-9]|1[0-2])\Z")


def _validate_windows_path(raw):
    import ntpath
    if not isinstance(raw,str) or not raw or any(ord(c)<32 for c in raw):
        raise ValueError("invalid_windows_path")
    if raw.startswith(("\\\\","//")):
        raise ValueError("unc_or_device_path")
    drive,tail=ntpath.splitdrive(raw)
    if not drive or len(drive)!=2 or drive[1] != ":" or ":" in tail:
        raise ValueError("device_or_ads_path")
    if not tail.startswith(("\\", "/")):
        raise ValueError("drive_relative_path")
    for part in tail.replace("/","\\").split("\\"):
        if not part: continue
        if part in {".",".."} or part.endswith(("."," ")) or any(c in part for c in '<>"|?*'):
            raise ValueError("invalid_windows_component")
        stem=part.split(".",1)[0].rstrip(" .").casefold()
        if stem in {"con","prn","aux","nul"} or stem in {f"com{i}" for i in range(1,10)} or stem in {f"lpt{i}" for i in range(1,10)}:
            raise ValueError("reserved_windows_name")


def _assert_no_reparse(path:Path,account:Path,allow_missing=False):
    q=Path(os.path.abspath(path))
    if not q.is_relative_to(account):
        raise ValueError("path_outside_account")
    cur=account
    for part in q.relative_to(account).parts:
        cur=cur/part
        try:
            st=cur.lstat()
        except FileNotFoundError:
            if allow_missing: continue
            raise
        if stat.S_ISLNK(st.st_mode) or bool(getattr(st,"st_file_attributes",0)&0x400):
            raise ValueError("reparse_point")
    return q


def _validate_video_target(target_raw,original_raw,account,expected_md5):
    _validate_windows_path(target_raw); _validate_windows_path(original_raw)
    if not _MD5.fullmatch(expected_md5 or ""):
        raise ValueError("invalid_expected_md5")
    target=Path(os.path.abspath(target_raw)); original=Path(os.path.abspath(original_raw))
    if not target.is_relative_to(account) or not original.is_relative_to(account):
        raise ValueError("path_outside_account")
    try:
        ore=original.relative_to(account); tre=target.relative_to(account)
    except ValueError:
        raise ValueError("path_outside_account") from None
    op=[p.casefold() for p in ore.parts]; tp=[p.casefold() for p in tre.parts]
    if (len(op)!=6 or op[:3]!=["nt_qq","nt_data","video"] or
        not _MONTH.fullmatch(ore.parts[3]) or op[4]!="ori" or Path(ore).suffix.casefold()!=".mp4" or
        Path(ore).stem.casefold()!=expected_md5.casefold()):
        raise ValueError("original_path_not_canonical_video_ori_mp4")
    if (len(tp)!=6 or tp[:3]!=["nt_qq","nt_data","video"] or
        not _MONTH.fullmatch(tre.parts[3]) or tp[3]!=op[3] or tp[4]!="thumb" or
        tp[5]!=expected_md5.casefold()+"_0.png"):
        raise ValueError("cover_path_not_primary_md5_thumb")
    _assert_no_reparse(original,account,allow_missing=False)
    _assert_no_reparse(target,account,allow_missing=True)
    return target,original


def _decode_first_frame(video_path:Path):
    try:
        import av
        from PIL import Image
    except ImportError as exc:
        raise ValueError("PyAV_and_Pillow_required") from exc
    with av.open(str(video_path),mode="r") as container:
        stream=next((s for s in container.streams if s.type=="video"),None)
        if stream is None:
            raise ValueError("video_stream_missing")
        frame=next(container.decode(stream),None)
        if frame is None:
            raise ValueError("video_has_no_decodable_frame")
        image=frame.to_image().convert("RGB")
    image.thumbnail((720,720),Image.Resampling.LANCZOS)
    output=BytesIO()
    image.save(output,format="PNG",optimize=False,compress_level=6)
    return output.getvalue()


def _hash_bytes(data):
    return {"size":len(data),"md5":hashlib.md5(data).hexdigest(),"sha256":hashlib.sha256(data).hexdigest()}


def _get_source_signature(path,roots):
    resolved,info=_authorized_file(path,roots)
    return str(resolved),_signature(info)


def _assert_source_signature(path,expected,roots):
    resolved,info=_authorized_file(path,roots)
    if str(resolved)!=expected[0] or _signature(info)!=expected[1]:
        raise ValueError("source_changed_after_verification")


def _read_plan(metadata_db:Path,account:Path,only_msg_id=None):
    db=sqlite3.connect(metadata_db.resolve(strict=True).as_uri()+"?mode=ro",uri=True)
    db.row_factory=sqlite3.Row
    required={
      "video_cover_targets":{"target_path","original_path","source_id","table_code","msg_id","segment_path","expected_size","expected_md5"},
      "verified_sources":{"source_id","size","md5","sha256","path"},
      "verified_refs":{"table_code","msg_id","segment_path","source_id","kind","nested"},
      "blocked_restore_paths":{"path","reason"},"restore_target_conflicts":{"path","existing_source_id","incoming_source_id"}}
    for table,cols in required.items():
        if not cols <= {r[1] for r in db.execute(f"PRAGMA table_info({table})")}:
            db.close();raise ValueError("metadata_schema_mismatch")
    sql="""SELECT v.*,s.size AS source_size,s.md5 AS source_md5,s.sha256 AS source_sha256
           FROM video_cover_targets v JOIN verified_sources s USING(source_id)
           JOIN verified_refs r ON r.source_id=v.source_id AND r.table_code=v.table_code
             AND r.msg_id=v.msg_id AND r.segment_path=v.segment_path AND r.kind=5 AND r.nested=0
           WHERE v.expected_size=s.size AND lower(v.expected_md5)=lower(s.md5)
             AND NOT EXISTS(SELECT 1 FROM blocked_restore_paths b WHERE b.path=v.target_path)
             AND NOT EXISTS(SELECT 1 FROM blocked_restore_paths b WHERE b.path=v.original_path)
             AND NOT EXISTS(SELECT 1 FROM restore_target_conflicts c WHERE c.path=v.target_path OR c.path=v.original_path)"""
    args=[]
    if only_msg_id is not None: sql+=" AND v.msg_id=?";args.append(only_msg_id)
    plans=[];seen={};conflicts=0
    for row in db.execute(sql,args):
        target,original=_validate_video_target(row["target_path"],row["original_path"],account,row["source_md5"])
        key=os.path.normcase(str(target));identity=(row["source_id"],row["expected_size"],row["source_md5"].lower(),row["source_sha256"].lower())
        if key in seen:
            if seen[key]!=identity: conflicts+=1;plans=[p for p in plans if os.path.normcase(p["target"])!=key];seen[key]=None
            continue
        seen[key]=identity
        plans.append({"target":str(target),"original":str(original),"source_id":row["source_id"],
          "size":row["source_size"],"md5":row["source_md5"].lower(),"sha256":row["source_sha256"].lower(),
          "msg_id":row["msg_id"],"table_code":row["table_code"],"segment_path":row["segment_path"],
          "media_kind":"video","derived_preview":True})
    db.close()
    return plans,conflicts


def _write_exclusive(target:Path,data:bytes,account:Path,source_signature,roots):
    _assert_no_reparse(target.parent,account,allow_missing=True)
    target.parent.mkdir(parents=True,exist_ok=True)
    _assert_no_reparse(target.parent,account,allow_missing=False)
    if target.exists() or target.is_symlink():
        return _existing_target_status(target)
    fd,name=tempfile.mkstemp(prefix=".qqnt-cover-",suffix=".tmp",dir=target.parent)
    tmp=Path(name)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(data);out.flush();os.fsync(out.fileno())
        _assert_source_signature(source_signature[0],source_signature,roots)
        try:
            if os.name=="nt": os.rename(tmp,target)
            else:
                os.link(tmp,target);tmp.unlink()
        except FileExistsError:
            return _existing_target_status(target)
        try:
            dfd=os.open(target.parent,os.O_RDONLY)
            try: os.fsync(dfd)
            finally: os.close(dfd)
        except OSError: pass
        return "created"
    finally:
        try: tmp.unlink()
        except FileNotFoundError: pass


def _existing_target_status(path:Path):
    try: st=path.lstat()
    except OSError:return "existing_target_protected"
    if stat.S_ISREG(st.st_mode) and st.st_nlink==1:
        return "existing_cover_preserved"
    return "existing_target_protected"


def run(args):
    account=args.account.resolve(strict=True)
    if not account.is_dir(): raise ValueError("account_not_directory")
    out=args.out.resolve(strict=False)
    if out.is_relative_to(account): raise ValueError("report_must_be_outside_account")
    plans,conflicts=_read_plan(args.metadata_db,account,args.only_msg_id)
    allowed=(account,)
    items=[];needed=0
    for plan in plans:
        target=Path(plan["target"]);original=Path(plan["original"])
        if target.exists() or target.is_symlink():
            items.append({"plan":plan,"status":_existing_target_status(target)});continue
        try:
            proof=verify_source({"path":plan["original"],"size":plan["size"],"md5":plan["md5"],"sha256":plan["sha256"]},allowed)
            signature=_get_source_signature(proof["path"],allowed)
            png=_decode_first_frame(Path(proof["path"]))
            _assert_source_signature(signature[0],signature,allowed)
            png_hash=_hash_bytes(png)
            items.append({"plan":plan,"status":"planned","preview":png_hash,"source_proof":proof,
                          "source_signature":signature,"png_bytes":png})
            needed+=png_hash["size"]
        except Exception as exc:
            items.append({"plan":plan,"status":"source_or_decode_failed","error":type(exc).__name__})
    cap=args.max_added_mib*1024*1024
    preflight_ok=needed<=cap and all(i["status"] in {"planned","existing_cover_preserved","existing_target_protected"} for i in items)
    if args.apply and preflight_ok:
        for pos,item in enumerate(items):
            if item["status"]!="planned":continue
            plan=item["plan"]
            try:
                _assert_source_signature(plan["original"],item["source_signature"],allowed)
                item["status"]=_write_exclusive(Path(plan["target"]),item["png_bytes"],account,item["source_signature"],allowed)
                item["derived_preview_sha256"]=item["preview"]["sha256"]
            except Exception as exc:
                item["status"]="apply_failed";item["error"]=type(exc).__name__
                for later in items[pos+1:]:
                    if later["status"]=="planned":later["status"]="not_attempted"
                break
    elif args.apply:
        for item in items:
            if item["status"]=="planned":item["status"]="blocked_all_or_nothing_preflight"
    counts={}
    for item in items:counts[item["status"]]=counts.get(item["status"],0)+1
    manifest={"created_local":datetime.now().astimezone().isoformat(),"qq_build":args.qq_build,
      "mode":"apply" if args.apply else "dry_run","max_added_mib":args.max_added_mib,
      "planned_bytes":needed,"preflight_ok":preflight_ok,"counts":counts,
      "cover_paths_created":sum(i["status"]=="created" for i in items),
      "existing_covers_preserved":counts.get("existing_cover_preserved",0),
      "existing_targets_protected":counts.get("existing_target_protected",0),
      "derived_previews":True,"ui_verified":0,"identity_conflicts_excluded":conflicts,
      "items":[{**i["plan"],"status":i["status"],**({"preview":i["preview"]} if i.get("preview") else {}),
                **({"source_proof":i["source_proof"]} if i.get("source_proof") else {}),
                **({"derived_preview_sha256":i["derived_preview_sha256"]} if i.get("derived_preview_sha256") else {}),
                **({"error":i["error"]} if i.get("error") else {})} for i in items]}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    temp=args.out.with_name(args.out.name+".tmp")
    temp.write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8");os.replace(temp,args.out)
    print(json.dumps({"mode":manifest["mode"],"counts":counts,"cover_paths_created":manifest["cover_paths_created"],
      "existing_covers_preserved":manifest["existing_covers_preserved"],"derived_previews":True,"ui_verified":0,
      "planned_bytes":needed,"preflight_ok":preflight_ok,"identity_conflicts_excluded":conflicts},separators=(",",":")))
    failed=any(i["status"] in {"source_or_decode_failed","apply_failed","not_attempted"} for i in items)
    return 3 if failed else (0 if preflight_ok else 2)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--metadata-db",type=Path,required=True)
    p.add_argument("--account",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--qq-build",default="9.9.31-49738")
    p.add_argument("--max-added-mib",type=int,default=128)
    p.add_argument("--only-msg-id",type=int)
    p.add_argument("--apply",action="store_true",help="create absent derived PNG previews; default is dry-run")
    a=p.parse_args()
    if a.max_added_mib<0:p.error("--max-added-mib must be nonnegative")
    try:return run(a)
    except Exception as exc:
        print(json.dumps({"error":type(exc).__name__,"message":str(exc) if isinstance(exc,ValueError) else "cover_preflight_failed"},separators=(",",":")))
        return 1


if __name__=="__main__":
    raise SystemExit(main())
