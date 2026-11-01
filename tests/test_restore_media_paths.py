import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills" / "qqnt-media-repair" / "scripts"))
import restore_media_paths as restore


class RestoreToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.account = self.root / "account"
        (self.account / "FileRecv").mkdir(parents=True)
        (self.account / "nt_qq" / "nt_data").mkdir(parents=True)
        self.source = self.account / "FileRecv" / "source.bin"
        self.data = b"synthetic verified image bytes\x00\x01"
        self.source.write_bytes(self.data)
        self.md5 = hashlib.md5(self.data).hexdigest()
        self.sha = hashlib.sha256(self.data).hexdigest()
        self.db_path = self.root / "metadata.sqlite"
        self.db = sqlite3.connect(self.db_path)
        self.db.executescript("""
          CREATE TABLE restore_targets(path TEXT PRIMARY KEY COLLATE NOCASE,source_id INTEGER NOT NULL,
            field INTEGER NOT NULL,table_code INTEGER NOT NULL,msg_id INTEGER NOT NULL,
            segment_path TEXT NOT NULL,kind INTEGER NOT NULL,expected_size INTEGER NOT NULL,
            expected_md5 TEXT NOT NULL,reference_count INTEGER NOT NULL DEFAULT 1);
          CREATE TABLE verified_sources(source_id INTEGER PRIMARY KEY,size INTEGER NOT NULL,
            md5 TEXT NOT NULL,sha256 TEXT NOT NULL,path TEXT NOT NULL);
          CREATE TABLE blocked_restore_paths(path TEXT PRIMARY KEY COLLATE NOCASE,reason TEXT NOT NULL);
          CREATE TABLE restore_target_conflicts(path TEXT NOT NULL,existing_source_id INTEGER NOT NULL,
            incoming_source_id INTEGER NOT NULL);
          CREATE TABLE verified_refs(table_code INTEGER NOT NULL,msg_id INTEGER NOT NULL,
            segment_path TEXT NOT NULL,source_id INTEGER NOT NULL,kind INTEGER NOT NULL,nested INTEGER NOT NULL);
          CREATE TABLE examples(category TEXT NOT NULL,ordinal INTEGER NOT NULL,details TEXT NOT NULL);
          CREATE TABLE declared_restoration_previews(path TEXT NOT NULL,source_id INTEGER NOT NULL,
            field INTEGER NOT NULL,table_code INTEGER NOT NULL,msg_id INTEGER NOT NULL,segment_path TEXT NOT NULL);
        """)
        self.db.execute("INSERT INTO verified_sources VALUES (1,?,?,?,?)",
                        (len(self.data), self.md5, self.sha, str(self.source)))
        self.out = self.root / "manifest.json"
        self.db.commit()
        self.db.close()
        self.add_target(1)

    def tearDown(self):
        self.tmp.cleanup()

    def target_path(self, n):
        return self.account / "nt_qq" / "nt_data" / "Pic" / "recv" / "2026-01" / "Ori" / f"{n}.jpg"

    def add_target(self, msg_id, *, path=None, source_id=1, field=45403, kind=2, nested=0,
                   expected_md5=None, source_md5=None, source_sha=None):
        path = path or self.target_path(msg_id)
        db = sqlite3.connect(self.db_path)
        if source_id != 1:
            db.execute("INSERT INTO verified_sources VALUES (?,?,?,?,?)",
                       (source_id, len(self.data), source_md5 or self.md5, source_sha or self.sha, str(self.source)))
        db.execute("INSERT INTO restore_targets VALUES (?,?,?,?,?,?,?,?,?,1)",
                   (str(path), source_id, field, 1, msg_id, f"seg/{msg_id}", kind, len(self.data), expected_md5 or self.md5))
        db.execute("INSERT INTO verified_refs VALUES (?,?,?,?,?,?)", (1, msg_id, f"seg/{msg_id}", source_id, kind, nested))
        db.commit()
        db.close()

    def args(self, *, apply=False, cap=10, media_kinds=("image",), previews=False):
        return type("Args", (), {"metadata_db": self.db_path, "account": self.account,
                                  "out": self.out, "apply": apply, "max_added_mib": cap,
                                  "only_msg_id": None, "include_declared_previews": previews,
                                  "media_kinds":media_kinds})()

    def test_no_clobber(self):
        dest = self.target_path(1)
        dest.parent.mkdir(parents=True)
        dest.write_bytes(b"preexisting different data")
        with self.assertRaises(FileExistsError):
            restore._copy_exclusive({"target":str(dest),"source":str(self.source),"size":len(self.data),
                                     "md5":self.md5,"sha256":self.sha,"preview":False},
                                    self.account.resolve(), [self.account.resolve()])
        self.assertEqual(dest.read_bytes(), b"preexisting different data")

    def test_stale_source_hash_blocks_apply(self):
        db = sqlite3.connect(self.db_path)
        bad = "0" * 32
        db.execute("UPDATE verified_sources SET md5=?", (bad,))
        db.execute("UPDATE restore_targets SET expected_md5=?", (bad,))
        db.commit(); db.close()
        rc = restore.run(self.args(apply=True))
        self.assertEqual(rc, 3)
        self.assertFalse(self.target_path(1).exists())
        self.assertEqual(json.loads(self.out.read_text())["counts"], {"source_verification_failed":1})

    def test_target_escape_rejected(self):
        with self.assertRaisesRegex(ValueError, "target_escape"):
            restore._target_policy(str(self.root / "outside" / "x.jpg"), self.account.resolve())

    def test_budget_is_all_or_nothing_preflight(self):
        self.add_target(2)
        rc = restore.run(self.args(apply=True, cap=0))
        self.assertEqual(rc, 2)
        self.assertFalse(self.target_path(1).exists())
        self.assertFalse(self.target_path(2).exists())
        self.assertEqual(json.loads(self.out.read_text())["counts"], {"blocked_all_or_nothing_preflight":2})

    def test_partial_failure_is_manifested_without_rollback(self):
        self.add_target(2)
        self.add_target(3)
        original = restore._copy_exclusive
        calls = 0
        def fail_second(plan, account, roots, aliases=()):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic")
            return original(plan, account, roots, aliases)
        with mock.patch.object(restore, "_copy_exclusive", side_effect=fail_second):
            rc = restore.run(self.args(apply=True))
        self.assertEqual(rc, 3)
        manifest = json.loads(self.out.read_text())
        self.assertEqual(manifest["counts"], {"created":1,"apply_failed":1,"not_attempted":1})
        self.assertEqual(manifest["source_original_paths"], 1)
        self.assertEqual(manifest["cache_previews_filled"], 0)
        self.assertEqual(manifest["ui_verified"], 0)
        self.assertTrue(self.target_path(1).exists())
        self.assertFalse(self.target_path(2).exists() or self.target_path(3).exists())

    def test_declared_preview_requires_same_missing_original_identity(self):
        db=sqlite3.connect(self.db_path)
        preview=self.account/"nt_qq"/"nt_data"/"Pic"/"recv"/"2026-01"/"Thumb"/"1_0.jpg"
        db.execute("INSERT INTO declared_restoration_previews VALUES (?,?,?,?,?,?)",
                   (str(preview),1,45812,1,1,"seg/1"))
        db.commit();db.close()
        plans,_=restore._read_plan(self.db_path,self.account,include_previews=True)
        self.assertEqual(sum(p["preview"] for p in plans),1)
        original=self.target_path(1);original.parent.mkdir(parents=True);original.write_bytes(self.data)
        plans,_=restore._read_plan(self.db_path,self.account,include_previews=True)
        self.assertEqual(sum(p["preview"] for p in plans),1)
        original.write_bytes(b"different bytes")
        plans,_=restore._read_plan(self.db_path,self.account,include_previews=True)
        self.assertFalse(any(p["preview"] for p in plans))

    def test_apply_original_then_declared_preview(self):
        db=sqlite3.connect(self.db_path)
        preview=self.account/"nt_qq"/"nt_data"/"Pic"/"recv"/"2026-01"/"Thumb"/"1_0.jpg"
        db.execute("INSERT INTO declared_restoration_previews VALUES (?,?,?,?,?,?)",
                   (str(preview),1,45812,1,1,"seg/1"))
        db.commit();db.close()
        first=restore.run(self.args(apply=True))
        self.assertEqual(first,0)
        self.assertEqual(self.target_path(1).read_bytes(),self.data)
        args=self.args(apply=True);args.include_declared_previews=True
        with mock.patch.object(restore,"_image_decodes"):
            second=restore.run(args)
        self.assertEqual(second,0)
        self.assertEqual(preview.read_bytes(),self.data)
        manifest=json.loads(self.out.read_text())
        self.assertEqual(manifest["source_original_paths"],0)
        self.assertEqual(manifest["source_originals_already_present"],1)
        self.assertEqual(manifest["cache_previews_filled"],1)
        self.assertEqual(manifest["ui_verified"],0)

    def test_existing_preview_is_preserved_while_missing_peer_is_filled(self):
        db=sqlite3.connect(self.db_path)
        thumbdir=self.account/"nt_qq"/"nt_data"/"Pic"/"recv"/"2026-01"/"Thumb"
        good=thumbdir/"1_0.jpg"; bad=thumbdir/"1_720.jpg"; missing=thumbdir/"1_1080.jpg"
        for path,field in ((good,45812),(bad,45814),(missing,45814)):
            db.execute("INSERT INTO declared_restoration_previews VALUES (?,?,?,?,?,?)",
                       (str(path),1,field,1,1,"seg/1"))
        db.commit();db.close()
        original=self.target_path(1);original.parent.mkdir(parents=True);original.write_bytes(self.data)
        thumbdir.mkdir(parents=True)
        good.write_bytes(b"existing compressed thumbnail")
        bad.write_bytes(b"existing undecodable thumbnail")
        prior_good=good.read_bytes();prior_bad=bad.read_bytes()
        args=self.args(apply=True);args.include_declared_previews=True
        def fake_decode(path):
            if Path(path).name=="1_720.jpg": raise ValueError("not an image")
        with mock.patch.object(restore,"_image_decodes",side_effect=fake_decode):
            rc=restore.run(args)
        self.assertEqual(rc,0)
        self.assertEqual(good.read_bytes(),prior_good)
        self.assertEqual(bad.read_bytes(),prior_bad)
        self.assertEqual(missing.read_bytes(),self.data)
        manifest=json.loads(self.out.read_text())
        self.assertEqual(manifest["counts"],{"already_present":1,"preserved_existing_preview":1,
                                               "protected_existing_preview":1,"created":1})
        self.assertEqual(manifest["cache_previews_filled"],1)
        self.assertEqual(manifest["cache_previews_preserved"],2)
        self.assertEqual(manifest["ui_verified"],0)

    def test_examples_fallback_requires_explicit_missing_original(self):
        db=sqlite3.connect(self.db_path)
        db.execute("DROP TABLE declared_restoration_previews")
        details={"kind":"image","id":"1","source_verified":{"path":str(self.source),"size":len(self.data),"md5":self.md5,"sha256":self.sha},
          "metadata":{"segment_path":"seg/1"},"path_status":[
            {"field":"45812","is_thumbnail_path":True,"status":"missing","resolved_path":str(self.account/"nt_qq"/"nt_data"/"Pic"/"recv"/"2026-01"/"Thumb"/"1_0.jpg")} ]}
        db.execute("INSERT INTO examples VALUES (?,?,?)",("cache_missing_with_verified_original",0,json.dumps(details)))
        db.commit();db.close()
        plans,_=restore._read_plan(self.db_path,self.account,include_previews=True)
        self.assertFalse(any(p["preview"] for p in plans))

    def test_examples_fallback_success_with_missing_original_and_joined_source(self):
        db=sqlite3.connect(self.db_path)
        db.execute("DROP TABLE declared_restoration_previews")
        ori=self.target_path(1)
        thumb=self.account/"nt_qq"/"nt_data"/"Pic"/"recv"/"2026-01"/"Thumb"/"1_0.jpg"
        details={"kind":"image","id":"1","source_verified":{"path":str(self.source),"size":len(self.data),"md5":self.md5,"sha256":self.sha},
          "metadata":{"segment_path":"seg/1"},"path_status":[
            {"field":"45403","is_thumbnail_path":False,"status":"missing","resolved_path":str(ori)},
            {"field":"45812","is_thumbnail_path":True,"status":"missing","resolved_path":str(thumb)}]}
        db.execute("INSERT INTO examples VALUES (?,?,?)",("cache_missing_with_verified_original",0,json.dumps(details)))
        db.commit();db.close()
        plans,_=restore._read_plan(self.db_path,self.account,include_previews=True)
        previews=[p for p in plans if p["preview"]]
        self.assertEqual(len(previews),1)
        self.assertEqual(previews[0]["target"],str(thumb))
        self.assertEqual(previews[0]["source"],str(self.source))

    def test_manifest_separates_original_and_preview_counts(self):
        db=sqlite3.connect(self.db_path)
        preview=self.account/"nt_qq"/"nt_data"/"Pic"/"recv"/"2026-01"/"Thumb"/"1_0.jpg"
        db.execute("INSERT INTO declared_restoration_previews VALUES (?,?,?,?,?,?)",
                   (str(preview),1,45812,1,1,"seg/1"))
        db.commit();db.close()
        with mock.patch.object(restore,"_copy_exclusive",return_value=("created",{"size":1,"md5":"a","sha256":"b"})), \
             mock.patch.object(restore,"_image_decodes"):
            rc=restore.run(type("Args",(),{"metadata_db":self.db_path,"account":self.account,"out":self.out,
                "apply":True,"max_added_mib":10,"only_msg_id":None,"include_declared_previews":True})())
        self.assertEqual(rc,0)
        m=json.loads(self.out.read_text())
        self.assertEqual(m["source_original_paths"],1)
        self.assertEqual(m["cache_previews_filled"],1)
        self.assertEqual(m["ui_verified"],0)

    def test_windows_ads_and_reserved_components_rejected(self):
        for raw in (str(self.target_path(1))+":stream", str(self.account/"nt_qq"/"nt_data"/"Pic"/"CON"/"Ori"/"x.jpg"),
                    str(self.account/"nt_qq"/"nt_data"/"Pic"/"bad?name"/"Ori"/"x.jpg")):
            with self.assertRaises(ValueError):
                restore._target_policy(raw,self.account.resolve())

    def test_video_and_file_targets_require_their_safe_ori_roots(self):
        video=self.account/"nt_qq"/"nt_data"/"Video"/"2026-02"/"Ori"/"clip.mp4"
        file=self.account/"nt_qq"/"nt_data"/"File"/"Ori"/"uuid"/"report.pdf"
        self.add_target(2,path=video,kind=5)
        self.add_target(3,path=file,kind=3)
        plans,_=restore._read_plan(self.db_path,self.account,media_kinds=("video","file"))
        self.assertEqual({p["media_kind"] for p in plans},{"video","file"})
        self.assertEqual(len(plans),2)
        image_plans,_=restore._read_plan(self.db_path,self.account)
        self.assertEqual({p["media_kind"] for p in image_plans},{"image"})
        self.assertEqual(restore._target_policy(str(video),self.account.resolve(),kind="video"),video)
        self.assertEqual(restore._target_policy(str(file),self.account.resolve(),kind="file"),file)
        with self.assertRaises(ValueError):
            restore._target_policy(str(file),self.account.resolve(),kind="video")
        with self.assertRaises(ValueError):
            restore._target_policy(str(video.with_suffix(".jpg")),self.account.resolve(),kind="video")

    def test_video_existing_different_file_is_never_overwritten(self):
        video=self.account/"nt_qq"/"nt_data"/"Video"/"2026-02"/"Ori"/"clip.mp4"
        self.add_target(2,path=video,kind=5)
        video.parent.mkdir(parents=True);video.write_bytes(b"preexisting video")
        rc=restore.run(self.args(apply=True,media_kinds=("video",)))
        self.assertEqual(rc,3)
        self.assertEqual(video.read_bytes(),b"preexisting video")
        self.assertEqual(json.loads(self.out.read_text())["counts"],{"exists_different":1})

    def test_video_file_plans_require_matching_non_nested_verified_refs(self):
        video=self.account/"nt_qq"/"nt_data"/"Video"/"2026-02"/"Ori"/"nested.mp4"
        file=self.account/"nt_qq"/"nt_data"/"File"/"Ori"/"uuid"/"blocked.pdf"
        self.add_target(2,path=video,kind=5,nested=1)
        self.add_target(3,path=file,kind=3)
        db=sqlite3.connect(self.db_path)
        db.execute("INSERT INTO blocked_restore_paths VALUES (?,?)",(str(file),"test_block"))
        db.commit();db.close()
        plans,_=restore._read_plan(self.db_path,self.account,media_kinds=("video","file"))
        self.assertEqual(plans,[])

    def test_previews_are_excluded_from_video_only_plan(self):
        video=self.account/"nt_qq"/"nt_data"/"Video"/"2026-02"/"Ori"/"clip.mp4"
        self.add_target(2,path=video,kind=5)
        db=sqlite3.connect(self.db_path)
        preview=self.account/"nt_qq"/"nt_data"/"Pic"/"recv"/"2026-01"/"Thumb"/"2_0.jpg"
        db.execute("INSERT INTO declared_restoration_previews VALUES (?,?,?,?,?,?)",
                   (str(preview),1,45812,1,2,"seg/2"))
        db.commit();db.close()
        plans,_=restore._read_plan(self.db_path,self.account,include_previews=True,media_kinds=("video",))
        self.assertEqual(len(plans),1)
        self.assertFalse(plans[0]["preview"])

    def test_bad_file_source_hash_blocks_apply(self):
        file=self.account/"nt_qq"/"nt_data"/"File"/"Ori"/"uuid"/"report.pdf"
        self.add_target(2,path=file,kind=3)
        self.source.write_bytes(b"changed source")
        rc=restore.run(self.args(apply=True,media_kinds=("file",)))
        self.assertEqual(rc,3)
        self.assertFalse(file.exists())
        self.assertEqual(json.loads(self.out.read_text())["counts"],{"source_verification_failed":1})


if __name__ == "__main__":
    unittest.main()
