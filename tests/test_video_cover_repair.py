import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

import av
from PIL import Image

import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"skills"/"qqnt-media-repair"/"scripts"))
import video_cover_repair as cover


class VideoCoverRepairTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.account=self.root/"account"
        self.original=self.account/"nt_qq"/"nt_data"/"Video"/"2024-02"/"Ori"
        self.original.mkdir(parents=True)
        self.md5=""
        self.video=self.original/"pending.mp4"
        self._make_video(self.video)
        self.data=self.video.read_bytes()
        self.md5=hashlib.md5(self.data).hexdigest()
        # QQ primary video path uses the MD5 of the verified original.
        self.video.rename(self.original/(self.md5+".mp4"))
        self.video=self.original/(self.md5+".mp4")
        self.target=self.video.parents[1]/"Thumb"/(self.md5+"_0.png")
        self.db_path=self.root/"metadata.sqlite"
        db=sqlite3.connect(self.db_path)
        db.executescript("""
          CREATE TABLE video_cover_targets(target_path TEXT PRIMARY KEY,original_path TEXT NOT NULL,
            source_id INTEGER NOT NULL,table_code INTEGER NOT NULL,msg_id INTEGER NOT NULL,
            segment_path TEXT NOT NULL,expected_size INTEGER NOT NULL,expected_md5 TEXT NOT NULL);
          CREATE TABLE verified_sources(source_id INTEGER PRIMARY KEY,size INTEGER NOT NULL,md5 TEXT NOT NULL,sha256 TEXT NOT NULL,path TEXT NOT NULL);
          CREATE TABLE verified_refs(table_code INTEGER NOT NULL,msg_id INTEGER NOT NULL,segment_path TEXT NOT NULL,
            source_id INTEGER NOT NULL,kind INTEGER NOT NULL,nested INTEGER NOT NULL);
          CREATE TABLE restore_targets(path TEXT NOT NULL,source_id INTEGER NOT NULL,field INTEGER NOT NULL,
            table_code INTEGER NOT NULL,msg_id INTEGER NOT NULL,segment_path TEXT NOT NULL,kind INTEGER NOT NULL,
            expected_size INTEGER NOT NULL,expected_md5 TEXT NOT NULL);
          CREATE TABLE blocked_restore_paths(path TEXT PRIMARY KEY,reason TEXT NOT NULL);
          CREATE TABLE restore_target_conflicts(path TEXT,existing_source_id INTEGER,incoming_source_id INTEGER);
        """)
        self.sha=hashlib.sha256(self.data).hexdigest()
        db.execute("INSERT INTO verified_sources VALUES (1,?,?,?,?)",(len(self.data),self.md5,self.sha,str(self.video)))
        db.execute("INSERT INTO verified_refs VALUES (1,100,'seg/1',1,5,0)")
        db.execute("INSERT INTO restore_targets VALUES (?,1,45403,1,100,'seg/1',5,?,?)",
                   (str(self.video),len(self.data),self.md5))
        self.add_plan_row(db)
        db.commit();db.close()
        self.out=self.root/"manifest.json"

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _make_video(path):
        out=av.open(str(path),mode="w")
        stream=out.add_stream("mpeg4",rate=1)
        stream.width=32;stream.height=24;stream.pix_fmt="yuv420p"
        frame=av.VideoFrame.from_image(Image.new("RGB",(32,24),(210,30,40)))
        for packet in stream.encode(frame):out.mux(packet)
        for packet in stream.encode():out.mux(packet)
        out.close()

    def add_plan_row(self,db,*,target=None,original=None,source_id=1,kind=5,nested=0):
        db.execute("INSERT INTO video_cover_targets VALUES (?,?,?,?,?,?,?,?)",
          (str(target or self.target),str(original or self.video),source_id,1,100,"seg/1",len(self.data),self.md5))

    def args(self,*,apply=False,cap=128):
        return type("Args",(),{"account":self.account,"metadata_db":self.db_path,"out":self.out,
          "qq_build":"9.9.31-49738","max_added_mib":cap,"only_msg_id":None,"apply":apply})()

    def test_apply_derives_png_from_first_frame_without_changing_video_or_db(self):
        video_before=self.video.read_bytes()
        db_before=self.db_path.read_bytes()
        rc=cover.run(self.args(apply=True))
        self.assertEqual(rc,0)
        self.assertTrue(self.target.is_file())
        with Image.open(self.target) as image:
            self.assertEqual(image.format,"PNG")
            self.assertLessEqual(max(image.size),720)
        self.assertEqual(self.video.read_bytes(),video_before)
        self.assertEqual(self.db_path.read_bytes(),db_before)
        manifest=json.loads(self.out.read_text())
        self.assertTrue(manifest["derived_previews"])
        self.assertEqual(manifest["ui_verified"],0)
        self.assertEqual(manifest["counts"],{"created":1})

    def test_dry_run_does_not_create_cover(self):
        rc=cover.run(self.args())
        self.assertEqual(rc,0)
        self.assertFalse(self.target.exists())
        self.assertEqual(json.loads(self.out.read_text())["counts"],{"planned":1})

    def test_existing_cover_is_never_overwritten(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"already cached thumbnail")
        before=self.target.read_bytes()
        rc=cover.run(self.args(apply=True))
        self.assertEqual(rc,0)
        self.assertEqual(self.target.read_bytes(),before)
        self.assertEqual(json.loads(self.out.read_text())["counts"],{"existing_cover_preserved":1})

    def test_budget_blocks_all_writes(self):
        rc=cover.run(self.args(apply=True,cap=0))
        self.assertEqual(rc,2)
        self.assertFalse(self.target.exists())
        self.assertEqual(json.loads(self.out.read_text())["counts"],{"blocked_all_or_nothing_preflight":1})

    def test_changed_original_hash_refuses_cover(self):
        self.video.write_bytes(b"changed source")
        rc=cover.run(self.args(apply=True))
        self.assertEqual(rc,3)
        self.assertFalse(self.target.exists())
        self.assertEqual(json.loads(self.out.read_text())["counts"],{"source_or_decode_failed":1})

    def test_source_change_after_preflight_refuses_atomic_publish(self):
        original_write=cover._write_exclusive
        def change_then_write(target,data,account,signature,roots):
            self.video.write_bytes(b"changed after preflight")
            return original_write(target,data,account,signature,roots)
        with mock.patch.object(cover,"_write_exclusive",side_effect=change_then_write):
            rc=cover.run(self.args(apply=True))
        self.assertEqual(rc,3)
        self.assertFalse(self.target.exists())
        self.assertEqual(json.loads(self.out.read_text())["counts"],{"apply_failed":1})

    def test_video_content_is_hashed_once_per_plan(self):
        verify=cover.verify_source
        with mock.patch.object(cover,"verify_source",side_effect=verify) as verified:
            self.assertEqual(cover.run(self.args(apply=True)),0)
        self.assertEqual(verified.call_count,1)

    def test_wrong_primary_name_month_or_extension_is_rejected(self):
        wrong=self.video.parent.parent/"Thumb"/("0"*32+"_0.png")
        with self.assertRaisesRegex(ValueError,"cover_path_not_primary_md5_thumb"):
            cover._validate_video_target(str(wrong),str(self.video),self.account.resolve(),self.md5)
        wrong_orig=self.video.with_suffix(".mkv")
        with self.assertRaisesRegex(ValueError,"original_path_not_canonical_video_ori_mp4"):
            cover._validate_video_target(str(self.target),str(wrong_orig),self.account.resolve(),self.md5)

    def test_nested_or_wrong_kind_ref_is_excluded(self):
        db=sqlite3.connect(self.db_path)
        db.execute("UPDATE verified_refs SET nested=1")
        db.commit();db.close()
        plans,_=cover._read_plan(self.db_path,self.account.resolve())
        self.assertEqual(plans,[])

    def test_cover_target_is_independent_of_missing_only_restore_targets(self):
        db=sqlite3.connect(self.db_path)
        db.execute("DROP TABLE restore_targets")
        db.commit();db.close()
        plans,_=cover._read_plan(self.db_path,self.account.resolve())
        self.assertEqual(len(plans),1)
        self.assertEqual(plans[0]["original"],str(self.video))

    def test_ads_collision_rejected(self):
        with self.assertRaisesRegex(ValueError,"device_or_ads_path"):
            cover._validate_windows_path(str(self.video)+":stream")

    def test_drive_relative_path_rejected(self):
        with self.assertRaisesRegex(ValueError,"drive_relative_path"):
            cover._validate_windows_path("D:nt_qq\\nt_data\\Video\\2024-02\\Ori\\clip.mp4")


if __name__=="__main__":
    unittest.main()
