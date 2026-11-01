import hashlib
from collections import Counter
from pathlib import Path
import sqlite3
import tempfile
import unittest
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"skills"/"qqnt-media-repair"/"scripts"))
import broad_media_scan as scan
from broad_media_extract import extract_media


def varint(value):
    out=bytearray()
    while value>127:
        out.append((value&127)|128);value>>=7
    out.append(value)
    return bytes(out)


def integer(number,value):
    return varint(number<<3)+varint(value)


def raw(number,value):
    value=value.encode() if isinstance(value,str) else value
    return varint((number<<3)|2)+varint(len(value))+value


class VideoCoverCollectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.account=self.root/"account"
        self.account.mkdir()
        self.out=scan.init_output(self.root/"metadata.sqlite")
        self.md5=hashlib.md5(b"verified video").hexdigest()
        self.sha=hashlib.sha256(b"verified video").hexdigest()
        self.size=len(b"verified video")
        self.out.execute("INSERT INTO verified_sources VALUES (1,?,?,?,?)",(self.size,self.md5,self.sha,"C:/source.mp4"))
        self.out.commit()
        self.original=self.account/"nt_qq"/"nt_data"/"Video"/"2024-02"/"Ori"/(self.md5+".mp4")
        self.target=self.account/"nt_qq"/"nt_data"/"Video"/"2024-02"/"Thumb"/(self.md5+"_0.png")
        self.record={"media_type":"video","nested_reference":False,"md5_conflict":False,
          "size_conflict":False,"type_conflict":False,"md5":self.md5,"size":self.size,"segment_path":"[]"}
        self.status=[{"field":"45403","is_thumbnail_path":False,"status":"missing","resolved_path":str(self.original)},
          {"field":"45404","is_thumbnail_path":True,"status":"missing","resolved_path":str(self.target)}]
        self.counts=Counter()

    def tearDown(self):
        self.out.close()
        self.tmp.cleanup()

    def collect(self,record=None,status=None,source_id=1,mid=100):
        scan.save_video_cover_targets(self.out,record or self.record,status or self.status,
          source_id,0,mid,self.account,self.counts)

    def test_existing_original_is_collected_for_declared_thumb(self):
        self.original.parent.mkdir(parents=True);self.original.write_bytes(b"verified video")
        self.status[0].update(status="exists",size=self.size)
        self.collect()
        row=self.out.execute("SELECT target_path,original_path,source_id,table_code,msg_id,segment_path,expected_size,expected_md5 FROM video_cover_targets").fetchone()
        self.assertEqual(row,(str(self.target),str(self.original),1,0,100,'"[]"',self.size,self.md5))
        self.assertEqual(self.counts["video_cover_targets.added"],1)

    def test_noncanonical_nested_or_mismatched_records_are_excluded(self):
        self.collect({**self.record,"nested_reference":True})
        self.collect({**self.record,"md5":"0"*32})
        bad=[{"field":"45403","is_thumbnail_path":False,"status":"missing",
              "resolved_path":str(self.original.with_suffix(".mkv"))},self.status[1]]
        self.collect(status=bad,mid=101)
        outside=[{"field":"45403","is_thumbnail_path":False,"status":"missing",
                  "resolved_path":str(self.root/"outside"/(self.md5+".mp4"))}]
        self.collect(status=outside,mid=102)
        self.assertEqual(self.out.execute("SELECT count(*) FROM video_cover_targets").fetchone()[0],0)
        self.assertGreaterEqual(self.counts.get("video_cover_targets.excluded_noncanonical_original_path",0),1)
        self.assertGreaterEqual(self.counts.get("video_cover_targets.excluded_outside_account",0),1)

    def test_conflicting_source_identity_blocks_derived_path(self):
        self.collect(mid=100)
        other_size=self.size+1
        self.out.execute("INSERT INTO verified_sources VALUES (2,?,?,?,?)",
                         (other_size,self.md5,hashlib.sha256(b"different").hexdigest(),"C:/other.mp4"))
        self.out.commit()
        changed={**self.record,"size":other_size}
        self.collect(changed,source_id=2,mid=101)
        self.assertEqual(self.out.execute("SELECT count(*) FROM video_cover_targets").fetchone()[0],0)
        self.assertEqual(self.out.execute("SELECT reason FROM blocked_restore_paths WHERE path=?",(str(self.target),)).fetchone()[0],"conflicting_video_cover_sources")
        self.assertEqual(self.counts["video_cover_targets.conflicting_paths"],1)

    def test_unverified_source_identity_is_rejected(self):
        self.collect(source_id=99)
        self.assertEqual(self.out.execute("SELECT count(*) FROM video_cover_targets").fetchone()[0],0)
        self.assertEqual(self.counts["video_cover_targets.excluded_unverified_source_identity"],1)

    def test_cover_requires_explicit_mapped_45404_and_exact_derived_path(self):
        self.collect(status=[self.status[0]])
        self.assertEqual(self.out.execute("SELECT count(*) FROM video_cover_targets").fetchone()[0],0)
        unknown_cover=[self.status[0],{"field":"45404","is_thumbnail_path":True,
                       "status":"outside_authorized_roots"}]
        self.collect(status=unknown_cover,mid=105)
        self.assertEqual(self.out.execute("SELECT count(*) FROM video_cover_targets").fetchone()[0],0)
        wrong_month=self.account/"nt_qq"/"nt_data"/"Video"/"2024-03"/"Thumb"/(self.md5+"_0.png")
        self.collect(status=[self.status[0],{**self.status[1],"resolved_path":str(wrong_month)}],mid=101)
        wrong_hash=self.target.with_name("0"*32+"_0.png")
        self.collect(status=[self.status[0],{**self.status[1],"resolved_path":str(wrong_hash)}],mid=102)
        outside=self.root/"outside"/self.target.name
        self.collect(status=[self.status[0],{**self.status[1],"resolved_path":str(outside)}],mid=103)
        conflicting=self.status+[{"field":"45404","is_thumbnail_path":True,"status":"missing",
                                  "resolved_path":str(self.target.with_name("other.png"))}]
        self.collect(status=conflicting,mid=104)
        self.assertEqual(self.out.execute("SELECT count(*) FROM video_cover_targets").fetchone()[0],0)
        self.assertEqual(self.counts["video_cover_targets.excluded_missing_declared_path"],3)
        self.assertGreaterEqual(self.counts["video_cover_targets.excluded_noncanonical_declared_cover_path"],2)
        self.assertGreaterEqual(self.counts["video_cover_targets.excluded_conflicting_declared_paths"],1)

    def test_extracts_45404_only_for_video(self):
        video=integer(45002,5)+raw(45403,str(self.original))+raw(45404,"::NTOSFull::"+str(self.target))
        records,stats=extract_media(raw(40800,video))
        self.assertEqual(stats["status"],"ok")
        self.assertEqual(records[0]["local_paths"]["45404"],[str(self.target)])
        image=integer(45002,2)+raw(45404,str(self.target))
        records,_=extract_media(raw(40800,image))
        self.assertNotIn("45404",records[0]["local_paths"])

    def test_mixed_valid_and_invalid_duplicate_45404_fails_closed(self):
        statuses=self.status
        valid_prefix=(integer(45002,5)+integer(45405,self.size)
                      +raw(45406,bytes.fromhex(self.md5))+raw(45403,str(self.original))
                      +raw(45404,str(self.target)))
        for ordinal,invalid in enumerate((raw(45404,"https://invalid/cover.png"),integer(45404,1)),start=110):
            records,_=extract_media(raw(40800,valid_prefix+invalid))
            record=records[0]
            self.assertEqual(record["local_paths"]["45404"],[str(self.target)])
            self.assertEqual(record["invalid_local_path_fields"]["45404"],1)
            self.collect(record=record,status=statuses,mid=ordinal)
        self.assertEqual(self.out.execute("SELECT count(*) FROM video_cover_targets").fetchone()[0],0)
        self.assertEqual(self.counts["video_cover_targets.excluded_invalid_declared_path"],2)

    def test_old_image_restore_targets_still_work_without_video_cover_row(self):
        image_md5=hashlib.md5(b"image").hexdigest()
        self.out.execute("INSERT INTO verified_sources VALUES (2,5,?,?,?)",(image_md5,hashlib.sha256(b"image").hexdigest(),"C:/image.jpg"))
        self.out.commit()
        image_path=self.account/"nt_qq"/"nt_data"/"Pic"/"recv"/"2024-02"/"Ori"/(image_md5+".jpg")
        image={"media_type":"image","nested_reference":False,"md5_conflict":False,"size_conflict":False,
          "type_conflict":False,"md5":image_md5,"size":5,"segment_path":"[]"}
        statuses=[{"field":"45403","is_thumbnail_path":False,"status":"missing","resolved_path":str(image_path)}]
        scan.save_restore_targets(self.out,image,statuses,2,0,200,self.account,self.counts)
        scan.save_video_cover_targets(self.out,image,statuses,2,0,200,self.account,self.counts)
        self.assertEqual(self.out.execute("SELECT count(*) FROM restore_targets").fetchone()[0],1)
        self.assertEqual(self.out.execute("SELECT count(*) FROM video_cover_targets").fetchone()[0],0)


if __name__=="__main__":
    unittest.main()
