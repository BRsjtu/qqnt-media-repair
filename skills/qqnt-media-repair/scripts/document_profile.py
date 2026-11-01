"""Opt-in, byte-preserving parser for verified legacy FILE subtype-7 records.

This driver reuses the bounded protobuf reader and path/hash primitives from
media_profile.py without modifying that file, preserving subtype-1 plan hashes.
Only recognized local paths, field 45406, a missing extension field, and exact
known legacy failure markers can be changed.
"""
from __future__ import annotations

import ntpath
import re

from media_profile import (
    FAILURE_TEXT, MAX_BLOB, ProfileError, _body, _encode_bytes, _hash,
    _safe_path, _text,
)

PROFILE="legacy-file-subtype7-v1"
NTOS_PREFIX="::NTOSFull::"
_HEX=re.compile(r"[0-9a-fA-F]{32}\Z")
_LOCAL_ABS=re.compile(r"^[A-Za-z]:[\\/]")
_KNOWN_WIRES={45002:0,45003:0,45402:2,45403:2,45405:0,45406:2,
              45407:2,45419:2,45507:0,45509:0,45554:2}


def _signed(value):
    return value-(1<<64) if value >= (1<<63) else value


def _digest_field(value):
    if not isinstance(value,bytes): return None
    if len(value)==16: return value.hex(),"raw16"
    if len(value)==32:
        try:
            text=value.decode("ascii")
        except UnicodeDecodeError:
            return None
        if _HEX.fullmatch(text): return text.lower(),"ascii32"
    return None


def _split_local_uri(value):
    """Accept only a raw local drive path or the observed NTOSFull wrapper."""
    if not isinstance(value,str): return None,None
    if value.startswith(NTOS_PREFIX):
        inner=value[len(NTOS_PREFIX):]
        try: return NTOS_PREFIX,_safe_path(inner)
        except ProfileError: return None,None
    if not _LOCAL_ABS.match(value): return None,None
    try: return "",_safe_path(value)
    except ProfileError: return None,None


def _record(fields,ordinal):
    by={}
    for field in fields: by.setdefault(field.number,[]).append(field)
    def scalar(number):
        xs=by.get(number,[])
        return xs[0].value if len(xs)==1 and xs[0].wire==0 else None
    duplicate_conflict=any(number not in (45411,45412) and
      len({(f.wire,f.value) for f in xs})>1 for number,xs in by.items())
    invalid_wire=any(f.wire!=_KNOWN_WIRES[n] for n,xs in by.items() if n in _KNOWN_WIRES for f in xs)
    filename=_text(by.get(45402,[None])[0]) if len(by.get(45402,[]))==1 else None
    if (not filename or filename.endswith((" ", "."))
            or any(ord(c)<32 or c in '\\/:*?"<>|' for c in filename)):
        filename=None
    extension=ntpath.splitext(filename)[1] if filename else ""
    if not extension or len(extension)>32: filename=None;extension=""
    path_field=by.get(45403,[])
    path_value=_text(path_field[0]) if len(path_field)==1 else None
    prefix,local_path=_split_local_uri(path_value)
    size=scalar(45405)
    legacy_fields=by.get(45407,[])
    legacy=None
    if len(legacy_fields)==1 and legacy_fields[0].wire==2 and len(legacy_fields[0].value)==32:
        try: candidate=legacy_fields[0].value.decode("ascii")
        except UnicodeDecodeError: candidate=""
        if _HEX.fullmatch(candidate): legacy=candidate.lower()
    canon_fields=by.get(45406,[])
    canonical=None;canonical_encoding="missing"
    if len(canon_fields)==1 and canon_fields[0].wire==2:
        decoded=_digest_field(canon_fields[0].value)
        if decoded: canonical,canonical_encoding=decoded
        else: canonical_encoding="invalid"
    elif canon_fields:
        canonical_encoding="invalid"
    ext_fields=by.get(45419,[])
    extension_ok=not ext_fields
    if len(ext_fields)==1 and ext_fields[0].wire==2:
        try:
            declared_extension=ext_fields[0].value.decode("utf-8")
        except UnicodeDecodeError:
            declared_extension=None
        extension_ok=(declared_extension is not None
                      and declared_extension.casefold()==extension.casefold())

    # A matching failure marker is optional. Unknown values in these known
    # flag fields are not interpreted or cleared by this profile.
    known_failure=False;flags_safe=True
    for number,allowed in ((45507,{-7003}),(45509,{1})):
        xs=by.get(number,[])
        if len(xs)>1: flags_safe=False
        elif xs:
            value=_signed(xs[0].value) if xs[0].wire==0 else None
            if value not in allowed: flags_safe=False
            else: known_failure=True
    xs=by.get(45554,[])
    if len(xs)>1: flags_safe=False
    elif xs:
        if xs[0].wire!=2 or xs[0].value!=FAILURE_TEXT: flags_safe=False
        else: known_failure=True
    present_flags={n for n in (45507,45509,45554) if by.get(n)}
    if present_flags and present_flags!={45507,45509,45554}:
        flags_safe=False

    legacy_file=(scalar(45002)==3 and scalar(45003)==7)
    supported=(legacy_file and filename is not None and type(size) is int and size>=0
      and legacy is not None and local_path is not None and extension_ok and flags_safe
      and not invalid_wire and not duplicate_conflict and canonical_encoding!="invalid"
      and (canonical is None or canonical==legacy))
    canonical_needs=canonical_encoding in {"missing","ascii32"}
    eligible=(supported and (canonical_needs or known_failure))
    return {"segment_ordinal":ordinal,"element_type":scalar(45002),"subtype":scalar(45003),
      "filename":filename,"extension":extension,"size":size,"md5":canonical,
      "legacy_md5":legacy,"local_path":local_path,"path_prefix":prefix,
      "canonical_encoding":canonical_encoding,"known_failure":known_failure,
      "failure_pattern_eligible":eligible,"repair_eligible":eligible,
      "supported_profile":supported,"duplicate_conflict":duplicate_conflict,
      "invalid_wire":invalid_wire,"flags_safe":flags_safe}


def inspect_body(blob):
    _,_,segments,stats=_body(blob)
    return {"records":[_record(fields,i) for i,fields in enumerate(segments)],"stats":stats}


def normalize_body(blob,replacements):
    data,outer,segments,stats=_body(blob)
    if not isinstance(replacements,dict): raise ProfileError("replacements must be a dictionary")
    changed={};changes=[]
    for ordinal,replacement in replacements.items():
        if type(ordinal) is not int or not 0<=ordinal<len(segments): raise ProfileError("invalid segment ordinal")
        if not isinstance(replacement,dict) or set(replacement)!={"source_path","md5","size"}:
            raise ProfileError("replacement requires source_path, md5 and size")
        path=_safe_path(replacement["source_path"]);md5=_hash(replacement["md5"]);size=replacement["size"]
        if md5 is None or type(size) is not int or not 0<=size<(1<<64): raise ProfileError("invalid source identity")
        fields=segments[ordinal];record=_record(fields,ordinal)
        if not record["supported_profile"]: raise ProfileError("selected segment is unsupported or conflicting")
        if (size,md5)!=(record["size"],record["legacy_md5"]): raise ProfileError("source size or MD5 does not match ASCII field 45407")
        prefix=record["path_prefix"] or ""
        desired_path=(prefix+path).encode("utf-8")
        digest=bytes.fromhex(md5)
        ext=record["extension"].encode("utf-8")
        failure_numbers={45507,45509,45554}
        no_flags=not any(f.number in failure_numbers for f in fields)
        canonical_raw=record["canonical_encoding"]=="raw16" and record["md5"]==md5
        already=(canonical_raw and no_flags and record["local_path"]==path and
                 len([f for f in fields if f.number==45419])==1)
        if not record["repair_eligible"]:
            if already: continue
            raise ProfileError("selected segment lacks missing/noncanonical MD5 or known failure marker")
        result=[];emitted_path=False;emitted_hash=False;emitted_ext=False
        for field in fields:
            if field.number in failure_numbers:
                # _record admitted only the exact known values above.
                continue
            if field.number==45403:
                if not emitted_path:
                    result.append(field.raw if field.value==desired_path else _encode_bytes(45403,desired_path))
                    emitted_path=True
                continue
            if field.number==45406:
                if not emitted_hash:
                    result.append(field.raw if field.value==digest else _encode_bytes(45406,digest))
                    emitted_hash=True
                continue
            if field.number==45419:
                if not emitted_ext:
                    result.append(field.raw);emitted_ext=True
                continue
            result.append(field.raw)
        if not emitted_path: result.append(_encode_bytes(45403,desired_path))
        if not emitted_hash: result.append(_encode_bytes(45406,digest))
        if not emitted_ext: result.append(_encode_bytes(45419,ext))
        changed[ordinal]=b"".join(result)
        changes.append({"segment_ordinal":ordinal,"source_path":path,"md5":md5,"size":size})
    output=[];ordinal=0
    for field in outer:
        if field.number==40800:
            output.append(_encode_bytes(40800,changed[ordinal]) if ordinal in changed else field.raw);ordinal+=1
        else: output.append(field.raw)
    new=b"".join(output) if changed else data
    if len(new)>MAX_BLOB: raise ProfileError("normalized body size bound exceeded")
    _body(new)
    return new,{"changed_segments":sorted(changed),"changes":changes,"stats":stats}
