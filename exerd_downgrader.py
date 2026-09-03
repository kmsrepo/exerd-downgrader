#!/usr/bin/env python3
"""
eXERD file downgrader
=====================
Allows a lower-version eXERD viewer to open a higher-version .exerd file
by lowering the file-header version (and the embedded Document versions).

File format (reverse-engineered from com.tomato.exerd.model):
  [header][zipped xml-content][zipped binary-content]

  header:
    10 bytes : b"eXERD File"
     4 bytes : major   (big-endian int, ByteBuffer.putInt)
     4 bytes : minor   (big-endian int)
     4 bytes : micro   (big-endian int)
     4 bytes : qualifier length N (big-endian int)
     N bytes : qualifier, e.g. b"20180228-1529"
     8 bytes : zippedXmlContentLength (big-endian long)
               == len of the whole first zip entry
                  (local header + deflated data + data-descriptor)

  each zip entry (no central directory, streaming format):
    PK\\x03\\x04 local header (ver=20, flag=0x0808, method=8 deflate,
      sizes=0 because bit3=data-descriptor is set)
    filename (e.g. "xml-content.xml", "binary-content")
    raw deflate stream
    PK\\x07\\x08 data-descriptor (crc32 of *uncompressed* data,
      compressed size, uncompressed size, all little-endian)

  xml-content.xml (decompressed) contains:
    <e:Document ... version="M.m.p.qualifier" ...>
    3.x files additionally have modelVersion="..." databaseVersion="..."
    and PrintSettings useClearTableName="...".

  binary-content (decompressed, EMF binary "emf\\n\\r\\x1a\\n") contains
  the same Document.version string and feature names "modelVersion",
  "databaseVersion", "useClearTableName" (see ErdResourceImpl).

Version check (ErdResourceImpl.doLoad):
  header.version.compareTo(installedModelVersion) > 0  ->  throw
  "document version (...) is higher than installed eXERD (...)".
So lowering the header version bypasses the gate.  We also patch the
embedded xml/binary versions for consistency, and (for 2.x targets)
neutralise fields that do not exist in the old ecore
(Document.modelVersion / databaseVersion, PrintSettings.useClearTableName)
by deleting them from XML and renaming them in binary to a harmless
same-type feature of the same EClass.

Usage:
  python exerd_downgrader.py info input.exerd
  python exerd_downgrader.py downgrade input.exerd output.exerd --target 2.5.12.20210616-1543
  python exerd_downgrader.py downgrade input.exerd output.exerd --target 2.5 --strip-new-fields

Only stdlib is used.
"""
from __future__ import annotations

import argparse
import binascii
import re
import struct
import sys
import zlib
from pathlib import Path

MAGIC = b"eXERD File"
LOCAL_SIG = b"PK\x03\x04"
DESC_SIG = b"PK\x07\x08"

# ---------------------------------------------------------------------------
# OSGi Version helpers (major.minor.micro.qualifier)
# ---------------------------------------------------------------------------

def parse_osgi_version(s: str):
    """Parse 'M.m.p.qualifier' (qualifier may itself contain dots).
    Accepts short forms like '2.5' or '2'."""
    s = s.strip()
    if not s:
        raise ValueError("empty version")
    parts = s.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        micro = int(parts[2]) if len(parts) > 2 else 0
    except ValueError as e:
        raise ValueError(f"invalid numeric version part in {s!r}") from e
    qualifier = ".".join(parts[3:]) if len(parts) > 3 else ""
    # OSGi qualifier must not contain whitespace; keep as-is otherwise
    return (major, minor, micro, qualifier)


def format_osgi_version(v) -> str:
    major, minor, micro, qualifier = v
    base = f"{major}.{minor}.{micro}"
    return f"{base}.{qualifier}" if qualifier else base


def compare_osgi(a, b) -> int:
    """OSGi Version.compareTo semantics (numeric major/minor/micro, then
    lexical qualifier). Returns -1/0/1."""
    for x, y in zip(a[:3], b[:3]):
        if x != y:
            return -1 if x < y else 1
    # qualifier: "" sorts before any non-empty (like OSGi)
    qa, qb = a[3], b[3]
    if qa == qb:
        return 0
    if qa == "":
        return -1
    if qb == "":
        return 1
    return -1 if qa < qb else 1


# ---------------------------------------------------------------------------
# EMF binary compressed-int (variable length, value+1 stored)
# ---------------------------------------------------------------------------

def encode_compressed_int(value: int) -> bytes:
    """Port of EObjectOutputStream.writeCompressedInt (value may be -1)."""
    v = value + 1
    if v < 0 or (v >> 30) > 63:
        raise ValueError(f"compressed-int out of range: {value}")
    b3 = (v >> 24) & 0xFF
    b2 = (v >> 16) & 0xFF
    b1 = (v >> 8) & 0xFF
    b0 = v & 0xFF
    if b3 != 0:
        return bytes([(b3 | 0xC0), b2, b1, b0])
    if b2 > 63:  # needs 4 bytes as well (top bits would overflow 3-byte form)
        return bytes([(b3 | 0xC0), b2, b1, b0])
    if b2 != 0:
        return bytes([(b2 | 0x80), b1, b0])
    if b1 != 0:
        return bytes([(b1 | 0x40), b0])
    if b0 > 63:
        return bytes([(b1 | 0x40), b0])
    return bytes([b0])


def decode_compressed_int(buf: bytes, pos: int = 0):
    """Return (value, new_pos). Inverse of encode_compressed_int."""
    first = buf[pos]
    kind = (first >> 6) & 0x03
    if kind == 0:
        return (first - 1, pos + 1)
    if kind == 1:
        v = ((first & 0x3F) << 8) | buf[pos + 1]
        return (v - 1, pos + 2)
    if kind == 2:
        v = ((first & 0x3F) << 16) | (buf[pos + 1] << 8) | buf[pos + 2]
        return (v - 1, pos + 3)
    v = ((first & 0x3F) << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3]
    return (v - 1, pos + 4)


def encode_emf_string(s: str) -> bytes:
    """Encode an ASCII-only string the way EMF binary does for short ASCII:
    compressed-int(charCount) + raw bytes.  Only used for our ASCII
    replacements (feature names / version strings)."""
    b = s.encode("ascii")
    return encode_compressed_int(len(s)) + b


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def parse_header(data: bytes):
    if data[: len(MAGIC)] != MAGIC:
        return None
    off = len(MAGIC)
    if len(data) < off + 4 + 4 + 4 + 4:
        raise ValueError("truncated exerd header")
    major = struct.unpack(">i", data[off: off + 4])[0]
    minor = struct.unpack(">i", data[off + 4: off + 8])[0]
    micro = struct.unpack(">i", data[off + 8: off + 12])[0]
    qlen = struct.unpack(">i", data[off + 12: off + 16])[0]
    if qlen < 0 or qlen > 4096:
        raise ValueError(f"insane qualifier length: {qlen}")
    off += 16
    if len(data) < off + qlen + 8:
        raise ValueError("truncated exerd header (qualifier/len)")
    qualifier = data[off: off + qlen].decode("utf-8", errors="replace")
    off += qlen
    zlen = struct.unpack(">q", data[off: off + 8])[0]
    off += 8
    return {
        "major": major,
        "minor": minor,
        "micro": micro,
        "qualifier": qualifier,
        "version": (major, minor, micro, qualifier),
        "version_str": format_osgi_version((major, minor, micro, qualifier)),
        "zipped_xml_len": zlen,
        "header_len": off,
    }


def build_header(version, zipped_xml_len: int) -> bytes:
    major, minor, micro, qualifier = version
    qbytes = qualifier.encode("utf-8")
    out = bytearray()
    out += MAGIC
    out += struct.pack(">i", major)
    out += struct.pack(">i", minor)
    out += struct.pack(">i", micro)
    out += struct.pack(">i", len(qbytes))
    out += qbytes
    out += struct.pack(">q", zipped_xml_len)
    return bytes(out)


# ---------------------------------------------------------------------------
# Streaming zip entries (local header + deflate + PK0708, no central dir)
# ---------------------------------------------------------------------------

def parse_entries(data: bytes, start: int):
    """Parse concatenated streaming entries starting at `start`.
    Returns list of dicts. Stops before central-directory (PK0102/PK0506)
    or end of data."""
    entries = []
    off = start
    n = len(data)
    while off < n:
        sig = data[off: off + 4]
        if sig in (b"PK\x01\x02", b"PK\x05\x06", b"PK\x06\x06", b"PK\x06\x07"):
            # central directory / EOCD -> not part of exerd payload
            break
        if sig != LOCAL_SIG:
            # trailing garbage? stop
            break
        if off + 30 > n:
            raise ValueError(f"truncated local header at {off}")
        ver, flag, method, mtime, mdate = struct.unpack("<HHHHH", data[off + 4: off + 14])
        crc0, cs0, us0 = struct.unpack("<III", data[off + 14: off + 26])
        fn_len, extra_len = struct.unpack("<HH", data[off + 26: off + 30])
        if off + 30 + fn_len + extra_len > n:
            raise ValueError("truncated filename/extra")
        fname = data[off + 30: off + 30 + fn_len]
        data_start = off + 30 + fn_len + extra_len
        has_descriptor = bool(flag & 0x08)
        if has_descriptor:
            desc_off = data.find(DESC_SIG, data_start)
            if desc_off < 0:
                raise ValueError(f"missing data descriptor for {fname!r}")
            comp = data[data_start:desc_off]
            if desc_off + 16 > n:
                raise ValueError("truncated descriptor")
            crc, cs, us = struct.unpack("<III", data[desc_off + 4: desc_off + 16])
            total_len = (desc_off + 16) - off
            next_off = desc_off + 16
        else:
            # sizes known in local header
            cs, us, crc = cs0, us0, crc0
            comp = data[data_start: data_start + cs]
            if len(comp) != cs:
                raise ValueError("truncated entry data")
            total_len = (data_start + cs) - off
            next_off = data_start + cs
            desc_off = None
        entries.append(
            {
                "offset": off,
                "ver": ver,
                "flag": flag,
                "method": method,
                "mtime": mtime,
                "mdate": mdate,
                "fname": fname,
                "extra": data[off + 30 + fn_len: data_start],
                "comp": comp,
                "crc": crc,
                "cs": cs,
                "us": us,
                "has_descriptor": has_descriptor,
                "total_len": total_len,
                "header_len": data_start - off,
            }
        )
        off = next_off
        if off >= n:
            break
    return entries


def build_entry(fname: bytes, raw: bytes, mtime: int, mdate: int, level: int = 6) -> bytes:
    """Build a streaming entry identical in spirit to eXERD's:
    local header (flag 0x0808, sizes 0) + raw-deflate + PK0708."""
    comp_obj = zlib.compressobj(level, zlib.DEFLATED, -15)
    comp = comp_obj.compress(raw) + comp_obj.flush()
    crc = binascii.crc32(raw) & 0xFFFFFFFF
    out = bytearray()
    out += LOCAL_SIG
    out += struct.pack("<HHHHH", 20, 0x0808, 8, mtime, mdate)
    out += struct.pack("<III", 0, 0, 0)
    out += struct.pack("<HH", len(fname), 0)
    out += fname
    out += comp
    out += DESC_SIG
    out += struct.pack("<III", crc, len(comp), len(raw))
    return bytes(out)


def decompress_entry(e) -> bytes:
    if e["method"] == 0:  # stored
        if len(e["comp"]) != e["us"]:
            # tolerate descriptor-based stored? just return as-is
            pass
        return e["comp"]
    if e["method"] != 8:
        raise ValueError(f"unsupported compression method {e['method']}")
    return zlib.decompress(e["comp"], -15)


# ---------------------------------------------------------------------------
# XML patching
# ---------------------------------------------------------------------------

DOC_VERSION_RE = re.compile(r'(<e:Document\b[^>]*?\sversion=")([^"]*)(")')
MODELVERSION_ATTR_RE = re.compile(r'\smodelVersion="[^"]*"')
DATABASEVERSION_ATTR_RE = re.compile(r'\sdatabaseVersion="[^"]*"')
USECLEARTABLENAME_ATTR_RE = re.compile(r'\suseClearTableName="[^"]*"')

# fallback: any version="x.y.z..." that looks like an exerd version
EXERD_VER_LIKE_RE = re.compile(r'\b\d+\.\d+\.\d+\.\d{8}-\d+\b')


def patch_xml(xml_bytes: bytes, target_str: str, strip_new_fields: bool):
    try:
        text = xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = xml_bytes.decode("utf-8", errors="replace")
    info = {"replaced_version": 0, "removed_modelVersion": 0,
            "removed_databaseVersion": 0, "removed_useClearTableName": 0}
    # 1) Document version="..." -> target (only the Document tag, not <?xml version=...>)
    def _doc_repl(m):
        info["replaced_version"] += 1
        return m.group(1) + target_str + m.group(3)
    new_text, n = DOC_VERSION_RE.subn(_doc_repl, text, count=1)
    text = new_text
    if strip_new_fields:
        text, n = MODELVERSION_ATTR_RE.subn("", text)
        info["removed_modelVersion"] = n
        text, n = DATABASEVERSION_ATTR_RE.subn("", text)
        info["removed_databaseVersion"] = n
        text, n = USECLEARTABLENAME_ATTR_RE.subn("", text)
        info["removed_useClearTableName"] = n
    else:
        # still normalise modelVersion/databaseVersion values to target so the
        # file is self-consistent (avoids a 3.x file claiming 2.x model mix)
        if 'modelVersion="' in text:
            text = re.sub(r'(\smodelVersion=")[^"]*(")', r"\g<1>" + target_str + r"\g<2>", text)
        if 'databaseVersion="' in text:
            text = re.sub(r'(\sdatabaseVersion=")[^"]*(")', r"\g<1>" + target_str + r"\g<2>", text)
    return text.encode("utf-8"), info


# ---------------------------------------------------------------------------
# Binary patching
# ---------------------------------------------------------------------------

def _replace_ascii_with_len_fix(blob: bytes, old: bytes, new: bytes) -> tuple[bytes, int]:
    """Replace every occurrence of encode_compressed_int(len(old))+old with
    encode_compressed_int(len(new))+new. Returns (patched, count)."""
    old_seq = encode_compressed_int(len(old)) + old
    new_seq = encode_compressed_int(len(new)) + new
    count = blob.count(old_seq)
    if count:
        blob = blob.replace(old_seq, new_seq)
    return blob, count


def patch_binary(raw: bytes, old_version_strs: list[str], target_str: str,
                 strip_new_fields: bool):
    info = {"version_replaced": 0, "renamed": {}}
    # 1) version values: replace each distinct old version string with target
    #    (dedupe, longest first to avoid partial overlaps)
    olds = sorted({s for s in old_version_strs if s}, key=len, reverse=True)
    for old in olds:
        if old == target_str:
            continue
        raw, c = _replace_ascii_with_len_fix(raw, old.encode("ascii"), target_str.encode("ascii"))
        info["version_replaced"] += c
    # 1b) catch-all: any remaining exerd-looking version (M.m.p.YYYYMMDD-N)
    #    in binary is almost certainly a version field (Document.version /
    #    modelVersion / databaseVersion), not user data - the pattern is too
    #    specific to appear in table/column names. Replace leftovers so a
    #    file that went through several upgrades doesn't keep a higher
    #    version string behind.
    try:
        text_probe = raw.decode("utf-8", errors="ignore")
        leftovers = sorted(set(EXERD_VER_LIKE_RE.findall(text_probe)), key=len, reverse=True)
        for lv in leftovers:
            if lv == target_str:
                continue
            # only downgrade (don't touch versions already lower than target;
            # they are harmless and might be user data)
            try:
                if compare_osgi(parse_osgi_version(lv), parse_osgi_version(target_str)) <= 0:
                    continue
            except ValueError:
                continue
            raw, c = _replace_ascii_with_len_fix(raw, lv.encode("ascii"), target_str.encode("ascii"))
            info["version_replaced"] += c
    except Exception:  # noqa: BLE001
        pass
    # 2) unknown-field neutralisation for old (2.x) viewers.
    #    Binary stores feature *names*; an old ecore throws on unknown names
    #    (modelVersion/databaseVersion in Document, useClearTableName in
    #    PrintSettings).  Rename them to a harmless same-type feature of the
    #    SAME EClass so the old loader accepts the entry:
    #      Document (EString): modelVersion/databaseVersion -> customDataTypeFile
    #        (optional EString, usually absent -> harmless overwrite)
    #      PrintSettings (boolean): useClearTableName -> useNoteBackground
    #        (same length! same type -> zero-size-change rename)
    if strip_new_fields:
        renames = [
            ("modelVersion", "customDataTypeFile"),
            ("databaseVersion", "customDataTypeFile"),
            ("useClearTableName", "useNoteBackground"),
        ]
        for old_name, new_name in renames:
            raw, c = _replace_ascii_with_len_fix(
                raw, old_name.encode("ascii"), new_name.encode("ascii"))
            if c:
                info["renamed"][f"{old_name}->{new_name}"] = c
    return raw, info


# ---------------------------------------------------------------------------
# High-level file handling
# ---------------------------------------------------------------------------

def load_exerd(path: Path):
    data = path.read_bytes()
    hdr = parse_header(data)
    if hdr is None:
        return {"path": path, "data": data, "header": None,
                "entries": [], "is_headerless": True}
    entries = parse_entries(data, hdr["header_len"])
    # sanity: header's zipped len should equal first entry len
    return {"path": path, "data": data, "header": hdr, "entries": entries,
            "is_headerless": False}


def describe(exerd) -> str:
    lines = []
    p = exerd["path"]
    data = exerd["data"]
    lines.append(f"file: {p} ({len(data)} bytes)")
    hdr = exerd["header"]
    if hdr is None:
        lines.append("header: NONE (legacy headerless raw-binary file)")
        lines.append("  -> no version gate; downgrade is a no-op (already loadable).")
        return "\n".join(lines)
    lines.append(
        f"header version : {hdr['version_str']} "
        f"(major={hdr['major']} minor={hdr['minor']} micro={hdr['micro']} "
        f"qualifier={hdr['qualifier']!r})"
    )
    lines.append(
        f"header zippedXmlLen: {hdr['zipped_xml_len']}  headerLen: {hdr['header_len']}"
    )
    entries = exerd["entries"]
    lines.append(f"zip entries: {len(entries)}")
    for i, e in enumerate(entries):
        try:
            raw = decompress_entry(e)
            ok = f"decompressed={len(raw)}B"
            # crc check
            calc = binascii.crc32(raw) & 0xFFFFFFFF
            crc_ok = "crcOK" if calc == e["crc"] else f"crcMISMATCH(calc={calc:08x} stored={e['crc']:08x})"
            size_ok = "sizeOK" if (len(e["comp"]) == e["cs"] and len(raw) == e["us"]) else "sizeMISMATCH"
        except Exception as ex:  # noqa: BLE001
            ok = f"decompress FAILED: {ex}"
            crc_ok = ""
            size_ok = ""
        try:
            fn = e["fname"].decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            fn = repr(e["fname"])
        lines.append(
            f"  [{i}] {fn} method={e['method']} comp={len(e['comp'])}B "
            f"(stored cs={e['cs']} us={e['us']}) {ok} {crc_ok} {size_ok}"
        )
    # xml versions
    for e in entries:
        try:
            fn = e["fname"].decode()
        except Exception:  # noqa: BLE001
            continue
        if fn == "xml-content.xml":
            try:
                raw = decompress_entry(e)
                txt = raw.decode("utf-8", errors="replace")
                m = re.search(r'<e:Document\b[^>]*>', txt)
                if m:
                    tag = m.group(0)
                    # shorten for display
                    short = tag if len(tag) < 600 else tag[:600] + "..."
                    lines.append(f"xml <e:Document>: {short}")
                    for mm in re.finditer(r'(version|modelVersion|databaseVersion|productId)="([^"]*)"', tag):
                        lines.append(f"    {mm.group(1)} = {mm.group(2)}")
                # check new-field presence in whole xml
                for attr in ("modelVersion=", "databaseVersion=", "useClearTableName="):
                    if attr in txt:
                        lines.append(f"  xml contains newer attribute: {attr.rstrip('=')}")
            except Exception as ex:  # noqa: BLE001
                lines.append(f"  xml parse failed: {ex}")
    # binary version strings
    for e in entries:
        try:
            fn = e["fname"].decode()
        except Exception:  # noqa: BLE001
            continue
        if fn == "binary-content":
            try:
                raw = decompress_entry(e)
                vers = sorted(set(EXERD_VER_LIKE_RE.findall(raw.decode("utf-8", errors="ignore"))))
                if vers:
                    lines.append(f"binary version-like strings: {vers}")
                for feat in ("modelVersion", "databaseVersion", "useClearTableName"):
                    seq = encode_compressed_int(len(feat)) + feat.encode()
                    if seq in raw:
                        lines.append(f"  binary contains newer feature name: {feat} ({raw.count(seq)}x)")
            except Exception as ex:  # noqa: BLE001
                lines.append(f"  binary scan failed: {ex}")
    # header/entry consistency
    if entries:
        first_len = entries[0]["total_len"]
        if first_len != hdr["zipped_xml_len"]:
            lines.append(
                f"WARNING: header zippedXmlLen ({hdr['zipped_xml_len']}) != "
                f"first-entry total ({first_len})"
            )
    return "\n".join(lines)


def downgrade_file(src: Path, dst: Path, target_str: str,
                   strip_new_fields: bool | None = None,
                   level: int = 6, verbose: bool = True) -> dict:
    target = parse_osgi_version(target_str)
    target_norm = format_osgi_version(target)
    target_is_2x = (target[0] == 2)
    if strip_new_fields is None:
        strip_new_fields = target_is_2x  # auto: strip when targeting 2.x

    blob = load_exerd(src)
    if blob["header"] is None:
        # headerless legacy file: patch raw binary version strings in place
        raw = blob["data"]
        # find version-like strings and replace? without header we don't know
        # old version; just report no-op. Still allow explicit replace if the
        # raw blob contains the target-different versions? We keep it simple:
        # copy file unchanged (already bypasses the gate).
        dst.write_bytes(raw)
        return {"note": "headerless input: copied unchanged (no gate to bypass)",
                "target": target_norm}

    hdr = blob["header"]
    entries = blob["entries"]
    if not entries:
        raise ValueError("no zip entries found after header")
    cmp = compare_osgi(target, hdr["version"])
    if cmp > 0 and verbose:
        print(f"NOTE: target {target_norm} is HIGHER than source {hdr['version_str']}; "
              f"this is an upgrade, not a downgrade.", file=sys.stderr)

    # locate xml / binary entries (names may vary in case? keep exact)
    xml_idx = next((i for i, e in enumerate(entries)
                    if e["fname"] == b"xml-content.xml"), None)
    bin_idx = next((i for i, e in enumerate(entries)
                    if e["fname"] == b"binary-content"), None)
    if xml_idx is None:
        raise ValueError("xml-content.xml entry not found")
    xml_entry = entries[xml_idx]
    xml_raw = decompress_entry(xml_entry)
    bin_raw = None
    bin_entry = None
    if bin_idx is not None:
        bin_entry = entries[bin_idx]
        bin_raw = decompress_entry(bin_entry)

    # collect old version strings for binary patching
    old_versions: list[str] = [hdr["version_str"]]
    try:
        xml_text = xml_raw.decode("utf-8", errors="replace")
        m = DOC_VERSION_RE.search(xml_text)
        if m and m.group(2) not in old_versions:
            old_versions.append(m.group(2))
        for mm in re.finditer(r'\s(?:modelVersion|databaseVersion)="([^"]*)"', xml_text):
            if mm.group(1) not in old_versions:
                old_versions.append(mm.group(1))
    except Exception:  # noqa: BLE001
        pass

    # ---- patch xml ----
    new_xml, xml_info = patch_xml(xml_raw, target_norm, strip_new_fields)
    # ---- patch binary ----
    bin_info = {}
    new_bin = bin_raw
    if bin_raw is not None:
        new_bin, bin_info = patch_binary(bin_raw, old_versions, target_norm,
                                         strip_new_fields)

    # ---- rebuild entries (preserve filenames/timestamps/order) ----
    new_parts: list[bytes] = []
    for i, e in enumerate(entries):
        if i == xml_idx:
            new_parts.append(build_entry(e["fname"], new_xml,
                                         e["mtime"], e["mdate"], level))
        elif i == bin_idx:
            assert new_bin is not None
            new_parts.append(build_entry(e["fname"], new_bin,
                                         e["mtime"], e["mdate"], level))
        else:
            # unknown extra entry: copy verbatim (re-emit with same bytes?)
            # safest: re-emit decompressed+recompressed to fix CRCs? No -
            # keep original bytes verbatim to avoid damage.
            start = e["offset"]
            new_parts.append(blob["data"][start: start + e["total_len"]])

    new_xml_part = new_parts[xml_idx]
    new_header = build_header(target, len(new_xml_part))
    out = bytearray()
    out += new_header
    for p in new_parts:
        out += p
    dst.write_bytes(bytes(out))
    return {
        "src_version": hdr["version_str"],
        "target": target_norm,
        "dst": str(dst),
        "xml_info": xml_info,
        "bin_info": bin_info,
        "old_versions_seen": old_versions,
        "new_size": len(out),
        "strip_new_fields": strip_new_fields,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

PRESETS = {
    "2.5-latest": "2.5.17.20220110-1118",
    "2.5.12": "2.5.12.20210616-1543",
    "2.5.0": "2.5.0.20180228-1529",
    "3.0-first": "3.0.0.20190111-1604",
}

def _resolve_target(s: str) -> str:
    if s in PRESETS:
        return PRESETS[s]
    # allow 'v' prefix
    if s.startswith("v"):
        s = s[1:]
    # validate
    parse_osgi_version(s)
    return s


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="eXERD .exerd downgrader: lower the file-header version so "
                    "an older eXERD viewer can open a newer file.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="show header / entry / version info")
    p_info.add_argument("input", type=Path, help="input .exerd file")

    p_down = sub.add_parser("downgrade", help="downgrade a file to a lower version")
    p_down.add_argument("input", type=Path, help="input .exerd (higher version)")
    p_down.add_argument("output", type=Path, help="output .exerd (patched)")
    p_down.add_argument("--target", required=True,
                        help="target version, e.g. 2.5.12.20210616-1543, 2.5, "
                             "or preset: " + ", ".join(f"{k}={v}" for k, v in PRESETS.items()))
    g = p_down.add_mutually_exclusive_group()
    g.add_argument("--strip-new-fields", dest="strip", action="store_true", default=None,
                   help="remove/neutralise 3.x-only fields (modelVersion, "
                        "databaseVersion, useClearTableName) [default when target is 2.x]")
    g.add_argument("--keep-new-fields", dest="strip", action="store_false",
                   help="keep 3.x-only fields (only header+version are lowered)")
    p_down.add_argument("--level", type=int, default=6, choices=range(1, 10),
                        help="deflate level for rebuilt entries (default 6)")
    p_down.add_argument("--force", action="store_true",
                        help="overwrite output if it exists")

    args = ap.parse_args(argv)
    if args.cmd == "info":
        ex = load_exerd(args.input)
        print(describe(ex))
        return 0
    if args.cmd == "downgrade":
        src: Path = args.input
        dst: Path = args.output
        if not src.is_file():
            print(f"input not found: {src}", file=sys.stderr)
            return 2
        if dst.exists() and not args.force:
            print(f"output exists: {dst} (use --force to overwrite)", file=sys.stderr)
            return 2
        try:
            target = _resolve_target(args.target)
        except ValueError as e:
            print(f"bad --target: {e}", file=sys.stderr)
            return 2
        # auto default for strip (None -> auto inside downgrade_file)
        strip = args.strip
        res = downgrade_file(src, dst, target, strip_new_fields=strip,
                             level=args.level, verbose=True)
        print(f"source version : {res.get('src_version')}")
        print(f"target version : {res.get('target')}")
        print(f"wrote          : {res.get('dst')} ({res.get('new_size')} bytes)")
        print(f"strip-new-fields: {res.get('strip_new_fields')}")
        if res.get("old_versions_seen"):
            print(f"old versions seen: {res['old_versions_seen']}")
        if res.get("xml_info"):
            print(f"xml patch      : {res['xml_info']}")
        if res.get("bin_info"):
            print(f"binary patch   : {res['bin_info']}")
        print("verify with: python exerd_downgrader.py info", dst)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
