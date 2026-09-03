#!/usr/bin/env python3
"""Self-tests for exerd_downgrader (stdlib only, no sample file required).

Creates synthetic .exerd files in-memory (2.5-style and 3.x-style) and
checks info/downgrade round-trips, CRCs and stripping.
Run:  python3 test_downgrader.py
"""
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from exerd_downgrader import (  # noqa: E402
    build_entry,
    build_header,
    compare_osgi,
    decode_compressed_int,
    decompress_entry,
    downgrade_file,
    encode_compressed_int,
    load_exerd,
    parse_header,
    parse_osgi_version,
)

ORIG_VER = "2.5.0.20180228-1529"
TARGET_2X = "2.5.12.20210616-1543"
TARGET_2017 = "2.4.7.20161226-2038"
SRC_3X_HDR = "3.0.0.20190111-1604"
SRC_3X_DOC = "3.3.56.20260820-1610"


def make_minimal_exerd(header_ver: str, doc_ver: str, extra_xml_attrs="",
                       extra_bin: bytes = b""):
    xml = (f'<?xml version="1.1" encoding="utf-8"?>\n'
           f'<e:Document xmi:version="2.0" xmlns:xmi="http://www.omg.org/XMI" '
           f'xmlns:e="http://exerd.tomato.com/model" version="{doc_ver}"{extra_xml_attrs} '
           f'productId="com.tomato.db.db2"></e:Document>').encode()
    # minimal EMF-binary-like blob: signature + version byte + our version strings.
    # (Not a full valid EMF model, but enough to exercise string patching.)
    blob = bytearray(b"\x89emf\n\r\x1a\n\x00")
    blob += encode_compressed_int(len(doc_ver)) + doc_ver.encode()
    blob += extra_bin
    xml_e = build_entry(b"xml-content.xml", xml, 0x4B7, 0x4BBF)
    bin_e = build_entry(b"binary-content", bytes(blob), 0x4B7, 0x4BBF)
    hdr = build_header(parse_osgi_version(header_ver), len(xml_e))
    return hdr + xml_e + bin_e


def test_version_helpers():
    assert parse_osgi_version("2.5.12.20210616-1543") == (2, 5, 12, "20210616-1543")
    assert parse_osgi_version("2.5") == (2, 5, 0, "")
    assert compare_osgi(parse_osgi_version("3.0.0.20190111-1604"),
                        parse_osgi_version("2.5.12.20210616-1543")) > 0
    assert compare_osgi(parse_osgi_version("2.4.7"),
                        parse_osgi_version("2.5.0.20180228-1529")) < 0
    for i in (-1, 0, 1, 7, 19, 63, 64, 1000, 1 << 20):
        enc = encode_compressed_int(i)
        dec, _ = decode_compressed_int(enc, 0)
        assert dec == i, (i, enc, dec)
    print("ok - version helpers")


def test_header_roundtrip():
    for vs in [ORIG_VER, TARGET_2X, SRC_3X_HDR, "2.4.7"]:
        h = build_header(parse_osgi_version(vs), 2879)
        p = parse_header(h + b"PK")
        assert p["version_str"] == vs, (vs, p)
    print("ok - header roundtrip")


def test_downgrade_2x_to_2x():
    with tempfile.TemporaryDirectory() as td:
        src = pathlib.Path(td) / "in.exerd"
        dst = pathlib.Path(td) / "out.exerd"
        src.write_bytes(make_minimal_exerd(ORIG_VER, ORIG_VER))
        res = downgrade_file(src, dst, "2.4.7")
        assert dst.exists()
        ex = load_exerd(dst)
        assert ex["header"]["version_str"] == "2.4.7"
        xml = decompress_entry(ex["entries"][0]).decode()
        assert 'version="2.4.7"' in xml
        print("ok - 2.x to 2.x downgrade", res["xml_info"], res["bin_info"])


def test_downgrade_3x_to_2x_strips():
    extra_xml = ' modelVersion="3.0.0.20190111-1604" databaseVersion="3.0.0.20190111-1604"'
    # binary extras: feature names + values (as the real files contain)
    extra_bin = (encode_compressed_int(len("modelVersion")) + b"modelVersion"
                 + encode_compressed_int(len(SRC_3X_HDR)) + SRC_3X_HDR.encode()
                 + encode_compressed_int(len("databaseVersion")) + b"databaseVersion"
                 + encode_compressed_int(len(SRC_3X_HDR)) + SRC_3X_HDR.encode()
                 + encode_compressed_int(len("useClearTableName")) + b"useClearTableName"
                 + bytes([1]))
    with tempfile.TemporaryDirectory() as td:
        src = pathlib.Path(td) / "in3.exerd"
        dst = pathlib.Path(td) / "out2.exerd"
        src.write_bytes(make_minimal_exerd(SRC_3X_HDR, SRC_3X_DOC, extra_xml, extra_bin))
        before = load_exerd(src)
        assert before["header"]["version_str"] == SRC_3X_HDR
        res = downgrade_file(src, dst, TARGET_2X)
        after = load_exerd(dst)
        assert after["header"]["version_str"] == TARGET_2X, after["header"]
        xml = decompress_entry(after["entries"][0]).decode()
        assert f'version="{TARGET_2X}"' in xml
        assert "modelVersion" not in xml, xml[:500]
        assert "databaseVersion" not in xml
        assert "useClearTableName" not in xml
        raw = decompress_entry(after["entries"][1])
        assert (encode_compressed_int(len("modelVersion")) + b"modelVersion") not in raw
        assert (encode_compressed_int(len("databaseVersion")) + b"databaseVersion") not in raw
        assert (encode_compressed_int(len("useClearTableName")) + b"useClearTableName") not in raw
        # renamed targets should exist instead (harmless same-type features)
        assert b"customDataTypeFile" in raw
        assert b"useNoteBackground" in raw
        # no higher version strings left
        assert SRC_3X_HDR.encode() not in raw
        assert SRC_3X_DOC.encode() not in raw
        print("ok - 3.x to 2.x strip", res["xml_info"], res["bin_info"])


def test_downgrade_to_2017():
    # 2018-style (2.5.0) and 2019-style (3.x) files -> 2017 viewer (2.4.7).
    # Ecore is identical across 2.4.7/2.5.x/3.0.0, so this is stamps-only
    # (+ stripping the post-3.0 fields for the 3.x file).
    extra_xml = ' modelVersion="3.0.0.20190111-1604" databaseVersion="3.0.0.20190111-1604"'
    extra_bin = (encode_compressed_int(len("modelVersion")) + b"modelVersion"
                 + encode_compressed_int(len(SRC_3X_HDR)) + SRC_3X_HDR.encode())
    cases = [
        (ORIG_VER, ORIG_VER, "", b""),
        (SRC_3X_HDR, SRC_3X_DOC, extra_xml, extra_bin),
    ]
    with tempfile.TemporaryDirectory() as td:
        for i, (hdr_ver, doc_ver, xa, xb) in enumerate(cases):
            src = pathlib.Path(td) / f"in{i}.exerd"
            dst = pathlib.Path(td) / f"out{i}.exerd"
            src.write_bytes(make_minimal_exerd(hdr_ver, doc_ver, xa, xb))
            downgrade_file(src, dst, TARGET_2017)
            after = load_exerd(dst)
            assert after["header"]["version_str"] == TARGET_2017, after["header"]
            xml = decompress_entry(after["entries"][0]).decode()
            assert f'version="{TARGET_2017}"' in xml
            assert "modelVersion" not in xml and "databaseVersion" not in xml
            raw = decompress_entry(after["entries"][1])
            assert (encode_compressed_int(len("modelVersion")) + b"modelVersion") not in raw
    print("ok - downgrade to 2017 (2.5.x and 3.x sources)")


def test_keep_new_fields():
    extra_xml = ' modelVersion="3.0.0.20190111-1604"'
    with tempfile.TemporaryDirectory() as td:
        src = pathlib.Path(td) / "in.exerd"
        dst = pathlib.Path(td) / "out.exerd"
        src.write_bytes(make_minimal_exerd(SRC_3X_HDR, SRC_3X_DOC, extra_xml))
        downgrade_file(src, dst, SRC_3X_HDR, strip_new_fields=False)
        xml = decompress_entry(load_exerd(dst)["entries"][0]).decode()
        assert "modelVersion" in xml  # kept, only version lowered/normalised
        print("ok - keep-new-fields")


if __name__ == "__main__":
    test_version_helpers()
    test_header_roundtrip()
    test_downgrade_2x_to_2x()
    test_downgrade_3x_to_2x_strips()
    test_downgrade_to_2017()
    test_keep_new_fields()
    print("ALL TESTS PASSED")
