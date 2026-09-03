# eXERD file downgrader

Let an **older eXERD viewer open a newer `.exerd` file** by lowering the
file-header version (plus the embedded Document versions for consistency).

Two implementations, same logic:

| File | Use |
|---|---|
| `index.html` | Offline browser version — double-click, drag & drop, no install, no upload |
| `exerd_downgrader.py` | Python CLI (stdlib only) for batch/scripting |
| `test_downgrader.py` | Self-tests for the Python CLI |

## Why

Newer eXERD refuses to open newer files on an old install:

```
문서의 버전(3.0.0.20190111-1604)이 설치된 eXERD(2.5.12.20210616-1543)보다 높아서 열 수 없습니다.
eXERD를 업데이트 받으신 후에 다시 여십시오.
    at ...ErdResourceImpl.doLoad(...)
```

`ErdResourceImpl.doLoad` compares **header version** (`ERDFileHeader.version`)
against the installed model version and throws when the file is newer.
Lowering the header (and the `version` inside `xml-content.xml` /
`binary-content`) bypasses that gate.

Reverse-engineered format (`com.tomato.exerd.model`):

```
[header][zipped xml-content.xml][zipped binary-content]
header = "eXERD File" + major(int BE) + minor + micro
       + qualifierLen(int BE) + qualifier + zippedXmlLen(long BE)
each zip entry = PK0304 local header (flag 0x0808, deflate, sizes 0)
               + filename + raw-deflate + PK0708 descriptor
               (crc32 of *uncompressed* data, comp size, uncomp size, LE)
xml  = <e:Document ... version="M.m.p.qualifier" ...>
binary = EMF binary ("emf\n\r\x1a\n", BinaryIO VERSION_1_0)
```

3.x files additionally contain fields missing in 2.x ecore:

- `Document.modelVersion`, `Document.databaseVersion`
- `PrintSettings.useClearTableName`

For a 2.x target these are removed from XML and *renamed* in binary to a
harmless same-type feature of the same EClass
(`modelVersion`/`databaseVersion` → `customDataTypeFile`,
`useClearTableName` → `useNoteBackground`, same length for the latter),
otherwise the old binary loader throws on the unknown feature name.
This works because 2.4.7 ecore == 3.0.0 ecore (no model change at the
2→3 boundary); files using only pre-3.3 features view fine after
downgrade. Files using brand-new 3.3-only semantics still open, but the
new-only attributes are dropped (viewer shows the rest).

## Requirements

- Browser version: any modern Chrome/Edge/Firefox (uses built-in
  `CompressionStream`/`DecompressionStream`, no network needed).
- Python CLI: Python 3.8+, stdlib only (`argparse`, `struct`, `zlib`,
  `binascii`, `re`).

## Usage — browser (offline)

Open `index.html` (double-click works, fully offline), drop the `.exerd`,
pick the target version (= the old viewer's version from its error
message), press **Downgrade & download**, then drop the output back in to
verify.

## Usage — Python

```bash
# inspect
python3 exerd_downgrader.py info model.exerd

# downgrade to the version installed on the old PC
# (use the exact version from the error message, or a preset)
python3 exerd_downgrader.py downgrade new.exerd old_viewable.exerd \
  --target 2.5.12.20210616-1543

# presets: 2.5-latest, 2.5.12, 2.5.0, 3.0-first
python3 exerd_downgrader.py downgrade new.exerd old.exerd --target 2.5-latest --force

# 3.x -> 3.x (keep new fields, only lower the version numbers)
python3 exerd_downgrader.py downgrade new.exerd older3x.exerd \
  --target 3.0-first --keep-new-fields --force
```

`--strip-new-fields` (default when target major is 2) removes/neutralises
the 3.x-only fields; `--keep-new-fields` keeps them.

Always keep a backup of the original. Downgrade is best-effort for
*viewing* — re-saving in the old version rewrites the version stamps.

## Verify

```bash
python3 test_downgrader.py          # self-tests, no sample needed
python3 exerd_downgrader.py info old_viewable.exerd
```

Look for `crcOK sizeOK`, header version == target, and no
`newer attribute/feature` lines.

## Limits

- Forward-compat is not guaranteed if the file uses features added after
  the target's ecore (they are dropped, not converted).
- Headerless legacy files (no `eXERD File` magic) have no gate and are
  copied unchanged.
- This tool only patches version/compat shims; it does not migrate model
  semantics (that is what eXERD's own `TransformService` does on upgrade).
