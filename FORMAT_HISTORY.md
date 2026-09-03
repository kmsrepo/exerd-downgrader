# eXERD file-format history, 2017 → 2019

How the `.exerd` format changed between 2017-era (2.4.x) and 2019
(3.0.0). Reverse-engineered from the official update-site plug-ins
(`com.tomato.exerd.model` 2.5.17 and 3.3.56) and real files.
Bottom line: **the format did not structurally change in 2017–2019** —
only version stamps were bumped, which is exactly what the version gate
checks.

## Timeline of version stamps

| Date | Stamp | What it is |
|---|---|---|
| 2016-12-26 | `2.4.7.20161226-2038` | Last 2.4.x model version (= 2017-era viewer) |
| 2018-02-28 | `2.5.0.20180228-1529` | 2.5.x file (real sample: `DockerFarm.exerd`) |
| 2019-01-11 | `3.0.0.20190111-1604` | First 3.x model version (`INITIAL_VERSION`) |

## What stayed identical

- **Container**: `eXERD File` magic + `ERDFileHeader`
  (`major/minor/micro` BE-ints + qualifier + `zippedXmlContentLength`
  BE-long) — same class, same methods in the 2.x and 3.x jars.
- **Entries**: streaming zip, `xml-content.xml` + `binary-content`,
  local headers (flag `0x0808`) + raw deflate + `PK0708` descriptors,
  no central directory — same writer/reader on both lines.
- **EMF binary**: same 8-byte signature, `BinaryIO.Version` enum has the
  single value `VERSION_1_0` on both lines.
- **Version gate**: `ErdResourceImpl.doLoad` does
  `header.version.compareTo(installedModelVersion) > 0 → throw`
  (`문서의 버전…보다 높아서 열 수 없습니다`) on both lines. Same check,
  only the installed version differs.

## Model (ecore) changes: effectively none

Byte-compared `model/history/*.ecore` inside both plug-ins:

- 2.x line: `exerd_2.4.7.ecore` **==** current 2.x `exerd.ecore`
  (zero diff) → nothing added during 2017–2018.
- 3.x line: `exerd_2.4.7.ecore` **==** `exerd_3.0.0.ecore`
  → the 2→3 jump added nothing; the bridge transform
  `[2.4.7.20161226-2038, 3.0.0.20190111-1604)` (the only
  `apply-version-range` added in 3.x's `plugin.xml`) is a no-op marker.
- 2.x-line `2.4.7` vs 3.x-line `2.4.7`: **2 lines differ**, both the same
  Draw2D fork rename for diagram-layout data types only:
  - `Point`: `org.eclipse.draw2d.geometry.Point`
    → `kr.co.tomatosystem.draw2d.geometry.Point`
  - `Dimension`: `org.eclipse.draw2d.geometry.Dimension`
    → `kr.co.tomatosystem.draw2d.geometry.Dimension`
  - (3.x ships its own `kr.co.tomatosystem.draw2d` plug-in instead of
    `org.eclipse.draw2d`.) Files store only the type *names* and the
    same lexical values, resolved against each viewer's own ecore, so
    layout data stays readable in practice.

## What changed AFTER 2019 (why new 3.x files need stripping)

Between `3.0.0` and `3.3.56`, three fields were added (absent in every
2017–2019 ecore):

- `Document.modelVersion` (required string)
- `Document.databaseVersion` (required string)
- `PrintSettings.useClearTableName` (boolean, default `false` — usually
  not even serialized unless set to `true`)

The downgrader in this repo deletes the first two/three from
`xml-content.xml` and renames them in `binary-content` to harmless
same-type features of the same EClass
(`→ customDataTypeFile`, `→ useNoteBackground`) when targeting 2.x.

## Practical consequence

- 2018 (2.5.x) → 2017 (2.4.x): version stamps only. ✅ tested
- 2019 (3.0.0) → 2017 (2.4.x): version stamps only
  (ecore-identical, Draw2D rename is name-compatible). ✅ tested
  (synthetic 3.x file → `2.4.7.20161226-2038`, `crcOK sizeOK`)
- Post-2019 3.x → 2017: stamps + the 3-field strip above. ✅ tested
