# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- 2017 downgrade support: `2.4.7` / `2.4-latest` / `2017` presets
  (`2.4.7.20161226-2038`) in the Python CLI and a `2.4.7 (2017)` preset in
  `index.html`, plus a test downgrading 2.5.x and 3.x sources to 2017.
  Works stamps-only — see `FORMAT_HISTORY.md` (2.4.7/2.5.x/3.0.0 ecores
  are identical).

## [1.1.0] - 2026-09-04

### Added

- Offline browser version (`index.html`): single file, no dependencies, no
  upload — drag & drop a `.exerd`, inspect header/entries/versions, pick a
  target, download the downgraded file. Uses built-in
  `CompressionStream`/`DecompressionStream` (`deflate-raw`).
- Catch-all binary patch: any remaining `M.m.p.YYYYMMDD-N` version string
  higher than the target is rewritten, so files that went through several
  upgrades keep no higher stamp behind.
- Version presets: `2.5-latest`, `2.5.12`, `2.5.0`, `3.0-first`.

### Fixed

- JS `replaceAllSeq` dropped bytes between false-positive matches (scan
  position and gap start were conflated). Rewrote with separate pointers;
  caught by Node E2E round-trip cross-checked with the Python parser.
- Removed duplicate `encCI` declaration in `index.html`.

### Verified

- JS downgrade output parses with the independent Python parser
  (`crcOK sizeOK`, byte-identical size to Python output).
- Downgrades tested: 2.5→2.4, 3.x→2.x, 2018→2017 (`2.4.7.20161226-2038`),
  2019→2017. Ecore check: `2.4.7 == 2.5.x == 3.0.0`, so 2018/2019→2017 is
  version-stamps only.

## [1.0.0] - 2026-09-03

### Added

- Python CLI (`exerd_downgrader.py`, stdlib only) with `info` and
  `downgrade` commands.
- Reverse-engineered `.exerd` format docs (header, streaming zip entries
  with `PK0708` descriptors, `xml-content.xml` / `binary-content`,
  `ErdResourceImpl.doLoad` version gate).
- Header + XML `Document.version` + binary version patching with
  EMF `compressed-int` length-aware replacement.
- 3.x-only field neutralisation for 2.x targets: `modelVersion` /
  `databaseVersion` removed from XML and renamed to `customDataTypeFile`
  in binary; `useClearTableName` removed/renamed to `useNoteBackground`.
- Self-tests (`test_downgrader.py`, all passing, no sample file needed).
- `README.md` with format notes, usage, and limits.
