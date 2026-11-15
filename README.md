# jPDFRsc

**PDF Resource Explorer** · Version 0.4.0

jPDFRsc is a Windows desktop application for inspecting PDF structure and resources, examining indirect objects and streams, and making controlled changes to PDF files. It is built with Python, PySide6, pikepdf, PyMuPDF and Pillow.

> **Important:** jPDFRsc is an inspection and editing utility, not a certified digital-forensics platform. It does not establish chain of custody, validate digital signatures, or guarantee byte-for-byte preservation. Keep the original file unchanged, work on a verified copy, and record acquisition hashes separately when required. Treat all embedded content as untrusted.

## Features

- PDF catalog, page tree and indirect-object browser.
- Object dictionary inspection, including object and generation references.
- Add, edit and remove dictionary entries using a restricted scalar-value parser.
- Create indirect dictionary objects; shallow-clone dictionaries; deep-clone reachable indirect object graphs with reference remapping.
- Attach existing indirect object references to dictionary keys.
- Snapshot-based undo and redo, with up to 30 in-memory checkpoints.
- Resource inventory covering fonts, XObjects, images, color spaces, patterns, shadings, graphics states and properties.
- Export and replace image resources.
- Extract embedded font programs when recognized font streams are present.
- Export raw or decoded streams; calculate stream hashes; inspect data in a hex viewer.
- Replace stream data.
- Inspect page content-stream operators and their frequencies.
- Compare original and current indirect-object fingerprints.
- Explore catalog-rooted references, including inbound and outbound references, reachability, orphan candidates and cycles.
- Run structural checks using pikepdf/qpdf diagnostics.
- Preview pages and search document text.
- Identify active-content entries for manual review.
- Export reference-graph and document-review reports.
- Record editing operations and application errors in a log file.

## Requirements

- Windows 10 or 11 (64-bit)
- Python 3.11 recommended; Python 3.10–3.12 may work depending on available binary wheels

## Install and run

Open PowerShell in the project directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

## Run tests

```powershell
pip install pytest
pytest -q
```

## Build for Windows

Install PyInstaller in the active environment, then run:

```powershell
pip install pyinstaller
pyinstaller --noconfirm --clean --windowed --name jPDFRsc `
  --collect-all pikepdf --collect-all fitz --collect-all PySide6 `
  --collect-all PIL main.py
```

The executable is created at `dist\jPDFRsc\jPDFRsc.exe`. The onedir build is recommended. Test the packaged application on a clean Windows machine before distribution.

## Project structure

```text
jpdfrsc/
  core/
    advanced.py
    forensics.py
    history.py
    pdf_document.py
    reference_graph.py
    rendering.py
  ui/
    main_window.py
    object_tree.py
main.py
requirements.txt
tests/
```

## Editing behavior and limitations

- **Undo and redo:** Supported changes create an in-memory PDF snapshot. Undo and redo restore a snapshot and reopen the document model; previously selected object handles may become stale, so views are refreshed.
- **Dictionary cloning:** A shallow clone copies a dictionary. A deep clone copies the selected indirect object and reachable indirect descendants, remapping references in the copied graph. Stream payloads are decoded and rewritten; original filter encoding and byte identity are not preserved.
- **Object deletion:** Arbitrary cross-reference-table slots are not deleted. The application can remove dictionary keys and references, but does not perform physical xref-slot deletion or automatic garbage collection. Unreachable objects are reported as orphan candidates for manual review.
- **Scalar editor:** Supports PDF names, literal strings, booleans, null, integers and decimals. It does not parse arbitrary arrays, dictionaries, hex strings or indirect references from text.
- **Stream replacement:** Replacement data is written as an unfiltered stream. For content streams, fonts, compressed data, object streams, image masks and other specialized streams, validate the result carefully. The application does not infer a suitable filter pipeline for arbitrary binary input.
- **Image replacement:** Replacements use 8-bit DeviceRGB samples. Transparency, soft masks, color profiles, indexed or bitonal color, and image interpolation metadata are not retained. Inspect the rendered page after replacement.
- **Font extraction:** Extraction is supported when a font descriptor contains a recognized `/FontFile`, `/FontFile2` or `/FontFile3` stream. Type 0 descendant-font traversal and some CFF-specific details may require additional handling.
- **Object comparison:** Fingerprints compare indirect-object representations and raw stream bytes. This is not a byte-level comparison of complete PDF files; a rewrite may change serialization without changing document meaning.
- **Digital signatures:** Editing or saving may invalidate existing signatures. Signature validation is not implemented.
- **Active content:** Entries such as `/OpenAction`, `/AA`, `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles` and `/RichMedia` are indicators for manual inspection, not proof of malicious activity. jPDFRsc does not execute embedded scripts.

## Reference graph

The reference graph starts at the document catalog (`/Root`) and follows nested dictionaries and arrays. Indirect objects are identified by object number and generation. Reachability is catalog-rooted; unreachable objects are labeled **orphan candidates**, not automatically disposable objects. Strongly connected components identify reference cycles, which are not necessarily invalid in a PDF.

Traversal is limited to 512 nested direct-container levels and 2,000,000 edges to guard against unusually complex or malformed files. The graph is an inspection view and does not delete objects or rewrite the cross-reference table.

## Safety

Use jPDFRsc only with files you are authorized to inspect or modify. Do not execute or automatically open extracted attachments. PDF parsing libraries may be exposed to malformed-file attacks, so avoid opening untrusted documents on a sensitive workstation. Save modifications to a separate output file and retain the original unchanged.

