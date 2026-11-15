# jPDFRsc — Advanced PDF Resource & Forensic Explorer

**Version 0.4.0** · Windows desktop · Python / PySide6 / pikepdf / PyMuPDF / Pillow

jPDFRsc is a desktop application for authorized PDF structure inspection, resource inventory, stream analysis, controlled editing and session reporting. It is inspired by low-level executable resource browsers, but operates on the PDF object model.

> **Forensic caution:** This is a development tool, not a certified forensic suite. It does not guarantee evidentiary chain of custody, validate signatures, or promise byte-for-byte preservation. Always preserve the original, work on a verified copy, record acquisition hashes independently where required, and save edits to a new file. Embedded content is untrusted data.

## Current capabilities

- Dark and light themes.
- PDF catalog, page tree and indirect object explorer.
- Object dictionary inspector with object/generation references.
- Add, edit and remove dictionary entries using a safe scalar parser (no `eval`).
- Create new indirect dictionary objects, shallow-clone dictionaries, and deep-clone reachable indirect subgraphs with reference remapping.
- Attach existing indirect objects to dictionary keys. Arbitrary xref-slot deletion remains unsupported by design.
- Snapshot-based undo/redo (up to 30 in-memory checkpoints).
- Resource inventory for fonts, XObjects, images, color spaces, patterns, shadings, graphics states and properties.
- Image resource export and replacement (replacement normalizes to 8-bit RGB; masks, alpha, ICC profiles and specialized color spaces are not retained).
- Embedded font-program extraction when a font descriptor contains `/FontFile`, `/FontFile2` or `/FontFile3`.
- Raw and decoded stream export, stream hashing and a hex dump viewer.
- Stream replacement with a normalized unfiltered stream payload.
- Parsed page content-stream operator listing and frequency counts.
- Original-versus-current indirect-object fingerprint comparison.
- Catalog-rooted reference graph with inbound/outbound references, reachability, orphan candidates and cycle detection.
- Deep indirect-object graph cloning with reference remapping and memoized cycle handling.
- Attach an existing indirect object reference to a selected dictionary key.
- Structural validation using pikepdf/qpdf diagnostics.
- Consistent error dialogs with technical traceback and rotating-independent application log at `%LOCALAPPDATA%\jPDFRsc\logs\jpdfrsc.log`.
- Exportable reference graph report and double-click navigation from graph nodes to the object inspector.
- Forensic review report with document summary, object hashes, resource inventory, configured active-content indicators and session operations.
- Page preview, text search, active-content indicators and operation log.

## Install and run (Windows 10/11, x64)

Python 3.11 is recommended. Python 3.10–3.12 should generally work depending on available binary wheels.

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

## Build a Windows application folder

```powershell
.\.venv\Scripts\Activate.ps1
pip install pyinstaller
pyinstaller --noconfirm --clean --windowed --name jPDFRsc `
  --collect-all pikepdf --collect-all fitz --collect-all PySide6 `
  --collect-all PIL main.py
```

The recommended onedir executable is `dist\jPDFRsc\jPDFRsc.exe`. Test the build on a clean Windows machine before distributing it. A one-file build is possible with `--onefile`, but native Qt and PDF libraries make onedir packaging easier to troubleshoot.

## Project layout

```text
jpdfrsc/
  core/
    reference_graph.py  Indirect-object graph, reachability, cycle detection, graph report
    advanced.py       Hex dumps, stream hashes, content parsing, image/font inventory, diff, report
    forensics.py      Resource inventory and active-content indicators
    history.py        Snapshot undo/redo
    pdf_document.py   PDF lifecycle and controlled mutations
    rendering.py      PyMuPDF page rendering
  ui/
    main_window.py   PySide6 application interface
    object_tree.py   PDF object and page tree
main.py
requirements.txt
tests/
```

## Editing model and limitations

- **Undo/redo:** Before a supported mutation, the application serializes an in-memory snapshot. Undo/redo restores a snapshot and reopens the PDF model. Object handles selected before undo/redo become stale; the interface refreshes the views.
- **Dictionary cloning:** Shallow clone remains available for a fast dictionary copy. Deep clone recursively copies the selected object and its reachable indirect descendants, remapping references inside the copied graph. Stream payloads are decoded and rewritten without preserving original filter encoding; byte identity is not guaranteed.
- **Deletion:** The app intentionally does not remove arbitrary xref/object-table slots. It removes a selected dictionary key/reference instead, avoiding unsafe dangling references. Physical xref-slot deletion and automatic garbage collection remain unsupported; review orphan candidates manually.
- **Scalar editor:** Supports PDF names, literal strings, booleans, null, integers and decimals. It does not currently parse arbitrary arrays, dictionaries, hex strings or indirect references from text.
- **Stream replacement:** The selected stream is replaced with unfiltered bytes. For specialized streams (for example content streams, fonts, compressed data, object streams or image masks), validate the result carefully. The app does not infer a correct filter pipeline for arbitrary binary input.
- **Image replacement:** Replaces a page's selected `/XObject` image resource with raw 8-bit DeviceRGB samples. It does not preserve transparency, soft masks, color profiles, indexed color, bitonal encoding or image interpolation metadata. Review the rendered page after replacement.
- **Font extraction:** Only extracts a font program when a direct `/FontDescriptor` contains a recognized font stream. Type 0 descendant font traversal and CFF-specific interpretation may need further work.
- **Diff:** Fingerprints compare indirect object representations and raw stream bytes. This is an object-level diagnostic, not a byte-level file diff; a full rewrite can change serialization without changing semantic content.
- **Signatures:** Any edit or save may invalidate digital signatures. Signature validation is not implemented.
- **Active content:** `/OpenAction`, `/AA`, `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFiles` and `/RichMedia` are indicators for manual review, not proof of maliciousness. jPDFRsc does not execute embedded scripts.

## Reference graph behavior

- The graph starts at the document catalog (`/Root`) and follows nested dictionaries and arrays.
- Each indirect object is represented by its object number and generation number.
- Inbound/outbound counts are based on discovered indirect-reference edges; direct nested containers are represented in the edge path.
- Reachability is catalog-rooted. Unreachable indirect objects are labeled **orphan candidates**, not automatically disposable objects.
- Strongly connected components identify indirect-reference cycles. Cycles are not inherently invalid in a PDF object graph.
- Traversal limits (512 nested direct-container levels and 2,000,000 edges) guard against pathological structures.
- The graph is an analysis view. jPDFRsc intentionally does not delete raw xref slots or perform automatic garbage collection.

## Suggested next engineering milestones

1. Reference-aware deep clone with cycle-safe remapping and explicit shared-reference policy.
2. Safe detach planner that previews every changed parent path before a user-approved edit.
3. Dedicated font panel for Type 0 descendants, CID fonts, CMaps and font-program metadata.
4. Image preview with masks/color-space interpretation and replacement options.
5. Content stream token editor with syntax-aware operator validation.
6. Signature inspection and incremental-save awareness.
7. Structured JSON forensic report and optional read-only evidence workspace.

## Safety

Use only with files you are authorized to inspect or modify. Never execute or automatically open extracted attachments. Save modifications to a separate output file and retain the original unchanged.


## v0.4 editing safety notes

Deep cloning recursively copies the selected indirect object and reachable indirect descendants, remapping references within the copied graph. Stream data is decoded and rewritten without the original filter chain; the result is not byte-identical to the source stream. If decoding fails, the clone is aborted and the document is restored to its pre-operation snapshot. Direct-container cycles and excessive nesting are rejected.

Reference attachment modifies a dictionary key to point at an existing indirect object. This is a low-level operation and can make a PDF semantically invalid; use the structural validator, inspect the reference graph, and save to a new file. Orphan candidates are informational only. jPDFRsc does not physically delete arbitrary xref entries.

Errors are displayed with actionable context and written to `jpdfrsc.log`. Avoid opening untrusted PDFs on a sensitive workstation; parsing libraries can still be exposed to malformed-file attacks.
