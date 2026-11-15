# jPDFRsc — Advanced PDF Resource & Forensic Explorer

**Version 0.4.0** · Windows desktop · Python / PySide6 / pikepdf / PyMuPDF / Pillow

jPDFRsc is a desktop application for authorized PDF structure inspection, resource inventory, stream analysis, controlled editing and session reporting. It is inspired by low-level executable resource browsers, but operates on the PDF object model.

> **Forensic caution:** This is a development tool, not a certified forensic suite. It does not guarantee evidentiary chain of custody, validate signatures, or promise byte-for-byte preservation. Preserve originals, work on verified copies, and treat embedded content as untrusted.

## Features
- PDF catalog, page tree and indirect-object explorer
- Dictionary inspection and controlled editing with a safe scalar parser
- Shallow and deep indirect-object cloning with reference remapping
- Snapshot-based undo/redo
- Resource inventory for fonts, XObjects, images, color spaces, patterns, shadings and graphics states
- Image and embedded-font extraction; image replacement
- Raw/decoded stream export, hashing, hex viewer and stream replacement
- Page content-stream operator listing and frequency counts
- Original-versus-current object fingerprint comparison
- Catalog-rooted reference graph, reachability, orphan candidates and cycle detection
- Structural validation using pikepdf/qpdf diagnostics
- Page preview, text search, active-content indicators and operation log
- Forensic review and reference-graph reports

## Windows setup
Python 3.11 is recommended (3.10–3.12 may work depending on wheels).

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

## Tests
```powershell
pip install pytest
pytest -q
```

## Build
```powershell
pip install pyinstaller
pyinstaller --noconfirm --clean --windowed --name jPDFRsc --collect-all pikepdf --collect-all fitz --collect-all PySide6 --collect-all PIL main.py
```

See [CHANGELOG.md](CHANGELOG.md) for version history. Review the limitations below before using editing functions.

## Important limitations
- This is not a certified forensic suite and does not provide evidentiary chain-of-custody guarantees.
- Editing or saving may invalidate digital signatures; signature validation is not implemented.
- Stream replacement writes unfiltered bytes and does not infer a correct filter pipeline for arbitrary binary input.
- Image replacement normalizes to 8-bit RGB; masks, alpha, ICC profiles and specialized color spaces are not retained.
- Font extraction currently supports recognized font streams in a direct font descriptor; complex Type 0/CID traversal may need further work.
- Orphan candidates are informational; arbitrary xref-slot deletion and automatic garbage collection are intentionally unsupported.
- Active-content markers are indicators for manual review, not proof of maliciousness. Embedded scripts are not executed.

Use only with files you are authorized to inspect or modify. Keep originals unchanged and save edits to a separate output file.
