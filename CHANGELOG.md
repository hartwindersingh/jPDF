# Changelog

## 0.4.0 — Reference-aware editing and UI hardening

- Added deep indirect-object graph cloning with memoized reference remapping.
- Added explicit dictionary reference attachment to existing indirect objects.
- Added qpdf-backed structural validation through pikepdf `Pdf.check()`.
- Added consistent actionable error dialogs, detailed diagnostic traces and `jpdfrsc.log`.
- Reworked object-operation controls into a compact three-column grid.
- Kept destructive xref-slot deletion intentionally unsupported; users detach references and review orphan candidates instead.
- Added package metadata and pytest configuration.

## 0.3.0
- Added catalog-rooted reference graph, reachability, orphan candidates, cycles and graph reports.
