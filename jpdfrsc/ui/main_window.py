from __future__ import annotations
from pathlib import Path
from io import BytesIO
import hashlib
import logging
import traceback

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QPixmap, QImage
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QTableWidget, QTableWidgetItem,
    QFileDialog, QMessageBox, QLabel, QLineEdit, QPushButton, QComboBox,
    QSpinBox, QInputDialog, QStatusBar, QToolBar, QHeaderView, QPlainTextEdit,
    QFormLayout, QDialog, QDialogButtonBox, QTableWidgetSelectionRange, QGridLayout
)
from PIL import ImageQt
import pikepdf

from jpdfrsc.core.pdf_document import PDFDocument
from jpdfrsc.core.forensics import safe_repr, object_details, resource_inventory, active_content_findings
from jpdfrsc.core.rendering import render_page
from jpdfrsc.core.advanced import (content_stream_report, image_resources, font_resources,
    hex_dump, stream_hashes, object_diff, forensic_report)
from jpdfrsc.core.reference_graph import build_reference_graph, format_graph_report
from jpdfrsc.ui.object_tree import ObjectTree

DARK = """
QMainWindow,QWidget { background:#20242b; color:#e7eaf0; }
QTreeWidget,QTextEdit,QTableWidget,QLineEdit,QComboBox,QSpinBox { background:#171a20; color:#e7eaf0; border:1px solid #414854; selection-background-color:#315b86; }
QHeaderView::section { background:#2b313b; color:#e7eaf0; padding:5px; border:0; }
QPushButton { background:#34465d; color:white; border:1px solid #53677f; padding:6px 10px; }
QPushButton:hover { background:#426080; }
QTabWidget::pane { border:1px solid #414854; }
QStatusBar,QToolBar { background:#292f38; }
"""
LIGHT = """
QMainWindow,QWidget { background:#f3f5f8; color:#202733; }
QTreeWidget,QTextEdit,QTableWidget,QLineEdit,QComboBox,QSpinBox { background:white; color:#202733; border:1px solid #c7ced8; selection-background-color:#c9def5; }
QHeaderView::section { background:#e5eaf0; color:#202733; padding:5px; border:0; }
QPushButton { background:#e4eaf2; color:#172334; border:1px solid #b8c3d1; padding:6px 10px; }
QPushButton:hover { background:#d4e1f0; }
QTabWidget::pane { border:1px solid #c7ced8; }
QStatusBar,QToolBar { background:#e9edf2; }
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("jPDFRsc 0.4.0 — PDF Resource & Forensic Explorer")
        self.resize(1500, 920)
        self.doc = PDFDocument()
        self.current_object = None
        self.current_ref = None
        self.theme = "dark"
        self.reference_graph = None
        self._build_ui()
        self._build_actions()
        self.apply_theme()
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready — open a PDF to begin")

    def _build_ui(self):
        central = QWidget()
        outer = QVBoxLayout(central)
        self.setCentralWidget(central)
        self.summary = QLabel("No document loaded")
        self.summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        outer.addWidget(self.summary)
        splitter = QSplitter(Qt.Horizontal)
        outer.addWidget(splitter, 1)
        self.object_tree = ObjectTree()
        self.object_tree.itemClicked.connect(self.on_tree_clicked)
        splitter.addWidget(self.object_tree)
        right = QTabWidget()
        self.tabs = right
        splitter.addWidget(right)
        splitter.setSizes([360, 1100])

        inspect = QWidget(); il = QVBoxLayout(inspect)
        self.object_header = QLabel("Select an object in the left tree")
        il.addWidget(self.object_header)
        self.detail_table = QTableWidget(0, 2); self.detail_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.detail_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.detail_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        il.addWidget(self.detail_table, 1)
        self.object_text = QTextEdit(); self.object_text.setReadOnly(True); self.object_text.setPlaceholderText("Object dictionary / representation")
        il.addWidget(self.object_text, 2)
        editrow = QHBoxLayout()
        self.edit_key = QLineEdit(); self.edit_key.setPlaceholderText("Existing key, e.g. /Title")
        self.edit_value = QLineEdit(); self.edit_value.setPlaceholderText("Scalar value: (text), /Name, true, 12")
        edit_btn = QPushButton("Set dictionary value"); edit_btn.clicked.connect(self.edit_value_clicked)
        editrow.addWidget(self.edit_key); editrow.addWidget(self.edit_value); editrow.addWidget(edit_btn)
        il.addLayout(editrow)
        streamrow = QHBoxLayout()
        raw_btn = QPushButton("Export raw stream…"); raw_btn.clicked.connect(lambda: self.export_stream(raw=True))
        decoded_btn = QPushButton("Export decoded stream…"); decoded_btn.clicked.connect(lambda: self.export_stream(raw=False))
        replace_btn = QPushButton("Replace stream…"); replace_btn.clicked.connect(self.replace_stream)
        streamrow.addWidget(raw_btn); streamrow.addWidget(decoded_btn); streamrow.addWidget(replace_btn)
        il.addLayout(streamrow)
        right.addTab(inspect, "Object Inspector")

        resources = QWidget(); rl = QVBoxLayout(resources)
        self.resource_table = QTableWidget(0, 4); self.resource_table.setHorizontalHeaderLabels(["Category", "Resource name", "Object ref", "Type"])
        self.resource_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        rl.addWidget(self.resource_table)
        right.addTab(resources, "Resources")

        pages = QWidget(); pl = QVBoxLayout(pages)
        nav = QHBoxLayout(); nav.addWidget(QLabel("Page"))
        self.page_spin = QSpinBox(); self.page_spin.setMinimum(1); self.page_spin.setMaximum(1); self.page_spin.valueChanged.connect(self.render_current_page)
        self.zoom = QComboBox(); self.zoom.addItems(["100%", "125%", "150%", "200%"]); self.zoom.setCurrentText("150%"); self.zoom.currentTextChanged.connect(self.render_current_page)
        nav.addWidget(self.page_spin); nav.addWidget(QLabel("Zoom")); nav.addWidget(self.zoom); nav.addStretch()
        pl.addLayout(nav)
        self.page_view = QLabel("Page preview appears here")
        self.page_view.setAlignment(Qt.AlignCenter); self.page_view.setMinimumSize(500, 500); self.page_view.setStyleSheet("background: #555; color: white;")
        pl.addWidget(self.page_view, 1)
        right.addTab(pages, "Page Preview")

        search = QWidget(); sl = QVBoxLayout(search)
        sr = QHBoxLayout(); self.search_box = QLineEdit(); self.search_box.setPlaceholderText("Search object dictionaries and resource names…")
        sb = QPushButton("Search"); sb.clicked.connect(self.search_objects); sr.addWidget(self.search_box); sr.addWidget(sb); sl.addLayout(sr)
        self.search_results = QTreeWidget(); self.search_results.setHeaderLabels(["Matches", "Type"]); self.search_results.itemClicked.connect(self.on_search_clicked); sl.addWidget(self.search_results)
        right.addTab(search, "Search")

        forensic = QWidget(); fl = QVBoxLayout(forensic)
        report_btn = QPushButton("Export forensic report…"); report_btn.clicked.connect(self.export_forensic_report); fl.addWidget(report_btn)
        self.findings = QTextEdit(); self.findings.setReadOnly(True); fl.addWidget(self.findings)
        right.addTab(forensic, "Forensic Findings")

        # Advanced object operations
        tools = QWidget(); tl = QVBoxLayout(tools)
        tl.addWidget(QLabel("Reference-aware object operations. Deep cloning remaps reachable indirect references; review the graph before attaching cloned structures."))
        form = QHBoxLayout()
        self.new_key = QLineEdit(); self.new_key.setPlaceholderText("Dictionary key, e.g. /Custom")
        self.new_value = QLineEdit(); self.new_value.setPlaceholderText("Scalar value, e.g. (value), /Name, 123")
        form.addWidget(self.new_key); form.addWidget(self.new_value); tl.addLayout(form)
        ops = QGridLayout()
        operation_buttons = [("Add key", self.add_key_clicked), ("Remove key", self.remove_key_clicked),
                             ("Shallow clone", self.clone_object_clicked), ("Deep clone graph", self.deep_clone_object_clicked),
                             ("Create dictionary", self.create_object_clicked), ("Attach reference…", self.attach_reference_clicked),
                             ("Validate PDF", self.validate_pdf_clicked), ("Undo", self.undo_clicked), ("Redo", self.redo_clicked)]
        for index, (label, callback) in enumerate(operation_buttons):
            b = QPushButton(label); b.clicked.connect(callback)
            b.setMinimumHeight(32)
            ops.addWidget(b, index // 3, index % 3)
        tl.addLayout(ops)
        self.validation_view = QPlainTextEdit(); self.validation_view.setReadOnly(True)
        self.validation_view.setPlaceholderText("Structural validation results will appear here.")
        tl.addWidget(self.validation_view, 1)
        tl.addWidget(QLabel("Safety policy: detach references by removing dictionary entries. Arbitrary xref-slot deletion is intentionally unsupported because it can create dangling references. Orphan candidates are review-only."))
        right.addTab(tools, "Object Operations")

        # Hex / stream inspection
        hexw = QWidget(); hl = QVBoxLayout(hexw)
        self.hex_info = QLabel("Select a stream object, then inspect raw or decoded bytes.")
        hl.addWidget(self.hex_info)
        hrow = QHBoxLayout()
        for label, callback in [("View raw bytes", lambda: self.show_hex(True)), ("View decoded bytes", lambda: self.show_hex(False)),
                                ("Export raw…", lambda: self.export_stream(raw=True)), ("Export decoded…", lambda: self.export_stream(raw=False))]:
            b = QPushButton(label); b.clicked.connect(callback); hrow.addWidget(b)
        hl.addLayout(hrow)
        self.hex_view = QPlainTextEdit(); self.hex_view.setReadOnly(True); self.hex_view.setLineWrapMode(QPlainTextEdit.NoWrap); hl.addWidget(self.hex_view, 1)
        right.addTab(hexw, "Hex Inspector")

        # Content stream parser
        content = QWidget(); cl = QVBoxLayout(content)
        crow = QHBoxLayout(); crow.addWidget(QLabel("Page"))
        self.content_page = QSpinBox(); self.content_page.setMinimum(1); self.content_page.setMaximum(1); crow.addWidget(self.content_page)
        cb = QPushButton("Parse operators"); cb.clicked.connect(self.parse_content_clicked); crow.addWidget(cb); crow.addStretch(); cl.addLayout(crow)
        self.content_view = QPlainTextEdit(); self.content_view.setReadOnly(True); cl.addWidget(self.content_view, 1)
        right.addTab(content, "Content Streams")

        # Images and fonts
        media = QWidget(); ml = QVBoxLayout(media)
        self.media_table = QTableWidget(0, 7); self.media_table.setHorizontalHeaderLabels(["Kind", "Page", "Resource", "Object ref", "Subtype / Size", "Details", ""])
        self.media_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); ml.addWidget(self.media_table)
        mrow = QHBoxLayout()
        for label, callback in [("Refresh inventory", self.populate_media), ("Export selected image…", self.export_selected_image), ("Replace selected image…", self.replace_selected_image), ("Export embedded font…", self.export_selected_font)]:
            b = QPushButton(label); b.clicked.connect(callback); mrow.addWidget(b)
        ml.addLayout(mrow); right.addTab(media, "Images & Fonts")

        # Object-level diff
        diffw = QWidget(); dl = QVBoxLayout(diffw)
        db = QPushButton("Compare original with current document"); db.clicked.connect(self.diff_clicked); dl.addWidget(db)
        self.diff_table = QTableWidget(0, 4); self.diff_table.setHorizontalHeaderLabels(["Object", "Status", "Original SHA-256", "Current SHA-256"])
        self.diff_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); dl.addWidget(self.diff_table)
        right.addTab(diffw, "Structure Diff")

        # Reference graph / reachability analysis
        graphw = QWidget(); gl = QVBoxLayout(graphw)
        gl.addWidget(QLabel("Reference graph from /Root. Orphan candidates are informational only; arbitrary xref deletion is deliberately disabled."))
        grow = QHBoxLayout()
        gb = QPushButton("Build / refresh graph"); gb.clicked.connect(self.populate_reference_graph); grow.addWidget(gb)
        nb = QPushButton("Show selected references"); nb.clicked.connect(self.show_graph_neighbors); grow.addWidget(nb)
        eb = QPushButton("Export graph report…"); eb.clicked.connect(self.export_graph_report); grow.addWidget(eb)
        grow.addStretch(); gl.addLayout(grow)
        self.graph_summary = QLabel("Open a PDF and build the reference graph."); gl.addWidget(self.graph_summary)
        self.graph_table = QTableWidget(0, 6)
        self.graph_table.setHorizontalHeaderLabels(["Object ref", "Type", "Reachability", "Inbound", "Outbound", "Cycle member"])
        self.graph_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.graph_table.itemDoubleClicked.connect(self.on_graph_object_activated)
        gl.addWidget(self.graph_table, 1)
        self.graph_details = QPlainTextEdit(); self.graph_details.setReadOnly(True); self.graph_details.setMaximumHeight(130)
        self.graph_details.setPlaceholderText("Select an object and choose Show selected references.")
        gl.addWidget(self.graph_details)
        right.addTab(graphw, "Reference Graph")

        self.log_view = QTextEdit(); self.log_view.setReadOnly(True); self.log_view.setMaximumHeight(115); self.log_view.setPlaceholderText("Session operation log")
        outer.addWidget(QLabel("Session log")); outer.addWidget(self.log_view)

    def _build_actions(self):
        toolbar = QToolBar("Main"); self.addToolBar(toolbar)
        for label, callback in [("Open", self.open_pdf), ("Save As", self.save_as), ("Close", self.close_pdf), ("Refresh", self.refresh_document), ("Theme", self.toggle_theme)]:
            action = QAction(label, self); action.triggered.connect(callback); toolbar.addAction(action)
        edit_menu = self.menuBar().addMenu("Edit")
        for label, callback in [("Undo", self.undo_clicked), ("Redo", self.redo_clicked)]:
            action = QAction(label, self); action.triggered.connect(callback); edit_menu.addAction(action)
        menu = self.menuBar().addMenu("File")
        for label, callback in [("Open PDF…", self.open_pdf), ("Save As…", self.save_as), ("Close", self.close_pdf), ("Exit", self.close)]:
            action = QAction(label, self); action.triggered.connect(callback); menu.addAction(action)

    def apply_theme(self):
        self.setStyleSheet(DARK if self.theme == "dark" else LIGHT)

    def toggle_theme(self):
        self.theme = "light" if self.theme == "dark" else "dark"; self.apply_theme()

    def open_pdf(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open PDF", "", "PDF files (*.pdf);;All files (*.*)")
        if not path: return
        try:
            self.doc.open(path); self.refresh_document()
            self.statusBar().showMessage(f"Opened {path}")
        except Exception as exc:
            QMessageBox.critical(self, "Open failed", str(exc))

    def save_as(self):
        if not self.doc.is_open: return
        path, _ = QFileDialog.getSaveFileName(self, "Save modified PDF as", str(self.doc.path.with_name(self.doc.path.stem + "_edited.pdf")), "PDF files (*.pdf)")
        if not path: return
        try:
            self.doc.save_as(path); self.update_log(); QMessageBox.information(self, "Saved", f"Saved output to:\n{path}")
        except Exception as exc: QMessageBox.critical(self, "Save failed", str(exc))

    def close_pdf(self):
        self.doc.close(); self.reference_graph = None
        self.object_tree.clear(); self.resource_table.setRowCount(0); self.detail_table.setRowCount(0)
        self.graph_table.setRowCount(0); self.graph_details.clear(); self.graph_summary.setText("No document loaded")
        self.object_text.clear(); self.summary.setText("No document loaded"); self.findings.clear(); self.log_view.clear(); self.page_view.setText("Page preview appears here")

    def refresh_document(self):
        if not self.doc.is_open: return
        self.object_tree.populate(self.doc)
        info = self.doc.summary()
        self.summary.setText("   |   ".join(f"{k}: {v}" for k, v in info.items() if k in ("File", "PDF version", "Pages", "Indirect objects", "Encrypted")))
        self.page_spin.setMaximum(max(1, len(self.doc.pdf.pages))); self.page_spin.setValue(1)
        self.content_page.setMaximum(max(1, len(self.doc.pdf.pages)))
        self.populate_media()
        self.populate_resources(); self.populate_findings(); self.populate_reference_graph(); self.update_log(); self.render_current_page()

    def update_log(self): self.log_view.setPlainText("\n".join(self.doc.operations))

    def populate_resources(self):
        rows = resource_inventory(self.doc.pdf); self.resource_table.setRowCount(len(rows))
        for r, (cat, name, ref, obj) in enumerate(rows):
            vals = [cat, name, ref, type(obj).__name__]
            for c, val in enumerate(vals): self.resource_table.setItem(r, c, QTableWidgetItem(str(val)))

    def populate_findings(self):
        findings = active_content_findings(self.doc.pdf)
        lines = ["ACTIVE CONTENT / STRUCTURE REVIEW", "", "The indicators below are leads for manual review, not proof of malicious behavior.", ""]
        lines.extend(findings or ["No configured active-content indicators were found in the scanned indirect dictionaries."])
        lines += ["", "Other review notes:", "• Inspect /AcroForm, /Names, /EmbeddedFiles, /OpenAction and /AA where present.", "• Verify signatures separately; saving modifications may invalidate them.", "• Exported streams and attachments are untrusted input."]
        self.findings.setPlainText("\n".join(lines))

    def on_tree_clicked(self, item, column):
        ref = item.data(0, Qt.UserRole)
        if not ref: return
        try:
            if ref == (0, 0): obj = self.doc.pdf.Root
            else: obj = self.doc.get_object(*ref)
            self.show_object(obj, ref)
        except Exception as exc: self.object_text.setPlainText(str(exc))

    def show_object(self, obj, ref=None):
        self.current_object = obj; self.current_ref = ref
        self.object_header.setText(f"Selected object: {ref[0]} {ref[1]} R" if ref and ref != (0, 0) else "Selected: Catalog /Root")
        details = object_details(obj); self.detail_table.setRowCount(len(details))
        for r, (k, v) in enumerate(details.items()):
            self.detail_table.setItem(r, 0, QTableWidgetItem(k)); self.detail_table.setItem(r, 1, QTableWidgetItem(v))
        self.object_text.setPlainText(safe_repr(obj))

    def edit_value_clicked(self):
        if not self.current_ref or self.current_ref == (0, 0):
            QMessageBox.warning(self, "Select object", "Select an indirect dictionary object first."); return
        try:
            self.doc.edit_dictionary_value(*self.current_ref, self.edit_key.text(), self.edit_value.text())
            self.refresh_document(); obj = self.doc.get_object(*self.current_ref); self.show_object(obj, self.current_ref)
        except Exception as exc: QMessageBox.warning(self, "Edit rejected", str(exc))

    def export_stream(self, raw=True):
        if self.current_object is None or not isinstance(self.current_object, pikepdf.Stream):
            QMessageBox.information(self, "No stream", "Select a stream object first."); return
        path, _ = QFileDialog.getSaveFileName(self, "Export stream", "stream.bin", "All files (*.*)")
        if not path: return
        try:
            data = self.current_object.read_raw_bytes() if raw else self.current_object.read_bytes()
            Path(path).write_bytes(data); self.doc.operations.append(f"Exported {'raw' if raw else 'decoded'} stream to {path}"); self.update_log()
        except Exception as exc: QMessageBox.critical(self, "Export failed", str(exc))

    def replace_stream(self):
        if self.current_object is None or not isinstance(self.current_object, pikepdf.Stream) or not self.current_ref or self.current_ref == (0, 0):
            QMessageBox.information(self, "No stream", "Select an indirect stream object first."); return
        answer = QMessageBox.warning(self, "Replace stream data", "This replaces the stream with unfiltered bytes and removes the existing filter chain. This may alter how the PDF interprets the stream. Continue?", QMessageBox.Yes | QMessageBox.No)
        if answer != QMessageBox.Yes: return
        path, _ = QFileDialog.getOpenFileName(self, "Choose replacement stream data", "", "All files (*.*)")
        if not path: return
        try:
            data = Path(path).read_bytes(); self.doc.replace_stream(*self.current_ref, data)
            self.refresh_document(); self.show_object(self.doc.get_object(*self.current_ref), self.current_ref)
        except Exception as exc: QMessageBox.critical(self, "Replacement failed", str(exc))

    def export_forensic_report(self):
        if not self.doc.is_open: return
        path, _ = QFileDialog.getSaveFileName(self, "Export forensic report", "jPDFRsc-forensic-report.txt", "Text report (*.txt)")
        if not path: return
        try:
            Path(path).write_text(forensic_report(self.doc), encoding="utf-8")
            self.doc.operations.append(f"Exported forensic report to {path}"); self.update_log()
            QMessageBox.information(self, "Report exported", f"Report saved to:\n{path}")
        except Exception as exc: QMessageBox.critical(self, "Report export failed", str(exc))

    def _selected_indirect_ref(self):
        if not self.current_ref or self.current_ref == (0, 0):
            raise RuntimeError("Select an indirect object first")
        return self.current_ref

    def add_key_clicked(self):
        try:
            ref = self._selected_indirect_ref()
            self.doc.add_dictionary_value(*ref, self.new_key.text(), self.new_value.text())
            self.refresh_document(); self.show_object(self.doc.get_object(*ref), ref)
        except Exception as exc: self.show_error("Add key failed", exc)

    def remove_key_clicked(self):
        try:
            ref = self._selected_indirect_ref()
            key = self.new_key.text().strip()
            if QMessageBox.question(self, "Remove dictionary entry", f"Remove {key} from {ref[0]} {ref[1]} R?", QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes: return
            self.doc.remove_dictionary_key(*ref, key)
            self.refresh_document(); self.show_object(self.doc.get_object(*ref), ref)
        except Exception as exc: self.show_error("Remove key failed", exc)

    def clone_object_clicked(self):
        try:
            ref = self._selected_indirect_ref(); new_ref = self.doc.clone_dictionary_object(*ref)
            self.refresh_document(); obj = self.doc.get_object(*new_ref); self.show_object(obj, new_ref)
            QMessageBox.information(self, "Dictionary cloned", f"Created {new_ref[0]} {new_ref[1]} R. Nested references are shared.")
        except Exception as exc: self.show_error("Shallow clone failed", exc)

    def deep_clone_object_clicked(self):
        try:
            ref = self._selected_indirect_ref()
            answer = QMessageBox.warning(self, "Deep clone object graph",
                "This creates independent copies of the selected object and its reachable indirect subgraph. "
                "Streams are decoded and rewritten; original byte encodings are not preserved. Continue?",
                QMessageBox.Yes | QMessageBox.No)
            if answer != QMessageBox.Yes: return
            new_ref, count = self.doc.clone_object_graph(*ref)
            self.refresh_document(); self.show_object(self.doc.get_object(*new_ref), new_ref)
            self.statusBar().showMessage(f"Deep clone created: {new_ref[0]} {new_ref[1]} R ({count} indirect nodes remapped)", 8000)
            QMessageBox.information(self, "Deep clone complete",
                f"Created {new_ref[0]} {new_ref[1]} R.\nRemapped indirect nodes: {count}\n\nReview the reference graph and save to a new file.")
        except Exception as exc:
            self.show_error("Deep clone failed", exc)

    def attach_reference_clicked(self):
        try:
            parent = self._selected_indirect_ref()
            target_text, ok = QInputDialog.getText(self, "Attach indirect reference", "Target object reference (object generation), e.g. 42 0:")
            if not ok: return
            parts = target_text.replace("R", " ").split()
            if len(parts) != 2: raise ValueError("Enter exactly two integers: object number and generation")
            key, ok = QInputDialog.getText(self, "Dictionary key", "Key to set on selected dictionary, e.g. /Custom:")
            if not ok: return
            target = (int(parts[0]), int(parts[1]))
            key_name = pikepdf.Name(key if key.startswith("/") else "/" + key)
            parent_obj = self.doc.get_object(*parent)
            target_obj = self.doc.get_object(*target)
            previous = safe_repr(parent_obj.get(key_name, "<key absent>"))
            target_kind = "Stream" if isinstance(target_obj, pikepdf.Stream) else type(target_obj).__name__
            preview = (f"Parent: {parent[0]} {parent[1]} R\nKey: {key_name}\n"
                       f"Previous value: {previous}\nNew value: {target[0]} {target[1]} R ({target_kind})\n\n"
                       "This operation changes the selected dictionary only. The reference graph will be rebuilt after commit.")
            if QMessageBox.question(self, "Preview reference change", preview,
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes: return
            self.doc.attach_object_reference(*parent, key, *target)
            self.refresh_document(); self.show_object(self.doc.get_object(*parent), parent)
        except Exception as exc:
            self.show_error("Attach reference failed", exc)

    def validate_pdf_clicked(self):
        if not self.doc.is_open: return
        messages = self.doc.validate_structure()
        if messages:
            self.validation_view.setPlainText("STRUCTURAL WARNINGS / ERRORS\n\n" + "\n".join(messages))
            self.statusBar().showMessage(f"Structural validation returned {len(messages)} diagnostic(s)", 8000)
        else:
            self.validation_view.setPlainText("No structural diagnostics reported by qpdf. This is not proof of safety, conformance, or signature validity.")
            self.statusBar().showMessage("Structural validation completed without reported diagnostics", 8000)

    def show_error(self, title, exc):
        """Consistent, actionable error dialog with technical detail."""
        message = str(exc).strip() or type(exc).__name__
        diagnostic = traceback.format_exc()
        logging.getLogger("jpdfrsc").exception("%s", title)
        self.statusBar().showMessage(f"{title}: {message[:180]}", 10000)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle(title)
        box.setText(message)
        box.setInformativeText("No success was assumed. Check the selected object, file permissions and operation log. The original input file is not overwritten by Save As. Technical diagnostics are written to the application log under your local app-data folder.")
        box.setDetailedText(f"{type(exc).__name__}: {exc}\n\nDiagnostic trace (also written to the application log):\n{diagnostic}")
        box.setStandardButtons(QMessageBox.Ok)
        box.exec()

    def create_object_clicked(self):
        try:
            key = self.new_key.text().strip(); value = self.new_value.text().strip()
            if not key or not value: raise ValueError("Enter a key and scalar value in the fields above")
            ref = self.doc.create_dictionary_object({key: value})
            self.refresh_document(); self.show_object(self.doc.get_object(*ref), ref)
        except Exception as exc: QMessageBox.warning(self, "Create object failed", str(exc))

    def undo_clicked(self):
        try:
            if self.doc.undo(): self.current_object = None; self.current_ref = None; self.refresh_document()
            else: self.statusBar().showMessage("Nothing to undo")
        except Exception as exc: QMessageBox.critical(self, "Undo failed", str(exc))

    def redo_clicked(self):
        try:
            if self.doc.redo(): self.current_object = None; self.current_ref = None; self.refresh_document()
            else: self.statusBar().showMessage("Nothing to redo")
        except Exception as exc: QMessageBox.critical(self, "Redo failed", str(exc))

    def show_hex(self, raw=True):
        if self.current_object is None or not isinstance(self.current_object, pikepdf.Stream):
            QMessageBox.information(self, "Select stream", "Select a stream object in the object tree first."); return
        try:
            data = self.current_object.read_raw_bytes() if raw else self.current_object.read_bytes()
            info = stream_hashes(self.current_object)
            self.hex_info.setText(("RAW" if raw else "DECODED") + " stream | " + " | ".join(f"{k}: {v}" for k, v in info.items()))
            self.hex_view.setPlainText(hex_dump(data))
        except Exception as exc: QMessageBox.warning(self, "Hex inspection failed", str(exc))

    def parse_content_clicked(self):
        if not self.doc.is_open: return
        try: self.content_view.setPlainText(content_stream_report(self.doc.pdf, self.content_page.value() - 1))
        except Exception as exc: self.content_view.setPlainText(f"Could not parse page content: {exc}")

    def populate_media(self):
        if not self.doc.is_open: return
        rows = []
        for page, name, ref, w, h, filt, obj in image_resources(self.doc.pdf):
            rows.append(("Image", page, name, f"{ref[0]} {ref[1]} R", f"{w} × {h}", filt, obj))
        for page, name, ref, subtype, basefont, obj in font_resources(self.doc.pdf):
            rows.append(("Font", page, name, f"{ref[0]} {ref[1]} R", subtype, basefont, obj))
        self.media_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(row[:6]): self.media_table.setItem(r, c, QTableWidgetItem(str(value)))
            self.media_table.item(r, 0).setData(Qt.UserRole, row[6])

    def export_selected_image(self):
        row = self.media_table.currentRow()
        if row < 0 or self.media_table.item(row, 0).text() != "Image":
            QMessageBox.information(self, "Select image", "Select an Image row first."); return
        obj = self.media_table.item(row, 0).data(Qt.UserRole)
        path, _ = QFileDialog.getSaveFileName(self, "Export image", "pdf-image.png", "PNG (*.png);;JPEG (*.jpg);;TIFF (*.tif);;All files (*.*)")
        if not path: return
        try:
            from pikepdf import PdfImage
            image = PdfImage(obj).as_pil_image()
            image.save(path); self.doc.operations.append(f"Exported image resource to {path}"); self.update_log()
        except Exception as exc: QMessageBox.critical(self, "Image export failed", str(exc))

    def replace_selected_image(self):
        row = self.media_table.currentRow()
        if row < 0 or self.media_table.item(row, 0).text() != "Image":
            QMessageBox.information(self, "Select image", "Select an Image row first."); return
        path, _ = QFileDialog.getOpenFileName(self, "Choose replacement image", "", "Images (*.png *.jpg *.jpeg *.bmp *.tif *.tiff)")
        if not path: return
        page = int(self.media_table.item(row, 1).text()) - 1
        name = self.media_table.item(row, 2).text()
        if QMessageBox.warning(self, "Replace PDF image", "The selected page resource will be replaced with a normalized RGB image. Existing masks, color profiles and transparency are not preserved. Continue?", QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes: return
        try:
            self.doc.replace_image_resource(page, name, Path(path).read_bytes())
            self.refresh_document(); QMessageBox.information(self, "Image replaced", "Image resource replaced. Review the page preview and save to a new PDF.")
        except Exception as exc: QMessageBox.critical(self, "Image replacement failed", str(exc))

    def export_selected_font(self):
        row = self.media_table.currentRow()
        if row < 0 or self.media_table.item(row, 0).text() != "Font":
            QMessageBox.information(self, "Select font", "Select a Font row first."); return
        font = self.media_table.item(row, 0).data(Qt.UserRole)
        try:
            descriptor = font.get("/FontDescriptor")
            if descriptor is None:
                descendants = font.get("/DescendantFonts")
                if descendants:
                    for descendant in descendants:
                        descriptor = descendant.get("/FontDescriptor")
                        if descriptor is not None: break
            if descriptor is None: raise ValueError("No embedded font descriptor found; this may be a standard font or an unsupported composite font")
            stream = next((descriptor.get(k) for k in ("/FontFile", "/FontFile2", "/FontFile3") if descriptor.get(k) is not None), None)
            if stream is None: raise ValueError("No embedded font program found in /FontDescriptor")
            data = stream.read_bytes()
            suffix = ".cff" if "/FontFile3" in descriptor else (".ttf" if "/FontFile2" in descriptor else ".pfb")
            path, _ = QFileDialog.getSaveFileName(self, "Export embedded font", "embedded-font" + suffix, "All files (*.*)")
            if not path: return
            Path(path).write_bytes(data); self.doc.operations.append(f"Exported embedded font program to {path}"); self.update_log()
            QMessageBox.information(self, "Font exported", f"Extracted {len(data):,} bytes. Treat font files as untrusted input.")
        except Exception as exc: QMessageBox.warning(self, "Font export unavailable", str(exc))

    def diff_clicked(self):
        if not self.doc.is_open or not self.doc.original_bytes: return
        try:
            original_stream = BytesIO(self.doc.original_bytes)
            original_pdf = pikepdf.open(original_stream)
            try: rows = object_diff(original_pdf, self.doc.pdf)
            finally: original_pdf.close()
            self.diff_table.setRowCount(len(rows))
            for r, (ref, status, old, new) in enumerate(rows):
                vals = [f"{ref[0]} {ref[1]} R", status, old[:16] + "…" if old else "—", new[:16] + "…" if new else "—"]
                for c, value in enumerate(vals): self.diff_table.setItem(r, c, QTableWidgetItem(value))
            self.statusBar().showMessage(f"Structure comparison: {len(rows)} changed/added/removed objects")
        except Exception as exc: QMessageBox.critical(self, "Diff failed", str(exc))

    def populate_reference_graph(self):
        if not self.doc.is_open: return
        try:
            self.reference_graph = build_reference_graph(self.doc.pdf)
            graph = self.reference_graph
            summary = graph.summary()
            self.graph_summary.setText("   |   ".join(f"{k.title()}: {v}" for k, v in summary.items()))
            cycle_refs = {ref for edge in graph.cycle_edges() for ref in edge[:2] if ref is not None}
            self.graph_table.setRowCount(len(graph.nodes))
            for row, node in enumerate(graph.rows()):
                values = [f"{node.ref[0]} {node.ref[1]} R", node.kind,
                          "Reachable" if node.reachable else "Orphan candidate",
                          str(len(node.inbound)), str(len(node.outbound)),
                          "Yes" if node.ref in cycle_refs else "No"]
                for col, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if col == 0: item.setData(Qt.UserRole, node.ref)
                    self.graph_table.setItem(row, col, item)
            self.doc.operations.append(f"Built reference graph: {summary['objects']} objects, {summary['references']} edges, {summary['orphaned']} orphan candidates")
            self.update_log()
        except Exception as exc:
            self.graph_summary.setText(f"Reference graph failed: {exc}")

    def _selected_graph_ref(self):
        row = self.graph_table.currentRow()
        if row < 0: raise RuntimeError("Select an object in the reference graph")
        return self.graph_table.item(row, 0).data(Qt.UserRole)

    def show_graph_neighbors(self):
        if not self.reference_graph: return
        try:
            ref = self._selected_graph_ref(); node = self.reference_graph.nodes[ref]
            lines = [f"OBJECT {ref[0]} {ref[1]} R", f"Type: {node.kind}",
                     f"Reachable from /Root: {node.reachable}", "", "INBOUND REFERENCES"]
            lines.extend(f"{src if src else 'ROOT'} -> {path}" for src, path in node.inbound)
            lines += ["", "OUTBOUND REFERENCES"]
            lines.extend(f"{target[0]} {target[1]} R at {path}" for target, path in node.outbound)
            self.graph_details.setPlainText("\n".join(lines))
        except Exception as exc: QMessageBox.warning(self, "Reference details", str(exc))

    def on_graph_object_activated(self, item, column):
        try:
            ref = self.graph_table.item(item.row(), 0).data(Qt.UserRole)
            obj = self.doc.get_object(*ref)
            self.show_object(obj, ref)
            self.tabs.setCurrentIndex(0)
        except Exception as exc: QMessageBox.warning(self, "Open object", str(exc))

    def export_graph_report(self):
        if not self.reference_graph: self.populate_reference_graph()
        if not self.reference_graph: return
        path, _ = QFileDialog.getSaveFileName(self, "Export reference graph report", "jPDFRsc-reference-graph.txt", "Text report (*.txt)")
        if not path: return
        try:
            Path(path).write_text(format_graph_report(self.reference_graph), encoding="utf-8")
            self.doc.operations.append(f"Exported reference graph report to {path}"); self.update_log()
            QMessageBox.information(self, "Graph report exported", f"Saved report to:\n{path}")
        except Exception as exc: QMessageBox.critical(self, "Graph export failed", str(exc))

    def render_current_page(self):
        if not self.doc.is_open: return
        try:
            scale = float(self.zoom.currentText().replace("%", "")) / 100
            image = render_page(self.doc.path, self.page_spin.value() - 1, scale)
            qimage = ImageQt.ImageQt(image)
            pix = QPixmap.fromImage(qimage)
            self.page_view.setPixmap(pix.scaled(self.page_view.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))
        except Exception as exc: self.page_view.setText(f"Render unavailable: {exc}")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.doc.is_open: self.render_current_page()

    def search_objects(self):
        if not self.doc.is_open: return
        query = self.search_box.text().casefold().strip(); self.search_results.clear()
        if not query: return
        for num, gen, obj in self.doc.indirect_objects():
            text = safe_repr(obj, 30000)
            if query in text.casefold():
                item = QTreeWidgetItem([f"{num} {gen} R", type(obj).__name__]); item.setData(0, Qt.UserRole, (num, gen)); self.search_results.addTopLevelItem(item)
        for cat, name, ref, obj in resource_inventory(self.doc.pdf):
            if query in (cat + " " + name + " " + ref).casefold():
                item = QTreeWidgetItem([f"{cat}: {name} ({ref})", "Resource"])
                try: item.setData(0, Qt.UserRole, tuple(obj.objgen))
                except Exception: item.setData(0, Qt.UserRole, None)
                self.search_results.addTopLevelItem(item)

    def on_search_clicked(self, item, column):
        ref = item.data(0, Qt.UserRole)
        if ref:
            try: self.show_object(self.doc.get_object(*ref), ref)
            except Exception: pass
