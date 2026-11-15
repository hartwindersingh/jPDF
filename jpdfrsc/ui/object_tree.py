from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
from PySide6.QtCore import Qt


class ObjectTree(QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["PDF structure / object", "Type"])
        self.setColumnWidth(0, 260)
        self.setAlternatingRowColors(True)

    def populate(self, document):
        self.clear()
        pdf = document.pdf
        root = QTreeWidgetItem(["Document", "PDF"])
        self.addTopLevelItem(root)
        catalog = QTreeWidgetItem(["Catalog (/Root)", "Dictionary"])
        catalog.setData(0, Qt.UserRole, (0, 0))
        root.addChild(catalog)
        objects = QTreeWidgetItem([f"Indirect objects ({len(pdf.objects)})", "Object table"])
        root.addChild(objects)
        for num, gen, obj in document.indirect_objects():
            typ = "Stream" if "Stream" in type(obj).__name__ else type(obj).__name__
            item = QTreeWidgetItem([f"{num} {gen} R", typ])
            item.setData(0, Qt.UserRole, (num, gen))
            objects.addChild(item)
        pages = QTreeWidgetItem([f"Pages ({len(pdf.pages)})", "Page tree"])
        root.addChild(pages)
        for i, page in enumerate(pdf.pages):
            item = QTreeWidgetItem([f"Page {i + 1}", "Page"])
            try:
                item.setData(0, Qt.UserRole, tuple(page.objgen))
            except Exception:
                item.setData(0, Qt.UserRole, None)
            pages.addChild(item)
        root.setExpanded(True)
        catalog.setExpanded(True)
        objects.setExpanded(True)
        pages.setExpanded(True)
