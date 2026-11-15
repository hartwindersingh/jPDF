import sys
import os
import logging
from pathlib import Path
from PySide6.QtWidgets import QApplication
from jpdfrsc.ui.main_window import MainWindow


def main():
    log_root = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "jPDFRsc" / "logs"
    log_root.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=log_root / "jpdfrsc.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        encoding="utf-8",
    )
    app = QApplication(sys.argv)
    app.setApplicationName("jPDFRsc")
    app.setOrganizationName("jPDFRsc")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
