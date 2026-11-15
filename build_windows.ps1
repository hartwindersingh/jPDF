$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.\.venv\Scripts\python.exe')) {
    py -3.11 -m venv .venv
}
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt pyinstaller pytest
.\.venv\Scripts\python.exe -m compileall -q .
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\pyinstaller.exe --noconfirm --clean --windowed --onedir --name jPDFRsc `
    --collect-all pikepdf --collect-all fitz --collect-all PySide6 --collect-all PIL main.py
Write-Host "Build complete: dist\jPDFRsc\jPDFRsc.exe"
