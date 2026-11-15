"""Advanced read-only analysis helpers; extracted content is always untrusted."""
from __future__ import annotations
import hashlib
import pikepdf


def object_fingerprint(obj) -> str:
    h = hashlib.sha256()
    try:
        if isinstance(obj, pikepdf.Stream): h.update(obj.read_raw_bytes())
        h.update(str(obj).encode("utf-8", "replace"))
    except Exception as exc: h.update(repr(exc).encode())
    return h.hexdigest()


def object_diff(original_pdf, current_pdf):
    """Compare indirect-object fingerprints between original and current PDFs."""
    def index(pdf):
        out = {}
        for obj in pdf.objects:
            try: ref = tuple(obj.objgen)
            except Exception: continue
            if ref != (0, 0): out[ref] = object_fingerprint(obj)
        return out
    old, new = index(original_pdf), index(current_pdf)
    rows = []
    for ref in sorted(set(old) | set(new)):
        if ref not in old: status = "Added"
        elif ref not in new: status = "Removed"
        elif old[ref] != new[ref]: status = "Changed"
        else: continue
        rows.append((ref, status, old.get(ref, ""), new.get(ref, "")))
    return rows


def content_stream_report(pdf, page_index: int):
    page = pdf.pages[page_index]
    instructions = pikepdf.parse_content_stream(page)
    lines = [f"PAGE {page_index + 1} — {len(instructions)} parsed instructions", ""]
    counts = {}
    for index, instruction in enumerate(instructions, 1):
        operator = str(instruction.operator)
        counts[operator] = counts.get(operator, 0) + 1
        operands = ", ".join(str(x) for x in instruction.operands)
        lines.append(f"{index:05d}  {operator:<8} {operands}")
    lines += ["", "OPERATOR COUNTS"]
    lines += [f"{key}: {value}" for key, value in sorted(counts.items(), key=lambda x: (-x[1], x[0]))]
    return "\n".join(lines)


def image_resources(pdf):
    found = []
    for page_no, page in enumerate(pdf.pages, 1):
        try: resources = page.obj.get("/Resources", pikepdf.Dictionary())
        except Exception: continue
        xobjects = resources.get("/XObject", pikepdf.Dictionary())
        for name, obj in xobjects.items():
            try:
                if str(obj.get("/Subtype", "")) != "/Image": continue
                ref = tuple(obj.objgen)
                width, height = obj.get("/Width", 0), obj.get("/Height", 0)
                filt = str(obj.get("/Filter", "None"))
                found.append((page_no, str(name), ref, int(width), int(height), filt, obj))
            except Exception: pass
    return found


def font_resources(pdf):
    found, seen = [], set()
    for page_no, page in enumerate(pdf.pages, 1):
        try: fonts = page.obj.get("/Resources", {}).get("/Font", {})
        except Exception: continue
        for name, font in fonts.items():
            try: ref = tuple(font.objgen)
            except Exception: ref = (0, 0)
            key = (page_no, str(name), ref)
            if key in seen: continue
            seen.add(key)
            found.append((page_no, str(name), ref, str(font.get("/Subtype", "")),
                          str(font.get("/BaseFont", "")), font))
    return found


def hex_dump(data: bytes, width: int = 16, max_bytes: int = 1024 * 1024) -> str:
    shown = data[:max_bytes]
    lines = []
    for offset in range(0, len(shown), width):
        chunk = shown[offset:offset + width]
        hx = " ".join(f"{b:02X}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08X}  {hx}  |{text}|")
    if len(data) > len(shown): lines.append(f"… truncated; showing {len(shown):,} of {len(data):,} bytes")
    return "\n".join(lines)


def stream_hashes(obj):
    raw = obj.read_raw_bytes()
    result = {"Raw size": len(raw), "Raw SHA-256": hashlib.sha256(raw).hexdigest()}
    try:
        decoded = obj.read_bytes()
        result["Decoded size"] = len(decoded)
        result["Decoded SHA-256"] = hashlib.sha256(decoded).hexdigest()
    except Exception as exc: result["Decode error"] = str(exc)
    return result


def forensic_report(document) -> str:
    """Create a plain-text session report; not a certified chain-of-custody record."""
    from jpdfrsc.core.forensics import active_content_findings, resource_inventory
    pdf = document.pdf
    lines = ["jPDFRsc FORENSIC REVIEW REPORT", "=" * 72,
             "NOTICE: Informational report only; not a certified forensic acquisition.",
             "", "DOCUMENT SUMMARY"]
    lines.extend(f"{k}: {v}" for k, v in document.summary().items())
    lines += ["", "OBJECT INVENTORY"]
    for num, gen, obj in document.indirect_objects():
        kind = "Stream" if isinstance(obj, pikepdf.Stream) else type(obj).__name__
        try: digest = object_fingerprint(obj)
        except Exception: digest = "unavailable"
        lines.append(f"{num} {gen} R | {kind} | SHA-256 {digest}")
    lines += ["", "RESOURCE INVENTORY"]
    for category, name, ref, obj in resource_inventory(pdf):
        lines.append(f"{category} | {name} | {ref} | {type(obj).__name__}")
    lines += ["", "ACTIVE-CONTENT INDICATORS",
              "Indicators are leads for manual review, not proof of malicious behavior."]
    lines.extend(active_content_findings(pdf) or ["No configured indicators found in scanned indirect dictionaries."])
    lines += ["", "SESSION OPERATIONS"]
    lines.extend(document.operations or ["No operations recorded."])
    lines += ["", "END OF REPORT"]
    return "\n".join(lines)
