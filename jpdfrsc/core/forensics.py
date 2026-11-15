from __future__ import annotations
import pikepdf

RESOURCE_KEYS = {
    "/Font": "Fonts", "/XObject": "XObjects", "/ColorSpace": "Color spaces",
    "/Pattern": "Patterns", "/Shading": "Shadings", "/ExtGState": "Graphics states",
    "/Properties": "Properties"
}
SUSPICIOUS_KEYS = {"/OpenAction", "/AA", "/JavaScript", "/JS", "/Launch", "/EmbeddedFiles", "/RichMedia"}


def safe_repr(obj, limit=12000):
    try:
        value = str(obj)
    except Exception as exc:
        value = f"<repr failed: {exc}>"
    return value if len(value) <= limit else value[:limit] + "\n… [truncated]"


def object_details(obj):
    details = {"Python/PDF type": type(obj).__name__, "Indirect reference": str(getattr(obj, "objgen", "direct object"))}
    try:
        details["Is stream"] = str(isinstance(obj, pikepdf.Stream))
        if isinstance(obj, pikepdf.Stream):
            details["Raw stream bytes"] = str(len(obj.read_raw_bytes()))
            try:
                details["Decoded stream bytes"] = str(len(obj.read_bytes()))
            except Exception as exc:
                details["Decoded stream"] = f"Unavailable: {exc}"
            details["Filter"] = str(obj.get("/Filter", "None"))
            details["Subtype"] = str(obj.get("/Subtype", ""))
        if isinstance(obj, pikepdf.Dictionary):
            details["Dictionary keys"] = str(len(obj.keys()))
    except Exception as exc:
        details["Inspection note"] = str(exc)
    return details


def resource_inventory(pdf):
    found = []
    seen = set()
    def walk(obj, trail="Root", depth=0):
        if depth > 30:
            return
        try:
            og = tuple(obj.objgen)
            if og != (0, 0):
                if og in seen:
                    return
                seen.add(og)
        except Exception:
            pass
        if isinstance(obj, pikepdf.Dictionary):
            for key, value in obj.items():
                key_s = str(key)
                if key_s in RESOURCE_KEYS and isinstance(value, pikepdf.Dictionary):
                    category = RESOURCE_KEYS[key_s]
                    for name, resource in value.items():
                        found.append((category, str(name), str(getattr(resource, "objgen", "direct")), resource))
                walk(value, f"{trail}/{key_s}", depth + 1)
        elif isinstance(obj, pikepdf.Array):
            for i, value in enumerate(obj):
                walk(value, f"{trail}[{i}]", depth + 1)
    walk(pdf.Root)
    return found


def active_content_findings(pdf):
    findings = []
    for obj in pdf.objects:
        if not isinstance(obj, pikepdf.Dictionary):
            continue
        try:
            og = obj.objgen
        except Exception:
            og = (0, 0)
        for key in SUSPICIOUS_KEYS:
            try:
                if key in obj:
                    findings.append(f"Object {og[0]} {og[1]} R contains {key}")
            except Exception:
                pass
    return findings
