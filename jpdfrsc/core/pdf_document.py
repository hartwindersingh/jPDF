from __future__ import annotations
from pathlib import Path
from io import BytesIO
import hashlib
import pikepdf
from jpdfrsc.core.history import SnapshotHistory

class PDFDocument:
    """Owns a pikepdf document and records reversible, audited edits."""
    def __init__(self):
        self.pdf: pikepdf.Pdf | None = None
        self.path: Path | None = None
        self.operations: list[str] = []
        self.original_sha256: str | None = None
        self.original_bytes: bytes | None = None
        self.history = SnapshotHistory(30)
        self._backing_stream = None

    @property
    def is_open(self): return self.pdf is not None

    def open(self, path):
        self.close()
        path = Path(path)
        raw = path.read_bytes()
        self.pdf = pikepdf.open(path)
        self.path = path
        self.original_bytes = raw
        self.original_sha256 = hashlib.sha256(raw).hexdigest()
        self.operations = [f"Opened {path.name}; SHA-256 {self.original_sha256}"]

    def close(self):
        if self.pdf is not None: self.pdf.close()
        self.pdf = None; self.path = None; self.operations = []
        self.original_sha256 = None; self.original_bytes = None
        self.history.clear(); self._backing_stream = None

    def _require(self):
        if self.pdf is None: raise RuntimeError("No PDF is open")

    def _bytes(self) -> bytes:
        self._require()
        stream = BytesIO(); self.pdf.save(stream); return stream.getvalue()

    def _checkpoint(self, label: str):
        self.history.checkpoint(label, self._bytes())

    def _restore(self, data: bytes):
        if self.pdf is not None: self.pdf.close()
        self._backing_stream = BytesIO(data)
        self.pdf = pikepdf.open(self._backing_stream)

    def undo(self):
        self._require(); target = self.history.take_undo(self._bytes())
        if target is None: return False
        self._restore(target.data); self.operations.append(f"UNDO: {target.label}"); return True

    def redo(self):
        self._require(); target = self.history.take_redo(self._bytes())
        if target is None: return False
        self._restore(target.data); self.operations.append(f"REDO: {target.label}"); return True

    def save_as(self, path):
        self._require(); out = Path(path); out.parent.mkdir(parents=True, exist_ok=True)
        self.pdf.save(out); self.operations.append(f"Saved output to {out}"); return out

    def indirect_objects(self):
        self._require(); rows = []
        for obj in self.pdf.objects:
            try: num, gen = obj.objgen
            except Exception: continue
            rows.append((num, gen, obj))
        return sorted(rows, key=lambda x: (x[0], x[1]))

    def get_object(self, objnum, generation=0):
        self._require(); return self.pdf.get_object((int(objnum), int(generation)))

    def edit_dictionary_value(self, objnum, generation, key, value_text):
        self._require(); obj = self.get_object(objnum, generation)
        if not isinstance(obj, pikepdf.Dictionary): raise TypeError("Selected object is not a dictionary")
        pdf_key = pikepdf.Name(key if key.startswith("/") else "/" + key)
        if pdf_key not in obj: raise KeyError(f"Dictionary key {pdf_key} does not exist; use Add key for new entries")
        value = parse_scalar(value_text); self._checkpoint(f"Edit {objnum} {generation} R {pdf_key}")
        obj[pdf_key] = value
        self.operations.append(f"Edited {objnum} {generation} R: {pdf_key} = {value_text}")

    def add_dictionary_value(self, objnum, generation, key, value_text):
        self._require(); obj = self.get_object(objnum, generation)
        if not isinstance(obj, pikepdf.Dictionary): raise TypeError("Selected object is not a dictionary")
        pdf_key = pikepdf.Name(key if key.startswith("/") else "/" + key)
        if pdf_key in obj: raise KeyError(f"{pdf_key} already exists")
        value = parse_scalar(value_text); self._checkpoint(f"Add {pdf_key} to {objnum} {generation} R")
        obj[pdf_key] = value; self.operations.append(f"Added {pdf_key} to {objnum} {generation} R")

    def remove_dictionary_key(self, objnum, generation, key):
        self._require(); obj = self.get_object(objnum, generation)
        if not isinstance(obj, pikepdf.Dictionary): raise TypeError("Selected object is not a dictionary")
        pdf_key = pikepdf.Name(key if key.startswith("/") else "/" + key)
        if pdf_key not in obj: raise KeyError(str(pdf_key))
        self._checkpoint(f"Remove {pdf_key} from {objnum} {generation} R")
        del obj[pdf_key]; self.operations.append(f"Removed {pdf_key} from {objnum} {generation} R")

    def create_dictionary_object(self, entries: dict[str, str]):
        self._require(); self._checkpoint("Create indirect dictionary object")
        d = pikepdf.Dictionary()
        for key, value in entries.items(): d[pikepdf.Name(key if key.startswith("/") else "/" + key)] = parse_scalar(value)
        obj = self.pdf.make_indirect(d); ref = tuple(obj.objgen)
        self.operations.append(f"Created indirect dictionary object {ref[0]} {ref[1]} R")
        return ref

    def clone_dictionary_object(self, objnum, generation):
        self._require(); source = self.get_object(objnum, generation)
        if not isinstance(source, pikepdf.Dictionary) or isinstance(source, pikepdf.Stream):
            raise TypeError("Only non-stream dictionaries can be cloned by this command")
        self._checkpoint(f"Clone dictionary {objnum} {generation} R")
        clone = pikepdf.Dictionary()
        for key, value in source.items(): clone[key] = value
        obj = self.pdf.make_indirect(clone); ref = tuple(obj.objgen)
        self.operations.append(f"Cloned dictionary {objnum} {generation} R to {ref[0]} {ref[1]} R (shallow clone; nested references shared)")
        return ref


    def clone_object_graph(self, objnum: int, generation: int = 0):
        """Deep-clone an indirect object's reachable indirect subgraph.

        Indirect references inside the cloned subgraph are remapped to cloned
        objects. Direct containers are copied recursively. Streams are decoded
        and rewritten without their original filter chain; semantic stream data
        is retained where decoding succeeds, but byte identity is not promised.
        The source graph is never modified.
        """
        self._require()
        source = self.get_object(objnum, generation)
        memo = {}
        active_direct = set()
        max_depth = 512

        def ref_of(value):
            try:
                ref = tuple(value.objgen)
                return ref if ref != (0, 0) else None
            except Exception:
                return None

        def clone(value, depth=0):
            if depth > max_depth:
                raise ValueError("Object nesting exceeds the 512-level clone safety limit")
            ref = ref_of(value)
            if ref is not None and ref in memo:
                return memo[ref]

            is_stream = isinstance(value, pikepdf.Stream)
            is_dict = isinstance(value, pikepdf.Dictionary) and not is_stream
            is_array = isinstance(value, pikepdf.Array)

            if is_stream:
                try:
                    payload = value.read_bytes()
                except Exception as exc:
                    raise ValueError(f"Cannot decode source stream {ref}: {exc}") from exc
                target = self.pdf.make_stream(payload)
                if ref is not None:
                    memo[ref] = target
                excluded = {"/Length", "/Filter", "/DecodeParms"}
                for key, child in value.items():
                    if str(key) in excluded:
                        continue
                    target[key] = clone(child, depth + 1)
                return target

            if is_dict:
                target = pikepdf.Dictionary()
                if ref is not None:
                    target = self.pdf.make_indirect(target)
                    memo[ref] = target
                marker = id(value)
                if marker in active_direct:
                    raise ValueError("Unsupported direct-container cycle in malformed PDF")
                active_direct.add(marker)
                try:
                    for key, child in value.items():
                        target[key] = clone(child, depth + 1)
                finally:
                    active_direct.discard(marker)
                return target

            if is_array:
                target = pikepdf.Array()
                if ref is not None:
                    target = self.pdf.make_indirect(target)
                    memo[ref] = target
                marker = id(value)
                if marker in active_direct:
                    raise ValueError("Unsupported direct-container cycle in malformed PDF")
                active_direct.add(marker)
                try:
                    for child in value:
                        target.append(clone(child, depth + 1))
                finally:
                    active_direct.discard(marker)
                return target

            # Primitive indirect objects can be copied as a value and wrapped.
            copied = value
            if ref is not None:
                copied = self.pdf.make_indirect(value)
                memo[ref] = copied
            return copied

        self._checkpoint(f"Deep clone object graph {objnum} {generation} R")
        try:
            result = clone(source)
            result_ref = ref_of(result)
            if result_ref is None:
                result = self.pdf.make_indirect(result)
                result_ref = tuple(result.objgen)
        except Exception:
            # Restore the pre-operation snapshot so a partial clone is not left behind.
            snapshot = self.history.undo_stack.pop() if self.history.undo_stack else None
            if snapshot is not None:
                self._restore(snapshot.data)
            raise
        self.operations.append(
            f"Deep-cloned object graph {objnum} {generation} R to "
            f"{result_ref[0]} {result_ref[1]} R; {len(memo)} indirect nodes remapped"
        )
        return result_ref, len(memo)

    def attach_object_reference(self, parent_num: int, parent_gen: int, key: str, target_num: int, target_gen: int = 0):
        """Set a dictionary key to reference an existing indirect object."""
        self._require()
        parent = self.get_object(parent_num, parent_gen)
        if not isinstance(parent, pikepdf.Dictionary) or isinstance(parent, pikepdf.Stream):
            raise TypeError("Parent must be a non-stream dictionary")
        pdf_key = pikepdf.Name(key if key.startswith("/") else "/" + key)
        target = self.get_object(target_num, target_gen)
        target_ref = tuple(target.objgen)
        if target_ref == (0, 0):
            raise ValueError("Target must be an indirect object")
        self._checkpoint(f"Attach {target_num} {target_gen} R at {pdf_key}")
        parent[pdf_key] = target
        self.operations.append(f"Attached {target_num} {target_gen} R to {parent_num} {parent_gen} R at {pdf_key}")

    def validate_structure(self) -> list[str]:
        """Run qpdf structural checks and return diagnostic messages."""
        self._require()
        try:
            messages = self.pdf.check()
            return [str(message) for message in messages] if messages else []
        except Exception as exc:
            return [f"Validation could not complete: {type(exc).__name__}: {exc}"]

    def replace_image_resource(self, page_index: int, resource_name: str, image_bytes: bytes):
        """Replace one page XObject image with a normalized 8-bit RGB image."""
        from PIL import Image
        from io import BytesIO
        self._require()
        image = Image.open(BytesIO(image_bytes)).convert("RGB")
        width, height = image.size
        if width * height > 100_000_000: raise ValueError("Image exceeds 100 megapixel safety limit")
        pixels = image.tobytes()
        self._checkpoint(f"Replace image {resource_name} on page {page_index + 1}")
        page = self.pdf.pages[page_index]
        # Resolve inherited page resources, then copy-on-write the resource and
        # XObject dictionaries so sibling pages that share them are not changed.
        inherited = None
        node = page.obj
        while node is not None:
            inherited = node.get("/Resources")
            if inherited is not None: break
            node = node.get("/Parent") if isinstance(node, pikepdf.Dictionary) else None
        resources = pikepdf.Dictionary()
        if inherited is not None:
            for rkey, rval in inherited.items(): resources[rkey] = rval
        old_xobjects = resources.get("/XObject")
        xobjects = pikepdf.Dictionary()
        if old_xobjects is not None:
            for xkey, xval in old_xobjects.items(): xobjects[xkey] = xval
        key = pikepdf.Name(resource_name if resource_name.startswith("/") else "/" + resource_name)
        if key not in xobjects: raise KeyError(f"Image resource {key} no longer exists on page")
        resources["/XObject"] = xobjects
        page.obj["/Resources"] = resources
        replacement = self.pdf.make_stream(pixels, Type=pikepdf.Name("/XObject"),
            Subtype=pikepdf.Name("/Image"), Width=width, Height=height,
            ColorSpace=pikepdf.Name("/DeviceRGB"), BitsPerComponent=8)
        xobjects[key] = replacement
        self.operations.append(f"Replaced image {key} on page {page_index + 1} with {width}x{height} RGB data")

    def replace_stream(self, objnum, generation, data: bytes, decoded=True):
        self._require(); obj = self.get_object(objnum, generation)
        if not isinstance(obj, pikepdf.Stream): raise TypeError("Selected object is not a stream")
        self._checkpoint(f"Replace stream {objnum} {generation} R")
        # pikepdf updates /Length and writes unfiltered bytes by default. Decoded data
        # is safest; the previous filter chain is removed to prevent stale metadata.
        if decoded:
            obj.write(data, filter=None)
        else:
            obj.write(data)
        self.operations.append(f"Replaced stream {objnum} {generation} R with {len(data)} bytes")

    def summary(self):
        self._require(); pdf = self.pdf
        return {"File": str(self.path), "PDF version": getattr(pdf, "pdf_version", "Unknown"),
                "Pages": str(len(pdf.pages)), "Indirect objects": str(len(pdf.objects)),
                "Encrypted": str(bool(pdf.is_encrypted)), "Original SHA-256": self.original_sha256 or "",
                "Title": str(pdf.docinfo.get("/Title", "")), "Author": str(pdf.docinfo.get("/Author", "")),
                "Creator": str(pdf.docinfo.get("/Creator", "")), "Producer": str(pdf.docinfo.get("/Producer", ""))}


def parse_scalar(text: str):
    s = text.strip()
    if s == "null": return None
    if s == "true": return True
    if s == "false": return False
    if s.startswith("/"):
        if any(ch.isspace() for ch in s): raise ValueError("PDF names cannot contain unescaped whitespace")
        return pikepdf.Name(s)
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")": return pikepdf.String(s[1:-1])
    try:
        if any(c in s for c in ".eE"): return float(s)
        return int(s)
    except ValueError: raise ValueError("Use /Name, (text), true, false, null, integer or decimal")
