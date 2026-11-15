import fitz
from PIL import Image
from io import BytesIO


def render_page(path, page_index: int, scale: float = 1.5) -> Image.Image:
    doc = fitz.open(path)
    try:
        page = doc.load_page(page_index)
        pix = page.get_pixmap(matrix=fitz.Matrix(scale, scale), alpha=False)
        return Image.open(BytesIO(pix.tobytes("png"))).convert("RGB")
    finally:
        doc.close()
