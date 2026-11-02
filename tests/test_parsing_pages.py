"""PDF page provenance: page offsets tracked when boundaries are exposed; None for TXT."""
from __future__ import annotations

import io

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from ragsec.parsing import page_for_offset, parse_document

LIMITS = dict(max_bytes=10_000_000, max_pages=200, max_chars=500_000, min_chars_per_page=1)


def _two_page_pdf() -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.drawString(72, 700, "PAGE ONE ALPHA content line")
    c.showPage()
    c.drawString(72, 700, "PAGE TWO BETA content line")
    c.showPage()
    c.save()
    return buf.getvalue()


def test_pdf_page_offsets_and_mapping():
    doc = parse_document(_two_page_pdf(), "two.pdf", **LIMITS)
    assert doc.file_type == "pdf" and doc.page_count == 2
    assert doc.page_offsets and len(doc.page_offsets) == 2
    assert page_for_offset(0, doc.page_offsets) == 1
    assert page_for_offset(doc.page_offsets[1], doc.page_offsets) == 2
    assert "ALPHA" in doc.text and "BETA" in doc.text


def test_txt_has_no_page_offsets():
    doc = parse_document("그냥 텍스트 문서".encode(), "a.txt", **LIMITS)
    assert doc.page_offsets is None
    assert page_for_offset(0, None) is None  # unsupported source -> page stays null (never invented)
