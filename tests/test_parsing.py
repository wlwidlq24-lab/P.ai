from __future__ import annotations

import io

import pytest
from reportlab.pdfgen import canvas

from ragsec.errors import (
    ContentTypeMismatchError, DamagedPdfError, EmptyDocumentError, ScannedPdfError, UnsupportedFileTypeError,
)
from ragsec.parsing import decode_text, parse_document, safe_filename

KW = dict(max_bytes=10_000_000, max_pages=200, max_chars=500_000, min_chars_per_page=20)


def _pdf(text: str) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.drawString(100, 700, text)
    c.save()
    return buf.getvalue()


def test_txt_utf8_and_cp949():
    doc = parse_document("안녕하세요 고객님".encode("utf-8"), "a.txt", **KW)
    assert "안녕하세요" in doc.text and doc.encoding == "utf-8"
    doc2 = parse_document("계좌번호".encode("cp949"), "b.txt", **KW)
    assert doc2.encoding == "cp949"


def test_empty_file_rejected():
    with pytest.raises(EmptyDocumentError):
        parse_document(b"", "a.txt", **KW)


def test_extension_content_mismatch():
    with pytest.raises(ContentTypeMismatchError):
        parse_document(b"%PDF-1.4 fake", "a.txt", **KW)  # pdf content, txt extension


def test_unsupported_extension():
    with pytest.raises(UnsupportedFileTypeError):
        parse_document(b"data", "a.exe", **KW)


def test_path_traversal_filename_sanitized():
    assert "/" not in safe_filename("../../etc/passwd")
    assert "\\" not in safe_filename("..\\..\\win.ini")


def test_real_pdf_extracts_text():
    doc = parse_document(_pdf("Hello 금융 RAG"), "ok.pdf", **KW)
    assert "Hello" in doc.text and doc.file_type == "pdf"


def test_damaged_pdf():
    with pytest.raises(DamagedPdfError):
        parse_document(b"%PDF-1.4\nnot a real pdf body", "x.pdf", **KW)


def test_scanned_pdf_no_text():
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.rect(100, 100, 50, 50)  # no text at all
    c.save()
    with pytest.raises(ScannedPdfError):
        parse_document(buf.getvalue(), "scan.pdf", **KW)


def test_binary_in_txt_rejected():
    with pytest.raises(ContentTypeMismatchError):
        parse_document(b"text\x00\x01\x02binary", "a.txt", **KW)
