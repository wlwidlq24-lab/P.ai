"""Upload validation and PDF/TXT text extraction. Synchronous: call via asyncio.to_thread.

Offset coordinate system: all char offsets elsewhere (chunk char_start/char_end, article spans, PDF page
boundaries) index into the ORIGINAL extracted text returned here (`ParsedDocument.text`). The NORMALIZED view
is a separate coordinate space; `textproc.NormalizedText.to_original` maps normalized offsets back to original.
`page_offsets[i]` is the original-text char offset where extracted page i (0-based) begins; it is None for TXT
and for PDFs whose boundaries are not exposed.
"""
from __future__ import annotations

import bisect
import io
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import PurePath

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from .errors import (
    ContentTypeMismatchError, DamagedPdfError, EmptyDocumentError, EncodingFailureError, EncryptedPdfError,
    FileTooLargeError, PageLimitError, ScannedPdfError, TextLimitError, UnsupportedFileTypeError,
)

log = logging.getLogger(__name__)
ALLOWED_EXTENSIONS = {".pdf", ".txt"}


@dataclass
class ParsedDocument:
    text: str
    file_type: str
    safe_filename: str
    page_count: int | None = None
    encoding: str | None = None
    warnings: list[str] = field(default_factory=list)
    page_offsets: list[int] | None = None  # original-text char offset where each (0-based) PDF page begins


def page_for_offset(offset: int, page_offsets: list[int] | None) -> int | None:
    """1-based page number for a char offset, or None when page boundaries are unknown (e.g. TXT)."""
    if not page_offsets:
        return None
    return bisect.bisect_right(page_offsets, offset)


def safe_filename(name: str | None) -> str:
    """Return a display-only basename. Uploaded files are stored by content hash, never by this name."""
    base = PurePath((name or "upload").replace("\\", "/")).name
    base = unicodedata.normalize("NFKC", base)
    base = re.sub(r"[^\w.\-가-힣]", "_", base).strip("._") or "upload"
    return base[:120]


def _ext(name: str) -> str:
    return PurePath(name).suffix.lower()


def validate_upload(data: bytes, filename: str | None, max_bytes: int) -> str:
    """Checks size, extension allow-list and extension/content agreement. Returns the file type."""
    if len(data) == 0:
        raise EmptyDocumentError("uploaded file is empty")
    if len(data) > max_bytes:
        raise FileTooLargeError(f"file exceeds {max_bytes} bytes", detail={"size": len(data)})
    name = safe_filename(filename)
    ext = _ext(name)
    if ext not in ALLOWED_EXTENSIONS:
        raise UnsupportedFileTypeError(f"extension {ext or '(none)'} not allowed; use .pdf or .txt")
    is_pdf_magic = data.lstrip()[:5] == b"%PDF-"
    if ext == ".pdf" and not is_pdf_magic:
        raise ContentTypeMismatchError("file has .pdf extension but no %PDF- header")
    if ext == ".txt" and is_pdf_magic:
        raise ContentTypeMismatchError("file has .txt extension but PDF content")
    if ext == ".txt" and b"\x00" in data[:4096] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ContentTypeMismatchError("binary content in .txt file")
    return ext[1:]


def decode_text(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8"), "utf-8-sig"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16"), "utf-16"
        except UnicodeDecodeError as e:
            raise EncodingFailureError("invalid UTF-16 text") from e
    for enc in ("utf-8", "cp949"):  # cp949 covers legacy Korean (EUC-KR superset) files
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    raise EncodingFailureError("text is neither UTF-8, UTF-16 (BOM) nor CP949")


def parse_pdf(data: bytes, max_pages: int, min_chars_per_page: int) -> tuple[str, int, list[str], list[int]]:
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise EncryptedPdfError("encrypted PDFs are rejected (no password handling in experiments)")
        n_pages = len(reader.pages)
    except EncryptedPdfError:
        raise
    except (PdfReadError, ValueError, KeyError, TypeError, OSError) as e:
        raise DamagedPdfError(f"cannot read PDF: {type(e).__name__}") from e
    if n_pages == 0:
        raise EmptyDocumentError("PDF has no pages")
    if n_pages > max_pages:
        raise PageLimitError(f"PDF has {n_pages} pages > limit {max_pages}")
    texts: list[str] = []
    warnings: list[str] = []
    empty_pages = 0
    for i, page in enumerate(reader.pages):
        try:
            t = page.extract_text() or ""
        except Exception as e:  # pypdf raises a variety of errors on malformed content streams
            raise DamagedPdfError(f"text extraction failed on page {i + 1}: {type(e).__name__}") from e
        if len(t.strip()) < min_chars_per_page:
            empty_pages += 1
        texts.append(t)
    # Build the joined text while recording where each page starts (char offset into the ORIGINAL text).
    sep = "\n\n"
    page_offsets: list[int] = []
    pos = 0
    for i, t in enumerate(texts):
        page_offsets.append(pos)
        pos += len(t) + (len(sep) if i != len(texts) - 1 else 0)
    full = sep.join(texts)
    if not full.strip():
        raise ScannedPdfError("no extractable text; scanned/image PDFs need OCR, which is out of scope")
    if empty_pages:
        warnings.append(f"{empty_pages}/{n_pages} pages had little or no extractable text (possible scans)")
    return full, n_pages, warnings, page_offsets


def parse_document(data: bytes, filename: str | None, *, max_bytes: int, max_pages: int,
                   max_chars: int, min_chars_per_page: int) -> ParsedDocument:
    ftype = validate_upload(data, filename, max_bytes)
    name = safe_filename(filename)
    if ftype == "pdf":
        text, pages, warnings, page_offsets = parse_pdf(data, max_pages, min_chars_per_page)
        doc = ParsedDocument(text=text, file_type="pdf", safe_filename=name, page_count=pages, warnings=warnings,
                             page_offsets=page_offsets)
    else:
        text, enc = decode_text(data)
        doc = ParsedDocument(text=text, file_type="txt", safe_filename=name, encoding=enc)
    if not doc.text.strip():
        raise EmptyDocumentError("document contains no text")
    if len(doc.text) > max_chars:
        raise TextLimitError(f"extracted text {len(doc.text)} chars > limit {max_chars}")
    return doc
