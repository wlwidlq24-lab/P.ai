"""Article-aware segmentation for Korean legal / policy documents.

This is a HEURISTIC structural parser. It recognizes common Korean statute/policy markers (장/절/조, 조의N,
article titles) to prefer article boundaries when chunking and to record structured provenance. It does NOT
establish authoritative legal structure — malformed extraction, tables, running headers and non-standard
drafting all degrade gracefully to generic character-window chunking with an explicit fallback reason.

Segmentation runs on the ORIGINAL extracted text (same view as textproc.chunk_text), so char offsets map
directly to the stored document text. Normalized text and its provenance are kept distinct elsewhere.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .schemas import SegmentStrategy
from .textproc import ChunkSpan, chunk_text

SEGMENTATION_VERSION = "ko-legal-seg/1"

# A structural marker at the start of a line: 제<n>장 / 제<n>절 / 제<n>조 / 제<n>조의<m>.
# Spacing is tolerated (제 15 조). Unit is captured so chapters/sections update context and articles create spans.
_MARKER_RE = re.compile(r"^[ \t]*제\s*(\d+)\s*(장|절|조)(?:\s*의\s*(\d+))?", re.MULTILINE)
# A parenthesized article title immediately after the marker, e.g. 제15조(개인정보의 수집·이용). Both ( ) and （ ）.
# No ^ anchor: we position the match explicitly with .match(text, pos) at the marker end (mid-line).
_TITLE_RE = re.compile(r"\s*[\(（]([^\)）\n]{1,80})[\)）]")


@dataclass(frozen=True)
class SegChunk:
    """A chunk plus its article-aware provenance. `strategy` records how it was produced."""
    index: int
    start: int
    end: int
    text: str
    strategy: SegmentStrategy = SegmentStrategy.GENERIC
    article_label: str | None = None
    article_title: str | None = None
    section_label: str | None = None
    fallback_reason: str | None = None


@dataclass(frozen=True)
class _Marker:
    start: int
    line_end: int
    kind: str          # "chapter" | "article"
    label: str         # e.g. "제2장", "제15조", "제15조의2"
    title: str | None


def _scan_markers(text: str) -> list[_Marker]:
    out: list[_Marker] = []
    for m in _MARKER_RE.finditer(text):
        n, unit, sub = m.group(1), m.group(2), m.group(3)
        line_end = text.find("\n", m.end())
        line_end = len(text) if line_end == -1 else line_end
        if unit == "조":
            label = f"제{n}조의{sub}" if sub else f"제{n}조"
            title_m = _TITLE_RE.match(text, m.end(), line_end + 1)
            title = title_m.group(1).strip() if title_m else None
            out.append(_Marker(m.start(), line_end, "article", label, title))
        else:  # 장 / 절
            label = f"제{n}{unit}" + (f"의{sub}" if sub else "")
            rest = text[m.end():line_end].strip(" \t:·-—()（）")
            out.append(_Marker(m.start(), line_end, "chapter", label, rest or None))
    return out


def segment_document(text: str, size: int, overlap: int, *, article_aware: bool,
                     min_articles: int = 2) -> tuple[list[SegChunk], str | None]:
    """Return (chunks, fallback_reason).

    When article_aware is False, or too few article markers are found, or article parsing is not applicable,
    returns generic character-window chunks (strategy=GENERIC) and a non-None fallback_reason describing why
    (None only when article-aware chunking was actually used). Oversized articles are split into parts that keep
    their article identity (strategy=ARTICLE_SPLIT). Source order and hierarchy (parent chapter) are preserved.
    """
    def _generic(reason: str | None) -> tuple[list[SegChunk], str | None]:
        chunks = [SegChunk(index=i, start=s.start, end=s.end, text=s.text,
                           strategy=SegmentStrategy.GENERIC, fallback_reason=reason)
                  for i, s in enumerate(chunk_text(text, size, overlap))]
        return chunks, reason

    if not article_aware:
        return _generic(None)  # generic mode is not a fallback; no reason recorded

    markers = _scan_markers(text)
    articles = [mk for mk in markers if mk.kind == "article"]
    if len(articles) < min_articles:
        return _generic(f"too_few_article_markers({len(articles)})")

    # Build article spans: each article runs until the next article/chapter marker (or end of document).
    boundaries = sorted(markers, key=lambda mk: mk.start)
    starts = [mk.start for mk in boundaries] + [len(text)]
    out: list[SegChunk] = []
    idx = 0
    current_section: str | None = None
    first_article_start = articles[0].start

    # Preamble before the first marker -> generic chunks (no article identity).
    if first_article_start > 0 and text[:first_article_start].strip():
        for sp in chunk_text(text[:first_article_start], size, overlap):
            out.append(SegChunk(index=idx, start=sp.start, end=sp.end, text=sp.text,
                                strategy=SegmentStrategy.GENERIC, fallback_reason="preamble_before_first_article"))
            idx += 1

    for i, mk in enumerate(boundaries):
        seg_start, seg_end = mk.start, starts[i + 1]
        if mk.kind == "chapter":
            current_section = mk.label
            # A chapter heading with no article before the next marker: keep its text as a section-labeled chunk.
            heading = text[seg_start:seg_end]
            if heading.strip() and (i + 1 >= len(boundaries) or boundaries[i + 1].kind != "article"
                                    or boundaries[i + 1].start > mk.line_end + 1):
                # only emit if there is non-marker body text under the chapter before the next article
                body = text[mk.line_end:seg_end]
                if body.strip():
                    for sp in chunk_text(text[seg_start:seg_end], size, overlap):
                        out.append(SegChunk(index=idx, start=seg_start + sp.start, end=seg_start + sp.end,
                                            text=sp.text, strategy=SegmentStrategy.ARTICLE_AWARE,
                                            section_label=current_section))
                        idx += 1
            continue
        # article
        seg_text = text[seg_start:seg_end]
        if len(seg_text) <= size:
            out.append(SegChunk(index=idx, start=seg_start, end=seg_end, text=seg_text,
                                strategy=SegmentStrategy.ARTICLE_AWARE, article_label=mk.label,
                                article_title=mk.title, section_label=current_section))
            idx += 1
        else:  # oversized article: split but preserve article identity
            for sp in chunk_text(seg_text, size, overlap):
                out.append(SegChunk(index=idx, start=seg_start + sp.start, end=seg_start + sp.end, text=sp.text,
                                    strategy=SegmentStrategy.ARTICLE_SPLIT, article_label=mk.label,
                                    article_title=mk.title, section_label=current_section))
                idx += 1
    if not out:  # defensive: parsing produced nothing usable
        return _generic("article_parse_empty")
    return out, None
