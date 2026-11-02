"""Request-scoped answer citations: parse [E#] labels from a generated answer and resolve them to the
authorized evidence chunks actually placed in the prompt.

Guarantees:
* Only labels that were ACTUALLY provided as evidence resolve to a Citation. A cited label not in the provided
  set is reported as INVALID (a likely hallucinated reference), never silently dropped.
* Citation fields (title, article, page) are copied from the chunk's recorded provenance — never invented. Page
  is None unless a reliable page number is known.
* Attribution is not entailment: a resolved citation says "the answer pointed here", NOT that every claim is
  supported by that evidence. The caller must not present syntactic validity as legal/semantic correctness.
"""
from __future__ import annotations

import re
from typing import Any

from .schemas import Citation

# A citation marker like [E1] / [ E12 ]. Only this exact label shape is recognized.
CITATION_RE = re.compile(r"\[\s*(E\d{1,3})\s*\]")


def extract_labels(text: str) -> list[str]:
    """Distinct cited labels in first-seen order."""
    return list(dict.fromkeys(m.group(1) for m in CITATION_RE.finditer(text or "")))


def resolve_citations(answer: str, label_to_chunk: dict[str, Any]) -> tuple[list[Citation], list[str], list[str]]:
    """Return (citations, invalid_labels, uncited_labels).

    label_to_chunk maps a request-scoped label (e.g. "E1") to the retrieved chunk object placed in the prompt
    (an object exposing .chunk_id and .metadata). Empty label_to_chunk (no evidence) yields no citations even
    if the answer contains markers — those markers are then all invalid.
    """
    cited = extract_labels(answer)
    valid = [l for l in cited if l in label_to_chunk]
    invalid = [l for l in cited if l not in label_to_chunk]
    uncited = [l for l in label_to_chunk if l not in valid]
    citations: list[Citation] = []
    for lab in sorted(valid, key=_label_num):
        c = label_to_chunk[lab]
        md = c.metadata
        citations.append(Citation(
            label=lab, document_id=md.document_id, document_version=md.document_version, chunk_id=c.chunk_id,
            display_title=md.source_name, source_trust_level=md.source_trust_level,
            article_label=md.article_label, article_title=md.article_title, section_label=md.section_label,
            page=getattr(md, "page", None), char_start=md.char_start, char_end=md.char_end,
            provenance_url=md.source_url))
    return citations, invalid, sorted(uncited, key=_label_num)


def _label_num(label: str) -> int:
    try:
        return int(label[1:])
    except ValueError:
        return 0
