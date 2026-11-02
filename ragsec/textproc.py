"""Unicode normalization with original<->normalized offset maps, chunking and hashing."""
from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass, field

NORMALIZATION_VERSION = "nfkc-zw-bidi-hg-ws/1"

ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­", "᠎", "⁡", "⁢", "⁣", "⁤"}
BIDI_CONTROLS = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩",
                 "‎", "‏", "؜"}
# Small confusables subset (Cyrillic/Greek -> Latin). A full UTS #39 skeleton is out of MVP scope.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "Ι": "I", "Ο": "O", "Α": "A", "Β": "B", "Ε": "E",
}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def short_hash(text: str, n: int = 12) -> str:
    return sha256_text(text)[:n]


@dataclass
class NormalizedText:
    original: str
    text: str
    to_original: list[int]  # to_original[j] = index in original of normalized char j
    version: str = NORMALIZATION_VERSION
    transforms: dict[str, int] = field(default_factory=dict)

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        if not self.to_original or start >= len(self.to_original):
            return (len(self.original), len(self.original))
        s = self.to_original[start]
        e = self.to_original[max(start, min(end, len(self.to_original)) - 1)] + 1
        return (s, e)


def normalize(text: str) -> NormalizedText:
    """Per-character NFKC + zero-width/bidi removal + homoglyph folding + whitespace collapse.

    Per-character processing keeps an exact offset map back to the original view. Limitation:
    compositions spanning several code points (e.g. decomposed Hangul jamo) are composed by NFKC only
    when the jamo arrive in one code point; this is recorded in the caveats report.
    """
    out: list[str] = []
    idx: list[int] = []
    counts = {"nfkc_changed": 0, "zero_width_removed": 0, "bidi_removed": 0, "homoglyph_folded": 0,
              "whitespace_collapsed": 0, "control_removed": 0}
    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH:
            counts["zero_width_removed"] += 1
            continue
        if ch in BIDI_CONTROLS:
            counts["bidi_removed"] += 1
            continue
        if ch == "\r":
            continue
        cat = unicodedata.category(ch)
        if cat == "Cc" and ch not in ("\n", "\t"):
            counts["control_removed"] += 1
            continue
        n = unicodedata.normalize("NFKC", ch)
        if n != ch:
            counts["nfkc_changed"] += 1
        for c in n:
            if c in HOMOGLYPHS:
                c = HOMOGLYPHS[c]
                counts["homoglyph_folded"] += 1
            if c == "\t" or (c.isspace() and c != "\n"):
                c = " "
            if c == " " and out and out[-1] in (" ", "\n"):
                counts["whitespace_collapsed"] += 1
                continue
            if c == "\n" and len(out) >= 2 and out[-1] == "\n" and out[-2] == "\n":
                counts["whitespace_collapsed"] += 1
                continue
            out.append(c)
            idx.append(i)
    return NormalizedText(original=text, text="".join(out), to_original=idx,
                          transforms={k: v for k, v in counts.items() if v})


@dataclass(frozen=True)
class ChunkSpan:
    index: int
    start: int
    end: int
    text: str


_BREAKS = ("\n\n", "\n", "다. ", ". ", "? ", "! ", " ")


def chunk_text(text: str, size: int, overlap: int) -> list[ChunkSpan]:
    """Character-window chunking on the ORIGINAL view, preferring natural boundaries near the window end."""
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValueError("require size > 0 and 0 <= overlap < size")
    spans: list[ChunkSpan] = []
    n = len(text)
    start = 0
    while start < n:
        end = min(start + size, n)
        if end < n:
            window = text[start:end]
            floor = int(size * 0.6)
            for b in _BREAKS:
                pos = window.rfind(b)
                if pos >= floor:
                    end = start + pos + len(b)
                    break
        piece = text[start:end]
        if piece.strip():
            spans.append(ChunkSpan(index=len(spans), start=start, end=end, text=piece))
        if end >= n:
            break
        start = max(end - overlap, start + 1)
    return spans
