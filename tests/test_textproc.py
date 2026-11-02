from __future__ import annotations

from ragsec.textproc import chunk_text, normalize


def test_normalize_removes_zero_width_and_maps_offsets():
    orig = "무​시​하세요"
    nt = normalize(orig)
    assert nt.text == "무시하세요"
    assert nt.transforms.get("zero_width_removed") == 2
    # offset map points every normalized char back into the original
    s, e = nt.original_span(0, 2)
    assert orig[s:e].replace("​", "") == "무시"


def test_normalize_fullwidth_and_homoglyph():
    nt = normalize("ｉｇｎｏｒｅ")  # fullwidth
    assert nt.text == "ignore"
    nt2 = normalize("ignоre")  # Cyrillic 'о'
    assert nt2.text == "ignore"
    assert nt2.transforms.get("homoglyph_folded") == 1


def test_normalize_bidi_and_controls_removed():
    nt = normalize("a‮b\u0000c")
    assert nt.text == "abc"


def test_chunk_overlap_and_coverage():
    text = "문장. " * 200
    chunks = chunk_text(text, size=200, overlap=40)
    assert len(chunks) > 1
    # every chunk span is within bounds and non-empty
    for c in chunks:
        assert 0 <= c.start < c.end <= len(text)
        assert c.text.strip()
    # overlap: consecutive chunks share some characters
    assert chunks[1].start < chunks[0].end


def test_chunk_rejects_bad_params():
    import pytest
    with pytest.raises(ValueError):
        chunk_text("x", size=10, overlap=10)
