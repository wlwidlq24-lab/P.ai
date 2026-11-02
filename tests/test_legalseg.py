"""Article-aware Korean legal segmentation (ragsec/legalseg.py). Fixtures are SYNTHETIC, not real law."""
from __future__ import annotations

from ragsec.legalseg import segment_document
from ragsec.schemas import SegmentStrategy

# Synthetic legal-style fixture (NOT actual legislation).
FIXTURE = """개인정보 보호 지침 (합성 예시)

제1장 총칙

제1조(목적) 이 지침은 합성 데이터 처리에 관한 사항을 규정함을 목적으로 한다.

제2조(정의) 이 지침에서 사용하는 용어의 뜻은 다음과 같다.

제2장 개인정보의 처리

제15조(개인정보의 수집·이용) 처리자는 다음 각 호의 경우에 개인정보를 수집할 수 있다.

제15조의2(가명정보의 처리) 처리자는 통계작성 목적으로 가명정보를 처리할 수 있다.

제16조(개인정보의 파기) 처리자는 보유기간이 지난 개인정보를 지체 없이 파기하여야 한다.
"""


def test_article_aware_recognizes_articles_and_sections():
    chunks, fb = segment_document(FIXTURE, size=800, overlap=120, article_aware=True)
    assert fb is None  # article-aware actually used
    labels = [c.article_label for c in chunks if c.article_label]
    assert "제15조" in labels and "제15조의2" in labels and "제16조" in labels
    art16 = next(c for c in chunks if c.article_label == "제16조")
    assert art16.section_label == "제2장"            # parent chapter tracked
    assert art16.strategy == SegmentStrategy.ARTICLE_AWARE
    art15 = next(c for c in chunks if c.article_label == "제15조")
    assert art15.article_title and "수집" in art15.article_title
    # source order preserved
    starts = [c.start for c in chunks]
    assert starts == sorted(starts)


def test_oversized_article_splits_but_keeps_identity():
    big = "제10조(긴 조문) " + ("가나다라마바사 " * 400)
    text = big + "\n\n제11조(다음) 짧은 조문.\n"
    chunks, fb = segment_document(text, size=400, overlap=40, article_aware=True)
    parts = [c for c in chunks if c.article_label == "제10조"]
    assert len(parts) > 1  # split into multiple parts
    assert all(c.strategy == SegmentStrategy.ARTICLE_SPLIT for c in parts)
    # offsets are contiguous/within the document and map back to real text
    for c in parts:
        assert text[c.start:c.end] == c.text


def test_fallback_when_no_article_markers():
    plain = "이것은 일반 업무 문서입니다. 조문 표시가 없습니다. " * 20
    chunks, fb = segment_document(plain, size=300, overlap=40, article_aware=True)
    assert fb is not None and "too_few_article_markers" in fb
    assert all(c.strategy == SegmentStrategy.GENERIC for c in chunks)


def test_disabled_is_generic_without_reason():
    chunks, fb = segment_document(FIXTURE, size=300, overlap=40, article_aware=False)
    assert fb is None
    assert all(c.strategy == SegmentStrategy.GENERIC and c.fallback_reason is None for c in chunks)


def test_offsets_round_trip_against_original_text():
    chunks, _ = segment_document(FIXTURE, size=800, overlap=120, article_aware=True)
    for c in chunks:
        assert FIXTURE[c.start:c.end] == c.text


def test_single_article_document_with_min_one():
    text = "제1조(목적) 이 지침의 목적을 규정한다.\n\n부칙 생략."
    chunks, fb = segment_document(text, size=800, overlap=120, article_aware=True, min_articles=1)
    assert fb is None and any(c.article_label == "제1조" for c in chunks)


def test_repeated_running_headers_do_not_break_articles():
    hdr = "개인정보 보호 지침 (머리말)\n"
    text = hdr + "제1조(목적) 목적.\n\n" + hdr + "제2조(정의) 정의.\n\n" + hdr + "제3조(적용) 적용.\n"
    chunks, fb = segment_document(text, size=800, overlap=120, article_aware=True)
    labels = {c.article_label for c in chunks if c.article_label}
    assert {"제1조", "제2조", "제3조"} <= labels


def test_malformed_extraction_falls_back_to_generic():
    text = "qwure!! \x0c garbled    no article markers here " * 10
    chunks, fb = segment_document(text, size=300, overlap=40, article_aware=True)
    assert fb is not None
    assert all(c.strategy == SegmentStrategy.GENERIC for c in chunks)
