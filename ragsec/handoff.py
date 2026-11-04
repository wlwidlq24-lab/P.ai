"""Handoff / evidence-disclosure CORE domain + the CreateHandoff and OpenEvidence use cases.

Context map (shared vocabulary):
  * requester  — the authenticated principal who generated the handoff and may read the source.
  * recipient  — the party the handoff is addressed to (e.g., a successor) — a disclosure SCOPE, not an identity.
  * viewer     — the authenticated principal who clicks an evidence link NOW (re-checked every request).
  * purpose/channel — the approved disclosure context of the handoff.
  * EvidenceRef — an immutable, server-assigned pointer to one source passage, pinned to its version/location.
  * grant       — the recipient/viewer's CURRENT entitlement to this handoff, held in trusted server state.

Policy decisions here are independent of HTTP, PDF parsing, vector storage, and the model SDK. The use cases
depend only on small ports (a chunk loader and a viewer-authorization function) implemented by existing adapters.
Evaluation-oracle labels never enter this module.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, Field

from .evaluation import mask_for_log
from .timeutil import utc_now

EVIDENCE_POLICIES = ("original_only", "approved_excerpt")
EXCERPT_CHARS = 240
ORIGINAL_CHARS = 1200


class EvidenceOutcome(StrEnum):
    ORIGINAL = "original"       # viewer may read the source passage (PII still masked defensively)
    EXCERPT = "excerpt"         # viewer may receive a policy-permitted excerpt only
    RESTRICTED = "restricted"   # nothing protected is exposed (no title / page / preview / bytes)


class EvidenceRef(BaseModel):
    """Immutable, server-assigned reference to one piece of evidence, pinned to a source version and location."""
    model_config = {"frozen": True}
    evidence_id: str
    label: str
    document_id: str
    document_version: int
    chunk_id: str
    index_version: str
    page: int | None = None
    char_start: int | None = None
    char_end: int | None = None
    title: str = ""             # source_name (authorized title)


class HandoverRecord(BaseModel):
    """Server-controlled handoff: its recipient/purpose/channel scope + the evidence it may cite. Opaque ids."""
    handover_id: str
    requester: str
    recipient: str | None = None
    purpose: str | None = None
    channel: str | None = None
    evidence_policy: str = "approved_excerpt"
    index_version: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    evidence: dict[str, EvidenceRef] = Field(default_factory=dict)


class EvidenceOpenResult(BaseModel):
    """Viewer-visible result of opening an evidence link. A RESTRICTED result carries NO protected metadata."""
    outcome: EvidenceOutcome
    handover_id: str
    evidence_id: str
    label: str | None = None
    title: str | None = None
    page: int | None = None
    document_version: int | None = None
    excerpt: str | None = None
    reason: str = ""


# --------------------------------------------------------------------------- pure decision (shared by both configs)
def decide_evidence_access(*, granted: bool, can_read_original: bool, evidence_policy: str) -> EvidenceOutcome:
    """Intersection of the viewer's CURRENT grant to the handoff and their entitlement to the original source:
      original_only    -> ORIGINAL when the viewer may read the source, else RESTRICTED.
      approved_excerpt -> ORIGINAL when permitted, else a policy-permitted EXCERPT.
    No grant => RESTRICTED (nothing is exposed). Pure; no I/O; reused by OpenEvidence for both configurations."""
    if not granted:
        return EvidenceOutcome.RESTRICTED
    if can_read_original:
        return EvidenceOutcome.ORIGINAL
    if evidence_policy == "approved_excerpt":
        return EvidenceOutcome.EXCERPT
    return EvidenceOutcome.RESTRICTED


# --------------------------------------------------------------------------- stores (trusted server state)
class HandoverStore:
    """Server-controlled handoff records (opaque ids). Not reachable or mutable by the client."""
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _p(self, hid: str) -> Path:
        return self.dir / f"{hid}.json"

    def create(self, rec: HandoverRecord) -> None:
        self._p(rec.handover_id).write_text(rec.model_dump_json(indent=2), encoding="utf-8", newline="")

    def get(self, hid: str) -> HandoverRecord | None:
        p = self._p(hid)
        if not (hid and p.exists()):
            return None
        return HandoverRecord.model_validate_json(p.read_text(encoding="utf-8"))


class GrantStore:
    """Trusted server-side recipient/viewer grants, resolved on EACH open. Revocation flips state HERE; the
    handoff record, evidence record, and URL stay unchanged. Only a protected mechanism (an admin path or a test
    fixture) manipulates this — never the client/request body."""
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _p(self, hid: str, viewer: str) -> Path:
        return self.dir / f"{hid}__{viewer}.json"

    def grant(self, hid: str, viewer: str, *, valid_from: datetime | None = None, valid_to: datetime | None = None) -> None:
        self._p(hid, viewer).write_text(json.dumps({
            "valid_from": valid_from.isoformat() if valid_from else None,
            "valid_to": valid_to.isoformat() if valid_to else None, "revoked": False}),
            encoding="utf-8", newline="")

    def revoke(self, hid: str, viewer: str) -> None:
        p = self._p(hid, viewer)
        d = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        d["revoked"] = True
        p.write_text(json.dumps(d), encoding="utf-8", newline="")

    def is_granted(self, hid: str, viewer: str, as_of: datetime) -> bool:
        p = self._p(hid, viewer)
        if not p.exists():
            return False
        d = json.loads(p.read_text(encoding="utf-8"))
        if d.get("revoked"):
            return False
        if d.get("valid_from") and datetime.fromisoformat(d["valid_from"]) > as_of:
            return False
        if d.get("valid_to") and datetime.fromisoformat(d["valid_to"]) <= as_of:
            return False
        return True


# --------------------------------------------------------------------------- use cases
def create_handover(store: HandoverStore, *, requester: str, recipient: str | None, purpose: str | None,
                    channel: str | None, index_version: str | None, citations: list[Any],
                    evidence_policy: str = "approved_excerpt") -> tuple[HandoverRecord, list[dict]]:
    """CreateHandoff: mint opaque evidence ids ONLY for citations that resolved to evidence (valid citations),
    preserving each source's version and location, and return a handoff with its evidence links."""
    if evidence_policy not in EVIDENCE_POLICIES:
        evidence_policy = "approved_excerpt"
    hid = "hv_" + secrets.token_hex(8)
    evidence: dict[str, EvidenceRef] = {}
    links: list[dict] = []
    for c in citations:
        eid = "ev_" + secrets.token_hex(8)
        evidence[eid] = EvidenceRef(
            evidence_id=eid, label=c.label, document_id=c.document_id, document_version=c.document_version,
            chunk_id=c.chunk_id, index_version=index_version or "", page=c.page, char_start=c.char_start,
            char_end=c.char_end, title=c.display_title)
        # Links are RECIPIENT-FACING and carry NO source metadata (no title/page/document id): only an opaque,
        # handover-scoped id + url. Title/page live in the server-side EvidenceRef and are disclosed (if at all)
        # by the authorized OpenEvidence per the recipient-facing policy.
        links.append({"label": c.label, "evidence_id": eid, "url": f"/handover/{hid}/evidence/{eid}"})
    rec = HandoverRecord(handover_id=hid, requester=requester, recipient=recipient, purpose=purpose,
                         channel=channel, evidence_policy=evidence_policy, index_version=index_version,
                         evidence=evidence)
    store.create(rec)
    return rec, links


def open_evidence(*, handover: HandoverRecord, evidence_id: str, granted: bool,
                  load_chunk: Callable[[str, str], Any | None],
                  authorize_original: Callable[[Any], bool]) -> EvidenceOpenResult:
    """OpenEvidence: resolve ONLY an id issued for this handoff, enforce (grant ∩ source entitlement), and return
    the permitted view. A forged/cross-handoff id, a missing source, or a denial yields RESTRICTED with no leak."""
    ref = handover.evidence.get(evidence_id)
    if ref is None:  # an id not issued for THIS handoff: do not confirm existence, do not leak
        return EvidenceOpenResult(outcome=EvidenceOutcome.RESTRICTED, handover_id=handover.handover_id,
                                  evidence_id=evidence_id, reason="unknown_evidence")
    chunk = load_chunk(ref.index_version, ref.chunk_id)
    if chunk is None or chunk.metadata.document_version != ref.document_version:
        return EvidenceOpenResult(outcome=EvidenceOutcome.RESTRICTED, handover_id=handover.handover_id,
                                  evidence_id=evidence_id, reason="evidence_unavailable")
    can_read_original = granted and authorize_original(chunk)
    outcome = decide_evidence_access(granted=granted, can_read_original=can_read_original,
                                     evidence_policy=handover.evidence_policy)
    if outcome == EvidenceOutcome.RESTRICTED:
        return EvidenceOpenResult(outcome=outcome, handover_id=handover.handover_id, evidence_id=evidence_id,
                                  reason="not_granted" if not granted else "no_original_access")
    # RECIPIENT-FACING metadata policy, applied BEFORE serializing. Requester-side provenance (source page and
    # document version) is a source-LOCATION detail disclosed only to a viewer entitled to the original source;
    # an excerpt-only recipient receives the cited title + the permitted excerpt, never the source page/version.
    original = outcome == EvidenceOutcome.ORIGINAL
    limit = ORIGINAL_CHARS if original else EXCERPT_CHARS
    excerpt = mask_for_log(chunk.text, None, limit)  # PII-masked; raw protected bytes never cross the boundary
    return EvidenceOpenResult(outcome=outcome, handover_id=handover.handover_id, evidence_id=evidence_id,
                              label=ref.label, title=ref.title, page=(ref.page if original else None),
                              document_version=(ref.document_version if original else None),
                              excerpt=excerpt, reason=outcome.value)
