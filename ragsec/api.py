"""FastAPI application. Run with ONE worker:  uv run uvicorn ragsec.api:app --host 127.0.0.1 --port 8000"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, File, Form, Header, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import ValidationError

from .auth import Principal, PrincipalStore, authenticate
from .config import get_settings
from .errors import (
    AuthenticationError, AuthorizationDeniedError, FileTooLargeError, JobNotFoundError, MetadataValidationError,
    RagSecError, UnknownUserError,
)
from .experiments import load_dataset, resolve_dataset_dir
from .handoff import EvidenceOpenResult, create_handover, open_evidence
from .ingestion import IngestItem
from .parsing import parse_document
from .schemas import DocumentMetadataIn, ExperimentManifest, QueryRequest, QueryResponse
from .services import Services, build_services
from .store import is_authorized
from .tenants import TenantRegistry
from .timeutil import utc_now

log = logging.getLogger(__name__)

# Map a QueryResponse.error_code to an HTTP status for the SYNCHRONOUS /query path. A handled failure still
# returns the structured QueryResponse body; only the status line changes. Unknown codes -> 500.
_HTTP_STATUS_FOR = {
    "DEADLINE_EXCEEDED": 504, "MODEL_TIMEOUT": 504,
    "MODEL_UNAVAILABLE": 503, "MODEL_NOT_FOUND": 503, "RESOURCE_EXHAUSTED": 503,
    "AUTHZ_FILTER_MISSING": 403, "NO_ACTIVE_INDEX": 409,
    "INTERNAL_ERROR": 500, "MODEL_ERROR": 502, "MALFORMED_MODEL_RESPONSE": 502,
}


# Module-level dependencies so string annotations (from __future__ import annotations) resolve to these
# names in module globals, not to locals of create_app (which FastAPI/get_type_hints cannot see).
def svc_dep(request: Request) -> Services:
    return request.app.state.svc


def _principal_store(request: Request) -> PrincipalStore | None:
    return getattr(request.app.state, "principal_store", None)


def principal_dep(request: Request, x_api_key: Annotated[str | None, Header()] = None) -> Principal:
    s = request.app.state.svc.settings
    p = authenticate(s, _principal_store(request), x_api_key)
    if p is None:
        raise AuthenticationError("missing or invalid API credential")
    request.state.principal = p
    return p


def admin_dep(principal: Annotated[Principal, Depends(principal_dep)]) -> Principal:
    if not principal.is_admin and "admin" not in principal.roles:
        raise AuthorizationDeniedError("administrative capability required for this endpoint")
    return principal


def _log_evidence(svc: Services, handover_id: str, evidence_id: str, viewer: str, outcome: str, reason: str,
                  policy_versions: dict) -> None:
    """Safe evidence-access log (reuses the safe-logging discipline): records policy version, outcome and reason
    only — NEVER a title, excerpt, preview, or document bytes."""
    try:
        p = svc.settings.log_dir / "evidence_access.jsonl"
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"at": utc_now().isoformat(), "handover_id": handover_id, "evidence_id": evidence_id,
                                "viewer": viewer, "outcome": outcome, "reason": reason,
                                "policy_versions": policy_versions}, ensure_ascii=False) + "\n")
    except Exception:
        log.exception("evidence access log failed")


Svc = Annotated[Services, Depends(svc_dep)]
Prin = Annotated[Principal, Depends(principal_dep)]
AdminPrin = Annotated[Principal, Depends(admin_dep)]
Auth = Depends(principal_dep)
AdminAuth = Depends(admin_dep)


def create_app(services: Services | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        svc = services or build_services(get_settings())
        app.state.svc = svc
        app.state.principal_store = (PrincipalStore.load(svc.settings.principals_file)
                                     if svc.settings.auth_mode == "multiuser" else None)
        try:
            svc.policies()
        except RagSecError as e:
            log.error("policy load failed at startup: %s %s", e.message, e.detail)
        # NOTE: the API server does NOT probe Ollama diagnostics at startup or in request handlers (diagnostics
        # are administrative and separated). Model provenance comes from the pre-run manifest / `ragsec doctor`.
        yield
        await svc.aclose()

    app = FastAPI(title="ragsec — Korean financial RAG IPI testbed", version="0.1.0", lifespan=lifespan)

    @app.exception_handler(RagSecError)
    async def _ragsec_error(_: Request, exc: RagSecError):
        return JSONResponse(status_code=exc.http_status, content={"code": exc.code, "message": exc.message,
                                                                  "detail": exc.detail})

    @app.get("/health")
    async def health(svc: Svc) -> dict[str, Any]:
        # No Ollama diagnostic call here (those are administrative). Reports only local config/policy/index.
        tenants_enabled: list[str] = []
        try:
            pols = svc.policies()
            pv = pols.versions
            policy_ok = True
            tenants_enabled = sorted(TenantRegistry.from_policies(pols, svc.settings.disabled_tenants).enabled)
        except RagSecError as e:
            pv, policy_ok = {"error": e.message}, False
        return {"status": "ok" if policy_ok else "degraded", "backend": svc.settings.llm_backend.value,
                "ollama_url": svc.settings.ollama_url,
                "active_index": await asyncio.to_thread(svc.repo.active_version), "policy_versions": pv,
                "vram_profile": svc.settings.vram_profile.value,
                # Safe startup diagnostics: the active auth mode is visible (never a secret/credential).
                "auth_mode": svc.settings.auth_mode, "tenants_enabled": tenants_enabled,
                "note": "Ollama reachability/version are checked administratively (ragsec doctor), not here."}

    @app.get("/models/status", dependencies=[Auth])
    async def models_status(svc: Svc) -> dict[str, Any]:
        # Returns the cached provenance snapshot (from the last admin probe / pre-run manifest). Does NOT issue
        # live diagnostics from this request handler; residency is tracked by the scheduler, not /api/ps.
        snap = svc.model_snapshot()
        required = [*svc.settings.allowed_target_models, svc.settings.embedding_model, svc.settings.guard_model]
        return {"profile": svc.settings.profile().model_dump(), "ollama_version": svc.ollama_version(),
                "snapshot_present": bool(snap),
                "models": {n: {"available": n in snap, **(snap.get(n, {}))} for n in required},
                "scheduler_tracked_resident": sorted(svc.scheduler._resident),
                "scheduler_switches": svc.scheduler.switch_count,
                "note": "Live residency/VRAM is not queried at runtime. Run `ragsec doctor` for live diagnostics."}

    @app.post("/documents")
    async def upload_document(svc: Svc, principal: AdminPrin, file: UploadFile = File(...),
                              metadata: str = Form(...), auto_activate: bool = Form(True)) -> dict[str, Any]:
        s = svc.settings
        try:
            meta = DocumentMetadataIn.model_validate_json(metadata)
        except ValidationError as e:
            raise MetadataValidationError("invalid metadata", detail={"errors": json.loads(e.json(include_url=False))}) from e
        # Tenant scoping: a tenant-scoped admin may ingest documents only for its own tenant (request-body
        # tenant_id is never trusted as authorization — it is checked against the authenticated principal).
        if not principal.may_use_tenant(meta.tenant_id):
            raise AuthorizationDeniedError(f"principal may not ingest documents for tenant {meta.tenant_id!r}")
        buf = bytearray()
        while chunk := await file.read(1024 * 1024):
            buf.extend(chunk)
            if len(buf) > s.max_upload_bytes:
                raise FileTooLargeError(f"file exceeds {s.max_upload_bytes} bytes")
        parsed = await asyncio.to_thread(parse_document, bytes(buf), file.filename, max_bytes=s.max_upload_bytes,
                                         max_pages=s.max_pdf_pages, max_chars=s.max_extracted_chars,
                                         min_chars_per_page=s.min_chars_per_page_for_text_pdf)
        res = await svc.ingestor.ingest([IngestItem(meta=meta, parsed=parsed)], svc.policies(),
                                        auto_activate=auto_activate)
        return {"ingestion_run_id": res.ingestion_run_id, "index_version": res.index_version,
                "activated": res.activated, "documents": res.documents, "skipped_duplicates": res.skipped_duplicates,
                "validation_errors": res.validation_errors, "file_type": parsed.file_type,
                "safe_filename": parsed.safe_filename}

    @app.get("/index", dependencies=[Auth])
    async def index_registry(svc: Svc) -> dict[str, Any]:
        return await asyncio.to_thread(svc.repo.registry)

    @app.post("/index/activate/{version}")
    async def index_activate(version: str, svc: Svc, principal: AdminPrin) -> dict[str, Any]:
        # The index is a single shared store; activation is a GLOBAL switch affecting every tenant, so only a
        # global (not tenant-scoped) admin may perform it. (Per-tenant isolation is enforced at retrieval.)
        if principal.tenant_id is not None:
            raise AuthorizationDeniedError("index activation is a global operation; requires a global admin")
        rep = await asyncio.to_thread(svc.repo.validate, version, svc.settings.embedding_model)
        if rep.ok or (await asyncio.to_thread(svc.repo.registry))["versions"].get(version, {}).get("status") == "retired":
            await asyncio.to_thread(svc.repo.activate, version)
        return {"version": version, "validation_ok": rep.ok, "errors": rep.errors,
                "active": await asyncio.to_thread(svc.repo.active_version)}

    @app.post("/index/rollback")
    async def index_rollback(svc: Svc, principal: AdminPrin) -> dict[str, Any]:
        if principal.tenant_id is not None:
            raise AuthorizationDeniedError("index rollback is a global operation; requires a global admin")
        return {"active": await asyncio.to_thread(svc.repo.rollback)}

    @app.post("/policies/reload", dependencies=[AdminAuth])
    async def policies_reload(svc: Svc) -> dict[str, Any]:
        return {"policy_versions": svc.reload_policies().versions}

    @app.get("/users", dependencies=[Auth])
    async def users(svc: Svc) -> list[dict[str, Any]]:
        return [u.model_dump() for u in svc.policies().users.users]

    @app.get("/cases", dependencies=[Auth])
    async def cases(svc: Svc, dataset_dir: str = Query("synthetic/v1")) -> list[dict[str, Any]]:
        ds = await asyncio.to_thread(load_dataset, resolve_dataset_dir(svc.settings, dataset_dir))
        return [{"case_id": c.case_id, "case_type": c.case_type.value, "attack_family": c.attack_family,
                 "language": c.language, "unicode_transform": c.unicode_transform, "split": c.split,
                 "user_id": c.user_id, "subject_id": c.subject_id, "query": c.query} for c in ds.cases]

    @app.post("/query", response_model=QueryResponse)
    async def query(req: QueryRequest, svc: Svc, principal: Prin, response: Response) -> QueryResponse:
        # Reject a spoofed identity: a scoped principal may only act as its own mapped user_id (admins/legacy
        # may act as any). This ties the request's user_id to the authenticated principal.
        if not principal.can_act_as(req.user_id):
            raise AuthorizationDeniedError("principal may not act as this user_id")
        qr = await svc.rag.answer(req)
        # CreateHandoff use case: mint server-assigned evidence links for the answer's VALID citations only.
        # (D10 annotate is preserved: invalid_citations stay in the body with no link; the UI marks them
        #  unavailable. Link issuance is independent of the per-click authorization enforced at OpenEvidence.)
        if req.create_handover and qr.status == "ok" and qr.citations:
            # Pin the EXACT version used to retrieve/validate the cited chunks (from the answer), not a fresh read
            # of the active version — an index activation between retrieval and here must not repoint citations.
            index_version = qr.active_index_version or await asyncio.to_thread(svc.repo.active_version)
            rec, links = create_handover(
                svc.handovers, requester=req.user_id, recipient=req.recipient, purpose=req.purpose,
                channel=req.channel, index_version=index_version, citations=qr.citations,
                evidence_policy=req.evidence_policy)
            qr.handover_id = rec.handover_id
            qr.evidence_links = links
        # Synchronous API status semantics: a handled failure returns a non-2xx with the structured body intact.
        # (A content BLOCK is a successful, policy-correct response -> 200.)
        response.status_code = _HTTP_STATUS_FOR.get(qr.error_code, 200) if qr.status != "ok" else 200
        return qr

    @app.get("/handover/{handover_id}/evidence/{evidence_id}", response_model=EvidenceOpenResult)
    async def open_evidence_ep(handover_id: str, evidence_id: str, svc: Svc, principal: Prin, response: Response,
                               viewer: Annotated[str, Query()]) -> EvidenceOpenResult:
        """OpenEvidence use case: authenticate the viewer NOW, resolve handoff + current grant + pinned source
        from trusted state, and return only the permitted view. Never serves source bytes/public URLs; never
        caches a stale authorization. Returns RESTRICTED (no protected metadata) for any denial or unknown id."""
        if not principal.can_act_as(viewer):   # the viewer is the authenticated identity, not a client claim
            raise AuthorizationDeniedError("principal may not act as this viewer")
        response.headers["Cache-Control"] = "no-store"   # a shared/response cache must not bypass authorization
        rec = svc.handovers.get(handover_id)
        policies = svc.policies()
        as_of = utc_now()

        def _restricted(reason: str) -> EvidenceOpenResult:
            # Uniform denial shape — no title/page/preview/version — so existence is not leaked via the response.
            _log_evidence(svc, handover_id, evidence_id, viewer, "restricted", reason, policies.versions)
            return EvidenceOpenResult(outcome="restricted", handover_id=handover_id, evidence_id=evidence_id,
                                      reason=reason)
        if rec is None:
            return _restricted("unknown_handover")
        try:
            viewer_user = policies.resolve_user(viewer)
            role_policy = policies.role_policy(viewer_user.role)
        except UnknownUserError:
            return _restricted("unknown_viewer")
        granted = svc.grants.is_granted(handover_id, viewer, as_of)
        result = open_evidence(
            handover=rec, evidence_id=evidence_id, granted=granted,
            load_chunk=lambda ver, cid: svc.repo.get_chunk(ver, cid),
            authorize_original=lambda ch: is_authorized(ch.metadata, viewer_user, role_policy, as_of))
        _log_evidence(svc, handover_id, evidence_id, viewer, result.outcome.value, result.reason, policies.versions)
        return result

    @app.post("/handover/{handover_id}/grant", dependencies=[AdminAuth])
    async def grant_evidence(handover_id: str, svc: Svc, viewer: Annotated[str, Query()],
                             action: Annotated[str, Query()] = "grant") -> dict[str, Any]:
        """PROTECTED (admin) grant control — a permission-changing mechanism kept OUT of the ordinary user screen.
        Grants or revokes a viewer's recipient entitlement in trusted state; the handoff record/URL stay unchanged."""
        if action == "revoke":
            svc.grants.revoke(handover_id, viewer)
        else:
            svc.grants.grant(handover_id, viewer)
        return {"handover_id": handover_id, "viewer": viewer, "action": action}

    @app.post("/experiments/run", dependencies=[AdminAuth])
    async def run_experiment(m: ExperimentManifest, svc: Svc) -> dict[str, Any]:
        resolve_dataset_dir(svc.settings, m.dataset_dir)  # validate before scheduling
        job = svc.jobs.submit(m)
        return job.to_dict()

    @app.get("/experiments/{run_or_experiment_id}", dependencies=[Auth])
    async def experiment_status(run_or_experiment_id: str, svc: Svc) -> dict[str, Any]:
        job = svc.jobs.get(run_or_experiment_id)
        out = job.to_dict()
        mp = job.dir / "metrics.json"
        if mp.exists():
            out["metrics"] = json.loads(mp.read_text(encoding="utf-8"))
        return out

    @app.post("/experiments/{run_id}/cancel", dependencies=[AdminAuth])
    async def experiment_cancel(run_id: str, svc: Svc) -> dict[str, Any]:
        return svc.jobs.cancel(run_id).to_dict()

    @app.get("/experiments/{run_id}/log", dependencies=[AdminAuth])
    async def experiment_log(run_id: str, svc: Svc) -> FileResponse:
        job = svc.jobs.get(run_id)
        p = job.dir / "requests.jsonl"
        if not p.exists():
            raise JobNotFoundError("log not written yet")
        return FileResponse(p, media_type="application/x-ndjson", filename=f"{job.run_id}_requests.jsonl")

    @app.get("/experiments/{run_id}/metrics", dependencies=[AdminAuth])
    async def experiment_metrics(run_id: str, svc: Svc, format: str = Query("json", pattern="^(json|csv)$")):
        job = svc.jobs.get(run_id)
        p = job.dir / f"metrics.{format}"
        if not p.exists():
            raise JobNotFoundError("metrics not available yet")
        return FileResponse(p, media_type="text/csv" if format == "csv" else "application/json",
                            filename=f"{job.run_id}_metrics.{format}")

    return app


app = create_app()
