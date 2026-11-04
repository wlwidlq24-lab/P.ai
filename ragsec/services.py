"""Process-wide service wiring (one instance per API/CLI process)."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .config import LLMBackend, Settings
from .errors import ModelError, RagSecError
from .experiments import JobManager
from .guards import ContextLeakPlugin, IpiRulePlugin, LlamaGuardPlugin, PiiRegexPlugin, ProvenancePlugin
from .guards.base import GuardPlugin
from .handoff import GrantStore, HandoverStore
from .ingestion import Ingestor
from .judge import GeminiJudge
from .llm import LLMClient, MockLLMClient, OllamaAdminClient, OllamaClient
from .logstore import JsonlWriter, RawArtifactStore
from .policy import PolicyBundle, load_active
from .rag import RagService
from .scheduler import ModelScheduler
from .schemas import ModelProvenance
from .sink import MockSink
from .store import ChromaRepository

log = logging.getLogger(__name__)


@dataclass
class Services:
    settings: Settings
    client: LLMClient
    scheduler: ModelScheduler
    repo: ChromaRepository
    plugins: dict[str, GuardPlugin]
    ingestor: Ingestor
    rag: RagService
    jobs: JobManager
    sink: MockSink
    handovers: HandoverStore | None = None   # evidence navigation: server-controlled handoff records
    grants: GrantStore | None = None         # trusted recipient/viewer grants (revocable)
    _policies: PolicyBundle | None = None
    _models: dict[str, ModelProvenance] = field(default_factory=dict)
    _ollama_version: str | None = None

    def policies(self) -> PolicyBundle:
        if self._policies is None:
            self._policies = load_active(self.settings.policy_dir)
        return self._policies

    def reload_policies(self) -> PolicyBundle:
        self._policies = load_active(self.settings.policy_dir)
        return self._policies

    def provenance(self, name: str) -> ModelProvenance:
        # Reads only the cached snapshot; never issues a diagnostic request (that is administrative).
        return self._models.get(name) or ModelProvenance(
            name=name, unavailable_reason="no admin probe snapshot (run `ragsec doctor` or an experiment)")

    def ollama_version(self) -> str | None:
        return self._ollama_version

    def make_admin_client(self):
        """Create a transient, loopback-validated ADMIN diagnostics client. Callers must aclose() it.

        Allowed only administratively (CLI doctor, experiment pre-run manifest). FastAPI/Streamlit/RAG must
        not call this. In mock mode the runtime mock doubles as the diagnostics source."""
        if self.settings.llm_backend == LLMBackend.MOCK:
            return self.client  # MockLLMClient implements version/tags/ps; do not aclose the shared client
        return OllamaAdminClient(self.settings.ollama_url)

    async def probe_models_admin(self) -> dict[str, ModelProvenance]:
        """One-time administrative probe (version + tags) to populate the provenance snapshot. Not for request
        handlers. Returns {} and records a reason if diagnostics are unreachable."""
        admin = self.make_admin_client()
        transient = admin is not self.client
        try:
            self._ollama_version = await admin.version()
            tags = await admin.tags()
        except (ModelError, RagSecError) as e:
            log.warning("admin model probe failed: %s", e)
            self._models = {}
            return {}
        finally:
            if transient:
                await admin.aclose()
        found: dict[str, ModelProvenance] = {}
        for t in tags:
            name = t.get("name") or t.get("model")
            d = t.get("details") or {}
            mp = ModelProvenance(name=name, digest=t.get("digest"), quantization=d.get("quantization_level"),
                                 parameter_size=d.get("parameter_size"))
            found[name] = mp
            if name.endswith(":latest"):
                found[name.removesuffix(":latest")] = mp
        self._models = found
        return found

    def model_snapshot(self) -> dict[str, dict]:
        return {k: v.model_dump() for k, v in self._models.items()}

    async def vram_snapshot_admin(self):
        """One-time administrative VRAM measurement via the admin client's /api/ps. Returns a VramSample."""
        from .schemas import VramSample
        admin = self.make_admin_client()
        transient = admin is not self.client
        try:
            ps = await admin.ps()
            return VramSample(ollama_size_vram_bytes={m.get("name", "?"): int(m.get("size_vram", 0)) for m in ps},
                              unavailable_reason=None if ps else "no models resident at probe time")
        except (ModelError, RagSecError) as e:
            return VramSample(unavailable_reason=f"admin ps failed: {getattr(e, 'code', type(e).__name__)}")
        finally:
            if transient:
                await admin.aclose()

    async def aclose(self) -> None:
        await self.client.aclose()


def build_services(settings: Settings, client: LLMClient | None = None) -> Services:
    settings.ensure_dirs()
    if client is None:
        if settings.llm_backend == LLMBackend.MOCK:
            client = MockLLMClient()
        else:
            client = OllamaClient(settings.ollama_url, allowed_models=settings.runtime_model_allowlist(),
                                  max_retries=settings.max_retries)
    prof = settings.profile()
    scheduler = ModelScheduler(client, prof, settings.lock_dir,
                               cpu_models={settings.embedding_model} if prof.embed_on_cpu else set())
    repo = ChromaRepository(settings.index_dir)
    guard = LlamaGuardPlugin(client, scheduler, settings.guard_model, prof.guard_num_ctx, prof.keep_alive,
                             settings.guard_call_timeout_s, settings.seed)
    plugins: dict[str, GuardPlugin] = {"pii_regex": PiiRegexPlugin(), "ipi_rules": IpiRulePlugin(),
                                       "provenance": ProvenancePlugin(), "llama_guard": guard,
                                       "context_leak": ContextLeakPlugin()}
    sink = MockSink(settings.sink_dir)
    raw = RawArtifactStore(settings.raw_dir, settings.raw_artifact_store, settings.raw_artifact_retention_days)
    raw.purge_expired()
    svc = Services(settings=settings, client=client, scheduler=scheduler, repo=repo, plugins=plugins,
                   ingestor=None, rag=None, jobs=None, sink=sink,  # type: ignore[arg-type]
                   handovers=HandoverStore(settings.data_dir / "handovers"),
                   grants=GrantStore(settings.data_dir / "grants"))
    svc.ingestor = Ingestor(settings, client, scheduler, repo, guard)
    judge = GeminiJudge(settings.gemini_api_key, settings.gemini_model, settings.gemini_enabled)
    svc.rag = RagService(settings, client, scheduler, repo, plugins, sink, raw, svc.policies, svc.provenance,
                         svc.ollama_version, JsonlWriter(settings.log_dir / "adhoc" / "requests.jsonl"), judge=judge)
    svc.jobs = JobManager(settings, svc.rag, svc.ingestor, scheduler, svc.policies, svc.provenance,
                          svc.ollama_version, admin_probe=svc.probe_models_admin, vram_probe=svc.vram_snapshot_admin)
    return svc
