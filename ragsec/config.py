"""Runtime configuration (environment / .env) and VRAM execution profiles."""
from __future__ import annotations

from enum import StrEnum
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .netguard import OllamaConnection, validate_loopback_url


class LLMBackend(StrEnum):
    OLLAMA = "ollama"
    MOCK = "mock"  # deterministic offline backend for tests/UI demos; never research data


class VramProfileName(StrEnum):
    VRAM_4GB = "vram_4gb"
    VRAM_6GB = "vram_6gb"
    VRAM_8GB_PLUS = "vram_8gb_plus"


class ModelBudget(BaseModel):
    num_ctx: int
    num_predict: int


class VramProfile(BaseModel):
    """Conservative scheduling profile. Values are planning assumptions, not measurements.

    `coresident` lists model groups allowed to stay loaded together. A model absent from
    every group the current residents belong to forces the others to be unloaded first.
    """

    name: VramProfileName
    coresident: list[list[str]]
    exclusive: list[str]  # models that must run alone (others unloaded first)
    generation: dict[str, ModelBudget]
    guard_num_ctx: int
    embed_batch_size: int
    keep_alive: str
    # ASSUMPTION (verify with /api/ps size_vram == 0): Ollama option num_gpu=0 keeps a model on CPU.
    embed_on_cpu: bool = False


def _profiles(embed: str, guard: str) -> dict[VramProfileName, VramProfile]:
    small = "exaone3.5:2.4b"
    large = "exaone3.5:7.8b"
    qwen = "qwen3:4b"
    return {
        VramProfileName.VRAM_4GB: VramProfile(
            name=VramProfileName.VRAM_4GB,
            coresident=[],  # one model at a time
            exclusive=[small, large, qwen, embed, guard],
            generation={small: ModelBudget(num_ctx=4096, num_predict=384),
                        large: ModelBudget(num_ctx=2048, num_predict=320),  # heavy CPU offload expected
                        qwen: ModelBudget(num_ctx=4096, num_predict=384)},
            guard_num_ctx=2048, embed_batch_size=8, keep_alive="2m", embed_on_cpu=True),
        VramProfileName.VRAM_6GB: VramProfile(
            name=VramProfileName.VRAM_6GB,
            coresident=[[small, guard], [qwen, guard]],
            exclusive=[large],
            generation={small: ModelBudget(num_ctx=4096, num_predict=512),
                        large: ModelBudget(num_ctx=4096, num_predict=384),  # partial CPU offload likely
                        qwen: ModelBudget(num_ctx=4096, num_predict=512)},
            guard_num_ctx=4096, embed_batch_size=16, keep_alive="5m", embed_on_cpu=True),
        VramProfileName.VRAM_8GB_PLUS: VramProfile(
            name=VramProfileName.VRAM_8GB_PLUS,
            coresident=[[small, guard, embed], [qwen, guard, embed], [large, guard]],
            exclusive=[],
            generation={small: ModelBudget(num_ctx=8192, num_predict=512),
                        large: ModelBudget(num_ctx=4096, num_predict=512),
                        qwen: ModelBudget(num_ctx=8192, num_predict=512)},
            guard_num_ctx=4096, embed_batch_size=32, keep_alive="10m"),
    }


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RAGSEC_", env_file=".env", extra="ignore")

    llm_backend: LLMBackend = LLMBackend.OLLAMA
    # Loopback-only; validated at construction so an invalid value PREVENTS startup (not a warning).
    # This is a trusted server-side setting; UI/documents/retrieved content/API bodies must never set it.
    ollama_url: str = "http://127.0.0.1:11434"
    vram_profile: VramProfileName = VramProfileName.VRAM_6GB

    default_target_model: str = "exaone3.5:2.4b"
    allowed_target_models: list[str] = ["exaone3.5:2.4b", "exaone3.5:7.8b", "qwen3:4b"]
    embedding_model: str = "bge-m3"
    guard_model: str = "llama-guard3:1b"

    data_dir: Path = Path("var")
    policy_dir: Path = Path("policies")
    dataset_root: Path = Path("data")
    # Tenant registry = the approved access policy's tenant list (bank_a, bank_b by default; add tenants by
    # editing the validated access_policy.yaml) MINUS any tenant named here. A disabled tenant is rejected at
    # ingestion/submission even though it still exists in the policy. See tenants.py.
    disabled_tenants: list[str] = []

    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_key: str = Field(default="change-me-local-only", min_length=8)
    # Authentication boundary. "legacy" = the single shared api_key authorizes everything (the original setup,
    # default for backward compatibility). "multiuser" = per-principal API tokens (policies/principals.json)
    # map to an identity/tenant/roles; the shared key is then accepted ONLY if allow_legacy_key is True
    # (disabled by default in the multi-user profile).
    auth_mode: str = "legacy"                               # "legacy" | "multiuser"
    principals_file: Path = Path("policies/principals.json")
    allow_legacy_key: bool = False                          # multiuser only; legacy mode always uses api_key

    # Upload limits (enforced in every guard mode)

    # Upload limits (enforced in every guard mode)
    max_upload_bytes: int = 10 * 1024 * 1024
    max_pdf_pages: int = 200
    max_extracted_chars: int = 500_000
    min_chars_per_page_for_text_pdf: int = 20

    chunk_size: int = 800
    chunk_overlap: int = 120
    # Prefer Korean legal article/section boundaries when chunking legislation/internal_policy documents
    # (heuristic; see legalseg.py). Off by default so existing datasets chunk identically.
    article_aware_chunking: bool = False
    retrieval_top_k: int = 4
    max_distance: float = 0.75  # cosine distance cut-off; chunks farther are treated as not retrieved

    seed: int = 20261027
    temperature: float = 0.0

    # Citation handling: "annotate" reports invalid/uncited citations but keeps the answer; "block" refuses an
    # answer that cites evidence not supplied to it (conservative). Never equates valid labels with correctness.
    citation_policy: str = "annotate"  # "annotate" | "block"

    # PROPOSED (2026-11-03) generated-artifact re-validation (research addition B). When True, the transformed
    # final response and the (not-yet-executed) action payloads are re-measured against the active DISCLOSURE
    # authorization (case-specific when present, else role policy) BEFORE execution; a surviving unauthorized
    # disclosure blocks the response and cancels pending actions (fail-closed, bounded single re-check — no loop).
    # Off by default so existing behaviour/metrics are unchanged; enable per experiment condition to study it.
    revalidate_transformed_output: bool = False

    request_deadline_s: float = 180.0
    llm_call_timeout_s: float = 150.0
    guard_call_timeout_s: float = 30.0
    plugin_timeout_s: float = 35.0
    max_retries: int = 2
    max_concurrent_requests: int = 1

    raw_artifact_store: bool = False  # opt-in only
    raw_artifact_retention_days: int = 14

    gemini_enabled: bool = False
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.5-flash"  # ASSUMPTION: verify current model id before use

    @field_validator("ollama_url")
    @classmethod
    def _validate_ollama_url(cls, v: str) -> str:
        # Raises UrlPolicyError (a ValueError) on violation -> Settings construction fails -> no startup.
        return validate_loopback_url(v).base_url

    def ollama_connection(self) -> OllamaConnection:
        """Immutable, validated connection target. Re-checked immediately before each request."""
        return validate_loopback_url(self.ollama_url)

    def runtime_model_allowlist(self) -> set[str]:
        """Model names the runtime inference client may address (targets + embedding + guard)."""
        return {*self.allowed_target_models, self.embedding_model, self.guard_model}

    def profile(self) -> VramProfile:
        return _profiles(self.embedding_model, self.guard_model)[self.vram_profile]

    @property
    def index_dir(self) -> Path:
        return self.data_dir / "chroma"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw_artifacts"

    @property
    def sink_dir(self) -> Path:
        return self.data_dir / "mock_sink"

    @property
    def lock_dir(self) -> Path:
        return self.data_dir / "locks"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.index_dir, self.log_dir, self.upload_dir, self.sink_dir, self.lock_dir):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
