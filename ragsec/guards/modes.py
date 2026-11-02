"""Exact plugin composition of each guard mode.

OFF disables *content guardrails only*. Authentication, pre-retrieval authorization filters, upload limits,
the local mock-sink boundary and evaluation-only leakage measurement stay active in every mode.

INGESTION-stage enforcement uses detection flags computed once at ingestion and is applied as a retrieval
filter (equivalent to never having indexed the quarantined chunk), so all modes share one index version and
comparisons stay paired.
"""
from __future__ import annotations

from ..schemas import GuardMode

MODE_PLUGINS: dict[GuardMode, tuple[str, ...]] = {
    GuardMode.OFF: (),
    GuardMode.REGEX_ONLY: ("pii_regex", "context_leak"),
    GuardMode.LLAMA_GUARD: ("llama_guard",),
    GuardMode.HYBRID: ("pii_regex", "ipi_rules", "provenance", "llama_guard", "context_leak"),
    # Ablations isolating the IPI-rule contribution
    GuardMode.HYBRID_NO_IPI: ("pii_regex", "provenance", "llama_guard", "context_leak"),
    GuardMode.IPI_ONLY: ("ipi_rules", "provenance"),
}

# Deterministic execution order within a stage (results are reported in this order).
PLUGIN_ORDER = ("pii_regex", "ipi_rules", "provenance", "llama_guard", "context_leak")


def plugins_for(mode: GuardMode) -> tuple[str, ...]:
    enabled = set(MODE_PLUGINS[mode])
    return tuple(p for p in PLUGIN_ORDER if p in enabled)
