from __future__ import annotations

import pytest

from ragsec.config import Settings
from ragsec.llm import MockLLMClient
from ragsec.services import build_services


@pytest.fixture
def settings(tmp_path):
    return Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies",
                    dataset_root="data", api_key="test-key-123456", vram_profile="vram_6gb")


@pytest.fixture
def mock_client():
    return MockLLMClient(available={"exaone3.5:2.4b", "exaone3.5:7.8b", "qwen3:4b", "bge-m3", "llama-guard3:1b"})


@pytest.fixture
def services(settings, mock_client):
    svc = build_services(settings, client=mock_client)
    yield svc
