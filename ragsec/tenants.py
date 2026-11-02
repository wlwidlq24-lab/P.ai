"""Configurable tenant registry.

The set of *known* tenants is the approved access policy's tenant list (authoritative, validated on load;
defaults bank_a/bank_b; add more by editing access_policy.yaml). A tenant can additionally be *disabled* via
Settings.disabled_tenants (server-side config) without removing it from the policy. The registry rejects both
unknown and disabled tenants. Tenant scope for a request is derived from the authenticated principal / the
authenticated user's directory record — never trusted from a request body.
"""
from __future__ import annotations

from dataclasses import dataclass

from .errors import DocumentError
from .policy import PolicyBundle


class TenantError(DocumentError):
    code = "TENANT_INVALID"
    http_status = 422


@dataclass(frozen=True)
class TenantRegistry:
    known: frozenset[str]
    disabled: frozenset[str]

    @classmethod
    def from_policies(cls, policies: PolicyBundle, disabled: list[str] | None = None) -> "TenantRegistry":
        return cls(known=frozenset(policies.access.tenants), disabled=frozenset(disabled or ()))

    @property
    def enabled(self) -> frozenset[str]:
        return self.known - self.disabled

    def is_enabled(self, tenant: str) -> bool:
        return tenant in self.known and tenant not in self.disabled

    def assert_enabled(self, tenant: str) -> None:
        if tenant not in self.known:
            raise TenantError(f"unknown tenant {tenant!r}", detail={"known": sorted(self.known)})
        if tenant in self.disabled:
            raise TenantError(f"tenant {tenant!r} is disabled", detail={"disabled": sorted(self.disabled)})
