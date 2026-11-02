"""Authentication boundary: principals, a hashed-token store, and token -> principal resolution.

Two modes (Settings.auth_mode):
  * "legacy"    — the single shared api_key authorizes everything (admin). Backward-compatible default.
  * "multiuser" — per-principal API tokens, each mapped server-side to an identity (user_id), a tenant scope
                  and roles, with an is_admin capability. The shared key is accepted ONLY when allow_legacy_key
                  is True (disabled by default), so a multi-user deployment is not silently bypassable.

Only SHA-256 token hashes are stored (never the plaintext token). A token is shown once at provisioning time.
Credentials are never logged. User management is CLI-only (there is no HTTP route that mints or lists tokens).
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path

PRINCIPALS_SCHEMA = "principals/1.0"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    user_id: str | None            # dataset identity this principal acts as (None for a pure legacy admin)
    tenant_id: str | None          # None => all tenants (legacy/admin). Otherwise the only tenant it may touch.
    roles: frozenset[str] = frozenset()
    is_admin: bool = False
    legacy: bool = False

    def can_act_as(self, user_id: str) -> bool:
        """May this principal submit a /query as `user_id`? Admins/legacy may act as anyone; a scoped principal
        may act only as its own mapped user_id (blocks spoofed user_id in the request body)."""
        return self.is_admin or self.user_id == user_id

    def may_use_tenant(self, tenant_id: str) -> bool:
        return self.tenant_id is None or self.tenant_id == tenant_id


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    return "rsk_" + secrets.token_urlsafe(32)


@dataclass
class PrincipalStore:
    path: Path
    entries: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "PrincipalStore":
        p = Path(path)
        if not p.exists():
            return cls(path=p, entries=[])
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(path=p, entries=list(data.get("principals", [])))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"schema": PRINCIPALS_SCHEMA, "principals": self.entries},
                                  ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def resolve(self, token: str | None) -> Principal | None:
        if not token:
            return None
        h = hash_token(token)
        for e in self.entries:
            if e.get("disabled"):
                continue
            if secrets.compare_digest(str(e.get("token_sha256", "")), h):
                return Principal(principal_id=e["principal_id"], user_id=e.get("user_id"),
                                 tenant_id=e.get("tenant_id"), roles=frozenset(e.get("roles", [])),
                                 is_admin=bool(e.get("is_admin", False)))
        return None

    # --- provisioning (CLI only; never exposed over HTTP) ---
    def add(self, principal_id: str, *, user_id: str | None, tenant_id: str | None, roles: list[str],
            is_admin: bool) -> str:
        if any(e["principal_id"] == principal_id for e in self.entries):
            raise ValueError(f"principal_id {principal_id!r} already exists")
        token = generate_token()
        self.entries.append({"principal_id": principal_id, "user_id": user_id, "tenant_id": tenant_id,
                             "roles": sorted(set(roles)), "is_admin": bool(is_admin),
                             "token_sha256": hash_token(token), "disabled": False})
        self.save()
        return token  # shown ONCE to the operator; only its hash is persisted

    def revoke(self, principal_id: str) -> bool:
        for e in self.entries:
            if e["principal_id"] == principal_id:
                e["disabled"] = True
                self.save()
                return True
        return False

    def public_list(self) -> list[dict]:
        """Metadata only — never the token or its hash."""
        return [{k: e.get(k) for k in ("principal_id", "user_id", "tenant_id", "roles", "is_admin", "disabled")}
                for e in self.entries]


def authenticate(settings, store: PrincipalStore | None, token: str | None) -> Principal | None:
    """Resolve a bearer token to a Principal, or None (=> 401). See module docstring for mode semantics."""
    if not token:
        return None
    legacy_admin = Principal(principal_id="legacy", user_id=None, tenant_id=None, is_admin=True, legacy=True)
    if settings.auth_mode == "legacy":
        return legacy_admin if secrets.compare_digest(token, settings.api_key) else None
    # multiuser
    if store is not None:
        p = store.resolve(token)
        if p is not None:
            return p
    if settings.allow_legacy_key and secrets.compare_digest(token, settings.api_key):
        return legacy_admin
    return None
