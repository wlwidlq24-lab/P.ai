"""Loading, cross-validation and activation of versioned policy files.

Replacing legislation documents in the index does NOT change these executable policies. Policies change
only when the Legal role edits a versioned file, it validates, and `active.json` is switched.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from .errors import PolicyValidationError, UnknownUserError
from .schemas import AccessPolicy, GuardPolicy, RolePolicy, UserContext, UserDirectory
from .textproc import sha256_bytes

ACTIVE_FILE = "active.json"


@dataclass(frozen=True)
class PolicyBundle:
    access: AccessPolicy
    users: UserDirectory
    guard: GuardPolicy
    file_hashes: dict[str, str]

    @property
    def versions(self) -> dict[str, str]:
        return {
            "access_policy": f"{self.access.policy_id}@{self.access.policy_version}",
            "user_directory": self.users.directory_version,
            "guard_policy": self.guard.guard_policy_version,
            **{f"sha256:{k}": v[:16] for k, v in self.file_hashes.items()},
        }

    def resolve_user(self, user_id: str) -> UserContext:
        for u in self.users.users:
            if u.user_id == user_id:
                return UserContext(user_id=u.user_id, role=u.role, tenant_id=u.tenant_id)
        raise UnknownUserError(f"unknown user_id {user_id!r}")

    def role_policy(self, role: str) -> RolePolicy:
        try:
            return self.access.roles[role]
        except KeyError as e:
            raise UnknownUserError(f"role {role!r} not defined in access policy") from e


def _load_file(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    try:
        data = yaml.safe_load(raw) if path.suffix in (".yaml", ".yml") else json.loads(raw)
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        raise PolicyValidationError(f"{path.name}: parse error: {e}") from e
    if not isinstance(data, dict):
        raise PolicyValidationError(f"{path.name}: top level must be a mapping")
    return data, sha256_bytes(raw)


def validate_bundle(policy_dir: Path, names: dict[str, str], *, allow_draft: bool = False) -> PolicyBundle:
    try:
        a_raw, a_h = _load_file(policy_dir / names["access_policy"])
        u_raw, u_h = _load_file(policy_dir / names["users"])
        g_raw, g_h = _load_file(policy_dir / names["guard_policy"])
        access = AccessPolicy.model_validate(a_raw)
        users = UserDirectory.model_validate(u_raw)
        guard = GuardPolicy.model_validate(g_raw)
    except KeyError as e:
        raise PolicyValidationError(f"active.json missing key {e}") from e
    except FileNotFoundError as e:
        raise PolicyValidationError(f"policy file not found: {e.filename}") from e
    except ValidationError as e:
        raise PolicyValidationError("policy schema validation failed", detail={"errors": e.errors(include_url=False)}) from e
    if access.status != "approved" and not allow_draft:
        raise PolicyValidationError(f"access policy status is {access.status!r}; only 'approved' can be activated")
    errors = []
    seen = set()
    for u in users.users:
        if u.user_id in seen:
            errors.append(f"duplicate user_id {u.user_id}")
        seen.add(u.user_id)
        if u.role not in access.roles:
            errors.append(f"user {u.user_id}: role {u.role!r} not in access policy")
        if u.tenant_id not in access.tenants:
            errors.append(f"user {u.user_id}: tenant {u.tenant_id!r} not in access policy")
    if errors:
        raise PolicyValidationError("policy cross-validation failed", detail={"errors": errors})
    return PolicyBundle(access=access, users=users, guard=guard,
                        file_hashes={"access_policy": a_h, "users": u_h, "guard_policy": g_h})


def load_active(policy_dir: Path) -> PolicyBundle:
    active = policy_dir / ACTIVE_FILE
    if not active.exists():
        raise PolicyValidationError(f"{active} not found")
    names = json.loads(active.read_text(encoding="utf-8"))
    return validate_bundle(policy_dir, names)


def activate(policy_dir: Path, names: dict[str, str]) -> PolicyBundle:
    """Validate first, then atomically switch active.json. The previous pointer is kept for rollback."""
    bundle = validate_bundle(policy_dir, names)
    active = policy_dir / ACTIVE_FILE
    if active.exists():
        (policy_dir / "active.previous.json").write_bytes(active.read_bytes())
    tmp = policy_dir / "active.json.tmp"
    tmp.write_text(json.dumps(names, indent=2), encoding="utf-8")
    os.replace(tmp, active)
    return bundle
