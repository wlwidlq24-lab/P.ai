from __future__ import annotations

import pytest

from ragsec.errors import AuthorizationFilterMissingError
from ragsec.schemas import AccessControlMode, PiiGrade, RolePolicy, UserContext
from ragsec.store import assert_authz_filter, build_where, is_authorized
from ragsec.timeutil import utc_now

USER = UserContext(user_id="u1", role="teller", tenant_id="bank_a")
RP = RolePolicy(description="t", max_pii_grade=PiiGrade.CREDIT)


def test_build_where_enforced_has_all_mandatory_clauses():
    where = build_where(USER, RP, AccessControlMode.ENFORCED, utc_now(), None)
    keys = {k for c in where["$and"] for k in c}
    assert "tenant_id" in keys
    assert "role__teller" in keys
    assert "pii_grade_rank" in keys
    assert "effective_from_ts" in keys and "effective_to_ts" in keys


def test_weakened_mode_drops_role_but_keeps_tenant():
    where = build_where(USER, RP, AccessControlMode.WEAKENED_NO_ROLE_FILTER, utc_now(), None)
    keys = {k for c in where["$and"] for k in c}
    assert "tenant_id" in keys
    assert "role__teller" not in keys  # intentionally weakened


def test_fail_closed_when_no_filter():
    with pytest.raises(AuthorizationFilterMissingError):
        assert_authz_filter(None, USER, AccessControlMode.ENFORCED)
    with pytest.raises(AuthorizationFilterMissingError):
        assert_authz_filter({"$and": []}, USER, AccessControlMode.ENFORCED)


def test_fail_closed_on_tenant_mismatch():
    bad = {"$and": [{"tenant_id": {"$eq": "bank_b"}}, {"role__teller": {"$eq": True}}, {"pii_grade_rank": {"$lte": 2}}]}
    with pytest.raises(AuthorizationFilterMissingError):
        assert_authz_filter(bad, USER, AccessControlMode.ENFORCED)


def test_fail_closed_when_role_filter_missing_under_enforced():
    bad = {"$and": [{"tenant_id": {"$eq": "bank_a"}}]}
    with pytest.raises(AuthorizationFilterMissingError):
        assert_authz_filter(bad, USER, AccessControlMode.ENFORCED)
