"""Focused tests for the initial-admin invitation API."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.requests import Request
from sqlalchemy import delete

from app.api.v1.endpoints import auth
from app.core.security import verify_password
from app.models.tenant import Tenant, User
from app.models.tenant_admin_invitation import TenantAdminInvitation

_RAW_TOKEN = "a" * 43


class _Result:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> Any:
        return self.value


class _InvitationSession:
    """Small transactional stand-in that models conditional UPDATE claims."""

    def __init__(self, *, expiry: datetime | None = None) -> None:
        self.tenant = Tenant(
            id=uuid.uuid4(),
            name="Sentinel Demo",
            slug="sentinel-demo",
            plan="managed-beta",
            is_active=True,
            settings={},
            limits={},
        )
        self.user = User(
            id=uuid.uuid4(),
            tenant_id=self.tenant.id,
            email="admin@example.test",
            username="admin",
            hashed_password="!invite-pending",
            role="tenant_admin",
            is_active=False,
            is_verified=False,
            preferences={},
        )
        self.invitation = TenantAdminInvitation(
            id=uuid.uuid4(),
            tenant_id=self.tenant.id,
            user_id=self.user.id,
            token_hash=hashlib.sha256(_RAW_TOKEN.encode()).hexdigest(),
            created_at=datetime.now(UTC),
            expires_at=expiry or datetime.now(UTC) + timedelta(hours=1),
        )
        self._claim_lock = asyncio.Lock()
        self.password_updates = 0

    async def execute(self, stmt: Any) -> _Result:
        sql = str(stmt).lower()
        if "set_config('app.current_tenant_id'" in sql:
            return _Result()
        if sql.startswith("select") and "tenant_admin_invitations" in sql:
            params = dict(stmt.compile().params)
            requested_hash = next((value for value in params.values() if isinstance(value, str) and len(value) == 64), None)
            invite = self.invitation
            valid = (
                requested_hash == invite.token_hash
                and invite.expires_at > datetime.now(UTC)
                and invite.consumed_at is None
                and invite.revoked_at is None
            )
            return _Result(invite if valid else None)
        if sql.startswith("select") and " from tenants" in sql:
            params = dict(stmt.compile().params)
            return _Result(self.tenant if self.tenant.slug in params.values() else None)
        if sql.startswith("select") and " from users" in sql:
            params = dict(stmt.compile().params)
            wanted = {v for v in params.values() if isinstance(v, uuid.UUID)}
            valid = (
                self.user.id in wanted
                and self.user.tenant_id in wanted
                and self.user.role == "tenant_admin"
                and not self.user.is_active
                and not self.user.is_verified
                and self.user.hashed_password == "!invite-pending"
            )
            return _Result(self.user if valid else None)
        if sql.startswith("update tenant_admin_invitations"):
            async with self._claim_lock:
                invite = self.invitation
                if (
                    invite.consumed_at is not None
                    or invite.revoked_at is not None
                    or invite.expires_at <= datetime.now(UTC)
                ):
                    return _Result()
                invite.consumed_at = datetime.now(UTC)
                return _Result(invite.id)
        if sql.startswith("update users"):
            user = self.user
            if user.is_active or user.is_verified or user.hashed_password != "!invite-pending":
                return _Result()
            self.password_updates += 1
            for column, bind in stmt._values.items():
                setattr(user, column.key, bind.value)
            return _Result(user.id)
        raise AssertionError(f"unexpected SQL in fake session: {sql}")


class _AllowLimiter:
    async def acquire(self, _key: str) -> SimpleNamespace:
        return SimpleNamespace(allowed=True, to_headers=lambda: {})


def _request(body: object) -> Request:
    body_bytes = json.dumps(body).encode()
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body_bytes, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/invitations",
            "headers": [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 12345),
        },
        receive,
    )


@pytest.fixture(autouse=True)
def _allow_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "get_signup_rate_limiter", lambda: _AllowLimiter())


@pytest.mark.asyncio
async def test_validate_invitation_returns_only_boolean() -> None:
    db = _InvitationSession()
    response = await auth.validate_admin_invitation(
        _request({"token": _RAW_TOKEN, "tenant": "sentinel-demo"}), db  # type: ignore[arg-type]
    )
    assert response == {"valid": True}
    assert "email" not in response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("token", "tenant", "expiry"),
    [
        ("x" * 43, "sentinel-demo", None),
        (_RAW_TOKEN, "another-tenant", None),
        (_RAW_TOKEN, "sentinel-demo", datetime.now(UTC) - timedelta(seconds=1)),
    ],
)
async def test_invalid_wrong_tenant_and_expired_invites_are_generic(
    token: str,
    tenant: str,
    expiry: datetime | None,
) -> None:
    db = _InvitationSession(expiry=expiry)
    response = await auth.validate_admin_invitation(
        _request({"token": token, "tenant": tenant}), db  # type: ignore[arg-type]
    )
    assert response == {"valid": False}


@pytest.mark.asyncio
async def test_revoked_invitation_is_not_valid() -> None:
    db = _InvitationSession()
    db.invitation.revoked_at = datetime.now(UTC)
    response = await auth.validate_admin_invitation(
        _request({"token": _RAW_TOKEN, "tenant": "sentinel-demo"}), db  # type: ignore[arg-type]
    )
    assert response == {"valid": False}


@pytest.mark.asyncio
async def test_redemption_activates_only_the_invited_initial_admin() -> None:
    db = _InvitationSession()
    response = await auth.redeem_admin_invitation(
        _request({"token": _RAW_TOKEN, "tenant": "sentinel-demo", "password": "valid-password-123"}),
        db,  # type: ignore[arg-type]
    )
    assert response == {"ok": True}
    assert db.invitation.consumed_at is not None
    assert db.user.is_active is True
    assert db.user.is_verified is True
    assert db.user.role == "tenant_admin"
    assert db.user.tenant_id == db.tenant.id
    assert db.user.hashed_password != "!invite-pending"
    assert db.user.hashed_password != "valid-password-123"


@pytest.mark.asyncio
async def test_redemption_refuses_short_password_without_echoing_input() -> None:
    token = _RAW_TOKEN
    password = "short"
    with pytest.raises(HTTPException) as error:
        await auth.redeem_admin_invitation(
            _request({"token": token, "tenant": "sentinel-demo", "password": password}),
            _InvitationSession(),  # type: ignore[arg-type]
        )
    assert error.value.status_code == 400
    assert token not in error.value.detail
    assert password not in error.value.detail


@pytest.mark.asyncio
async def test_invitation_cannot_activate_a_changed_user_identity() -> None:
    db = _InvitationSession()
    db.user.role = "soc_analyst"
    response = await auth.validate_admin_invitation(
        _request({"token": _RAW_TOKEN, "tenant": "sentinel-demo"}), db  # type: ignore[arg-type]
    )
    assert response == {"valid": False}


@pytest.mark.asyncio
async def test_replay_is_rejected_and_does_not_change_password_again() -> None:
    db = _InvitationSession()
    request = lambda: _request(
        {"token": _RAW_TOKEN, "tenant": "sentinel-demo", "password": "valid-password-123"}
    )
    await auth.redeem_admin_invitation(request(), db)  # type: ignore[arg-type]
    saved_hash = db.user.hashed_password
    with pytest.raises(HTTPException) as error:
        await auth.redeem_admin_invitation(request(), db)  # type: ignore[arg-type]
    assert error.value.status_code == 400
    assert error.value.detail == auth._INVITATION_ERROR
    assert db.user.hashed_password == saved_hash
    assert db.password_updates == 1


@pytest.mark.asyncio
async def test_concurrent_redemptions_allow_exactly_one_claim() -> None:
    db = _InvitationSession()
    body = {"token": _RAW_TOKEN, "tenant": "sentinel-demo", "password": "valid-password-123"}
    outcomes = await asyncio.gather(
        auth.redeem_admin_invitation(_request(body), db),  # type: ignore[arg-type]
        auth.redeem_admin_invitation(_request(body), db),  # type: ignore[arg-type]
        return_exceptions=True,
    )
    assert sum(result == {"ok": True} for result in outcomes) == 1
    assert sum(isinstance(result, HTTPException) for result in outcomes) == 1
    assert db.password_updates == 1


@pytest.mark.integration
def test_postgres_concurrent_invitation_redemption_is_single_use() -> None:
    """Exercise the conditional claim against PostgreSQL, not the fake above."""
    if not os.getenv("AISOC_RUN_INTEGRATION"):
        pytest.skip("set AISOC_RUN_INTEGRATION=1 to run invitation redemption against PostgreSQL")

    from app.db.database import AsyncSessionLocal

    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    invite_id = uuid.uuid4()
    slug = f"invite-test-{tenant_id.hex[:12]}"
    email = f"invite-test-{tenant_id.hex[:12]}@example.test"
    token = "b" * 43
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    password = "integration-password-123"

    async def run() -> None:
        try:
            async with AsyncSessionLocal() as session:
                session.add(
                    Tenant(
                        id=tenant_id,
                        name="Invitation integration fixture",
                        slug=slug,
                        plan="managed-beta",
                        is_active=True,
                        mssp_role="standalone",
                        settings={},
                        limits={},
                    )
                )
                session.add(
                    User(
                        id=user_id,
                        tenant_id=tenant_id,
                        email=email,
                        username="invite-test",
                        hashed_password="!invite-pending",
                        role="tenant_admin",
                        is_active=False,
                        is_verified=False,
                        preferences={},
                    )
                )
                session.add(
                    TenantAdminInvitation(
                        id=invite_id,
                        tenant_id=tenant_id,
                        user_id=user_id,
                        token_hash=token_hash,
                        created_at=datetime.now(UTC),
                        expires_at=datetime.now(UTC) + timedelta(hours=1),
                    )
                )
                await session.commit()

            async def redeem_once() -> object:
                async with AsyncSessionLocal() as session:
                    try:
                        result = await auth.redeem_admin_invitation(
                            _request({"token": token, "tenant": slug, "password": password}),
                            session,  # type: ignore[arg-type]
                        )
                        await session.commit()
                        return result
                    except HTTPException as exc:
                        await session.rollback()
                        return exc

            outcomes = await asyncio.gather(redeem_once(), redeem_once())
            assert sum(result == {"ok": True} for result in outcomes) == 1
            assert sum(isinstance(result, HTTPException) for result in outcomes) == 1

            async with AsyncSessionLocal() as session:
                user = await session.get(User, user_id)
                invitation = await session.get(TenantAdminInvitation, invite_id)
                assert user is not None and user.is_active and user.is_verified
                assert user.role == "tenant_admin" and user.tenant_id == tenant_id
                assert user.hashed_password != "!invite-pending"
                assert verify_password(password, user.hashed_password)
                assert invitation is not None and invitation.consumed_at is not None
        finally:
            async with AsyncSessionLocal() as cleanup:
                await cleanup.execute(
                    delete(TenantAdminInvitation).where(TenantAdminInvitation.id == invite_id)
                )
                await cleanup.execute(delete(User).where(User.id == user_id))
                await cleanup.execute(delete(Tenant).where(Tenant.id == tenant_id))
                await cleanup.commit()

    asyncio.run(run())
