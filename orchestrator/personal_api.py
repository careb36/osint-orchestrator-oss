"""Personal access and account administration; machine keys cannot impersonate staff."""

import asyncio
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import delete
from sqlmodel import col, select

from orchestrator import accounts
from orchestrator.auth import require_admin, require_api_key, require_person
from orchestrator.config import settings
from orchestrator.database import get_session
from orchestrator.i18n import t
from orchestrator.models import UserAccount, UserSession

router = APIRouter()


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=128)


class AccountBody(LoginBody):
    display_name: str = Field(min_length=1, max_length=80)
    role: Literal["admin", "accountant"] = "accountant"


class AccountUpdate(BaseModel):
    active: bool
    password: SecretStr | None = Field(default=None, min_length=12, max_length=128)


class PasswordBody(BaseModel):
    current_password: SecretStr = Field(max_length=128)
    password: SecretStr = Field(min_length=12, max_length=128)


@router.get("/auth/status")
async def access_status():
    return {"personal_access": await accounts.accounts_exist()}


@router.post("/auth/login")
async def login(body: LoginBody, request: Request, response: Response):
    accounts.check_browser_request(request)
    token, user = await accounts.login(body.username, body.password.get_secret_value())
    response.set_cookie(
        accounts.COOKIE_NAME,
        token,
        max_age=accounts.SESSION_SECONDS,
        httponly=True,
        secure=settings.orchestrator_cookie_secure,
        samesite="strict",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return user


@router.get("/auth/me", dependencies=[Depends(require_api_key)])
async def me(request: Request):
    return require_person(request)


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    accounts.check_browser_request(request)
    await accounts.revoke_session(request)
    response.delete_cookie(
        accounts.COOKIE_NAME,
        path="/",
        secure=settings.orchestrator_cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return {"ok": True}


@router.post("/auth/password", dependencies=[Depends(require_api_key)])
async def change_password(body: PasswordBody, request: Request, response: Response):
    actor = require_person(request)
    async with get_session() as session:
        user = await session.get(UserAccount, actor["id"])
        if not user or not await asyncio.to_thread(
            accounts.verify_password, body.current_password.get_secret_value(), user.password_hash
        ):
            raise HTTPException(400, t("password_invalid"))
        user.password_hash = await asyncio.to_thread(
            accounts.digest_password, body.password.get_secret_value()
        )
        session.add(user)
        await session.exec(delete(UserSession).where(col(UserSession.user_id) == user.id))
        await session.commit()
    response.delete_cookie(accounts.COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/accounts", dependencies=[Depends(require_api_key)])
async def list_accounts(request: Request):
    require_admin(request)
    async with get_session() as session:
        return [
            accounts.public_user(user)
            for user in (
                await session.exec(select(UserAccount).order_by(UserAccount.username))
            ).all()
        ]


@router.post("/accounts", status_code=201, dependencies=[Depends(require_api_key)])
async def create_account(body: AccountBody, request: Request):
    require_admin(request)
    return await accounts.create_account(
        body.username, body.display_name, body.role, body.password.get_secret_value()
    )


@router.post("/accounts/{user_id}", dependencies=[Depends(require_api_key)])
async def update_account(user_id: int, body: AccountUpdate, request: Request):
    require_admin(request)
    async with get_session() as session:
        user = await session.get(UserAccount, user_id)
        if not user:
            raise HTTPException(404, t("account_invalid"))
        # Administrator deactivation is a local identity-store operation; no pair
        # of web requests can race to disable the last administrator.
        if not body.active and user.role == "admin":
            raise HTTPException(409, t("last_admin"))
        user.active = body.active
        if body.password:
            user.password_hash = await asyncio.to_thread(
                accounts.digest_password, body.password.get_secret_value()
            )
            user.failed_logins = 0
            user.locked_until = None
        session.add(user)
        await session.exec(delete(UserSession).where(col(UserSession.user_id) == user_id))
        await session.commit()
        await session.refresh(user)
        return accounts.public_user(user)
