"""Personal password authentication with revocable, server-side sessions."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request
from sqlalchemy import case, delete, update
from sqlmodel import col, select

from orchestrator.database import get_session
from orchestrator.i18n import t
from orchestrator.models import UserAccount, UserSession

COOKIE_NAME = "orchestrator_session"
SESSION_SECONDS = 8 * 60 * 60


def digest_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return f"pbkdf2-sha256${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt, expected = encoded.split("$")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
        return algorithm == "pbkdf2-sha256" and hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def public_user(user: UserAccount) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "active": user.active,
    }


async def accounts_exist() -> bool:
    async with get_session() as session:
        return (await session.exec(select(UserAccount.id).limit(1))).first() is not None


async def create_account(username: str, display_name: str, role: str, password: str) -> dict:
    username = username.strip().lower()
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", username)
        or not display_name.strip()
        or len(display_name) > 80
        or not 12 <= len(password) <= 128
        or role not in ("admin", "accountant")
    ):
        raise HTTPException(422, t("account_invalid"))
    encoded = await asyncio.to_thread(digest_password, password)
    async with get_session() as session:
        from sqlalchemy.exc import IntegrityError

        user = UserAccount(
            username=username, display_name=display_name.strip(), role=role, password_hash=encoded
        )
        session.add(user)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise HTTPException(409, t("account_exists")) from None
        await session.refresh(user)
        return public_user(user)


async def login(username: str, password: str) -> tuple[str, dict]:
    now = datetime.now(UTC)
    async with get_session() as session:
        user = (
            await session.exec(
                select(UserAccount).where(UserAccount.username == username.strip().lower())
            )
        ).first()
        # Unknown accounts still incur password-derivation work.
        dummy = "pbkdf2-sha256$" + "00" * 16 + "$" + "00" * 32
        matches = await asyncio.to_thread(
            verify_password, password, user.password_hash if user else dummy
        )
        locked = user and user.locked_until and user.locked_until.replace(tzinfo=UTC) > now
        if not user or not user.active or locked or not matches:
            if user and not locked:
                await session.exec(
                    update(UserAccount)
                    .where(col(UserAccount.id) == user.id)
                    .values(
                        failed_logins=UserAccount.failed_logins + 1,
                        locked_until=case(
                            (col(UserAccount.failed_logins) >= 4, now + timedelta(minutes=15)),
                            else_=None,
                        ),
                    )
                )
                await session.commit()
            raise HTTPException(401, t("login_invalid"))
        user.failed_logins = 0
        user.locked_until = None
        token = secrets.token_urlsafe(32)
        assert user.id is not None
        # Expired sessions are removed on successful login; only digests persist.
        await session.exec(delete(UserSession).where(col(UserSession.expires_at) <= now))
        session.add(
            UserSession(
                id=hashlib.sha256(token.encode()).hexdigest(),
                user_id=user.id,
                expires_at=now + timedelta(seconds=SESSION_SECONDS),
            )
        )
        session.add(user)
        await session.commit()
        return token, public_user(user)


async def session_user(request: Request) -> dict | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token or len(token) > 128:
        return None
    async with get_session() as session:
        row = await session.get(UserSession, hashlib.sha256(token.encode()).hexdigest())
        if not row or row.expires_at.replace(tzinfo=UTC) <= datetime.now(UTC):
            return None
        user = await session.get(UserAccount, row.user_id)
        return public_user(user) if user and user.active else None


async def revoke_session(request: Request) -> None:
    token = request.cookies.get(COOKIE_NAME, "")
    async with get_session() as session:
        await session.exec(
            delete(UserSession).where(
                col(UserSession.id) == hashlib.sha256(token.encode()).hexdigest()
            )
        )
        await session.commit()


def check_browser_request(request: Request) -> None:
    from urllib.parse import urlsplit

    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    origin = request.headers.get("origin")
    actual = urlsplit(origin) if origin else None
    if request.headers.get("x-requested-with") != "XMLHttpRequest" or (
        actual and (actual.scheme != request.url.scheme or actual.netloc != request.url.netloc)
    ):
        raise HTTPException(403, t("request_untrusted"))


async def bootstrap(username: str, display_name: str) -> None:
    from orchestrator.database import create_db_and_tables

    await create_db_and_tables()
    password = getpass.getpass("Password (at least 12 characters): ")
    if password != getpass.getpass("Confirm password: "):
        raise SystemExit("Passwords do not match")
    await create_account(username, display_name, "admin", password)
    print("Administrator created. Personal sign-in is now required for browser users.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create an administrator locally; passwords are never command-line arguments."
    )
    parser.add_argument("username")
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    asyncio.run(bootstrap(args.username, args.name))


if __name__ == "__main__":
    main()
