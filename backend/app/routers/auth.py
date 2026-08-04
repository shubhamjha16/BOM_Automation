"""Auth endpoints. Handlers stay thin; the rules live in the controller."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request

from app.controllers import authController as controller
from app.routers.deps import CurrentUserDep, SessionDep, UserRepoDep
from app.schemas.request.auth import MfaEnrolIn, MfaVerifyIn, SignInIn, SignUpIn
from app.schemas.response.auth import MfaEnrolmentOut, TokenOut, UserOut
from app.utils.security import InvalidToken, decode_token

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=UserOut, status_code=201)
async def signup(body: SignUpIn, users: UserRepoDep, session: SessionDep) -> UserOut:
    user = await controller.sign_up(
        users, org_id=body.org_id, email=body.email, password=body.password
    )
    await session.commit()
    return UserOut(
        id=str(user.id),
        email=user.email,
        role=str(user.role),
        org_id=str(user.org_id),
        mfa_enabled=user.mfa_enabled,
    )


@router.post("/signin")
async def signin(body: SignInIn, users: UserRepoDep, session: SessionDep, request: Request) -> dict:
    result = await controller.sign_in_or_challenge(
        users, body=body, ip=request.client.host if request.client else None
    )
    await session.commit()
    return result


@router.post("/mfa/verify", response_model=TokenOut)
async def mfa_verify(
    body: MfaVerifyIn, users: UserRepoDep, session: SessionDep, request: Request
) -> TokenOut:
    tokens = await controller.verify_mfa_or_reject(
        users, body=body, ip=request.client.host if request.client else None
    )
    await session.commit()
    return TokenOut(**asdict(tokens))


@router.post("/mfa/enrol", response_model=MfaEnrolmentOut)
async def mfa_begin(user: CurrentUserDep, users: UserRepoDep) -> MfaEnrolmentOut:
    secret, uri = await controller.begin_mfa_enrolment(users, user)
    return MfaEnrolmentOut(secret=secret, provisioning_uri=uri)


@router.post("/mfa/enrol/confirm", response_model=UserOut)
async def mfa_confirm(
    body: MfaEnrolIn, user: CurrentUserDep, users: UserRepoDep, session: SessionDep
) -> UserOut:
    enrolled = await controller.complete_mfa_enrolment(
        users, user, secret=body.secret, code=body.code
    )
    await session.commit()
    return UserOut(
        id=str(enrolled.id),
        email=enrolled.email,
        role=str(enrolled.role),
        org_id=str(enrolled.org_id),
        mfa_enabled=enrolled.mfa_enabled,
    )


@router.get("/me", response_model=UserOut)
async def me(user: CurrentUserDep) -> UserOut:
    return UserOut(
        id=str(user.id),
        email=user.email,
        role=str(user.role),
        org_id=str(user.org_id),
        mfa_enabled=user.mfa_enabled,
    )


@router.post("/refresh", response_model=TokenOut)
async def refresh(body: dict, users: UserRepoDep) -> TokenOut:
    try:
        claims = decode_token(str(body.get("refresh_token", "")), expect="refresh")
    except InvalidToken as error:
        raise HTTPException(401, str(error)) from None
    return TokenOut(**asdict(await controller.refresh_tokens(users, claims=claims)))
