"""FastAPI application: RPKI table cut-over guard.

Workflow
--------
1. Collector feeds BGP announcements/withdrawals; receipts carry the verdict
   under the table that is effective at receipt time.
2. Operator submits a whole candidate authorization table (POST /api/candidates
   or PUT /api/candidates/{id}); the service trials it against current routes
   and returns a trial token, the authorization version/fingerprint and the
   routes that would newly become Invalid.
3. Enabling re-validates trial freshness (authorization version must not have
   changed) and *always* re-runs the new-Invalid check against routes still
   announced at enable time. Any blocker rejects the cut-over and leaves the
   active table untouched.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .models import (
    AnnouncementIn,
    CandidateTableIn,
    EnableIn,
    PutCandidateIn,
    WithdrawalIn,
)
from .rtr import DEFAULT_RTR_HOST, DEFAULT_RTR_PORT, RTRServer
from .store import StoreConflict, store

logger = logging.getLogger("app")


def _rtr_enabled() -> bool:
    return os.getenv("RTR_ENABLED", "1").strip().lower() not in (
        "0",
        "false",
        "no",
        "off",
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    rtr_server: RTRServer | None = None
    if _rtr_enabled():
        rtr_host = os.getenv("RTR_HOST", DEFAULT_RTR_HOST)
        rtr_port = int(os.getenv("RTR_PORT", str(DEFAULT_RTR_PORT)))
        rtr_server = RTRServer(store, rtr_host, rtr_port).start()
        _app.state.rtr_server = rtr_server
        logger.info(
            "RFC 8210 RTR v1 interface available at %s:%d", rtr_host, rtr_server.server_port
        )
    else:
        _app.state.rtr_server = None
    try:
        yield
    finally:
        if rtr_server is not None:
            rtr_server.stop()


app = FastAPI(
    title="RPKI Cut-over Guard",
    version=__version__,
    lifespan=lifespan,
    description=(
        "单实例 RPKI 授权表切换守门服务：接收 IPv4 BGP 通告/撤回，"
        "试算候选授权整表，并在启用时按仍在播路由重核新增 Invalid；"
        "启用后的 IPv4 起源授权另通过 RFC 8210 RTR v1 TCP 接口供边界路由器读取。"
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(StoreConflict)
async def store_conflict_handler(_request: Request, exc: StoreConflict) -> JSONResponse:
    detail = {"code": exc.code, "message": exc.message, **exc.extra}
    return JSONResponse(status_code=409, content={"detail": detail})


@app.get("/", tags=["meta"])
def root() -> dict:
    return {
        "service": "rpki-cutover-guard",
        "version": __version__,
        "docs": "/docs",
        "endpoints": {
            "health": "GET /healthz",
            "active_table": "GET /api/active/authorizations",
            "routes": "GET /api/routes?state=valid|invalid|not_found",
            "announcements": "POST /api/bgp/announcements",
            "withdrawals": "POST /api/bgp/withdrawals",
            "submit_candidate": "POST /api/candidates",
            "replace_candidate": "PUT /api/candidates/{candidate_id}",
            "list_candidates": "GET /api/candidates",
            "candidate_detail": "GET /api/candidates/{candidate_id}",
            "retrial": "POST /api/candidates/{candidate_id}/trial",
            "enable": "POST /api/candidates/{candidate_id}/enable",
            "rtr_tcp": (
                f"RFC8210 RTRv1 on tcp/{os.getenv('RTR_PORT', str(DEFAULT_RTR_PORT))} "
                "(Reset Query / Serial Query / Serial Notify)"
            ),
        },
    }


@app.get("/healthz", tags=["meta"])
def healthz() -> dict:
    return store.health()


@app.get("/health", tags=["meta"], include_in_schema=False)
def health_alias() -> dict:
    return store.health()


@app.get("/api/active/authorizations", tags=["authorizations"])
def get_active_table() -> dict:
    """The currently effective authorization table (with version)."""
    return store.active_table_view()


@app.get("/api/routes", tags=["bgp"])
def get_routes(
    state: str | None = Query(
        default=None, pattern="^(valid|invalid|not_found)$"
    ),
) -> dict:
    """Currently announced routes, each evaluated under the active table."""
    routes = store.list_routes(state_filter=state)
    return {"count": len(routes), "state_filter": state, "routes": routes}


@app.post("/api/bgp/announcements", tags=["bgp"], status_code=200)
def post_announcement(payload: AnnouncementIn) -> dict:
    return store.announce(
        prefix=payload.prefix,
        origin_asn=payload.origin_asn,
        collector=payload.collector,
        peer=payload.peer,
    )


@app.post("/api/bgp/withdrawals", tags=["bgp"])
def post_withdrawal(payload: WithdrawalIn) -> dict:
    return store.withdraw(
        prefix=payload.prefix,
        origin_asn=payload.origin_asn,
        collector=payload.collector,
    )


@app.post("/api/candidates", tags=["candidates"], status_code=201)
def post_candidate(payload: CandidateTableIn) -> dict:
    candidate, trial, created = store.create_candidate(
        candidate_id=payload.candidate_id,
        version=payload.version,
        description=payload.description,
        record_models=payload.records,
    )
    return {
        "candidate_id": candidate.id,
        "created": created,
        "candidate": candidate.summary(),
        "trial": trial,
    }


@app.put("/api/candidates/{candidate_id}", tags=["candidates"])
def put_candidate(candidate_id: str, payload: PutCandidateIn) -> dict:
    candidate, trial = store.replace_candidate(
        candidate_id=candidate_id,
        version=payload.version,
        description=payload.description,
        record_models=payload.records,
    )
    return {
        "candidate_id": candidate.id,
        "candidate": candidate.summary(),
        "trial": trial,
    }


@app.get("/api/candidates", tags=["candidates"])
def list_candidates() -> dict:
    items = store.list_candidates()
    return {"count": len(items), "candidates": items}


@app.get("/api/candidates/{candidate_id}", tags=["candidates"])
def get_candidate(candidate_id: str) -> dict:
    detail = store.candidate_detail(candidate_id)
    if detail is None:
        raise HTTPException(status_code=404, detail={"code": "CANDIDATE_NOT_FOUND"})
    return detail


@app.post("/api/candidates/{candidate_id}/trial", tags=["candidates"])
def post_retrial(candidate_id: str) -> dict:
    try:
        trial = store.run_trial(candidate_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "CANDIDATE_NOT_FOUND"})
    return trial


@app.post("/api/candidates/{candidate_id}/enable", tags=["candidates"])
def post_enable(candidate_id: str, payload: EnableIn | None = None) -> dict:
    payload = payload or EnableIn()
    try:
        return store.enable_candidate(
            candidate_id=candidate_id,
            trial_id=payload.trial_id,
            expected_version=payload.authorization_version,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "CANDIDATE_NOT_FOUND"})
    except StoreConflict as conflict:
        detail = {"code": conflict.code, "message": conflict.message, **conflict.extra}
        raise HTTPException(status_code=409, detail=detail)
