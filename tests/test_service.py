"""End-to-end API tests for the RPKI cut-over guard.

Run from the repository root with the project venv:
    .venv/bin/python -m pytest -q
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import DEFAULT_SEED_PATH, load_seed_table, store


@pytest.fixture(autouse=True)
def _reset_state():
    store.reset(load_seed_table(DEFAULT_SEED_PATH))
    yield
    store.reset(load_seed_table(DEFAULT_SEED_PATH))


@pytest.fixture()
def client():
    return TestClient(app)


def announce(client: TestClient, prefix: str, asn, **extra):
    body = {"prefix": prefix, "origin_asn": asn, **extra}
    r = client.post("/api/bgp/announcements", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def put_candidate(client: TestClient, cid: str, records, version=None):
    body = {"records": records}
    if version is not None:
        body["version"] = version
    r = client.put(f"/api/candidates/{cid}", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def enable(client: TestClient, cid: str, **body):
    return client.post(f"/api/candidates/{cid}/enable", json=body or {})


SEED_RECORDS = [
    {"prefix": "192.0.2.0/24", "max_length": 25, "origin_asn": 65001},
    {"prefix": "198.51.100.0/24", "max_length": 28, "origin_asn": 65002},
    {"prefix": "203.0.113.0/24", "max_length": 24, "origin_asn": 65003},
]


def test_health_and_seed_loaded(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["active_version"] == "2026-11-26-active-1"
    assert data["announced_routes"] == 0

    table = client.get("/api/active/authorizations").json()
    assert table["record_count"] == 3
    assert table["fingerprint"].startswith("sha256:")


@pytest.mark.parametrize(
    "prefix,asn,state,reason",
    [
        ("192.0.2.0/24", 65001, "valid", None),
        ("192.0.2.128/25", 65001, "valid", None),
        # length within /24 but beyond maxLength 25
        ("192.0.2.192/26", 65001, "invalid", "max_length_exceeded"),
        # covering prefix but wrong origin ASN
        ("192.0.2.0/24", 65099, "invalid", "origin_as_unauthorized"),
        # no covering ROA
        ("198.18.0.0/16", 65010, "not_found", None),
    ],
)
def test_route_classification(client, prefix, asn, state, reason):
    result = announce(client, prefix, asn)
    verdict = result["validation"]
    assert verdict["state"] == state
    if reason is not None:
        assert verdict["reason"] == reason
    assert result["active_version"] == "2026-11-26-active-1"


def test_asn_string_form_accepted(client):
    result = announce(client, "192.0.2.0/24", "AS65001")
    assert result["route"]["origin_asn"] == 65001
    assert result["validation"]["state"] == "valid"


def test_routes_distinguished_by_prefix_and_asn(client):
    announce(client, "192.0.2.0/24", 65001)
    announce(client, "192.0.2.0/24", 65099)  # same prefix, different origin
    routes = client.get("/api/routes").json()["routes"]
    assert len(routes) == 2

    # Withdrawing one exact (prefix, ASN) leaves the other.
    r = client.post(
        "/api/bgp/withdrawals",
        json={"prefix": "192.0.2.0/24", "origin_asn": 65099},
    )
    assert r.status_code == 200
    assert r.json()["removed_count"] == 1
    routes = client.get("/api/routes").json()["routes"]
    assert len(routes) == 1
    assert routes[0]["origin_asn"] == 65001


def test_withdraw_without_asn_removes_all_origins_of_prefix(client):
    announce(client, "192.0.2.0/24", 65001)
    announce(client, "192.0.2.0/24", 65099)
    r = client.post("/api/bgp/withdrawals", json={"prefix": "192.0.2.0/24"})
    assert r.json()["removed_count"] == 2
    assert client.get("/api/routes").json()["count"] == 0

    # Idempotent: withdrawing again removes nothing but is still 200.
    r = client.post("/api/bgp/withdrawals", json={"prefix": "192.0.2.0/24"})
    assert r.status_code == 200
    assert r.json()["removed_count"] == 0


def test_invalid_prefixes_rejected(client):
    # IPv6 is out of scope.
    r = client.post(
        "/api/bgp/announcements",
        json={"prefix": "2001:db8::/32", "origin_asn": 65001},
    )
    assert r.status_code == 422
    # Host bits set (non-strict prefix).
    r = client.post(
        "/api/bgp/announcements",
        json={"prefix": "192.0.2.7/24", "origin_asn": 65001},
    )
    assert r.status_code == 422
    # max_length below prefix length.
    r = client.put(
        "/api/candidates/bad",
        json={
            "version": "bad-1",
            "records": [
                {"prefix": "192.0.2.0/24", "max_length": 23, "origin_asn": 65001}
            ],
        },
    )
    assert r.status_code == 422


def test_trial_reports_new_invalid_routes(client):
    # Allowed under active table: valid and not_found routes.
    announce(client, "192.0.2.0/24", 65001)
    announce(client, "198.18.0.0/16", 65010)

    # Candidate moves 192.0.2.0/24 to a different ASN -> new Invalid.
    data = put_candidate(
        client,
        "c1",
        [
            {"prefix": "192.0.2.0/24", "max_length": 25, "origin_asn": 65077},
        ],
        version="v2-draft",
    )
    trial = data["trial"]
    assert trial["authorization_version"] == "v2-draft"
    assert trial["new_invalid_count"] == 1
    blocker = trial["new_invalid"][0]
    assert blocker["prefix"] == "192.0.2.0/24"
    assert blocker["origin_asn"] == 65001
    assert blocker["active_state"] == "valid"
    assert blocker["candidate_state"] == "invalid"


def test_new_announcement_after_clean_trial_blocks_enable(client):
    # Baseline route; candidate only ADDS an authorization -> clean trial.
    announce(client, "198.18.0.0/16", 65010)
    data = put_candidate(
        client,
        "cutover",
        SEED_RECORDS
        + [{"prefix": "198.18.0.0/16", "max_length": 24, "origin_asn": 65010}],
        version="v2-final",
    )
    trial_id = data["trial"]["trial_id"]
    assert data["trial"]["new_invalid_count"] == 0

    # New routes arrive AFTER trial. Receipts are still judged by active v1,
    # under which 198.18/16 has no covering ROA -> not_found (allowed).
    rcpt_as = announce(client, "198.18.1.0/24", 65099, collector="collector-a")
    assert rcpt_as["active_version"] == "2026-11-26-active-1"
    assert rcpt_as["validation"]["state"] == "not_found"

    rcpt_len = announce(client, "198.18.0.0/25", 65010)
    assert rcpt_len["validation"]["state"] == "not_found"

    # Enable with unchanged authorization version -> live recheck blocks.
    r = enable(client, "cutover", trial_id=trial_id)
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["code"] == "ENABLE_BLOCKED"
    assert detail["recheck"]["routes_checked"] == 3
    assert detail["recheck"]["new_invalid_count"] == 2
    prefixes = {b["prefix"] for b in detail["blockers"]}
    assert prefixes == {"198.18.1.0/24", "198.18.0.0/25"}
    reasons = {b["prefix"]: b["candidate_reason"] for b in detail["blockers"]}
    assert reasons["198.18.1.0/24"] == "origin_as_unauthorized"
    assert reasons["198.18.0.0/25"] == "max_length_exceeded"

    # Active table must be untouched.
    health = client.get("/healthz").json()
    assert health["active_version"] == "2026-11-26-active-1"

    # Withdraw the still-announced blockers, then the SAME trial enables:
    # version unchanged, but recheck now sees no blockers.
    for prefix, asn in [
        ("198.18.1.0/24", 65099),
        ("198.18.0.0/25", 65010),
    ]:
        w = client.post(
            "/api/bgp/withdrawals", json={"prefix": prefix, "origin_asn": asn}
        )
        assert w.status_code == 200

    r = enable(client, "cutover", trial_id=trial_id)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is True
    assert body["already_active"] is False
    assert body["active_version"] == "v2-final"
    assert body["recheck"]["new_invalid_count"] == 0

    # Table really switched: the formerly allowed bad-origin route receipt
    # is now Invalid under the new effective table.
    rcpt = announce(client, "198.18.1.0/24", 65099)
    assert rcpt["active_version"] == "v2-final"
    assert rcpt["validation"]["state"] == "invalid"


def test_changed_candidate_authorization_requires_retrial(client):
    announce(client, "198.18.0.0/16", 65010)

    r1 = put_candidate(
        client,
        "c",
        SEED_RECORDS
        + [{"prefix": "198.18.0.0/16", "max_length": 16, "origin_asn": 65010}],
        version="rc1",
    )
    old_trial = r1["trial"]["trial_id"]

    # Replace whole table under the same candidate id -> authorization changes.
    r2 = put_candidate(
        client,
        "c",
        SEED_RECORDS
        + [{"prefix": "198.18.0.0/16", "max_length": 24, "origin_asn": 65010}],
        version="rc2",
    )
    new_trial = r2["trial"]["trial_id"]
    assert old_trial != new_trial

    # Presenting the stale trial token is rejected with RETRIAL_REQUIRED.
    r = enable(client, "c", trial_id=old_trial)
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["code"] == "RETRIAL_REQUIRED"
    assert detail["reason"] == "candidate_authorization_changed"

    # A wrong asserted version is likewise rejected.
    r = enable(client, "c", authorization_version="rc1")
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "RETRIAL_REQUIRED"

    # Explicit retrial produces a usable token and enable succeeds.
    rt = client.post("/api/candidates/c/trial").json()
    r = enable(client, "c", trial_id=rt["trial_id"])
    assert r.status_code == 200, r.text
    assert r.json()["active_version"] == "rc2"


def test_active_table_changed_since_trial_requires_retrial(client):
    """Two candidates: enabling A moves the active table, so B's trial is stale."""
    announce(client, "198.18.0.0/16", 65010)

    a = put_candidate(
        client,
        "a",
        SEED_RECORDS
        + [{"prefix": "203.0.113.128/25", "max_length": 25, "origin_asn": 65003}],
        version="v-a",
    )
    b = put_candidate(
        client,
        "b",
        SEED_RECORDS
        + [{"prefix": "203.0.113.0/25", "max_length": 25, "origin_asn": 65004}],
        version="v-b",
    )
    trial_b = b["trial"]["trial_id"]

    assert enable(client, "a", trial_id=a["trial"]["trial_id"]).status_code == 200

    r = enable(client, "b", trial_id=trial_b)
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["code"] == "RETRIAL_REQUIRED"
    assert detail["reason"] == "active_table_changed"


def test_trial_blocker_can_disappear_after_withdrawal_without_retrial(client):
    # Active table has no 198.18/16 cover -> this route is allowed (NotFound).
    announce(client, "198.18.1.0/24", 65099)
    data = put_candidate(
        client,
        "c",
        [{"prefix": "198.18.0.0/16", "max_length": 24, "origin_asn": 65010}],
        version="v-x",
    )
    tid = data["trial"]["trial_id"]
    assert data["trial"]["new_invalid_count"] == 1

    # ... but operators withdraw it before enable; same trial token then works
    # because enable rechecks the live route set.
    client.post(
        "/api/bgp/withdrawals",
        json={"prefix": "198.18.1.0/24", "origin_asn": 65099},
    )
    r = enable(client, "c", trial_id=tid)
    assert r.status_code == 200, r.text


def test_enable_unknown_candidate_404(client):
    r = enable(client, "nope")
    assert r.status_code == 404


def test_post_duplicate_candidate_id_conflicts(client):
    body = {"candidate_id": "dup", "version": "v1", "records": SEED_RECORDS}
    assert client.post("/api/candidates", json=body).status_code == 201
    r = client.post("/api/candidates", json=body)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "CANDIDATE_EXISTS"


def test_enable_without_trial_for_freshly_posted_candidate_uses_latest(client):
    r = client.post(
        "/api/candidates",
        json={
            "candidate_id": "auto",
            "version": "v9",
            "records": SEED_RECORDS,
        },
    )
    assert r.status_code == 201
    # No explicit trial_id: latest trial is used; table equals seed content
    # except version label -> fingerprint differs, recheck clean -> enabled.
    r = enable(client, "auto")
    assert r.status_code == 200, r.text
    assert r.json()["active_version"] == "v9"
