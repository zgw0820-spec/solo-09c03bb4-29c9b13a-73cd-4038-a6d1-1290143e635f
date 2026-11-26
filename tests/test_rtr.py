"""Tests for the RFC 8210 RTR v1 TCP interface.

Covers wire encoding, Reset/Serial Query semantics, Serial Notify on content
enabling, snapshot consistency, coalesced latest-serial notify, and the
slow-connection isolation requirement using real loopback sockets.
"""

from __future__ import annotations

import socket
import struct
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.rtr import (
    PDU_CACHE_RESET,
    PDU_CACHE_RESPONSE,
    PDU_END_OF_DATA,
    PDU_IPV4_PREFIX,
    PDU_SERIAL_NOTIFY,
    RTRConnection,
    RTRServer,
    parse_pdu,
    pdu_reset_query,
    pdu_serial_query,
)
from app.store import DEFAULT_SEED_PATH, load_seed_table, store

SEED_RECORDS = [
    {"prefix": "192.0.2.0/24", "max_length": 25, "origin_asn": 65001},
    {"prefix": "198.51.100.0/24", "max_length": 28, "origin_asn": 65002},
    {"prefix": "203.0.113.0/24", "max_length": 24, "origin_asn": 65003},
]

EXTRA_RECORD = {"prefix": "198.19.10.0/24", "max_length": 24, "origin_asn": 65088}


@pytest.fixture(autouse=True)
def _reset_store():
    store.reset(load_seed_table(DEFAULT_SEED_PATH))
    yield
    store.reset(load_seed_table(DEFAULT_SEED_PATH))


@pytest.fixture()
def rtr_server(_reset_store):
    server = RTRServer(store, "127.0.0.1", 0).start()
    try:
        yield server
    finally:
        server.stop()


# --------------------------------------------------------------------------- #
# socket helpers
# --------------------------------------------------------------------------- #


def connect(port: int, timeout: float = 5.0) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("peer closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_pdu(sock: socket.socket) -> dict:
    header = recv_exact(sock, 8)
    _v, _t, _f, length = struct.unpack("!BBHI", header)
    rest = recv_exact(sock, length - 8) if length > 8 else b""
    return parse_pdu(header + rest)


def read_until_end(sock: socket.socket) -> list[dict]:
    pdus = []
    while True:
        pdu = read_pdu(sock)
        pdus.append(pdu)
        if pdu["type"] in (PDU_END_OF_DATA, PDU_CACHE_RESET):
            return pdus


def enable_table(records, version: str):
    candidate, trial, _ = store.create_candidate(None, version, None, records)
    return store.enable_candidate(candidate.id, trial["trial_id"])


def types(pdus):
    return [p["type"] for p in pdus]


# --------------------------------------------------------------------------- #
# Reset Query
# --------------------------------------------------------------------------- #


def test_reset_query_returns_full_seed_table(rtr_server):
    sid, serial = store.rtr_state()
    assert serial == 0

    with connect(rtr_server.server_port) as sock:
        sock.sendall(pdu_reset_query())
        pdus = read_until_end(sock)

    assert types(pdus) == [
        PDU_CACHE_RESPONSE,
        PDU_IPV4_PREFIX,
        PDU_IPV4_PREFIX,
        PDU_IPV4_PREFIX,
        PDU_END_OF_DATA,
    ]
    cache_response, *prefixes, eod = pdus
    assert cache_response["session_id"] == sid

    # Exact wire layout of the first seed record.
    first = prefixes[0]
    assert first["prefix"] == "192.0.2.0/24"
    assert first["prefix_length"] == 24
    assert first["max_length"] == 25
    assert first["origin_asn"] == 65001
    assert first["flags"] == 0x01 and first["is_announcement"] is True
    assert first["length"] == 20

    assert {p["prefix"] for p in prefixes} == {
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    }
    # v1 End of Data is 12 bytes and carries session + serial.
    assert eod["length"] == 12
    assert eod["session_id"] == sid
    assert eod["serial"] == 0


# --------------------------------------------------------------------------- #
# Serial Query
# --------------------------------------------------------------------------- #


def test_serial_query_exact_session_and_serial_is_empty_update(rtr_server):
    sid, serial = store.rtr_state()
    with connect(rtr_server.server_port) as sock:
        sock.sendall(pdu_serial_query(sid, serial))
        pdus = read_until_end(sock)

    assert types(pdus) == [PDU_CACHE_RESPONSE, PDU_END_OF_DATA]
    assert pdus[0]["session_id"] == sid
    assert pdus[1]["session_id"] == sid
    assert pdus[1]["serial"] == serial


def test_serial_query_stale_serial_triggers_cache_reset(rtr_server):
    sid, serial = store.rtr_state()
    with connect(rtr_server.server_port) as sock:
        sock.sendall(pdu_serial_query(sid, serial + 5))
        pdus = read_until_end(sock)

    assert len(pdus) == 1
    reset = pdus[0]
    assert reset["type"] == PDU_CACHE_RESET
    assert reset["version"] == 1
    assert reset["length"] == 8


def test_serial_query_wrong_session_triggers_cache_reset(rtr_server):
    sid, serial = store.rtr_state()
    other_session = 1 if sid != 1 else 2
    with connect(rtr_server.server_port) as sock:
        sock.sendall(pdu_serial_query(other_session, serial))
        pdus = read_until_end(sock)

    assert types(pdus) == [PDU_CACHE_RESET]


# --------------------------------------------------------------------------- #
# Serial Notify / serial advancement rules
# --------------------------------------------------------------------------- #


def test_idle_connection_receives_serial_notify_after_content_enable(rtr_server):
    sid, _ = store.rtr_state()
    with connect(rtr_server.server_port) as sock:
        # Synchronize with the handler: this round trip proves it initialized
        # its reported-serial bookmark at the current serial.
        sock.sendall(pdu_serial_query(sid, 0))
        assert types(read_until_end(sock)) == [
            PDU_CACHE_RESPONSE,
            PDU_END_OF_DATA,
        ]

        # A record-set-changing enable happens while the connection is idle.
        result = enable_table(SEED_RECORDS + [EXTRA_RECORD], "v2")
        assert result["rtr"]["serial_advanced"] is True
        assert result["rtr"]["serial"] == 1

        sock.settimeout(3.0)
        notify = read_pdu(sock)

    assert notify["type"] == PDU_SERIAL_NOTIFY
    assert notify["session_id"] == sid
    assert notify["serial"] == 1
    assert notify["length"] == 12

    health = TestClient(app).get("/healthz").json()
    assert health["rtr_serial"] == 1
    assert health["rtr_session_id"] == sid


def test_http_enable_drives_rtr_and_notifies(rtr_server):
    client = TestClient(app)  # no context manager -> app lifespan/RTR not doubled
    sid, _ = store.rtr_state()
    with connect(rtr_server.server_port) as sock:
        sock.sendall(pdu_serial_query(sid, 0))
        read_until_end(sock)  # synchronize handler bookmark

        body = {"version": "api-v2", "records": SEED_RECORDS + [EXTRA_RECORD]}
        put = client.put("/api/candidates/rtr-api", json=body)
        trial_id = put.json()["trial"]["trial_id"]
        response = client.post(
            "/api/candidates/rtr-api/enable", json={"trial_id": trial_id}
        )
        assert response.status_code == 200, response.text
        rtr_info = response.json()["rtr"]
        assert rtr_info["serial_advanced"] is True
        assert rtr_info["serial"] == 1
        assert rtr_info["session_id"] == sid

        sock.settimeout(3.0)
        notify = read_pdu(sock)
        assert notify["type"] == PDU_SERIAL_NOTIFY
        assert notify["serial"] == 1


def test_relabel_only_enable_does_not_advance_serial_or_notify(rtr_server):
    sid, _ = store.rtr_state()
    with connect(rtr_server.server_port) as sock:
        sock.sendall(pdu_serial_query(sid, 0))
        read_until_end(sock)  # synchronize handler bookmark

        result = enable_table(SEED_RECORDS, "same-records-new-label")
        assert result["rtr"]["serial_advanced"] is False
        assert result["rtr"]["serial"] == 0

        # No Serial Notify may be emitted.
        sock.settimeout(0.8)
        with pytest.raises(socket.timeout):
            read_pdu(sock)


def test_duplicate_records_do_not_change_the_set(rtr_server):
    # Exact duplicate of an existing seed record adds nothing to the set.
    result = enable_table(
        SEED_RECORDS + [dict(SEED_RECORDS[0])], "with-duplicate"
    )
    assert result["rtr"]["serial_advanced"] is False
    assert store.rtr_state()[1] == 0


# --------------------------------------------------------------------------- #
# Snapshot consistency + coalesced notify (deterministic, fake socket)
# --------------------------------------------------------------------------- #


class FakeSocket:
    def __init__(self, send_hook=None):
        self.sent = bytearray()
        self.send_calls = 0
        self.send_hook = send_hook

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)
        self.send_calls += 1
        if self.send_hook is not None:
            self.send_hook(self)

    def setsockopt(self, *_args) -> None:
        pass


def decode_all(data: bytes) -> list[dict]:
    pdus = []
    offset = 0
    while offset < len(data):
        (_v, _t, _f, length) = struct.unpack_from("!BBHI", data, offset)
        pdus.append(parse_pdu(bytes(data[offset : offset + length])))
        offset += length
    return pdus


def test_response_keeps_one_snapshot_and_notify_is_coalesced_to_latest():
    snap = store.rtr_snapshot()
    assert snap.serial == 0 and len(snap.entries) == 3

    state = {"mutated": False}

    def hook(fake: FakeSocket):
        # CacheResponse is call #1, prefixes are #2..#4. Mutate twice after
        # the second prefix PDU, i.e. deterministically mid-response.
        if not state["mutated"] and fake.send_calls == 3:
            enable_table(SEED_RECORDS + [{"prefix": "198.19.1.0/24",
                                          "max_length": 24, "origin_asn": 65081}], "m1")
            enable_table(
                SEED_RECORDS
                + [
                    {"prefix": "198.19.1.0/24", "max_length": 24, "origin_asn": 65081},
                    {"prefix": "198.19.2.0/24", "max_length": 24, "origin_asn": 65082},
                ],
                "m2",
            )
            state["mutated"] = True

    fake = FakeSocket(hook)
    handler = RTRConnection(fake, ("fake", 0), store)
    count = handler.send_table_response(snap)
    assert count == 3

    pdus = decode_all(bytes(fake.sent))
    assert types(pdus) == [
        PDU_CACHE_RESPONSE,
        PDU_IPV4_PREFIX,
        PDU_IPV4_PREFIX,
        PDU_IPV4_PREFIX,
        PDU_END_OF_DATA,
    ]
    # The whole response still describes the OLD snapshot/revision.
    assert sorted(p["prefix"] for p in pdus if p["type"] == PDU_IPV4_PREFIX) == sorted(
        r.prefix_text for r in snap.entries
    )
    assert pdus[-1]["serial"] == 0

    # Idle point: exactly one notify, carrying the NEWEST serial (2).
    handler.reported_serial = snap.serial
    assert handler.maybe_send_notify() is True
    after_first = len(decode_all(bytes(fake.sent)))
    assert decode_all(bytes(fake.sent))[-1]["serial"] == 2
    assert handler.maybe_send_notify() is False
    assert len(decode_all(bytes(fake.sent))) == after_first


# --------------------------------------------------------------------------- #
# Slow client isolation (real TCP, small buffers)
# --------------------------------------------------------------------------- #


def _big_table(n: int) -> list[dict]:
    records = []
    for i in range(n):
        records.append(
            {
                "prefix": f"10.{i // 256}.{i % 256}.0/24",
                "max_length": 24,
                "origin_asn": 65000 + i,
            }
        )
    return records


def test_slow_connection_does_not_block_enables_or_others_and_gets_one_latest_notify():
    n = 6000
    big = _big_table(n)
    store.reset({"version": "big-1", "records": big})

    server = RTRServer(
        store, "127.0.0.1", 0, client_send_buffer=4096
    ).start()
    try:
        port = server.server_port

        # Slow router: tiny receive buffer, reads one PDU then stalls.
        slow = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        slow.settimeout(20.0)
        slow.connect(("127.0.0.1", port))
        slow.sendall(pdu_reset_query())
        recv_exact(slow, 8 + 20)  # Cache Response + first IPv4 PDU
        time.sleep(0.5)  # let the server fill buffers and block mid-response

        extra1 = {"prefix": "198.19.1.0/24", "max_length": 24, "origin_asn": 65081}
        extra2 = {"prefix": "198.19.2.0/24", "max_length": 24, "origin_asn": 65082}

        # Two revisions while the slow router is still receiving revision 0.
        started = time.perf_counter()
        r1 = enable_table(big + [extra1], "big-2")
        r2 = enable_table(big + [extra1, extra2], "big-3")
        enable_elapsed = time.perf_counter() - started
        assert r1["rtr"]["serial_advanced"] and r1["rtr"]["serial"] == 1
        assert r2["rtr"]["serial"] == 2
        # Enables do no socket I/O and must not wait on the slow connection.
        assert enable_elapsed < 2.0

        # Another router fetches the NEW table in full while slow is stalled.
        with connect(port, timeout=10.0) as fast:
            fast.sendall(pdu_reset_query())
            fast_pdus = read_until_end(fast)
        fast_prefixes = [p for p in fast_pdus if p["type"] == PDU_IPV4_PREFIX]
        assert len(fast_prefixes) == n + 2
        assert fast_pdus[-1]["type"] == PDU_END_OF_DATA
        assert fast_pdus[-1]["serial"] == 2

        # Finally let the slow router drain: it must still own revision 0.
        remaining = read_until_end(slow)
        remaining_prefixes = [p for p in remaining if p["type"] == PDU_IPV4_PREFIX]
        assert len(remaining_prefixes) == n - 1  # first PDU consumed earlier
        eod = remaining[-1]
        assert eod["type"] == PDU_END_OF_DATA
        assert eod["serial"] == 0

        # Exactly one coalesced notify with the newest serial (2).
        notify = read_pdu(slow)
        assert notify["type"] == PDU_SERIAL_NOTIFY
        assert notify["serial"] == 2

        slow.settimeout(0.8)
        with pytest.raises(socket.timeout):
            read_pdu(slow)
        slow.close()
    finally:
        server.stop()
