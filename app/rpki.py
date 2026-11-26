"""RPKI / ROA matching primitives for IPv4 prefixes.

Terminology used across the service:

* ROA / authorization record: ``(prefix, max_length, origin_asn)`` verified by
  the validator whose table is being replaced.
* Route: an IPv4 BGP announcement identified by ``(prefix, origin_asn)``.
* Valid: at least one covering authorization matches the origin ASN and the
  route length does not exceed that authorization's ``max_length``.
* Invalid: one or more authorizations cover the prefix, but none match both
  constraints.
* NotFound: no authorization covers the prefix.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import Iterable, Optional

INVALID = "invalid"
VALID = "valid"
NOT_FOUND = "not_found"

STATE_ORDER = (VALID, INVALID, NOT_FOUND)


def parse_ipv4_prefix(value: str) -> ipaddress.IPv4Network:
    """Parse a strict, canonical IPv4 prefix (host bits are rejected)."""
    if not isinstance(value, str):
        raise ValueError("prefix must be a string")
    text = value.strip()
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise ValueError(f"invalid IPv4 prefix {value!r}: {exc}") from exc
    if network.version != 4:
        raise ValueError(f"only IPv4 prefixes are supported, got {value!r}")
    return network


class RoaRecord:
    """A verified authorization (ROA-like record)."""

    __slots__ = ("prefix", "max_length", "origin_asn")

    def __init__(
        self,
        prefix: ipaddress.IPv4Network | str,
        max_length: int,
        origin_asn: int,
    ) -> None:
        net = parse_ipv4_prefix(prefix) if isinstance(prefix, str) else prefix
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError("only IPv4 prefixes are supported")
        if not net.prefixlen <= int(max_length) <= 32:
            raise ValueError(
                f"max_length {max_length} out of range for {net} "
                f"(prefix length {net.prefixlen})"
            )
        if not 0 <= int(origin_asn) <= 4_294_967_295:
            raise ValueError(f"origin ASN {origin_asn} out of 32-bit range")
        self.prefix = net
        self.max_length = int(max_length)
        self.origin_asn = int(origin_asn)

    @property
    def prefix_text(self) -> str:
        return str(self.prefix)

    def as_dict(self) -> dict:
        return {
            "prefix": str(self.prefix),
            "max_length": self.max_length,
            "origin_asn": self.origin_asn,
        }

    def canonical_tuple(self) -> tuple[str, int, int]:
        return (str(self.prefix), self.max_length, self.origin_asn)


def table_fingerprint(records: Iterable[RoaRecord]) -> str:
    """Content identity of an authorization table.

    Order independent and duplicate independent: the canonical record tuples
    are sorted and de-duplicated before hashing.
    """
    canonical = sorted({r.canonical_tuple() for r in records})
    blob = json.dumps(
        canonical, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()[:16]


def _cover_detail(
    roa: RoaRecord, network: ipaddress.IPv4Network, origin_asn: int
) -> Optional[dict]:
    """Return per-ROA match detail when ``roa`` covers ``network``."""
    if network.prefixlen < roa.prefix.prefixlen:
        return None
    # subnet_of also accepts equal networks.
    if not network.subnet_of(roa.prefix):
        return None
    return {
        "prefix": str(roa.prefix),
        "max_length": roa.max_length,
        "origin_asn": roa.origin_asn,
        "asn_match": origin_asn == roa.origin_asn,
        "length_ok": network.prefixlen <= roa.max_length,
    }


def evaluate_network(
    network: ipaddress.IPv4Network,
    origin_asn: int,
    records: Iterable[RoaRecord],
) -> dict:
    """Evaluate one already-parsed route against an authorization table."""
    covering = [
        detail
        for roa in records
        if (detail := _cover_detail(roa, network, origin_asn)) is not None
    ]

    if not covering:
        return {"state": NOT_FOUND, "reason": None, "covering": []}

    if any(item["asn_match"] and item["length_ok"] for item in covering):
        return {"state": VALID, "reason": None, "covering": covering}

    has_length_ok = any(item["length_ok"] for item in covering)
    has_asn_match = any(item["asn_match"] for item in covering)
    if has_length_ok and not has_asn_match:
        reason = "origin_as_unauthorized"
    elif has_asn_match and not has_length_ok:
        reason = "max_length_exceeded"
    else:
        reason = "origin_as_or_max_length_mismatch"

    return {"state": INVALID, "reason": reason, "covering": covering}


def evaluate_route(prefix: str, origin_asn: int, records: Iterable[RoaRecord]) -> dict:
    return evaluate_network(parse_ipv4_prefix(prefix), int(origin_asn), records)


def count_states(
    routes: Iterable["RouteLike"],  # noqa: F821 - duck typed (prefix, origin_asn)
    records: Iterable[RoaRecord],
) -> dict:
    counts = {VALID: 0, INVALID: 0, NOT_FOUND: 0}
    for route in routes:
        verdict = evaluate_route(route.prefix, route.origin_asn, records)
        counts[verdict["state"]] += 1
    return counts


def diff_new_invalid(
    routes: Iterable["RouteLike"],  # noqa: F821
    active_records: Iterable[RoaRecord],
    candidate_records: Iterable[RoaRecord],
) -> list[dict]:
    """Routes allowed by the active table but INVALID under the candidate.

    "Allowed" means either Valid or NotFound under the active table; only
    routes that become Invalid are blocking for a cut-over. Routes already
    Invalid under the active table are not "new" and therefore not blockers.
    Only currently present (still announced) routes are passed in, so this
    same function serves both submission-time trial and enable-time recheck.
    """
    blockers: list[dict] = []
    for route in routes:
        network = parse_ipv4_prefix(route.prefix)
        active_verdict = evaluate_network(network, route.origin_asn, active_records)
        candidate_verdict = evaluate_network(
            network, route.origin_asn, candidate_records
        )
        if candidate_verdict["state"] != INVALID:
            continue
        if active_verdict["state"] == INVALID:
            continue
        blockers.append(
            {
                "prefix": route.prefix,
                "origin_asn": route.origin_asn,
                "active_state": active_verdict["state"],
                "candidate_state": candidate_verdict["state"],
                "candidate_reason": candidate_verdict["reason"],
                "covering": candidate_verdict["covering"],
                "first_seen_at": getattr(route, "first_seen_at", None),
                "last_seen_at": getattr(route, "last_seen_at", None),
                "collector": getattr(route, "last_collector", None),
            }
        )
    blockers.sort(key=lambda item: (item["prefix"], item["origin_asn"]))
    return blockers
