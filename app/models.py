"""Pydantic request/response schemas (also drives the OpenAPI page)."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Optional

from pydantic import BaseModel, BeforeValidator, Field, AfterValidator


def _normalize_asn(value: object) -> int:
    if isinstance(value, str):
        text = value.strip().lower()
        if text.startswith("as"):
            text = text[2:]
        value = text
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid ASN: {value!r}") from exc


Asn = Annotated[
    int,
    BeforeValidator(_normalize_asn),
    Field(ge=0, le=4_294_967_295, description="32-bit ASN; 'AS65001' accepted"),
]


def _canonical_ipv4_prefix(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("prefix must be a string")
    try:
        network = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    if network.version != 4:
        raise ValueError("only IPv4 prefixes are supported")
    return str(network)


Ipv4Prefix = Annotated[
    str,
    AfterValidator(_canonical_ipv4_prefix),
    Field(description="Canonical strict IPv4 prefix, e.g. 192.0.2.0/24"),
]


class RoaRecordIn(BaseModel):
    prefix: Ipv4Prefix
    max_length: int = Field(..., ge=0, le=32, examples=[24])
    origin_asn: Asn = Field(..., examples=[65001])

    def model_post_init(self, __context: object) -> None:
        network = ipaddress.ip_network(self.prefix)
        if self.max_length < network.prefixlen:
            raise ValueError(
                f"max_length {self.max_length} must be >= prefix length "
                f"{network.prefixlen} for {self.prefix}"
            )


class CandidateTableIn(BaseModel):
    """A whole candidate authorization table."""

    version: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Authorization version label from the validator export. "
        "If omitted, a content-derived label is assigned.",
        examples=["2026-11-26-v2"],
    )
    description: Optional[str] = Field(default=None, max_length=512)
    records: list[RoaRecordIn] = Field(..., description="Full replacement table")
    candidate_id: Optional[str] = Field(
        default=None,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$",
        description="Optional client-chosen candidate id (POST only)",
    )


class PutCandidateIn(BaseModel):
    version: Optional[str] = Field(default=None, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    records: list[RoaRecordIn]


class AnnouncementIn(BaseModel):
    prefix: Ipv4Prefix
    origin_asn: Asn
    collector: Optional[str] = Field(default=None, max_length=128)
    peer: Optional[str] = Field(default=None, max_length=128)


class WithdrawalIn(BaseModel):
    prefix: Ipv4Prefix
    origin_asn: Optional[Asn] = Field(
        default=None,
        description="Withdraw one exact (prefix, ASN) route. If omitted, all "
        "currently announced origin ASNs for this prefix are withdrawn.",
    )
    collector: Optional[str] = Field(default=None, max_length=128)


class EnableIn(BaseModel):
    trial_id: Optional[str] = Field(
        default=None,
        description="Trial token returned at submission/retrial. When given, "
        "the server verifies the authorization version has not changed.",
    )
    authorization_version: Optional[str] = Field(
        default=None,
        description="Optional assertion of the authorization version that was "
        "trialed; mismatches are rejected with RETRIAL_REQUIRED.",
    )
