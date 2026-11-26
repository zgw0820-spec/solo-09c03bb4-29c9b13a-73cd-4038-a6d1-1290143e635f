"""In-memory singleton state: active table, live routes, candidates/trials.

The service is explicitly single-instance. A re-entrant lock serializes all
state transitions; because table switching is an atomic reference swap under
that lock, an announcement is always judged by exactly one effective table,
and the enable-time recheck sees a consistent route set.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .rpki import (
    RoaRecord,
    count_states,
    diff_new_invalid,
    evaluate_route,
    table_fingerprint,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SEED_PATH = Path(
    os.getenv("RPKI_SEED_PATH", str(PROJECT_ROOT / "data" / "active_table.json"))
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class StoreConflict(Exception):
    """A state conflict that maps to HTTP 409 with a structured detail."""

    def __init__(self, code: str, message: str, extra: Optional[dict] = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = extra or {}


@dataclass
class RouteState:
    prefix: str
    origin_asn: int
    first_seen_at: str
    last_seen_at: str
    announcement_count: int = 1
    last_collector: Optional[str] = None
    last_peer: Optional[str] = None

    @property
    def key(self) -> tuple[str, int]:
        return (self.prefix, self.origin_asn)

    def as_dict(self) -> dict:
        return {
            "prefix": self.prefix,
            "origin_asn": self.origin_asn,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "announcement_count": self.announcement_count,
            "last_collector": self.last_collector,
            "last_peer": self.last_peer,
        }


@dataclass
class Candidate:
    id: str
    version: str
    description: Optional[str]
    records: list[RoaRecord]
    fingerprint: str
    created_at: str
    updated_at: str
    trials: dict[str, dict] = field(default_factory=dict)
    latest_trial_id: Optional[str] = None
    enabled_at: Optional[str] = None

    def summary(self) -> dict:
        return {
            "candidate_id": self.id,
            "version": self.version,
            "description": self.description,
            "fingerprint": self.fingerprint,
            "record_count": len(self.records),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "latest_trial_id": self.latest_trial_id,
            "enabled_at": self.enabled_at,
        }


class Store:
    def __init__(self, seed_table: dict) -> None:
        self.lock = threading.RLock()
        self._load_seed_into_state(seed_table)
        self.routes: dict[tuple[str, int], RouteState] = {}
        self.candidates: dict[str, Candidate] = {}

    def _load_seed_into_state(self, seed_table: dict) -> None:
        records = [
            RoaRecord(
                prefix=item["prefix"],
                max_length=int(item["max_length"]),
                origin_asn=int(item["origin_asn"]),
            )
            for item in seed_table.get("records", [])
        ]
        self.seed_version = seed_table.get("version", "seed-unknown")
        self.seed_description = seed_table.get("description")
        self.active_version: str = str(seed_table.get("version", "active-1"))
        self.active_description: Optional[str] = seed_table.get("description")
        self.active_records: list[RoaRecord] = records
        self.active_fingerprint: str = table_fingerprint(records)
        self.activated_at: str = utc_now_iso()

    def reset(self, seed_table: dict) -> None:
        """Restore the freshly seeded state (used by tests)."""
        with self.lock:
            self._load_seed_into_state(seed_table)
            self.routes.clear()
            self.candidates.clear()

    # ------------------------------------------------------------------ views

    def active_table_view(self) -> dict:
        with self.lock:
            return {
                "version": self.active_version,
                "description": self.active_description,
                "fingerprint": self.active_fingerprint,
                "record_count": len(self.active_records),
                "activated_at": self.activated_at,
                "records": [r.as_dict() for r in self.active_records],
            }

    def health(self) -> dict:
        with self.lock:
            invalid = sum(
                1
                for route in self.routes.values()
                if evaluate_route(route.prefix, route.origin_asn, self.active_records)[
                    "state"
                ]
                == "invalid"
            )
            return {
                "status": "ok",
                "time": utc_now_iso(),
                "active_version": self.active_version,
                "active_fingerprint": self.active_fingerprint,
                "announced_routes": len(self.routes),
                "invalid_routes_under_active_table": invalid,
                "candidates": len(self.candidates),
            }

    def list_routes(self, state_filter: Optional[str] = None) -> list[dict]:
        with self.lock:
            items = []
            for route in sorted(self.routes.values(), key=lambda r: r.key):
                verdict = evaluate_route(
                    route.prefix, route.origin_asn, self.active_records
                )
                if state_filter and verdict["state"] != state_filter:
                    continue
                items.append({**route.as_dict(), "validation": verdict})
            return items

    # ------------------------------------------------------------- BGP ingress

    def announce(
        self,
        prefix: str,
        origin_asn: int,
        collector: Optional[str] = None,
        peer: Optional[str] = None,
    ) -> dict:
        with self.lock:
            key = (prefix, int(origin_asn))
            now = utc_now_iso()
            route = self.routes.get(key)
            if route is None:
                route = RouteState(
                    prefix=prefix,
                    origin_asn=int(origin_asn),
                    first_seen_at=now,
                    last_seen_at=now,
                    last_collector=collector,
                    last_peer=peer,
                )
                self.routes[key] = route
            else:
                route.last_seen_at = now
                route.announcement_count += 1
                if collector is not None:
                    route.last_collector = collector
                if peer is not None:
                    route.last_peer = peer

            # Judged by the table effective at receipt time, inside the lock.
            verdict = evaluate_route(prefix, origin_asn, self.active_records)
            return {
                "accepted": True,
                "received_at": now,
                "active_version": self.active_version,
                "active_fingerprint": self.active_fingerprint,
                "route": route.as_dict(),
                "validation": verdict,
            }

    def withdraw(
        self,
        prefix: str,
        origin_asn: Optional[int] = None,
        collector: Optional[str] = None,
    ) -> dict:
        with self.lock:
            if origin_asn is not None:
                keys = [(prefix, int(origin_asn))]
            else:
                keys = [key for key in self.routes if key[0] == prefix]

            removed: list[dict] = []
            for key in keys:
                route = self.routes.pop(key, None)
                if route is None:
                    continue
                last_verdict = evaluate_route(
                    route.prefix, route.origin_asn, self.active_records
                )
                item = route.as_dict()
                item["last_validation_under_active_table"] = last_verdict
                if collector is not None:
                    item["withdrawn_by_collector"] = collector
                removed.append(item)

            removed.sort(key=lambda r: (r["prefix"], r["origin_asn"]))
            return {
                "prefix": prefix,
                "origin_asn": origin_asn,
                "removed_count": len(removed),
                "removed": removed,
                "active_version": self.active_version,
                "processed_at": utc_now_iso(),
            }

    # ------------------------------------------------------------- candidates

    def _records_from_dicts(self, items: list) -> list[RoaRecord]:
        return [
            RoaRecord(
                prefix=item.prefix if hasattr(item, "prefix") else item["prefix"],
                max_length=(
                    item.max_length if hasattr(item, "max_length") else item["max_length"]
                ),
                origin_asn=(
                    item.origin_asn if hasattr(item, "origin_asn") else item["origin_asn"]
                ),
            )
            for item in items
        ]

    def create_candidate(
        self,
        candidate_id: Optional[str],
        version: Optional[str],
        description: Optional[str],
        record_models: list,
    ) -> tuple[Candidate, dict, bool]:
        with self.lock:
            cid = candidate_id or f"cand-{uuid.uuid4().hex[:12]}"
            if cid in self.candidates:
                raise StoreConflict(
                    "CANDIDATE_EXISTS",
                    f"candidate {cid!r} already exists; use PUT to replace it",
                    {"candidate_id": cid},
                )
            records = self._records_from_dicts(record_models)
            fingerprint = table_fingerprint(records)
            resolved_version = version or f"candidate-{fingerprint.split(':', 1)[1]}"
            now = utc_now_iso()
            candidate = Candidate(
                id=cid,
                version=resolved_version,
                description=description,
                records=records,
                fingerprint=fingerprint,
                created_at=now,
                updated_at=now,
            )
            self.candidates[cid] = candidate
            trial = self._build_trial(candidate)
            candidate.latest_trial_id = trial["trial_id"]
            candidate.trials[trial["trial_id"]] = trial
            return candidate, trial, True

    def replace_candidate(
        self,
        candidate_id: str,
        version: Optional[str],
        description: Optional[str],
        record_models: list,
    ) -> tuple[Candidate, dict]:
        with self.lock:
            records = self._records_from_dicts(record_models)
            fingerprint = table_fingerprint(records)
            resolved_version = version or f"candidate-{fingerprint.split(':', 1)[1]}"
            existing = self.candidates.get(candidate_id)
            now = utc_now_iso()
            if existing is None:
                candidate = Candidate(
                    id=candidate_id,
                    version=resolved_version,
                    description=description,
                    records=records,
                    fingerprint=fingerprint,
                    created_at=now,
                    updated_at=now,
                )
                self.candidates[candidate_id] = candidate
            else:
                # Whole-table replacement: prior trial tokens describe the old
                # authorization version/content and become stale.
                existing.version = resolved_version
                existing.description = description
                existing.records = records
                existing.fingerprint = fingerprint
                existing.updated_at = now
                candidate = existing
            trial = self._build_trial(candidate)
            candidate.latest_trial_id = trial["trial_id"]
            candidate.trials[trial["trial_id"]] = trial
            return candidate, trial

    def list_candidates(self) -> list[dict]:
        with self.lock:
            return [c.summary() for c in sorted(self.candidates.values(), key=lambda c: c.created_at)]

    def get_candidate(self, candidate_id: str) -> Optional[Candidate]:
        with self.lock:
            return self.candidates.get(candidate_id)

    def candidate_detail(self, candidate_id: str) -> Optional[dict]:
        with self.lock:
            candidate = self.candidates.get(candidate_id)
            if candidate is None:
                return None
            latest = (
                candidate.trials.get(candidate.latest_trial_id)
                if candidate.latest_trial_id
                else None
            )
            return {
                **candidate.summary(),
                "records": [r.as_dict() for r in candidate.records],
                "latest_trial": latest,
                "trial_ids": list(candidate.trials.keys()),
            }

    def run_trial(self, candidate_id: str) -> dict:
        with self.lock:
            candidate = self.candidates.get(candidate_id)
            if candidate is None:
                raise KeyError(candidate_id)
            trial = self._build_trial(candidate)
            candidate.latest_trial_id = trial["trial_id"]
            candidate.trials[trial["trial_id"]] = trial
            return trial

    def _build_trial(self, candidate: Candidate) -> dict:
        """Compute the trial against the routes currently in the table."""
        routes = list(self.routes.values())
        blockers = diff_new_invalid(
            routes, self.active_records, candidate.records
        )
        active_counts = count_states(routes, self.active_records)
        candidate_counts = count_states(routes, candidate.records)
        return {
            "trial_id": f"trial-{uuid.uuid4().hex[:12]}",
            "candidate_id": candidate.id,
            "created_at": utc_now_iso(),
            "authorization_version": candidate.version,
            "authorization_fingerprint": candidate.fingerprint,
            "active_version_at_trial": self.active_version,
            "active_fingerprint_at_trial": self.active_fingerprint,
            "routes_evaluated": len(routes),
            "new_invalid_count": len(blockers),
            "new_invalid": blockers,
            "summary": {
                "active": active_counts,
                "candidate": candidate_counts,
            },
        }

    # --------------------------------------------------------------- enable

    def enable_candidate(
        self,
        candidate_id: str,
        trial_id: Optional[str] = None,
        expected_version: Optional[str] = None,
    ) -> dict:
        """Validate trial freshness, re-check live routes, then swap table.

        Raises StoreConflict with codes:
          * CANDIDATE_NOT_FOUND (mapped to 404 by the API layer)
          * TRIAL_REQUIRED
          * RETRIAL_REQUIRED (candidate authorization or active table moved)
          * ENABLE_BLOCKED (fresh recheck found new Invalid routes)
        """
        with self.lock:
            candidate = self.candidates.get(candidate_id)
            if candidate is None:
                raise KeyError(candidate_id)

            # Idempotent no-op: this exact authorization version/content is
            # already the effective table. Same content under a new version
            # label still goes through the checks and re-labels the active table.
            if (
                candidate.fingerprint == self.active_fingerprint
                and candidate.version == self.active_version
            ):
                return {
                    "enabled": True,
                    "already_active": True,
                    "candidate_id": candidate.id,
                    "active_version": self.active_version,
                    "active_fingerprint": self.active_fingerprint,
                    "activated_at": self.activated_at,
                }

            if expected_version is not None and expected_version != candidate.version:
                raise StoreConflict(
                    "RETRIAL_REQUIRED",
                    "提交试算后候选授权版号已变化，需重新试算后再启用",
                    {
                        "candidate_id": candidate.id,
                        "trial_authorization_version": expected_version,
                        "current_authorization_version": candidate.version,
                        "current_authorization_fingerprint": candidate.fingerprint,
                        "reason": "candidate_authorization_changed",
                    },
                )

            if trial_id is not None:
                trial = candidate.trials.get(trial_id)
                if trial is None:
                    raise StoreConflict(
                        "TRIAL_NOT_FOUND",
                        f"trial {trial_id!r} does not belong to candidate "
                        f"{candidate_id!r}",
                        {"candidate_id": candidate.id, "trial_id": trial_id},
                    )
            else:
                if candidate.latest_trial_id is None:
                    raise StoreConflict(
                        "TRIAL_REQUIRED", "候选表尚未试算", {"candidate_id": candidate.id}
                    )
                trial = candidate.trials[candidate.latest_trial_id]

            # "授权版已变就要求重做试算": either the version label or the
            # actual content fingerprint moved since the trial token was issued.
            if (
                trial["authorization_fingerprint"] != candidate.fingerprint
                or trial["authorization_version"] != candidate.version
            ):
                changed_fields = []
                if trial["authorization_version"] != candidate.version:
                    changed_fields.append("version")
                if trial["authorization_fingerprint"] != candidate.fingerprint:
                    changed_fields.append("records")
                raise StoreConflict(
                    "RETRIAL_REQUIRED",
                    "试算所用授权表已变更（"
                    + "/".join(changed_fields)
                    + "），请重新试算后再启用",
                    {
                        "candidate_id": candidate.id,
                        "trial_id": trial["trial_id"],
                        "reason": "candidate_authorization_changed",
                        "changed_fields": changed_fields,
                        "trial_authorization_version": trial[
                            "authorization_version"
                        ],
                        "current_authorization_version": candidate.version,
                        "trial_authorization_fingerprint": trial[
                            "authorization_fingerprint"
                        ],
                        "current_authorization_fingerprint": candidate.fingerprint,
                    },
                )

            # ... or the effective table itself changed since the trial.
            if trial["active_fingerprint_at_trial"] != self.active_fingerprint:
                raise StoreConflict(
                    "RETRIAL_REQUIRED",
                    "试算基准生效表已变更，请重新试算后再启用",
                    {
                        "candidate_id": candidate.id,
                        "trial_id": trial["trial_id"],
                        "reason": "active_table_changed",
                        "trial_active_version": trial["active_version_at_trial"],
                        "current_active_version": self.active_version,
                    },
                )

            # "未变也要按启用时仍在播的路由重核": always recompute from the
            # live route set rather than trusting the submission-time result.
            live_routes = list(self.routes.values())
            blockers = diff_new_invalid(
                live_routes, self.active_records, candidate.records
            )
            recheck = {
                "checked_at": utc_now_iso(),
                "routes_checked": len(live_routes),
                "new_invalid_count": len(blockers),
            }
            if blockers:
                raise StoreConflict(
                    "ENABLE_BLOCKED",
                    f"启用重核发现 {len(blockers)} 条将新增为 Invalid 的在播路由，"
                    "已保留原生效表；请撤回相关路由或修订候选表",
                    {
                        "candidate_id": candidate.id,
                        "trial_id": trial["trial_id"],
                        "active_version": self.active_version,
                        "active_fingerprint": self.active_fingerprint,
                        "recheck": recheck,
                        "blockers": blockers,
                    },
                )

            # Atomic cut-over.
            previous_version = self.active_version
            self.active_records = candidate.records
            self.active_fingerprint = candidate.fingerprint
            self.active_version = candidate.version
            self.active_description = candidate.description
            self.activated_at = utc_now_iso()
            candidate.enabled_at = self.activated_at
            return {
                "enabled": True,
                "already_active": False,
                "candidate_id": candidate.id,
                "trial_id": trial["trial_id"],
                "previous_active_version": previous_version,
                "active_version": self.active_version,
                "active_fingerprint": self.active_fingerprint,
                "activated_at": self.activated_at,
                "recheck": recheck,
            }


def load_seed_table(path: Path | str = DEFAULT_SEED_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


# Process-wide singleton. Single uvicorn worker only.
store = Store(load_seed_table())
