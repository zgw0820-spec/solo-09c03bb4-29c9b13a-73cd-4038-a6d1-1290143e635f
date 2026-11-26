#!/usr/bin/env python3
"""Minimal local RFC 8210 RTR version 1 client (stdlib only).

Used by scripts/demo_rtr.sh and handy for manual checks against the service
or a ``docker compose`` deployment (TCP port 8282).

Examples
--------
# Fetch the full active table (Reset Query):
python3 scripts/rtr_client.py reset
python3 scripts/rtr_client.py reset --json

# Poll with the session/serial learned from a previous fetch:
python3 scripts/rtr_client.py serial 0 --session 12345 --json
#   -> {"status": "empty_update", ...}   (session+serial current)
#   -> {"status": "cache_reset", ...}    (serial/session stale)

# Stay connected, show Serial Notifies, and re-fetch after each notify:
python3 scripts/rtr_client.py watch --duration 10 --refetch
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
from typing import Optional

RTR_VERSION = 1

T_SERIAL_NOTIFY = 0
T_SERIAL_QUERY = 1
T_RESET_QUERY = 2
T_CACHE_RESPONSE = 3
T_IPV4_PREFIX = 4
T_END_OF_DATA = 7
T_CACHE_RESET = 8
T_ERROR_REPORT = 10

TYPE_NAMES = {
    0: "Serial Notify",
    1: "Serial Query",
    2: "Reset Query",
    3: "Cache Response",
    4: "IPv4 Prefix",
    6: "IPv6 Prefix",
    7: "End of Data",
    8: "Cache Reset",
    10: "Error Report",
}


def reset_query() -> bytes:
    return struct.pack("!BBHI", RTR_VERSION, T_RESET_QUERY, 0, 8)


def serial_query(session_id: int, serial: int) -> bytes:
    return struct.pack("!BBHII", RTR_VERSION, T_SERIAL_QUERY, session_id, 12, serial)


class RtrReader:
    """Length-delimited PDU reader with an internal partial-read buffer."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def _fill_until(self, size: int) -> None:
        while len(self.buf) < size:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed by server")
            self.buf += chunk

    def read_pdu(self) -> dict:
        self._fill_until(8)
        version, ptype, field16, length = struct.unpack_from("!BBHI", self.buf, 0)
        if length < 8:
            raise ValueError(f"bad PDU length {length}")
        self._fill_until(length)
        raw = self.buf[:length]
        self.buf = self.buf[length:]
        return decode_pdu(raw, version, ptype, field16, length)


def decode_pdu(raw: bytes, version: int, ptype: int, field16: int, length: int) -> dict:
    pdu: dict = {
        "version": version,
        "type": ptype,
        "type_name": TYPE_NAMES.get(ptype, f"Unknown({ptype})"),
        "length": length,
    }
    if ptype in (T_SERIAL_NOTIFY, T_SERIAL_QUERY, T_END_OF_DATA):
        (serial,) = struct.unpack_from("!I", raw, 8)
        pdu["session_id"] = field16
        pdu["serial"] = serial
    elif ptype == T_CACHE_RESPONSE:
        pdu["session_id"] = field16
    elif ptype == T_IPV4_PREFIX:
        flags, plen, mlen, _ = struct.unpack_from("!BBBB", raw, 8)
        addr = socket.inet_ntoa(raw[12:16])
        (asn,) = struct.unpack_from("!I", raw, 16)
        pdu.update(
            flags=flags,
            is_announcement=bool(flags & 0x01),
            prefix=f"{addr}/{plen}",
            prefix_length=plen,
            max_length=mlen,
            origin_asn=asn,
        )
    elif ptype == T_ERROR_REPORT and len(raw) >= 12:
        (enc_len,) = struct.unpack_from("!I", raw, 8)
        text_len_offset = 12 + enc_len
        text = ""
        if len(raw) >= text_len_offset + 4:
            (text_len,) = struct.unpack_from("!I", raw, text_len_offset)
            text = raw[text_len_offset + 4 : text_len_offset + 4 + text_len].decode(
                "utf-8", "replace"
            )
        pdu["error_code"] = field16
        pdu["error_text"] = text
    return pdu


def connect(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(1.0)
    return sock


def fetch_table(reader: RtrReader, query: bytes) -> dict:
    """Send query and read until End of Data / Cache Reset.

    Takes a shared :class:`RtrReader` so bytes already buffered after an
    unrelated PDU are not lost (important for watch -> re-fetch).
    """
    reader.sock.sendall(query)
    prefixes: list[dict] = []
    session_id: Optional[int] = None
    serial: Optional[int] = None
    saw_cache_response = False

    while True:
        pdu = reader.read_pdu()
        if pdu["type"] == T_CACHE_RESPONSE:
            saw_cache_response = True
            session_id = pdu["session_id"]
        elif pdu["type"] == T_IPV4_PREFIX:
            prefixes.append(
                {
                    "prefix": pdu["prefix"],
                    "max_length": pdu["max_length"],
                    "origin_asn": pdu["origin_asn"],
                    "flags": pdu["flags"],
                    "is_announcement": pdu["is_announcement"],
                }
            )
        elif pdu["type"] == T_END_OF_DATA:
            session_id = pdu["session_id"]
            serial = pdu["serial"]
            return {
                "status": "end_of_data",
                "update_kind": (
                    "empty_update" if saw_cache_response and not prefixes else "full_update"
                ),
                "session_id": session_id,
                "serial": serial,
                "prefix_count": len(prefixes),
                "prefixes": prefixes,
            }
        elif pdu["type"] == T_CACHE_RESET:
            return {"status": "cache_reset", "prefix_count": len(prefixes)}
        elif pdu["type"] == T_ERROR_REPORT:
            return {
                "status": "error",
                "error_code": pdu.get("error_code"),
                "error_text": pdu.get("error_text", ""),
            }


def print_table(result: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if result["status"] == "cache_reset":
        print("<<< Cache Reset (router must Reset Query and re-fetch)")
        return
    if result["status"] == "error":
        print(f"<<< Error Report code={result['error_code']}: {result['error_text']}")
        return
    kind = "empty update" if result["prefix_count"] == 0 else "table update"
    print(
        f"<<< Cache Response + {result['prefix_count']} IPv4 Prefix PDU(s) + "
        f"End of Data (session={result['session_id']}, serial={result['serial']}) "
        f"[{kind}]"
    )
    for item in result["prefixes"]:
        flag = "A" if item["is_announcement"] else "W"
        print(
            f"    [{flag}] {item['prefix']:<18} "
            f"maxLength={item['max_length']:<2} AS{item['origin_asn']}"
        )


def cmd_reset(args: argparse.Namespace) -> int:
    with connect(args.host, args.port, args.timeout) as sock:
        result = fetch_table(RtrReader(sock), reset_query())
    print_table(result, args.json)
    return 0 if result["status"] == "end_of_data" else 2


def cmd_serial(args: argparse.Namespace) -> int:
    with connect(args.host, args.port, args.timeout) as sock:
        result = fetch_table(RtrReader(sock), serial_query(args.session, args.serial))
    if args.json:
        out = dict(result)
        if result["status"] == "end_of_data" and result["prefix_count"] == 0:
            out["status"] = "empty_update"
        elif result["status"] == "end_of_data":
            out["status"] = "incremental_update"
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print_table(result, False)
        if result["status"] == "end_of_data" and result["prefix_count"] == 0:
            print("    => session id and serial match current; empty update")
        elif result["status"] == "cache_reset":
            print("    => session/serial mismatch (or stale); server asks for Cache Reset")
    if result["status"] == "cache_reset":
        return 3
    return 0 if result["status"] == "end_of_data" else 2


def cmd_watch(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.duration if args.duration > 0 else None
    with connect(args.host, args.port, args.timeout) as sock:
        reader = RtrReader(sock)
        if not args.no_reset:
            result = fetch_table(reader, reset_query())
            if args.json:
                print(json.dumps({"event": "initial_table", **result}, ensure_ascii=False))
            else:
                print_table(result, False)
                print("--- watching for Serial Notify (Ctrl-C to stop) ---")

        while deadline is None or time.monotonic() < deadline:
            remaining = 1.0 if deadline is None else min(1.0, max(0.05, deadline - time.monotonic()))
            sock.settimeout(remaining)
            try:
                pdu = reader.read_pdu()
            except socket.timeout:
                continue
            if pdu["type"] == T_SERIAL_NOTIFY:
                if args.json:
                    print(
                        json.dumps(
                            {
                                "event": "serial_notify",
                                "session_id": pdu["session_id"],
                                "serial": pdu["serial"],
                            },
                            ensure_ascii=False,
                        ),
                        flush=True,
                    )
                else:
                    print(
                        f"<<< Serial Notify: session={pdu['session_id']} "
                        f"newest serial={pdu['serial']}",
                        flush=True,
                    )
                if args.refetch:
                    # A full re-fetch may stream many PDUs; use the generous
                    # configured timeout per recv rather than the watch tick.
                    sock.settimeout(max(args.timeout, 1.0))
                    result = fetch_table(reader, reset_query())
                    sock.settimeout(remaining)
                    if args.json:
                        print(
                            json.dumps({"event": "refetched", **result}, ensure_ascii=False),
                            flush=True,
                        )
                    else:
                        print_table(result, False)
            elif pdu["type"] == T_ERROR_REPORT:
                if args.json:
                    print(json.dumps({"event": "error", **pdu}, ensure_ascii=False), flush=True)
                else:
                    print(f"<<< Error Report: {pdu.get('error_text', '')}")
            else:
                if args.json:
                    print(json.dumps({"event": "pdu", **pdu}, ensure_ascii=False, default=str))
                else:
                    print(f"<<< {pdu['type_name']}: {pdu}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local RFC 8210 RTR v1 client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8282)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--json", action="store_true", default=False,
                        help="JSON output (may also be given after the subcommand)")

    # Allows `rtr_client.py reset --json` as well as `--json reset`.
    json_parent = argparse.ArgumentParser(add_help=False)
    json_parent.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("reset", parents=[json_parent], help="Send Reset Query and print full table")

    serial_p = sub.add_parser("serial", parents=[json_parent], help="Send Serial Query")
    serial_p.add_argument("serial", type=int, help="Last seen serial number")
    serial_p.add_argument("--session", type=int, required=True, help="RTR session id")

    watch_p = sub.add_parser("watch", parents=[json_parent],
                             help="Listen for Serial Notify PDUs")
    watch_p.add_argument("--duration", type=float, default=8.0, help="0 = forever")
    watch_p.add_argument(
        "--no-reset", action="store_true", help="Do not fetch a table before watching"
    )
    watch_p.add_argument(
        "--refetch",
        action="store_true",
        help="Automatically Reset Query after each Serial Notify",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "reset":
            return cmd_reset(args)
        if args.command == "serial":
            return cmd_serial(args)
        if args.command == "watch":
            return cmd_watch(args)
    except (OSError, ConnectionError, ValueError) as exc:
        print(f"rtr_client: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
