"""RFC 8210 (RTR) version 1 TCP interface for enabled IPv4 origin authorizations.

Scope (deliberately small)
--------------------------
* Speaks RTR protocol version 1, binary PDUs over TCP.
* ``Reset Query``  -> ``Cache Response`` + the **complete** active table as
  IPv4 Prefix PDUs + v1 ``End of Data`` carrying the table serial.
* ``Serial Query`` -> when BOTH session id and serial equal the current
  values: ``Cache Response`` + ``End of Data`` with zero prefix PDUs (empty
  update). Any mismatch -> ``Cache Reset``.
* No incremental updates: a stale serial always results in Cache Reset and
  the router re-fetches with Reset Query.
* Unsolicited ``Serial Notify`` is emitted when the store serial advances
  (which only happens on an enable that changes the record set).

Consistency / slow clients
--------------------------
Every table response is built from one :class:`RtrSnapshot` captured under
the store lock. The lock is released before any socket write, and all writes
for one connection happen on that connection's own daemon thread, so a slow
router can never block an enable, the store lock, accepts, or other routers.
If the table changes while a response is being written, the connection keeps
sending its captured revision through End of Data; at the next idle point it
sends at most one Serial Notify, carrying only the newest serial.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .store import Store

logger = logging.getLogger("app.rtr")

RTR_VERSION = 1
RTR_SERIAL_INITIAL = 0
DEFAULT_RTR_HOST = "0.0.0.0"
DEFAULT_RTR_PORT = 8282

# RFC 8210 PDU type codes.
PDU_SERIAL_NOTIFY = 0
PDU_SERIAL_QUERY = 1
PDU_RESET_QUERY = 2
PDU_CACHE_RESPONSE = 3
PDU_IPV4_PREFIX = 4
PDU_IPV6_PREFIX = 6
PDU_END_OF_DATA = 7
PDU_CACHE_RESET = 8
PDU_ROUTER_KEY = 9
PDU_ERROR_REPORT = 10

PDU_TYPE_NAMES = {
    PDU_SERIAL_NOTIFY: "Serial Notify",
    PDU_SERIAL_QUERY: "Serial Query",
    PDU_RESET_QUERY: "Reset Query",
    PDU_CACHE_RESPONSE: "Cache Response",
    PDU_IPV4_PREFIX: "IPv4 Prefix",
    PDU_IPV6_PREFIX: "IPv6 Prefix",
    PDU_END_OF_DATA: "End of Data",
    PDU_CACHE_RESET: "Cache Reset",
    PDU_ROUTER_KEY: "Router Key",
    PDU_ERROR_REPORT: "Error Report",
}

# RFC 8210 error codes used here.
ERR_CORRUPT_DATA = 0
ERR_INTERNAL = 1
ERR_INVALID_REQUEST = 3
ERR_UNSUPPORTED_VERSION = 4
ERR_UNSUPPORTED_PDU_TYPE = 5

_HEADER = struct.Struct("!BBHI")  # version, type, session/reserved, length
_SERIAL_PDU = struct.Struct("!BBHII")  # + serial
_PREFIX_BODY = struct.Struct("!BBBB4sI")  # flags, plen, maxlen, zero, addr, asn

# We only ever receive 8/12-byte queries; reject absurd framing early.
MAX_RECEIVE_PDU = 65536
_READ_POLL_SECONDS = 0.2


@dataclass(frozen=True)
class RtrSnapshot:
    """One immutable revision of the active authorization table."""

    session_id: int
    serial: int
    entries: tuple  # tuple[RoaRecord, ...]
    active_version: str = ""
    fingerprint: str = ""


# --------------------------------------------------------------------------- #
# PDU encoding
# --------------------------------------------------------------------------- #


def pdu_serial_notify(session_id: int, serial: int) -> bytes:
    return _SERIAL_PDU.pack(
        RTR_VERSION, PDU_SERIAL_NOTIFY, session_id & 0xFFFF, 12, serial & 0xFFFFFFFF
    )


def pdu_serial_query(session_id: int, serial: int, version: int = RTR_VERSION) -> bytes:
    return _SERIAL_PDU.pack(
        version, PDU_SERIAL_QUERY, session_id & 0xFFFF, 12, serial & 0xFFFFFFFF
    )


def pdu_reset_query(version: int = RTR_VERSION) -> bytes:
    return _HEADER.pack(version, PDU_RESET_QUERY, 0, 8)


def pdu_cache_response(session_id: int) -> bytes:
    return _HEADER.pack(RTR_VERSION, PDU_CACHE_RESPONSE, session_id & 0xFFFF, 8)


def pdu_cache_reset() -> bytes:
    # The reserved 16-bit field is zero; length is 8.
    return _HEADER.pack(RTR_VERSION, PDU_CACHE_RESET, 0, 8)


def pdu_end_of_data(session_id: int, serial: int) -> bytes:
    # RTR v1 End of Data carries the serial number and has length 12.
    return _SERIAL_PDU.pack(
        RTR_VERSION, PDU_END_OF_DATA, session_id & 0xFFFF, 12, serial & 0xFFFFFFFF
    )


def pdu_ipv4_prefix(record, is_announcement: bool = True) -> bytes:
    """Encode one RoaRecord as a 20-byte IPv4 Prefix PDU.

    Flags low-order bit: 1 = announcement, 0 = withdrawal (RFC 8210 5.6).
    This server only sends full-table announcements.
    """
    flags = 0x01 if is_announcement else 0x00
    addr = record.prefix.network_address.packed
    body = _PREFIX_BODY.pack(
        flags,
        record.prefix.prefixlen,
        record.max_length,
        0,
        addr,
        record.origin_asn & 0xFFFFFFFF,
    )
    return _HEADER.pack(RTR_VERSION, PDU_IPV4_PREFIX, 0, 20) + body


def pdu_error_report(error_code: int, erroneous_pdu: bytes, text: str = "") -> bytes:
    text_bytes = text.encode("utf-8")
    enc_len = len(erroneous_pdu)
    total_length = 8 + 4 + enc_len + 4 + len(text_bytes)
    return (
        struct.pack("!BBHI", RTR_VERSION, PDU_ERROR_REPORT, error_code & 0xFFFF, total_length)
        + struct.pack("!I", enc_len)
        + erroneous_pdu
        + struct.pack("!I", len(text_bytes))
        + text_bytes
    )


# --------------------------------------------------------------------------- #
# PDU decoding (used by the test-suite / cross checks; the demo client is
# self-contained on purpose so it can be copied off-box).
# --------------------------------------------------------------------------- #


def parse_pdu(pdu: bytes) -> dict:
    if len(pdu) < 8:
        raise ValueError(f"PDU shorter than 8 bytes: {len(pdu)}")
    version, ptype, field16, length = _HEADER.unpack_from(pdu, 0)
    info: dict = {
        "version": version,
        "type": ptype,
        "type_name": PDU_TYPE_NAMES.get(ptype, f"Unknown({ptype})"),
        "field16": field16,
        "length": length,
        "raw": pdu,
    }
    if ptype in (PDU_SERIAL_NOTIFY, PDU_SERIAL_QUERY, PDU_END_OF_DATA):
        if length < 12 or len(pdu) < 12:
            raise ValueError(f"{info['type_name']} PDU too short for serial")
        (serial,) = struct.unpack_from("!I", pdu, 8)
        info["session_id"] = field16
        info["serial"] = serial
    elif ptype == PDU_CACHE_RESPONSE:
        info["session_id"] = field16
    elif ptype == PDU_IPV4_PREFIX:
        if length != 20 or len(pdu) < 20:
            raise ValueError("bad IPv4 Prefix PDU length")
        flags, plen, mlen, _zero = struct.unpack_from("!BBBB", pdu, 8)
        addr = socket.inet_ntoa(pdu[12:16])
        (asn,) = struct.unpack_from("!I", pdu, 16)
        info.update(
            flags=flags,
            is_announcement=bool(flags & 0x01),
            prefix_length=plen,
            max_length=mlen,
            address=addr,
            prefix=f"{addr}/{plen}",
            origin_asn=asn,
        )
    elif ptype == PDU_ERROR_REPORT and len(pdu) >= 12:
        (enc_len,) = struct.unpack_from("!I", pdu, 8)
        info["error_code"] = field16
        info["encapsulated_length"] = enc_len
    return info


def serial_is_newer(candidate: int, reference: int) -> bool:
    """RFC 1982 style comparison for 32-bit RTR serials."""
    candidate &= 0xFFFFFFFF
    reference &= 0xFFFFFFFF
    if candidate == reference:
        return False
    return ((candidate - reference) & 0xFFFFFFFF) < 0x80000000


class PduReader:
    """Incrementally frame length-delimited PDUs on a streaming socket."""

    def __init__(self, conn: socket.socket) -> None:
        self.conn = conn
        self.buf = b""

    def next_pdu(self) -> Optional[bytes]:
        """Return one complete PDU, or None on read timeout (buffer kept)."""
        while True:
            if len(self.buf) >= 8:
                (_v, _t, _f, length) = _HEADER.unpack_from(self.buf, 0)
                if length < 8 or length > MAX_RECEIVE_PDU:
                    raise ProtocolError(f"illegal PDU length {length}")
                if len(self.buf) >= length:
                    pdu = self.buf[:length]
                    self.buf = self.buf[length:]
                    return pdu
            try:
                chunk = self.conn.recv(65536)
            except socket.timeout:
                return None
            except (ConnectionResetError, OSError) as exc:
                raise ConnectionClosed(str(exc)) from exc
            if not chunk:
                raise ConnectionClosed("peer closed connection")
            self.buf += chunk


class ProtocolError(Exception):
    pass


class ConnectionClosed(Exception):
    pass


# --------------------------------------------------------------------------- #
# Per-connection handler
# --------------------------------------------------------------------------- #


class RTRConnection:
    """One router TCP connection. All writes happen on the calling thread."""

    def __init__(
        self,
        conn: socket.socket,
        addr,
        store: "Store",
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        self.conn = conn
        self.addr = addr
        self.store = store
        self.stop_event = stop_event or threading.Event()
        self.reported_serial: int = RTR_SERIAL_INITIAL
        self.prefix_pdus_sent = 0

    def run(self) -> None:
        self.conn.settimeout(_READ_POLL_SECONDS)
        self.conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        reader = PduReader(self.conn)
        _sid, serial = self.store.rtr_state()
        self.reported_serial = serial

        while not self.stop_event.is_set():
            # Idle safe point: emit at most one coalesced Serial Notify with
            # the newest serial observed since the last safe point.
            try:
                self.maybe_send_notify()
            except OSError as exc:
                logger.debug("rtr %s notify write failed: %s", self.addr, exc)
                return

            try:
                pdu = reader.next_pdu()
            except (ProtocolError, ConnectionClosed) as exc:
                logger.debug("rtr %s closing: %s", self.addr, exc)
                return
            if pdu is None:
                continue  # read poll timed out; re-check serial / stop

            try:
                self.handle_pdu(pdu)
            except ConnectionClosed:
                return
            except OSError as exc:
                # Slow/dead router: only this connection is affected.
                logger.debug("rtr %s write failed: %s", self.addr, exc)
                return

    # -- sending ------------------------------------------------------------ #

    def _sendall(self, data: bytes) -> None:
        self.conn.sendall(data)

    def maybe_send_notify(self) -> bool:
        sid, current_serial = self.store.rtr_state()
        if not serial_is_newer(current_serial, self.reported_serial):
            return False
        # Coalesced: whatever happened, report only the current newest serial.
        self._sendall(pdu_serial_notify(sid, current_serial))
        self.reported_serial = current_serial
        logger.debug(
            "rtr %s sent Serial Notify session=%d serial=%d",
            self.addr,
            sid,
            current_serial,
        )
        return True

    def send_table_response(self, snap: RtrSnapshot) -> int:
        """Cache Response + all IPv4 PDUs + End of Data from one snapshot."""
        self._sendall(pdu_cache_response(snap.session_id))
        count = 0
        for record in snap.entries:
            self._sendall(pdu_ipv4_prefix(record))
            count += 1
        self._sendall(pdu_end_of_data(snap.session_id, snap.serial))
        self.prefix_pdus_sent += count
        return count

    def send_empty_update(self, snap: RtrSnapshot) -> None:
        self._sendall(pdu_cache_response(snap.session_id))
        self._sendall(pdu_end_of_data(snap.session_id, snap.serial))

    # -- request dispatch --------------------------------------------------- #

    def handle_pdu(self, pdu: bytes) -> None:
        info = parse_pdu(pdu)
        ptype = info["type"]
        version = info["version"]

        if version != RTR_VERSION:
            self._sendall(
                pdu_error_report(
                    ERR_UNSUPPORTED_VERSION, pdu, "only RTR version 1 is supported"
                )
            )
            raise ConnectionClosed("unsupported protocol version")

        if ptype == PDU_RESET_QUERY:
            snap = self.store.rtr_snapshot()
            count = self.send_table_response(snap)
            # Do not notify mid-response. Any revision newer than this
            # snapshot is reported by maybe_send_notify() at the next loop
            # iteration, coalesced to the latest serial.
            self.reported_serial = snap.serial
            logger.info(
                "rtr %s Reset Query -> %d IPv4 PDU(s), session=%d serial=%d",
                self.addr,
                count,
                snap.session_id,
                snap.serial,
            )
            return

        if ptype == PDU_SERIAL_QUERY:
            query_session = info["session_id"]
            query_serial = info["serial"]
            snap = self.store.rtr_snapshot()
            if (
                query_session == snap.session_id
                and query_serial == snap.serial
            ):
                self.send_empty_update(snap)
                logger.info(
                    "rtr %s Serial Query %d/%d matched -> empty update",
                    self.addr,
                    query_session,
                    query_serial,
                )
            else:
                # No incremental support: stale serial OR wrong session both
                # force a full re-fetch via Reset Query.
                self._sendall(pdu_cache_reset())
                logger.info(
                    "rtr %s Serial Query %d/%d mismatch current %d/%d "
                    "-> Cache Reset",
                    self.addr,
                    query_session,
                    query_serial,
                    snap.session_id,
                    snap.serial,
                )
            self.reported_serial = snap.serial
            return

        # Anything else is not a valid cache->server query in our subset.
        self._sendall(
            pdu_error_report(ERR_UNSUPPORTED_PDU_TYPE, pdu, "unsupported PDU type")
        )
        raise ConnectionClosed(f"unsupported PDU type {ptype}")


# --------------------------------------------------------------------------- #
# TCP server with one daemon thread per router
# --------------------------------------------------------------------------- #


class RTRServer:
    def __init__(
        self,
        store: "Store",
        host: str = DEFAULT_RTR_HOST,
        port: int = DEFAULT_RTR_PORT,
        *,
        client_send_buffer: Optional[int] = None,
        backlog: int = 64,
    ) -> None:
        self.store = store
        self.host = host
        self.requested_port = port
        self.client_send_buffer = client_send_buffer
        self.backlog = backlog
        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._accept_thread: Optional[threading.Thread] = None
        self._threads: list[threading.Thread] = []
        self._threads_lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------- #

    def start(self) -> "RTRServer":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.requested_port))
        sock.listen(self.backlog)
        sock.settimeout(0.5)
        self._sock = sock
        self._stop_event.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="rtr-accept", daemon=True
        )
        self._accept_thread.start()
        logger.info("RTR server listening on %s:%d", self.host, self.server_port)
        return self

    def stop(self) -> None:
        self._stop_event.set()
        sock = self._sock
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        thread = self._accept_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)

    @property
    def server_port(self) -> int:
        if self._sock is None:
            raise RuntimeError("RTRServer has not been started")
        return self._sock.getsockname()[1]

    # -- accept ------------------------------------------------------------- #

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return  # socket closed by stop()
            self._configure_client_socket(conn)
            worker = threading.Thread(
                target=self._run_connection,
                args=(conn, addr),
                name=f"rtr-conn-{addr[0]}:{addr[1]}",
                daemon=True,
            )
            worker.start()
            with self._threads_lock:
                # Drop finished connection threads so many router reconnects
                # do not accumulate dead Thread objects.
                self._threads = [t for t in self._threads if t.is_alive()]
                self._threads.append(worker)

    def _configure_client_socket(self, conn: socket.socket) -> None:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.client_send_buffer is not None:
            try:
                conn.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_SNDBUF,
                    int(self.client_send_buffer),
                )
            except OSError:  # pragma: no cover - platform tuning only
                logger.debug("could not set SO_SNDBUF", exc_info=True)

    def _run_connection(self, conn: socket.socket, addr) -> None:
        handler = RTRConnection(conn, addr, self.store, self._stop_event)
        try:
            handler.run()
        except Exception:  # never let a connection thread die loudly/whole
            logger.exception("rtr %s unhandled connection error", addr)
        finally:
            try:
                conn.close()
            except OSError:
                pass
