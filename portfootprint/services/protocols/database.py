"""
DatabaseFingerprinter implementing passive and active checks for MySQL, Postgres, Redis, and Mongo.
"""

import contextlib
import socket
import struct
from typing import Any, Optional

from portfootprint.core.models import ServiceMetadata
from portfootprint.services.protocols.base import BaseFingerprintModule
from portfootprint.services.registry import registry


@registry.register(ports=[3306, 5432, 6379, 27017], keywords=["mysql", "postgres", "redis", "mongodb", "ping"], priority=10)
class DatabaseFingerprinter(BaseFingerprintModule):
    """
    Database Fingerprinting module.
    Runs non-intrusive handshakes for MySQL, PostgreSQL, Redis, and MongoDB.
    """
    def _fingerprint_mysql(self, sock: socket.socket, timeout: float) -> Optional[ServiceMetadata]:
        # MySQL immediately sends a greeting packet (passive)
        original_timeout = sock.gettimeout()
        sock.settimeout(timeout)
        is_mysql = False
        version = "Unknown"
        banner = ""

        try:
            data = sock.recv(1024)
            # MySQL handshake packet protocol version is typically 10 (or 9) at offset 4
            if len(data) >= 5:
                proto_ver = data[4]
                if proto_ver in (9, 10):
                    is_mysql = True
                    # Extract null-terminated version string starting at offset 5
                    ver_bytes = data[5:].split(b"\x00", 1)[0]
                    version = self.safe_decode(ver_bytes)
                    banner = f"MySQL Protocol v{proto_ver} (Server: {version})"
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                sock.settimeout(original_timeout)

        if is_mysql:
            return ServiceMetadata(
                service_name="MySQL",
                protocol="tcp",
                version=version,
                banner=banner,
                extra_details={"mysql_version": version}
            )
        return None

    def _fingerprint_postgres(self, sock: socket.socket, timeout: float) -> Optional[ServiceMetadata]:
        # PostgreSQL: send SSLRequest first to verify
        # SSLRequest payload: length (8) + request code
        ssl_probe = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
        resp = self.send_and_recv(sock, ssl_probe, read_timeout=timeout, max_bytes=1)

        is_postgres = False
        extra: dict[str, Any] = {}

        if resp in (b"S", b"N"):
            is_postgres = True
            extra["ssl_supported"] = (resp == b"S")

            # Send StartupMessage to provoke an auth request/error containing Postgres tag
            # StartupMessage: len (28) + protocol version 3.0 + parameters (user=postgres)
            startup_probe = b"\x00\x00\x00\x1c\x00\x03\x00\x00user\x00postgres\x00\x00"
            resp_bytes = self.send_and_recv(sock, startup_probe, read_timeout=timeout)
            resp_text = self.safe_decode(resp_bytes)

            # Responses start with R (AuthenticationRequest) or E (ErrorResponse)
            if resp_bytes and chr(resp_bytes[0]) in ("R", "E"):
                extra["response_header"] = chr(resp_bytes[0])
                if "postgres" in resp_text.lower() or "fatal" in resp_text.lower():
                    extra["postgres_verified"] = True

        if is_postgres:
            return ServiceMetadata(
                service_name="PostgreSQL",
                protocol="tcp",
                version="PostgreSQL Database Server",
                banner="PostgreSQL",
                extra_details=extra
            )
        return None

    def _fingerprint_redis(self, sock: socket.socket, timeout: float) -> Optional[ServiceMetadata]:
        # Redis: send PING
        resp_bytes = self.send_and_recv(sock, b"PING\r\n", read_timeout=timeout)
        resp_text = self.safe_decode(resp_bytes)

        is_redis = False
        extra: dict[str, Any] = {}

        if resp_text and (resp_text.startswith("+PONG") or resp_text.startswith("-NOAUTH")):
            is_redis = True
            extra["redis_response"] = resp_text.split("\r\n")[0]
            extra["auth_required"] = resp_text.startswith("-NOAUTH")

        if is_redis:
            return ServiceMetadata(
                service_name="Redis",
                protocol="tcp",
                version="Redis Key-Value Store",
                banner=extra["redis_response"],
                extra_details=extra
            )
        return None

    def _fingerprint_mongodb(self, sock: socket.socket, timeout: float) -> Optional[ServiceMetadata]:
        # MongoDB: send standard OP_QUERY isMaster payload (59 bytes)
        mongo_probe = (
            b"\x3b\x00\x00\x00"          # Message length (59 bytes)
            b"\x01\x00\x00\x00"          # Request ID
            b"\x00\x00\x00\x00"          # Response To
            b"\xd4\x07\x00\x00"          # Opcode OP_QUERY (2004)
            b"\x00\x00\x00\x00"          # Query Flags
            b"admin.$cmd\x00"             # Collection name
            b"\x00\x00\x00\x00"          # Number to skip
            b"\xff\xff\xff\xff"          # Number to return (-1)
            # Query document: {"isMaster": 1}
            b"\x13\x00\x00\x00"          # Document length (19 bytes)
            b"\x10isMaster\x00\x01\x00\x00\x00"  # Int32 key:value
            b"\x00"                      # End of document
        )

        resp_bytes = self.send_and_recv(sock, mongo_probe, read_timeout=timeout)

        is_mongo = False
        extra: dict[str, Any] = {}

        # MongoDB OP_REPLY message has opcode 2005 (0x07d5) at offset 12-16
        if len(resp_bytes) >= 16:
            opcode = struct.unpack("<I", resp_bytes[12:16])[0]
            if opcode == 2005:
                is_mongo = True
                # Safely inspect BSON strings
                resp_text = self.safe_decode(resp_bytes[16:])
                if "ismaster" in resp_text.lower() or "maxbsonobjectsize" in resp_text.lower():
                    extra["mongodb_is_master_resp"] = True
                extra["opcode"] = opcode

        if is_mongo:
            return ServiceMetadata(
                service_name="MongoDB",
                protocol="tcp",
                version="MongoDB NoSQL Database Server",
                banner="MongoDB OP_REPLY response",
                extra_details=extra
            )
        return None

    def fingerprint(self, sock: socket.socket, target: str, port: int, timeout: float) -> ServiceMetadata:
        # Match based on port mapping checks
        if port == 3306:
            res = self._fingerprint_mysql(sock, timeout)
            if res:
                return res
        elif port == 5432:
            res = self._fingerprint_postgres(sock, timeout)
            if res:
                return res
        elif port == 6379:
            res = self._fingerprint_redis(sock, timeout)
            if res:
                return res
        elif port == 27017:
            res = self._fingerprint_mongodb(sock, timeout)
            if res:
                return res

        # Fallback sequential checks if port wasn't standard but matched banner keywords
        for func in (self._fingerprint_mysql, self._fingerprint_redis, self._fingerprint_postgres, self._fingerprint_mongodb):
            try:
                res = func(sock, timeout)
                if res:
                    return res
            except Exception:  # nosec B110
                pass

        # Return empty/fallback service metadata if not matched
        return ServiceMetadata(
            service_name="Database",
            protocol="tcp",
            version="Generic Database",
            banner="Unrecognized database handshakes"
        )
