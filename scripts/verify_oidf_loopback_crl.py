#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Verify the local signed-CRL exception without admitting plaintext APIs."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import http.client
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import FrameType
from typing import Callable, Iterator, NamedTuple, NoReturn

from verify_oidf_local_endpoints import EndpointError, LoopbackEndpoint, validate_endpoint

MAX_CRL_BYTES = 1024 * 1024
MAX_ROOT_BYTES = 32 * 1024
MAX_MEDIA_TYPE_BYTES = 256
HTTP_TIMEOUT_SECONDS = 10
OPENSSL_TIMEOUT_SECONDS = 10
CRL_PATH = "/mdoc-iaca.crl"
BLOCKED_HTTP_STATUSES = frozenset({400, 403, 421, 426, 500})
# Use non-mutating control paths even if a deployment is misconfigured.
PRIVATE_PATH_PROBES = (
    ("GET", "/api/runner/available"),
    ("POST", "/api/runner/available"),
    ("POST", "/test/a/plaintext-boundary-check/credential"),
)


class CrlEndpointError(Exception):
    """Fixed failure reasons, without URLs, credentials or backend diagnostics."""


class HttpResult(NamedTuple):
    status: int
    media_type: str
    body: bytes


def validate_crl_origin(origin: str) -> LoopbackEndpoint:
    if not origin.startswith("http://"):
        raise CrlEndpointError("crl_origin_invalid")
    try:
        return validate_endpoint("https://" + origin[len("http://"):])
    except EndpointError as error:
        raise CrlEndpointError("crl_origin_invalid") from error


@contextmanager
def http_deadline() -> Iterator[None]:
    # Socket timeouts alone restart after each received byte. Bound the whole
    # exchange, including partial headers, so a local peer cannot stall preflight.
    if not hasattr(signal, "ITIMER_REAL") or not hasattr(signal, "SIGALRM"):
        raise CrlEndpointError("crl_execution_context_invalid")
    if threading.current_thread() is not threading.main_thread() or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        raise CrlEndpointError("crl_execution_context_invalid")
    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, expire_http_deadline)
    try:
        signal.setitimer(signal.ITIMER_REAL, HTTP_TIMEOUT_SECONDS)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def expire_http_deadline(_number: int, _frame: FrameType | None) -> NoReturn:
    raise CrlEndpointError("crl_http_unavailable")


def fetch(
    endpoint: LoopbackEndpoint,
    address: str,
    method: str,
    path: str,
    headers: dict[str, str],
) -> HttpResult:
    host = endpoint.server_name
    if ":" in host:
        host = "[" + host + "]"
    connection = http.client.HTTPConnection(address, endpoint.port, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        with http_deadline():
            # Connect to the already admitted address; DNS is not consulted again.
            connection.request(method, path, headers={"Host": host + ":" + str(endpoint.port), **headers})
            response = connection.getresponse()
            media_type = response.getheader("Content-Type", "")
            if len(media_type) > MAX_MEDIA_TYPE_BYTES:
                raise CrlEndpointError("crl_http_response_invalid")
            body = response.read(MAX_CRL_BYTES + 1)
            if len(body) > MAX_CRL_BYTES:
                raise CrlEndpointError("crl_http_response_too_large")
            return HttpResult(response.status, media_type, body)
    except (OSError, http.client.HTTPException) as error:
        raise CrlEndpointError("crl_http_unavailable") from error
    finally:
        connection.close()


def verify_signature(crl: bytes, root: Path) -> None:
    try:
        metadata = root.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1
                or metadata.st_size > MAX_ROOT_BYTES or metadata.st_mode & 0o022):
            raise CrlEndpointError("crl_root_invalid")
        with os.fdopen(os.open(root, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
            opened = os.fstat(source.fileno())
            if (opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino
                    or not stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o022):
                raise CrlEndpointError("crl_root_invalid")
            root_bytes = source.read(MAX_ROOT_BYTES + 1)
        if not root_bytes or len(root_bytes) > MAX_ROOT_BYTES:
            raise CrlEndpointError("crl_root_invalid")
        # Copy the bounded public root into the same private directory as the
        # response, so replacement of the caller's path cannot change the signer.
        with tempfile.TemporaryDirectory(prefix="oidf-crl-check-") as temporary:
            directory = Path(temporary)
            crl_path = directory / "issuer.crl"
            root_path = directory / "iaca.pem"
            for path, data in ((crl_path, crl), (root_path, root_bytes)):
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(data)
            common = ["openssl", "crl", "-inform", "DER", "-in", str(crl_path), "-noout"]
            checked = subprocess.run(
                [*common, "-verify", "-CAfile", str(root_path)],
                capture_output=True, timeout=OPENSSL_TIMEOUT_SECONDS, check=False,
            )
            # OpenSSL 3.0 can report a failed CRL signature in its output while
            # returning success. Accept only the single affirmative marker so
            # a version-specific exit-code behavior cannot bypass validation.
            verification_messages = [
                line.strip()
                for output in (checked.stdout, checked.stderr)
                for line in output.splitlines()
                if line.strip()
            ]
            if checked.returncode != 0 or verification_messages != [b"verify OK"]:
                raise CrlEndpointError("crl_signature_invalid")
            interval = subprocess.run(
                [*common, "-lastupdate", "-nextupdate"],
                capture_output=True, timeout=OPENSSL_TIMEOUT_SECONDS, check=False,
            )
            if interval.returncode != 0 or len(interval.stdout) > 256:
                raise CrlEndpointError("crl_freshness_invalid")
            validate_interval(interval.stdout, datetime.now(timezone.utc))
    except (OSError, subprocess.SubprocessError) as error:
        raise CrlEndpointError("crl_verification_unavailable") from error


def validate_interval(encoded: bytes, now: datetime) -> None:
    try:
        lines = encoded.decode("ascii").splitlines()
        if len(lines) != 2 or not lines[0].startswith("lastUpdate=") or not lines[1].startswith("nextUpdate="):
            raise CrlEndpointError("crl_freshness_invalid")
        start = datetime.strptime(lines[0][len("lastUpdate="):], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
        end = datetime.strptime(lines[1][len("nextUpdate="):], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
        if not start <= now < end:
            raise CrlEndpointError("crl_freshness_invalid")
    except (ValueError, UnicodeError) as error:
        raise CrlEndpointError("crl_freshness_invalid") from error


def verify_boundary(
    endpoint: LoopbackEndpoint,
    root: Path,
    request: Callable[[LoopbackEndpoint, str, str, str, dict[str, str]], HttpResult] = fetch,
    authenticate: Callable[[bytes, Path], None] = verify_signature,
) -> None:
    for address in endpoint.addresses:
        response = request(endpoint, address, "GET", CRL_PATH, {"Accept": "application/pkix-crl"})
        if (response.status != 200 or response.media_type.split(";", 1)[0].strip().lower() != "application/pkix-crl"
                or not response.body or len(response.body) > MAX_CRL_BYTES):
            raise CrlEndpointError("crl_http_response_invalid")
        authenticate(response.body, root)
        for headers in ({}, {"X-Forwarded-Proto": "https", "Forwarded": "proto=https"}):
            for method, path in PRIVATE_PATH_PROBES:
                blocked = request(endpoint, address, method, path, headers)
                if blocked.status not in BLOCKED_HTTP_STATUSES:
                    raise CrlEndpointError("plaintext_api_not_rejected")
        for method, path in (("POST", CRL_PATH), ("GET", CRL_PATH + "?extra=1")):
            if request(endpoint, address, method, path, {}).status not in BLOCKED_HTTP_STATUSES | {405}:
                raise CrlEndpointError("crl_http_scope_invalid")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--http-origin", required=True)
    parser.add_argument("--iaca-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify_boundary(validate_crl_origin(args.http_origin), args.iaca_root)
    except CrlEndpointError as error:
        print(str(error), file=sys.stderr)
        return 65
    print("OIDF loopback CRL signature, freshness and plaintext API rejection verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
