#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Require OIDF development endpoints to resolve to an explicit local host."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
import stat
import sys
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit


MAX_ENDPOINT_BYTES = 2048
MIN_UNPRIVILEGED_PORT = 1024
MAX_PORT = 65_535
MAX_CA_BUNDLE_BYTES = 1024 * 1024
TLS_TIMEOUT_SECONDS = 10


class EndpointError(Exception):
    """Stable, non-sensitive endpoint validation failure."""


class LoopbackEndpoint(NamedTuple):
    """A canonical HTTPS endpoint restricted to a loopback-only authority."""

    addresses: tuple[str, ...]
    server_name: str
    port: int


def validate_endpoint(endpoint: str) -> LoopbackEndpoint:
    if (
        not endpoint.isascii()
        or not endpoint
        or len(endpoint.encode("ascii")) > MAX_ENDPOINT_BYTES
        or any(character.isspace() for character in endpoint)
        or "\\" in endpoint
    ):
        raise EndpointError("local_endpoint_invalid")
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise EndpointError("local_endpoint_invalid") from error
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or port is None
        or port < MIN_UNPRIVILEGED_PORT
        or port > MAX_PORT
    ):
        raise EndpointError("local_endpoint_invalid")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        # Only the IETF-reserved localhost name is accepted. Allowing an
        # arbitrary DNS name which currently resolves to loopback would make
        # the preflight vulnerable to rebinding between validation and use.
        if hostname != "localhost":
            raise EndpointError("local_endpoint_must_use_loopback_authority")
        try:
            resolved = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        except OSError as error:
            raise EndpointError("local_endpoint_resolution_failed") from error
        addresses = tuple(sorted({entry[4][0] for entry in resolved}))
        if not addresses:
            raise EndpointError("local_endpoint_resolution_failed")
        try:
            if any(not ipaddress.ip_address(item).is_loopback for item in addresses):
                raise EndpointError("local_endpoint_not_loopback")
        except ValueError as error:
            raise EndpointError("local_endpoint_resolution_failed") from error
        return LoopbackEndpoint(
            addresses=addresses,
            server_name=hostname,
            port=port,
        )
    if not address.is_loopback:
        raise EndpointError("local_endpoint_not_loopback")
    return LoopbackEndpoint(
        addresses=(str(address),),
        server_name=str(address),
        port=port,
    )


def require_ca_bundle(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EndpointError("local_tls_ca_unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > MAX_CA_BUNDLE_BYTES
        or metadata.st_mode & 0o022
    ):
        raise EndpointError("local_tls_ca_invalid")
    return path


def verify_tls(endpoint: LoopbackEndpoint, ca_bundle: Path) -> None:
    try:
        context = ssl.create_default_context(cafile=str(ca_bundle))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        for address in endpoint.addresses:
            with socket.create_connection(
                (address, endpoint.port), timeout=TLS_TIMEOUT_SECONDS
            ) as connection:
                with context.wrap_socket(
                    connection, server_hostname=endpoint.server_name
                ) as tls_connection:
                    if tls_connection.version() not in {"TLSv1.2", "TLSv1.3"}:
                        raise EndpointError("local_tls_version_invalid")
                    if not tls_connection.getpeercert(binary_form=True):
                        raise EndpointError("local_tls_peer_certificate_missing")
    except EndpointError:
        raise
    except (OSError, ssl.SSLError) as error:
        raise EndpointError("local_tls_verification_failed") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-cert", required=True, type=Path)
    parser.add_argument("endpoints", nargs="+")
    args = parser.parse_args()
    try:
        ca_bundle = require_ca_bundle(args.ca_cert)
        endpoints = {validate_endpoint(endpoint) for endpoint in args.endpoints}
        for endpoint in endpoints:
            verify_tls(endpoint, ca_bundle)
    except EndpointError as error:
        print(str(error), file=sys.stderr)
        return 65
    print("OIDF development endpoints are verified loopback TLS origins")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
