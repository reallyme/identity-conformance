# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import shutil
import signal
import time
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_oidf_loopback_crl as crl


class LoopbackCrlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.endpoint = crl.LoopbackEndpoint(("127.0.0.1", "::1"), "localhost", 8080)

    def request(self, _endpoint, _address, method, path, _headers):
        if method == "GET" and path == crl.CRL_PATH:
            return crl.HttpResult(200, "application/pkix-crl", b"signed-crl")
        return crl.HttpResult(403, "text/plain", b"")

    def test_public_crl_is_authenticated_and_every_loopback_address_is_checked(self) -> None:
        authenticated = mock.Mock()
        request = mock.Mock(side_effect=self.request)
        crl.verify_boundary(self.endpoint, Path("root.pem"), request, authenticated)
        self.assertEqual(authenticated.call_count, 2)
        addresses = {call.args[1] for call in request.call_args_list}
        self.assertEqual(addresses, {"127.0.0.1", "::1"})

    def test_http_origin_rejects_nonloopback_and_noncanonical_routes(self) -> None:
        for origin in ("https://localhost:8080", "http://192.0.2.1:8080", "http://localhost.attacker.example:8080", "http://localhost:8080/mdoc-iaca.crl", "http://localhost:8080/?x=1", "http://user@localhost:8080", "http://127.0.0.1:80"):
            with self.subTest(origin=origin), self.assertRaises(crl.CrlEndpointError):
                crl.validate_crl_origin(origin)
        self.assertEqual(crl.validate_crl_origin("http://127.0.0.1:8080").port, 8080)

    def test_redirected_empty_wrong_media_and_oversized_crls_are_rejected(self) -> None:
        for response in (crl.HttpResult(302, "application/pkix-crl", b"crl"), crl.HttpResult(200, "text/html", b"crl"), crl.HttpResult(200, "application/pkix-crl", b""), crl.HttpResult(200, "application/pkix-crl", b"x" * (crl.MAX_CRL_BYTES + 1))):
            with self.subTest(status=response.status), self.assertRaises(crl.CrlEndpointError) as caught:
                crl.verify_boundary(self.endpoint, Path("root.pem"), mock.Mock(return_value=response), mock.Mock())
            self.assertEqual(str(caught.exception), "crl_http_response_invalid")

    def test_forwarded_header_spoofing_cannot_enable_plaintext_apis(self) -> None:
        def request(endpoint, address, method, path, headers):
            if path != crl.CRL_PATH and headers:
                return crl.HttpResult(200, "application/json", b"{}")
            return self.request(endpoint, address, method, path, headers)
        with self.assertRaises(crl.CrlEndpointError) as caught:
            crl.verify_boundary(self.endpoint, Path("root.pem"), request, mock.Mock())
        self.assertEqual(str(caught.exception), "plaintext_api_not_rejected")

    def test_authentication_errors_and_missing_routes_do_not_prove_tls_rejection(self) -> None:
        for status in (200, 204, 302, 401, 404):
            def request(endpoint, address, method, path, headers):
                if path != crl.CRL_PATH:
                    return crl.HttpResult(status, "application/json", b"{}")
                return self.request(endpoint, address, method, path, headers)
            with self.subTest(status=status), self.assertRaises(crl.CrlEndpointError):
                crl.verify_boundary(self.endpoint, Path("root.pem"), request, mock.Mock())

    def test_crl_exception_rejects_post_and_query_extensions(self) -> None:
        for accepted in (("POST", crl.CRL_PATH), ("GET", crl.CRL_PATH + "?extra=1")):
            def request(endpoint, address, method, path, headers):
                if (method, path) == accepted:
                    return crl.HttpResult(200, "application/pkix-crl", b"crl")
                return self.request(endpoint, address, method, path, headers)
            with self.subTest(route=accepted), self.assertRaises(crl.CrlEndpointError) as caught:
                crl.verify_boundary(self.endpoint, Path("root.pem"), request, mock.Mock())
            self.assertEqual(str(caught.exception), "crl_http_scope_invalid")

    def test_absolute_http_deadline_interrupts_a_stalled_exchange_and_restores_state(self) -> None:
        handler = signal.getsignal(signal.SIGALRM)
        with mock.patch.object(crl, "HTTP_TIMEOUT_SECONDS", 0.01):
            with self.assertRaises(crl.CrlEndpointError) as caught:
                with crl.http_deadline():
                    time.sleep(1)
        self.assertEqual(str(caught.exception), "crl_http_unavailable")
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)

    def test_expired_future_missing_and_malformed_intervals_fail_closed(self) -> None:
        now = datetime(2026, 11, 10, 12, tzinfo=timezone.utc)
        crl.validate_interval(b"lastUpdate=Nov 10 11:00:00 2026 GMT\nnextUpdate=Nov 10 13:00:00 2026 GMT\n", now)
        for encoded in (b"lastUpdate=Nov 10 13:00:00 2026 GMT\nnextUpdate=Nov 10 14:00:00 2026 GMT\n", b"lastUpdate=Nov 10 10:00:00 2026 GMT\nnextUpdate=Nov 10 12:00:00 2026 GMT\n", b"lastUpdate=Nov 10 10:00:00 2026 GMT\n", b"untrusted backend output"):
            with self.assertRaises(crl.CrlEndpointError) as caught:
                crl.validate_interval(encoded, now)
            self.assertEqual(str(caught.exception), "crl_freshness_invalid")


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for signature integration tests")
class CrlSignatureTests(unittest.TestCase):
    def test_success_exit_with_failure_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root.pem"
            root.write_bytes(b"bounded public root")
            completed = subprocess.CompletedProcess(
                args=["openssl"],
                returncode=0,
                stdout=b"",
                stderr=b"verify failure\n",
            )
            with mock.patch.object(crl.subprocess, "run", return_value=completed):
                with self.assertRaises(crl.CrlEndpointError) as caught:
                    crl.verify_signature(b"bounded crl", root)
            self.assertEqual(str(caught.exception), "crl_signature_invalid")

    def test_real_crl_signature_rejects_wrong_root_and_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "ca.cnf"
            (root / "index").write_text("")
            (root / "serial").write_text("01\n")
            (root / "crlnumber").write_text("01\n")
            config.write_text("[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=" + str(root / "index") + "\nserial=" + str(root / "serial") + "\ncrlnumber=" + str(root / "crlnumber") + "\ncertificate=" + str(root / "ca.pem") + "\nprivate_key=" + str(root / "key.pem") + "\ndefault_md=sha256\ndefault_crl_days=1\n")
            def run(args):
                result = subprocess.run(["openssl", *args], capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 0, "fixture certificate operation failed")
            run(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-x509", "-days", "2", "-subj", "/CN=Local CRL Test Root", "-keyout", str(root / "key.pem"), "-out", str(root / "ca.pem")])
            run(["ca", "-gencrl", "-batch", "-config", str(config), "-out", str(root / "crl.pem")])
            run(["crl", "-in", str(root / "crl.pem"), "-outform", "DER", "-out", str(root / "crl.der")])
            run(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-x509", "-days", "2", "-subj", "/CN=Untrusted CRL Root", "-keyout", str(root / "wrong-key.pem"), "-out", str(root / "wrong.pem")])
            encoded = (root / "crl.der").read_bytes()
            crl.verify_signature(encoded, root / "ca.pem")
            for bad_crl, bad_root in ((encoded, root / "wrong.pem"), (encoded[:-1] + bytes([encoded[-1] ^ 1]), root / "ca.pem")):
                with self.assertRaises(crl.CrlEndpointError) as caught:
                    crl.verify_signature(bad_crl, bad_root)
                self.assertEqual(str(caught.exception), "crl_signature_invalid")


if __name__ == "__main__":
    unittest.main()
