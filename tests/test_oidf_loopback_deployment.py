# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("docker"), "Docker Compose is required for deployment merging")
class LoopbackDeploymentTests(unittest.TestCase):
    def test_overlay_removes_backend_publication_and_scopes_every_proxy_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            base = temporary / "compose.yml"
            # Model the upstream listener that would otherwise be inherited;
            # `config` resolves Compose without pulling images or starting services.
            base.write_text("services:\n  nginx:\n    image: nginx:1.27.3\n    ports: [\"8443:8443\"]\n  server:\n    image: example.invalid/unused\n    ports: [\"8080:8080\"]\n")
            environment = os.environ.copy()
            environment.update(
                OIDF_LOOPBACK_TLS_CERT=str(temporary / "server.crt"),
                OIDF_LOOPBACK_TLS_KEY=str(temporary / "server.key"),
                OIDF_LOOPBACK_NGINX_CONFIG=str(ROOT / "scripts/oidf-loopback-nginx.conf"),
            )
            command = ["docker", "compose", "-f", str(base), "-f", str(ROOT / "scripts/oidf-loopback-compose.yml"), "config", "--format", "json"]
            result = subprocess.run(command, env=environment, capture_output=True, timeout=15, check=False)
            self.assertEqual(result.returncode, 0, "Compose configuration merge failed")
            services = json.loads(result.stdout)["services"]
            self.assertFalse(services["server"].get("ports"))
            observed = {(str(item["published"]), item["host_ip"]) for item in services["nginx"]["ports"]}
            self.assertEqual(observed, {(str(port), address) for port in (8080, 8443, 8444) for address in ("127.0.0.1", "::1")})
            self.assertIn("--fintechlabs.base_http_url=http://localhost:8080", services["server"]["command"])
            mounted = [item for item in services["nginx"]["volumes"] if item["target"] == "/etc/nginx/nginx.conf"]
            self.assertEqual(len(mounted), 1)
            self.assertTrue(mounted[0]["read_only"])
            self.assertEqual(mounted[0]["source"], str(ROOT / "scripts/oidf-loopback-nginx.conf"))
            environment.pop("OIDF_LOOPBACK_NGINX_CONFIG")
            missing = subprocess.run(command, env=environment, capture_output=True, timeout=15, check=False)
            self.assertNotEqual(missing.returncode, 0)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for TLS setup")
class LoopbackTlsTests(unittest.TestCase):
    def test_generated_leaf_verifies_under_strict_tls_and_is_loopback_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tls = Path(directory) / "tls"
            result = subprocess.run(
                [str(ROOT / "scripts/create_oidf_loopback_tls.sh"), str(tls)],
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual({path.name for path in tls.iterdir()}, {"ca.crt", "server.crt", "server.key"})
            self.assertEqual((tls / "server.key").stat().st_mode & 0o777, 0o600)
            verify = [
                "openssl", "verify", "-x509_strict", "-purpose", "sslserver",
                "-CAfile", str(tls / "ca.crt"),
            ]
            certificate = str(tls / "server.crt")
            for host, option in (("localhost", "-verify_hostname"), ("127.0.0.1", "-verify_ip"), ("::1", "-verify_ip")):
                with self.subTest(host=host):
                    result = subprocess.run(
                        [*verify, option, host, certificate], capture_output=True, timeout=10, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
            result = subprocess.run(
                [*verify, "-verify_hostname", "external.example", certificate],
                capture_output=True, timeout=10, check=False,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
