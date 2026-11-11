#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail
umask 077

fail() {
  printf 'OIDF loopback TLS setup: %s\n' "$1" >&2
  exit 78
}

[[ "$#" -eq 1 ]] || fail "exactly one output directory is required"
command -v openssl >/dev/null 2>&1 || fail "openssl is required"

output_parent="$(cd -- "$(dirname -- "$1")" && pwd)" || \
  fail "output parent directory is unavailable"
output_directory="${output_parent}/$(basename -- "$1")"
readonly output_parent output_directory
[[ ! -e "${output_directory}" ]] || fail "output directory already exists"
mkdir -m 700 -- "${output_directory}" || fail "output directory creation failed"

readonly ca_key="${output_directory}/ca.key"
readonly ca_certificate="${output_directory}/ca.crt"
readonly server_key="${output_directory}/server.key"
readonly server_request="${output_directory}/server.csr"
readonly server_certificate="${output_directory}/server.crt"
readonly certificate_extensions="${output_directory}/server.ext"
generation_complete=0

cleanup_incomplete_generation() {
  if [[ "${generation_complete}" -eq 0 ]]; then
    # Remove only the files owned by this invocation. This prevents a failed
    # OpenSSL operation from leaving a usable CA signing key behind.
    rm -f -- \
      "${ca_key}" \
      "${ca_certificate}" \
      "${server_key}" \
      "${server_request}" \
      "${server_certificate}" \
      "${certificate_extensions}" \
      "${output_directory}/ca.srl"
    rmdir -- "${output_directory}" 2>/dev/null || true
  fi
}

trap cleanup_incomplete_generation EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

openssl genpkey -quiet -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 -out "${ca_key}" || \
  fail "CA key generation failed"
openssl req -new -x509 -sha256 -days 30 \
  -key "${ca_key}" -out "${ca_certificate}" \
  -subj "/CN=ReallyMe Local OIDF Loopback CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" || \
  fail "CA certificate generation failed"

openssl genpkey -quiet -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 -out "${server_key}" || \
  fail "server key generation failed"
openssl req -new -sha256 -key "${server_key}" -out "${server_request}" \
  -subj "/CN=127.0.0.1" || fail "server request generation failed"

printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  'subjectKeyIdentifier=hash' \
  'authorityKeyIdentifier=keyid:always' \
  'subjectAltName=IP:127.0.0.1,IP:::1,DNS:localhost' \
  > "${certificate_extensions}"
openssl x509 -req -sha256 -days 7 \
  -in "${server_request}" \
  -CA "${ca_certificate}" -CAkey "${ca_key}" -CAcreateserial \
  -extfile "${certificate_extensions}" -out "${server_certificate}" || \
  fail "server certificate signing failed"

# Rehearsal clients use strict certificate verification, including CA and
# leaf key identifiers and server authentication usage.
for loopback_address in 127.0.0.1 ::1; do
  openssl verify -x509_strict -purpose sslserver -verify_ip "${loopback_address}" \
    -CAfile "${ca_certificate}" "${server_certificate}" >/dev/null || \
    fail "server certificate loopback IP verification failed"
done
openssl verify -x509_strict -purpose sslserver -verify_hostname localhost \
  -CAfile "${ca_certificate}" "${server_certificate}" >/dev/null || \
  fail "server certificate localhost verification failed"

# The local CA is intentionally non-renewable. Removing its signing key after
# the one scoped leaf is issued prevents another process from minting a peer
# certificate that the rehearsal client would trust.
rm -- "${ca_key}" "${server_request}" "${certificate_extensions}" \
  "${output_directory}/ca.srl"
chmod 600 "${server_key}"
chmod 644 "${ca_certificate}" "${server_certificate}"
generation_complete=1

printf 'Created scoped OIDF loopback TLS material under %s\n' "${output_directory}"
printf 'Set SSL_CERT_FILE and OIDF_LOOPBACK_TLS_CA to %s\n' "${ca_certificate}"
printf 'Set OIDF_LOOPBACK_TLS_CERT to %s\n' "${server_certificate}"
printf 'Set OIDF_LOOPBACK_TLS_KEY to %s\n' "${server_key}"
