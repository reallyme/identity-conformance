#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly trivy_version="0.76.2"
readonly trivy_archive="trivy_${trivy_version}_Linux-64bit.tar.gz"
readonly trivy_archive_sha256="bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"
readonly trivy_url="https://github.com/aquasecurity/trivy/releases/download/v${trivy_version}/${trivy_archive}"
readonly image="reallyme/oidf-maven:3.9.16-patched"

scan_directory=""

cleanup() {
    if [[ -n "${scan_directory}" && -d "${scan_directory}" ]]; then
        rm -r -- "${scan_directory}"
    fi
}
trap cleanup EXIT

for required_command in curl docker mktemp sha256sum tar; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        printf 'error: required command is unavailable: %s\n' "${required_command}" >&2
        exit 78
    fi
done

scan_directory="$(mktemp -d)"
readonly scan_directory
archive_path="${scan_directory}/${trivy_archive}"
readonly archive_path

curl --fail --location --proto '=https' --silent --show-error --tlsv1.2 \
    --output "${archive_path}" \
    "${trivy_url}"
printf '%s  %s\n' "${trivy_archive_sha256}" "${archive_path}" | \
    sha256sum --check --strict
tar --extract --gzip --file "${archive_path}" --directory "${scan_directory}" trivy

# Any published fix, regardless of severity, is mandatory for the certification
# build toolchain. Advisories without an upstream fix remain visible to the
# separate security-review process but cannot be remediated in this image.
"${scan_directory}/trivy" image \
    --exit-code 1 \
    --ignore-unfixed \
    --no-progress \
    --scanners vuln \
    --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
    "${image}"
