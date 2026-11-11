#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

readonly actionlint_version="1.7.12"
readonly archive="actionlint_${actionlint_version}_linux_amd64.tar.gz"
readonly archive_sha256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
readonly download_url="https://github.com/rhysd/actionlint/releases/download/v${actionlint_version}/${archive}"

temporary_directory=""

# A correctly versioned local binary avoids downloading a Linux archive on
# non-Linux maintainer workstations. CI still follows the digest-verified path.
if command -v actionlint >/dev/null 2>&1; then
    installed_version="$(actionlint -version | head -n 1 | cut -d ' ' -f 1)"
    readonly installed_version
    if [[ "${installed_version}" == "${actionlint_version}" ]]; then
        exec actionlint -config-file .github/actionlint.yaml
    fi
fi

cleanup() {
    if [[ -n "${temporary_directory}" && -d "${temporary_directory}" ]]; then
        rm -r -- "${temporary_directory}"
    fi
}
trap cleanup EXIT

for required_command in curl mktemp sha256sum tar; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        printf 'error: required command is unavailable: %s\n' "${required_command}" >&2
        exit 78
    fi
done

temporary_directory="$(mktemp -d)"
readonly temporary_directory
archive_path="${temporary_directory}/${archive}"
readonly archive_path

curl --fail --location --proto '=https' --silent --show-error --tlsv1.2 \
    --output "${archive_path}" \
    "${download_url}"
printf '%s  %s\n' "${archive_sha256}" "${archive_path}" | \
    sha256sum --check --strict
tar --extract --gzip --file "${archive_path}" \
    --directory "${temporary_directory}" actionlint
"${temporary_directory}/actionlint" -config-file .github/actionlint.yaml
