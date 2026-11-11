#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd -- "${script_dir}/.." && pwd)"
readonly repository_root
cd "${repository_root}"

readonly suite_lock="upstream/oidf/conformance-suite.lock.json"
[[ -f "${suite_lock}" ]] || {
    printf 'OIDF suite lock is unavailable: %s\n' "${suite_lock}" >&2
    exit 78
}
scripts/verify_oidf_manifests.py
suite_repository="$(jq -er '.repository | select(type == "string" and length > 0)' "${suite_lock}")"
readonly suite_repository
suite_ref="$(jq -er '.pinned_ref | select(type == "string" and length > 0)' "${suite_lock}")"
readonly suite_ref
suite_commit="$(jq -er '.commit | select(type == "string" and test("^[0-9a-f]{40}$"))' "${suite_lock}")"
readonly suite_commit
default_suite_dir="$(jq -er '.local_checkout | select(type == "string" and length > 0)' "${suite_lock}")"
readonly default_suite_dir
readonly suite_dir="${1:-${default_suite_dir}}"

if [[ -e "${suite_dir}" ]]; then
    if [[ ! -d "${suite_dir}/.git" ]]; then
        printf 'Existing suite path is not a Git checkout: %s\n' "${suite_dir}" >&2
        exit 78
    fi
else
    mkdir -p "$(dirname "${suite_dir}")"
    git clone --depth 1 --branch "${suite_ref}" "${suite_repository}" "${suite_dir}"
fi

actual_commit="$(git -C "${suite_dir}" rev-parse HEAD)"
readonly actual_commit
if [[ "${actual_commit}" != "${suite_commit}" ]]; then
    printf 'Suite checkout is not the expected commit: %s\n' "${suite_dir}" >&2
    exit 78
fi

scripts/verify_oidf_certification_parameters.py "${suite_dir}"
scripts/verify_oidf_certification_parameters.py "${suite_dir}" \
    --manifest plans/oidf/engineering.json

printf 'OIDF conformance suite is ready at %s\n' "${suite_dir}"
