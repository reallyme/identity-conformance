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

readonly expected_gitleaks_version="8.30.1"
readonly gitleaks_bin="${GITLEAKS_BIN:-gitleaks}"
readonly release_readiness_revision="18a6d91d99837e80f92e41fe04effb0b043d754e"

fail() {
    printf 'Publication readiness: %s\n' "$1" >&2
    exit 78
}

command -v "${gitleaks_bin}" >/dev/null 2>&1 || \
    fail "Gitleaks ${expected_gitleaks_version} is required"
actual_version="$("${gitleaks_bin}" version)"
readonly actual_version
[[ "${actual_version}" == "${expected_gitleaks_version}" ]] || \
    fail "Gitleaks must be version ${expected_gitleaks_version}"

git diff --cached --quiet && fail "no staged publication candidate exists"

# The immutable shared runner inspects the Git index, so ignored local
# checkouts, standards documents, and raw results cannot enter the candidate
# unnoticed. npm 11 requires explicit approval for Git-hosted packages.
npm exec --yes --allow-remote=root \
    --package="github:reallyme/release-readiness#${release_readiness_revision}" \
    -- reallyme-release-readiness
"${gitleaks_bin}" git --staged --redact --no-banner --verbose .
git diff --cached --check

printf 'The staged publication candidate passed release and secret checks\n'
