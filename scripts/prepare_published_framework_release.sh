#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  printf 'usage: %s FRAMEWORK_ROOT EXPECTED_COMMIT\n' "$0" >&2
  exit 64
fi

readonly framework_root="$1"
readonly expected_commit="$2"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

if [[ ! "${expected_commit}" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'framework commit must be a full lowercase Git commit\n' >&2
  exit 65
fi
if [[ ! -d "${framework_root}" || -L "${framework_root}" ]]; then
  printf 'framework checkout is unavailable or unsafe\n' >&2
  exit 65
fi
if [[ "$(git -C "${framework_root}" rev-parse HEAD)" != "${expected_commit}" ]]; then
  printf 'framework checkout does not match the selected commit\n' >&2
  exit 65
fi

framework_version="$(tr -d '\n' < "${framework_root}/VERSION")"
readonly framework_version
if [[ ! "${framework_version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'framework version is invalid\n' >&2
  exit 65
fi

readonly release_tag="v${framework_version}"
readonly release_dir="${RUNNER_TEMP}/identity-conformance-framework-release"
if [[ -e "${release_dir}" || -L "${release_dir}" ]]; then
  printf 'framework release working directory already exists\n' >&2
  exit 65
fi
umask 077
mkdir "${release_dir}"

gh api "repos/reallyme/identity-conformance/releases/tags/${release_tag}" \
  > "${release_dir}/release.json"
tag_commit="$(
  gh api "repos/reallyme/identity-conformance/commits/${release_tag}" --jq '.sha'
)"
readonly tag_commit
gh release download "${release_tag}" \
  --repo reallyme/identity-conformance \
  --pattern conformance-framework-release.json \
  --dir "${release_dir}"

python3 "${framework_root}/scripts/verify_published_framework_release.py" \
  --framework-root "${framework_root}" \
  --expected-commit "${expected_commit}" \
  --release-metadata "${release_dir}/release.json" \
  --tag-commit "${tag_commit}" \
  --manifest "${release_dir}/conformance-framework-release.json" \
  --output "${release_dir}/selection.json"

printf 'version=%s\n' "${framework_version}" >> "${GITHUB_OUTPUT}"
printf 'tag=%s\n' "${release_tag}" >> "${GITHUB_OUTPUT}"
printf '## Selected Identity Conformance %s\n\nFramework commit: %s\n' \
  "${release_tag}" "${expected_commit}" >> "${GITHUB_STEP_SUMMARY}"
