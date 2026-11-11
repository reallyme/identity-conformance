#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail
umask 077

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repository_root="$(cd -- "${script_dir}/.." && pwd)"
readonly repository_root
cd "${repository_root}"

readonly matrix_scope="${1:-all}"
readonly suite_dir="${OIDF_CONFORMANCE_SUITE_DIR:-upstream/oidf/openid-conformance-suite}"
readonly result_dir="${OIDF_CONFORMANCE_RESULTS_DIR:-results/local/oidf-final}"
readonly adapter_registry="adapters/registry.json"
readonly official_runner="${suite_dir}/scripts/run-test-plan.py"

fail() {
    printf 'OIDF matrix runner: %s\n' "$1" >&2
    exit 78
}

case "${matrix_scope}" in
    certification | engineering | engineering-master | all) ;;
    *) fail "scope must be certification, engineering, engineering-master, or all" ;;
esac

[[ -n "${CONFORMANCE_SERVER:-}" ]] || fail "CONFORMANCE_SERVER is required"
[[ ! -e "${result_dir}" ]] || fail "result directory already exists"
case "${CONFORMANCE_SERVER}" in
    https://*) ;;
    http://127.0.0.1* | http://localhost*)
        [[ -n "${CONFORMANCE_DEV_MODE:-}" ]] || \
            fail "plain HTTP is permitted only with CONFORMANCE_DEV_MODE"
        ;;
    *) fail "CONFORMANCE_SERVER must use HTTPS outside local development" ;;
esac
if [[ -z "${CONFORMANCE_DEV_MODE:-}" && -z "${CONFORMANCE_TOKEN:-}" ]]; then
    fail "CONFORMANCE_TOKEN is required for a hosted conformance server"
fi

[[ -f "${official_runner}" ]] || fail "official run-test-plan.py is unavailable"
scripts/verify_oidf_manifests.py
if [[ "${matrix_scope}" == "engineering-master" ]]; then
    scripts/verify_oidf_certification_parameters.py "${suite_dir}" \
        --manifest plans/oidf/engineering-master.json
else
    scripts/verify_oidf_certification_parameters.py "${suite_dir}"
    scripts/verify_oidf_certification_parameters.py "${suite_dir}" \
        --manifest plans/oidf/engineering.json
fi

config_for_plan() {
    local plan_id="$1"
    local configuration_env
    configuration_env="$(
        jq -er --arg plan_id "${plan_id}" '
          [.adapters[] | select(.plan_ids | index($plan_id)) | .configuration_env]
          | if length == 1 then .[0] else error("plan must have one adapter") end
        ' "${adapter_registry}"
    )" || fail "manifest plan does not have exactly one adapter"
    [[ "${configuration_env}" =~ ^OIDF_[A-Z0-9_]+_CONFIG$ ]] || \
        fail "adapter configuration environment variable is invalid"
    printf '%s' "${!configuration_env:-}"
}

runner_arguments=()
append_manifest() {
    local manifest_path="$1"
    local plan_id
    local expression
    local config_path

    while IFS=$'\t' read -r plan_id expression; do
        [[ -n "${plan_id}" && -n "${expression}" ]] || \
            fail "manifest contains an incomplete run"
        [[ "${expression}" != *:* ]] || \
            fail "module selection is prohibited in matrix expressions"
        config_path="$(config_for_plan "${plan_id}")"
        [[ -n "${config_path}" ]] || fail "a role configuration path is missing"
        [[ -f "${config_path}" && -r "${config_path}" ]] || \
            fail "a role configuration file is unavailable"
        jq empty "${config_path}" >/dev/null || fail "a role configuration file is invalid JSON"
        runner_arguments+=("${expression}" "${config_path}")
    done < <(
        jq -r '
          .plans[] as $plan
          | ($plan.certification_runs // $plan.engineering_runs)[]
          | [$plan.plan_id, .expression]
          | @tsv
        ' "${manifest_path}"
    )
}

if [[ "${matrix_scope}" == "certification" || "${matrix_scope}" == "all" ]]; then
    append_manifest plans/oidf/certification.json
fi
if [[ "${matrix_scope}" == "engineering" || "${matrix_scope}" == "all" ]]; then
    append_manifest plans/oidf/engineering.json
fi
if [[ "${matrix_scope}" == "engineering-master" ]]; then
    append_manifest plans/oidf/engineering-master.json
fi
[[ "${#runner_arguments[@]}" -gt 0 ]] || fail "the selected matrix contains no runs"

mkdir -p "${result_dir}"
printf '{"schema_version":1,"scope":"%s","certification_evidence":false,"reason":"interactive_product_and_deployment_evidence_not_collected"}\n' \
    "${matrix_scope}" > "${result_dir}/evidence-scope.json"
python3 "${official_runner}" --export-dir "${result_dir}" "${runner_arguments[@]}"
