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
openid4vp_root="$(cd -- "${repository_root}/../openid4vp" && pwd)"
readonly openid4vp_root
suite_dir="${OIDF_CONFORMANCE_SUITE_DIR:-${repository_root}/upstream/oidf/openid-conformance-suite}"
result_root="${OIDF_OPENID4VP_REHEARSAL_RESULT_DIR:-${repository_root}/results/local/openid4vp-rehearsal}"
readonly suite_dir result_root
local_api_token=""
local_api_token_id=""

fail() {
  printf 'OIDF OpenID4VP local rehearsal: %s\n' "$1" >&2
  exit 78
}

delete_local_api_token() {
  if [[ -z "${local_api_token}" || -z "${local_api_token_id}" ]]; then
    return
  fi
  curl --fail --silent --show-error --max-time 15 \
    --cacert "${SSL_CERT_FILE}" \
    --request DELETE \
    --header "Authorization: Bearer ${local_api_token}" \
    "${CONFORMANCE_SERVER%/}/api/token/${local_api_token_id}" >/dev/null || true
}

trap delete_local_api_token EXIT

require_file() {
  [[ -f "$1" && -r "$1" && ! -L "$1" ]] || fail "$2"
}

require_variable() {
  [[ -n "${!1:-}" ]] || fail "$2"
}

resolve_file() {
  local input="$1"
  local directory
  directory="$(cd -- "$(dirname -- "${input}")" && pwd)" || \
    fail "input directory is unavailable"
  printf '%s/%s\n' "${directory}" "$(basename -- "${input}")"
}

require_secure_local_mode() {
  case "${OIDF_LOCAL_REHEARSAL:-}" in
    1 | true | TRUE | yes | YES) ;;
    *) fail "OIDF_LOCAL_REHEARSAL must be enabled for a local rehearsal" ;;
  esac
  [[ -z "${CONFORMANCE_DEV_MODE+x}" ]] || \
    fail "CONFORMANCE_DEV_MODE must be unset because the upstream runner disables TLS verification"
  [[ -z "${DISABLE_SSL_VERIFY+x}" ]] || \
    fail "DISABLE_SSL_VERIFY must be unset for a local rehearsal"
  [[ -z "${CONFORMANCE_TOKEN:-}" ]] || \
    fail "CONFORMANCE_TOKEN must be unset; local rehearsal does not accept operator credentials"
  [[ -z "${CONFORMANCE_API_TOKEN:-}" ]] || \
    fail "CONFORMANCE_API_TOKEN must be unset; local rehearsal does not accept operator credentials"
  case "${CONFORMANCE_VERIFY_SSL:-}" in
    1 | true | TRUE | yes | YES) ;;
    *) fail "CONFORMANCE_VERIFY_SSL must be explicitly enabled" ;;
  esac
}

profile_expression() {
  local role="$1"
  local profile_id="$2"
  local plan_id
  local expression
  case "${role}" in
    verifier) plan_id="oid4vp-1final-verifier-haip-test-plan" ;;
    wallet) plan_id="oid4vp-1final-wallet-haip-test-plan" ;;
    *) fail "unsupported OpenID4VP rehearsal role" ;;
  esac
  expression="$(jq -er \
    --arg plan_id "${plan_id}" \
    --arg profile_id "${profile_id}" \
    '.plans[]
     | select(.protocol == "openid4vp" and .plan_id == $plan_id)
     | .certification_runs[]
     | select(.profile_id == $profile_id)
     | .expression' \
    "${certification_plan}")" || fail "rehearsal profile is missing"
  case "${expression}" in
    "" | *$'\n'*) fail "rehearsal profile is missing or duplicated" ;;
  esac
  jq -e \
    --arg profile_id "${profile_id}" \
    --arg expression "${expression}" \
    '.profiles
     | map(select(.id == $profile_id and .expression == $expression))
     | length == 1' \
    "${openid_profile_matrix}" >/dev/null || \
    fail "selected rehearsal profile is unsupported by the locked OpenID4VP component"
}

require_validated_profile() {
  local role="$1"
  local profile_id="$2"
  local result_file="${result_root}/control/${role}/${profile_id}.json"
  local export_dir="${result_root}/exports/${role}/${profile_id}"
  require_file "${result_file}" "profile result is missing"
  jq -e \
    --arg profile_id "${profile_id}" \
    '.profile_id == $profile_id and .status == "validated"' \
    "${result_file}" >/dev/null || fail "profile result is not validated"
  [[ -d "${export_dir}" ]] || fail "profile export is missing"
  [[ -n "$(find "${export_dir}" -type f -print -quit)" ]] || \
    fail "profile export is empty"
}

archive_verifier_preflight() {
  local profile_id="$1"
  local preflight_result="${result_root}/control/verifier/oidf-verifier-flow-driver-preflight.json"
  local preflight_archive="${result_root}/control/verifier/preflight/${profile_id}.json"
  require_file "${preflight_result}" "verifier flow-driver preflight result is missing"
  [[ ! -e "${preflight_archive}" ]] || \
    fail "verifier flow-driver preflight archive already exists"
  mkdir -p "$(dirname -- "${preflight_archive}")"
  mv -- "${preflight_result}" "${preflight_archive}"
}

for command in git jq python3 curl; do
  command -v "${command}" >/dev/null 2>&1 || fail "required command is unavailable"
done

require_secure_local_mode
require_variable CONFORMANCE_SERVER "CONFORMANCE_SERVER is required"
require_variable CONFORMANCE_SERVER_MTLS "CONFORMANCE_SERVER_MTLS is required"
require_variable SSL_CERT_FILE "SSL_CERT_FILE is required"
require_variable OIDF_LOOPBACK_HTTP_ORIGIN "OIDF_LOOPBACK_HTTP_ORIGIN is required"
require_variable OIDF_VP_VERIFIER_CONFIG "OIDF_VP_VERIFIER_CONFIG is required"
require_variable OIDF_VP_WALLET_SD_JWT_CONFIG \
  "OIDF_VP_WALLET_SD_JWT_CONFIG is required"
require_variable OIDF_VP_WALLET_MDOC_CONFIG \
  "OIDF_VP_WALLET_MDOC_CONFIG is required"
require_variable EXAMPLE_VERIFIER_BASE_URL "EXAMPLE_VERIFIER_BASE_URL is required"
require_variable OIDF_VERIFIER_LAUNCH_ENDPOINT \
  "OIDF_VERIFIER_LAUNCH_ENDPOINT is required"
require_variable OIDF_VERIFIER_EVIDENCE_ENDPOINT \
  "OIDF_VERIFIER_EVIDENCE_ENDPOINT is required"
require_variable OIDF_VERIFIER_HEALTH_ENDPOINT \
  "OIDF_VERIFIER_HEALTH_ENDPOINT is required"
require_variable OIDF_VERIFIER_LAUNCH_TOKEN \
  "OIDF_VERIFIER_LAUNCH_TOKEN is required"
require_variable OIDF_VERIFIER_EVIDENCE_TOKEN \
  "OIDF_VERIFIER_EVIDENCE_TOKEN is required"
require_variable OIDF_WALLET_HARNESS_ENDPOINT \
  "OIDF_WALLET_HARNESS_ENDPOINT is required"
require_variable OIDF_WALLET_HARNESS_HEALTH_ENDPOINT \
  "OIDF_WALLET_HARNESS_HEALTH_ENDPOINT is required"
require_variable OIDF_WALLET_HARNESS_TOKEN \
  "OIDF_WALLET_HARNESS_TOKEN is required"
require_variable OIDF_WALLET_SCREENSHOT_BROWSER \
  "OIDF_WALLET_SCREENSHOT_BROWSER is required"

python3 "${script_dir}/verify_oidf_local_endpoints.py" \
  --ca-cert "${SSL_CERT_FILE}" \
  "${CONFORMANCE_SERVER}" "${CONFORMANCE_SERVER_MTLS}" || \
  fail "conformance servers must be verified loopback TLS endpoints"
curl --fail --silent --show-error --max-time 15 \
  --cacert "${SSL_CERT_FILE}" \
  "${CONFORMANCE_SERVER%/}/api/runner/available" >/dev/null || \
  fail "local conformance API is not anonymously reachable over verified TLS"

# The upstream runner couples anonymous dummy-user access to its TLS-disabling
# development mode. Create a short-lived token for the local, non-admin dummy
# user so every downstream request stays on the ordinary verified-TLS path.
local_token_response="$(curl --fail --silent --show-error --max-time 15 \
  --cacert "${SSL_CERT_FILE}" \
  --header "Content-Type: application/json" \
  --data '{"permanent":false}' \
  "${CONFORMANCE_SERVER%/}/api/token")" || \
  fail "local conformance API token creation failed"
local_api_token="$(jq -er '.token | select(type == "string")' \
  <<<"${local_token_response}")" || fail "local conformance API token is invalid"
local_api_token_id="$(jq -er '._id | select(type == "string")' \
  <<<"${local_token_response}")" || fail "local conformance API token id is invalid"
[[ "${#local_api_token}" -ge 32 && "${#local_api_token}" -le 4096 \
  && "${local_api_token}" != *[![:graph:]]* ]] || \
  fail "local conformance API token is invalid"
[[ "${local_api_token_id}" =~ ^[A-Za-z0-9_-]{1,128}$ ]] || \
  fail "local conformance API token id is invalid"
unset local_token_response
export CONFORMANCE_TOKEN="${local_api_token}"
export CONFORMANCE_API_TOKEN="${local_api_token}"

verifier_config="$(resolve_file "${OIDF_VP_VERIFIER_CONFIG}")"
wallet_sd_jwt_config="$(resolve_file "${OIDF_VP_WALLET_SD_JWT_CONFIG}")"
wallet_mdoc_config="$(resolve_file "${OIDF_VP_WALLET_MDOC_CONFIG}")"
readonly verifier_config wallet_sd_jwt_config wallet_mdoc_config
require_file "${verifier_config}" "verifier configuration is unavailable"
require_file "${wallet_sd_jwt_config}" "SD-JWT wallet configuration is unavailable"
require_file "${wallet_mdoc_config}" "mdoc wallet configuration is unavailable"
[[ -d "${suite_dir}" ]] || fail "pinned conformance suite checkout is unavailable"
[[ ! -e "${result_root}" ]] || fail "result directory already exists"

cd "${repository_root}"
python3 scripts/verify_component_lock.py --verify-checkouts
scripts/verify_oidf_manifests.py
scripts/verify_oidf_certification_parameters.py "${suite_dir}"

readonly certification_plan="${repository_root}/plans/oidf/certification.json"
readonly openid_profile_matrix="${openid4vp_root}/conformance/oidf/profile-matrix.json"
readonly openid_result_assertion="${openid4vp_root}/conformance/scripts/assert_oidf_results.sh"
readonly openid_target_verifier="${openid4vp_root}/conformance/scripts/verify_oidf_certification_target.py"
readonly openid_matrix_reader="${openid4vp_root}/conformance/scripts/read_oidf_certification_matrix.py"
readonly openid_wallet_config_verifier="${openid4vp_root}/conformance/scripts/verify_oidf_wallet_config.py"
readonly verifier_flow_driver="${openid4vp_root}/conformance/scripts/drive_oidf_verifier_flow.py"
readonly wallet_flow_driver="${openid4vp_root}/conformance/scripts/drive_oidf_wallet_flow.py"

# Trust material remains protocol-owned. Validate both exact format-specific
# roots before any profile starts, then verify the deployment's signed public
# CRL exception without allowing plaintext control or credential routes.
python3 "${openid_wallet_config_verifier}" "${suite_dir}" \
  "${wallet_sd_jwt_config}" --credential-format sd_jwt_vc
python3 "${openid_wallet_config_verifier}" "${suite_dir}" \
  "${wallet_mdoc_config}" --credential-format iso_mdl
python3 "${script_dir}/verify_oidf_loopback_crl.py" \
  --http-origin "${OIDF_LOOPBACK_HTTP_ORIGIN}" \
  --iaca-root "${suite_dir}/scripts/certs-keys/mdoc-iaca-root.crt"

verifier_config_fingerprint="$(python3 scripts/hash_oidf_input.py "${verifier_config}")"
wallet_sd_jwt_config_fingerprint="$(python3 scripts/hash_oidf_input.py "${wallet_sd_jwt_config}")"
wallet_mdoc_config_fingerprint="$(python3 scripts/hash_oidf_input.py "${wallet_mdoc_config}")"
plan_fingerprint="$(python3 scripts/hash_oidf_input.py "${certification_plan}")"
profile_matrix_fingerprint="$(python3 scripts/hash_oidf_input.py "${openid_profile_matrix}")"
readonly verifier_config_fingerprint wallet_sd_jwt_config_fingerprint
readonly wallet_mdoc_config_fingerprint plan_fingerprint profile_matrix_fingerprint

mkdir -p "${result_root}/control/verifier" "${result_root}/control/wallet"
printf '%s\n' \
  '{"schema_version":1,"protocol":"openid4vp","execution_scope":"local_rehearsal","certification_evidence":false,"submission_authorized":false}' \
  > "${result_root}/evidence-scope.json"
cp "${repository_root}/components.lock.json" "${result_root}/components.lock.json"
cp "${certification_plan}" "${result_root}/certification-plan.json"
cp "${openid_profile_matrix}" "${result_root}/openid4vp-profile-matrix.json"

mapfile -t verifier_profiles < <(jq -er '
  .plans[]
  | select(.protocol == "openid4vp" and .role == "verifier")
  | .certification_runs[].profile_id
' "${certification_plan}")
mapfile -t wallet_profiles < <(jq -er '
  .plans[]
  | select(.protocol == "openid4vp" and .role == "wallet")
  | .certification_runs[].profile_id
' "${certification_plan}")
[[ "${#verifier_profiles[@]}" -eq 2 && "${#wallet_profiles[@]}" -eq 4 ]] || \
  fail "certification plan does not select the complete OpenID4VP profile set"

for profile_id in "${verifier_profiles[@]}"; do
  profile_expression verifier "${profile_id}"
  (
    cd "${openid4vp_root}"
    CONFORMANCE_SUITE_DIR="${suite_dir}" \
    CONFORMANCE_RESULTS_DIR="${result_root}/control/verifier" \
    OIDF_EXPORT_DIR="${result_root}/exports/verifier" \
    OIDF_PROFILE_MATRIX="${openid_profile_matrix}" \
    OIDF_PROFILE_ID="${profile_id}" \
    OIDF_RESULT_ASSERTION="${openid_result_assertion}" \
    OIDF_TARGET_VERIFIER="${openid_target_verifier}" \
    OIDF_MATRIX_READER="${openid_matrix_reader}" \
    OIDF_VERIFIER_FLOW_DRIVER="${verifier_flow_driver}" \
    OIDF_CONFIG_FILE="${verifier_config}" \
    OIDF_RUNNER_MODE=execute \
    OIDF_VERIFIER_FLOW_DRIVER_MODE=execute \
    conformance/scripts/run_oidf_verifier_plan.sh
  )
  # The upstream runner uses one fixed preflight filename. Retain each result
  # under its profile before starting the next independently configured run.
  archive_verifier_preflight "${profile_id}"
  require_validated_profile verifier "${profile_id}"
done

for profile_id in "${wallet_profiles[@]}"; do
  profile_expression wallet "${profile_id}"
  (
    cd "${openid4vp_root}"
    CONFORMANCE_SUITE_DIR="${suite_dir}" \
    CONFORMANCE_RESULTS_DIR="${result_root}/control/wallet" \
    OIDF_WALLET_EXPORT_DIR="${result_root}/exports/wallet" \
    OIDF_PROFILE_MATRIX="${openid_profile_matrix}" \
    OIDF_PROFILE_ID="${profile_id}" \
    OIDF_RESULT_ASSERTION="${openid_result_assertion}" \
    OIDF_TARGET_VERIFIER="${openid_target_verifier}" \
    OIDF_MATRIX_READER="${openid_matrix_reader}" \
    OIDF_WALLET_CONFIG_VERIFIER="${openid_wallet_config_verifier}" \
    OIDF_WALLET_FLOW_DRIVER="${wallet_flow_driver}" \
    OIDF_WALLET_SD_JWT_CONFIG_FILE="${wallet_sd_jwt_config}" \
    OIDF_WALLET_MDOC_CONFIG_FILE="${wallet_mdoc_config}" \
    OIDF_WALLET_RUNNER_MODE=execute \
    OIDF_WALLET_FLOW_DRIVER_MODE=execute \
    conformance/scripts/run_oidf_wallet_plan.sh
  )
  require_validated_profile wallet "${profile_id}"
done

# Recheck every mutable source input after the external run. A local pass must
# still describe the exact code and configuration bytes that initiated it.
python3 scripts/verify_component_lock.py --verify-checkouts
scripts/verify_oidf_certification_parameters.py "${suite_dir}"
[[ "$(python3 scripts/hash_oidf_input.py "${verifier_config}")" == \
  "${verifier_config_fingerprint}" ]] || fail "verifier configuration changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${wallet_sd_jwt_config}")" == \
  "${wallet_sd_jwt_config_fingerprint}" ]] || \
  fail "SD-JWT wallet configuration changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${wallet_mdoc_config}")" == \
  "${wallet_mdoc_config_fingerprint}" ]] || \
  fail "mdoc wallet configuration changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${certification_plan}")" == \
  "${plan_fingerprint}" ]] || fail "certification plan changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${openid_profile_matrix}")" == \
  "${profile_matrix_fingerprint}" ]] || \
  fail "OpenID4VP profile matrix changed during execution"

suite_revision="$(git -C "${suite_dir}" rev-parse HEAD)"
readonly suite_revision
printf '%s\n' "${suite_revision}" > "${result_root}/oidf-suite-revision.txt"
python3 scripts/assert_oidf_openid4vp_local_rehearsal.py \
  --result-root "${result_root}" \
  --certification-plan "${result_root}/certification-plan.json" \
  --profile-matrix "${result_root}/openid4vp-profile-matrix.json" \
  --component-lock "${result_root}/components.lock.json" \
  --openid4vp-source-dir "${openid4vp_root}" \
  --result-assertion "${openid_result_assertion}"
printf '%s\n' \
  '{"schema_version":1,"protocol":"openid4vp","execution_scope":"local_rehearsal","status":"validated","profile_count":6,"certification_evidence":false,"submission_authorized":false}' \
  > "${result_root}/local-rehearsal-result.json"
printf 'Validated six local OpenID4VP rehearsal profiles under %s\n' "${result_root}"
