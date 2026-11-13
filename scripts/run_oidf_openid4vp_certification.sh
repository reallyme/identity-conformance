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
suite_dir="${OIDF_CONFORMANCE_SUITE_DIR:-${repository_root}/upstream/oidf/openid-conformance-suite}"
result_root="${OIDF_OPENID4VP_RESULT_DIR:-${repository_root}/results/local/openid4vp-certification}"
readonly suite_dir result_root

fail() {
  printf 'OIDF OpenID4VP certification runner: %s\n' "$1" >&2
  exit 78
}

openid4vp_root="$(cd -- "${OIDF_OPENID4VP_SOURCE_DIR:-${repository_root}/../openid4vp}" && pwd)" || \
  fail "OpenID4VP adapter source repository is unavailable"
readonly openid4vp_root

require_file() {
  [[ -f "$1" && -r "$1" && ! -L "$1" ]] || fail "$2"
}

require_variable() {
  [[ -n "${!1:-}" ]] || fail "$2"
}

resolve_file() {
  local input="$1"
  local directory
  directory="$(cd -- "$(dirname -- "${input}")" && pwd)" || fail "input directory is unavailable"
  printf '%s/%s\n' "${directory}" "$(basename -- "${input}")"
}

require_public_https_endpoint() {
  case "$1" in
    https://localhost* | https://127.* | https://host.docker.internal* | https://\[::1\]*)
      fail "$2"
      ;;
    https://*) ;;
    *) fail "$2" ;;
  esac
  case "${1#https://}" in
    "" | *@* | *\?* | *\#*) fail "$2" ;;
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
    *) fail "unsupported OpenID4VP certification role" ;;
  esac
  expression="$(jq -er \
    --arg plan_id "${plan_id}" \
    --arg profile_id "${profile_id}" \
    '.plans[]
     | select(.protocol == "openid4vp" and .plan_id == $plan_id)
     | .certification_runs[]
     | select(.profile_id == $profile_id)
     | .expression' \
    "${certification_plan}")" || fail "certification profile is missing"
  case "${expression}" in
    "" | *$'\n'*) fail "certification profile is missing or duplicated" ;;
  esac
  jq -e \
    --arg profile_id "${profile_id}" \
    --arg expression "${expression}" \
    '.profiles
     | map(select(.id == $profile_id and .expression == $expression))
     | length == 1' \
    "${openid_profile_matrix}" >/dev/null || \
    fail "selected certification profile is absent from the framework profile matrix"
  printf '%s\n' "${expression}"
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
  [[ -n "$(find "${export_dir}" -type f -print -quit)" ]] || fail "profile export is empty"
}

for command in git jq python3 curl; do
  command -v "${command}" >/dev/null 2>&1 || fail "required command is unavailable"
done

require_variable CONFORMANCE_SERVER "CONFORMANCE_SERVER is required"
require_variable CONFORMANCE_SERVER_MTLS "CONFORMANCE_SERVER_MTLS is required"
require_variable CONFORMANCE_TOKEN "CONFORMANCE_TOKEN is required"
require_variable OIDF_VP_VERIFIER_CONFIG "OIDF_VP_VERIFIER_CONFIG is required"
require_variable OIDF_VP_WALLET_SD_JWT_CONFIG \
  "OIDF_VP_WALLET_SD_JWT_CONFIG is required"
require_variable OIDF_VP_WALLET_MDOC_CONFIG \
  "OIDF_VP_WALLET_MDOC_CONFIG is required"
require_variable OIDF_DEPLOYMENT_MANIFEST "OIDF_DEPLOYMENT_MANIFEST is required"
require_variable OIDF_PRODUCT_COMPONENT_BOM "OIDF_PRODUCT_COMPONENT_BOM is required"
require_variable OIDF_PRODUCT_SOURCE_DIR "OIDF_PRODUCT_SOURCE_DIR is required"
require_variable CONFORMANCE_FRAMEWORK_COMMIT "CONFORMANCE_FRAMEWORK_COMMIT is required"
require_variable CONFORMANCE_WORKFLOW_COMMIT "CONFORMANCE_WORKFLOW_COMMIT is required"
require_variable EXAMPLE_VERIFIER_BASE_URL "EXAMPLE_VERIFIER_BASE_URL is required"
require_variable OIDF_VERIFIER_LAUNCH_ENDPOINT "OIDF_VERIFIER_LAUNCH_ENDPOINT is required"
require_variable OIDF_VERIFIER_EVIDENCE_ENDPOINT "OIDF_VERIFIER_EVIDENCE_ENDPOINT is required"
require_variable OIDF_VERIFIER_HEALTH_ENDPOINT "OIDF_VERIFIER_HEALTH_ENDPOINT is required"
require_variable OIDF_VERIFIER_LAUNCH_TOKEN "OIDF_VERIFIER_LAUNCH_TOKEN is required"
require_variable OIDF_VERIFIER_EVIDENCE_TOKEN "OIDF_VERIFIER_EVIDENCE_TOKEN is required"
require_variable OIDF_WALLET_HARNESS_ENDPOINT "OIDF_WALLET_HARNESS_ENDPOINT is required"
require_variable OIDF_WALLET_HARNESS_HEALTH_ENDPOINT \
  "OIDF_WALLET_HARNESS_HEALTH_ENDPOINT is required"
require_variable OIDF_WALLET_HARNESS_TOKEN "OIDF_WALLET_HARNESS_TOKEN is required"
verifier_config="$(resolve_file "${OIDF_VP_VERIFIER_CONFIG}")"
wallet_sd_jwt_config="$(resolve_file "${OIDF_VP_WALLET_SD_JWT_CONFIG}")"
wallet_mdoc_config="$(resolve_file "${OIDF_VP_WALLET_MDOC_CONFIG}")"
deployment_manifest="$(resolve_file "${OIDF_DEPLOYMENT_MANIFEST}")"
product_component_bom="$(resolve_file "${OIDF_PRODUCT_COMPONENT_BOM}")"
product_source_dir="$(cd -- "${OIDF_PRODUCT_SOURCE_DIR}" && pwd)" || \
  fail "product source repository is unavailable"
readonly verifier_config wallet_sd_jwt_config wallet_mdoc_config deployment_manifest
readonly product_component_bom product_source_dir
require_file "${verifier_config}" "verifier configuration is unavailable"
require_file "${wallet_sd_jwt_config}" "SD-JWT wallet configuration is unavailable"
require_file "${wallet_mdoc_config}" "mdoc wallet configuration is unavailable"
require_file "${deployment_manifest}" "deployment manifest is unavailable"
require_file "${product_component_bom}" "product component BOM is unavailable"
[[ -d "${suite_dir}" ]] || fail "pinned conformance suite checkout is unavailable"
[[ ! -e "${result_root}" ]] || fail "result directory already exists"

require_public_https_endpoint "${CONFORMANCE_SERVER}" "hosted conformance server must be a public HTTPS endpoint"
require_public_https_endpoint "${CONFORMANCE_SERVER_MTLS}" "hosted mTLS conformance server must be a public HTTPS endpoint"
expected_conformance_server="$(jq -er '.execution_contract.production_endpoints.api' \
  "${repository_root}/plans/oidf/certification.json")" || \
  fail "certification manifest does not declare the production conformance server"
expected_conformance_server_mtls="$(jq -er '.execution_contract.production_endpoints.mtls' \
  "${repository_root}/plans/oidf/certification.json")" || \
  fail "certification manifest does not declare the production mTLS server"
readonly expected_conformance_server expected_conformance_server_mtls
[[ "${CONFORMANCE_SERVER}" == "${expected_conformance_server}" ]] || \
  fail "certification evidence must use the official OIDF production server"
[[ "${CONFORMANCE_SERVER_MTLS}" == "${expected_conformance_server_mtls}" ]] || \
  fail "certification evidence must use the official OIDF production mTLS server"
require_public_https_endpoint "${EXAMPLE_VERIFIER_BASE_URL}" "verifier base URL must be a public HTTPS endpoint"
require_public_https_endpoint "${OIDF_VERIFIER_LAUNCH_ENDPOINT}" "verifier launch endpoint must be a public HTTPS endpoint"
require_public_https_endpoint "${OIDF_VERIFIER_EVIDENCE_ENDPOINT}" "verifier evidence endpoint must be a public HTTPS endpoint"
require_public_https_endpoint "${OIDF_VERIFIER_HEALTH_ENDPOINT}" "verifier health endpoint must be a public HTTPS endpoint"
require_public_https_endpoint "${OIDF_WALLET_HARNESS_ENDPOINT}" "wallet harness must be a public HTTPS endpoint"
require_public_https_endpoint "${OIDF_WALLET_HARNESS_HEALTH_ENDPOINT}" \
  "wallet harness health endpoint must be a public HTTPS endpoint"

adapter_component_id="$(jq -er \
  '[.components[] | select(.adapter_contracts | index("openid4vp"))] | if length == 1 then .[0].component_id else error("OpenID4VP adapter provider must be unique") end' \
  "${product_component_bom}")" || fail "OpenID4VP adapter provider is invalid"
product_component_id="$(jq -er \
  '.product_component_id | select(type == "string" and length > 0)' \
  "${product_component_bom}")" || fail "product component identity is invalid"
readonly adapter_component_id product_component_id
checkout_arguments=(--checkout "${adapter_component_id}=${openid4vp_root}")
if [[ "${product_component_id}" == "${adapter_component_id}" ]]; then
  [[ "${product_source_dir}" == "${openid4vp_root}" ]] || \
    fail "one component cannot be represented by two source checkouts"
else
  checkout_arguments+=(--checkout "${product_component_id}=${product_source_dir}")
fi

cd "${repository_root}"
python3 scripts/verify_product_component_bom.py \
  --bom "${product_component_bom}" --plan plans/oidf/certification.json \
  --require-release-refs "${checkout_arguments[@]}"
scripts/verify_oidf_manifests.py
scripts/verify_oidf_certification_parameters.py "${suite_dir}"
python3 scripts/verify_oidf_deployment_manifest.py \
  --manifest "${deployment_manifest}" \
  --product-component-bom "${product_component_bom}" \
  --binding openid4vp_verifier.verifier_base_url "${EXAMPLE_VERIFIER_BASE_URL}" \
  --binding openid4vp_verifier.verifier_launch_endpoint "${OIDF_VERIFIER_LAUNCH_ENDPOINT}" \
  --binding openid4vp_verifier.verifier_evidence_endpoint "${OIDF_VERIFIER_EVIDENCE_ENDPOINT}" \
  --binding openid4vp_verifier.verifier_health_endpoint "${OIDF_VERIFIER_HEALTH_ENDPOINT}" \
  --binding openid4vp_wallet.wallet_harness_endpoint "${OIDF_WALLET_HARNESS_ENDPOINT}" \
  --binding openid4vp_wallet.wallet_harness_health_endpoint "${OIDF_WALLET_HARNESS_HEALTH_ENDPOINT}"

readonly certification_plan="${repository_root}/plans/oidf/certification.json"
mkdir -p "${result_root}"
runtime_contracts="${result_root}/runtime-contracts"
python3 scripts/build_oidf_runtime_contracts.py \
  --product-component-bom "${product_component_bom}" \
  --output-dir "${runtime_contracts}" \
  --require-release-refs
readonly runtime_contracts
readonly openid_profile_matrix="${runtime_contracts}/openid4vp-profile-matrix.json"
readonly openid_result_assertion="${repository_root}/scripts/assert_oidf_openid4vp_suite_results.py"
readonly openid_target_verifier="${openid4vp_root}/conformance/scripts/verify_oidf_certification_target.py"
readonly openid_matrix_reader="${openid4vp_root}/conformance/scripts/read_oidf_certification_matrix.py"
readonly openid_wallet_config_verifier="${openid4vp_root}/conformance/scripts/verify_oidf_wallet_config.py"
readonly verifier_flow_driver="${openid4vp_root}/conformance/scripts/drive_oidf_verifier_flow.py"
readonly wallet_flow_driver="${openid4vp_root}/conformance/scripts/drive_oidf_wallet_flow.py"
require_file "${openid_profile_matrix}" "OpenID4VP profile matrix is unavailable"
require_file "${openid_result_assertion}" "OpenID4VP result assertion is unavailable"
expected_suite_revision="$(jq -er '.commit' \
  "${repository_root}/upstream/oidf/conformance-suite.lock.json")" || \
  fail "framework suite revision is unavailable"
checked_suite_revision="$(git -C "${suite_dir}" rev-parse HEAD)" || \
  fail "suite checkout revision is unavailable"
readonly expected_suite_revision checked_suite_revision
[[ "${checked_suite_revision}" == "${expected_suite_revision}" ]] || \
  fail "suite checkout disagrees with the framework release"
python3 scripts/verify_oidf_wallet_plan.py --suite-checkout "${suite_dir}"
verifier_config_fingerprint="$(python3 scripts/hash_oidf_input.py "${verifier_config}")"
wallet_sd_jwt_config_fingerprint="$(python3 scripts/hash_oidf_input.py "${wallet_sd_jwt_config}")"
wallet_mdoc_config_fingerprint="$(python3 scripts/hash_oidf_input.py "${wallet_mdoc_config}")"
plan_fingerprint="$(python3 scripts/hash_oidf_input.py "${certification_plan}")"
profile_matrix_fingerprint="$(python3 scripts/hash_oidf_input.py "${openid_profile_matrix}")"
readonly verifier_config_fingerprint wallet_sd_jwt_config_fingerprint
readonly wallet_mdoc_config_fingerprint plan_fingerprint profile_matrix_fingerprint

mkdir -p "${result_root}/control/verifier" "${result_root}/control/wallet"
cp "${deployment_manifest}" "${result_root}/deployment-manifest.json"
cp "${product_component_bom}" "${result_root}/product-component-bom.json"
cp "${certification_plan}" "${result_root}/certification-plan.json"
cp "${openid_profile_matrix}" "${result_root}/openid4vp-profile-matrix.json"
python3 scripts/verify_oidf_deployment_manifest.py \
  --manifest "${result_root}/deployment-manifest.json" \
  --product-component-bom "${result_root}/product-component-bom.json" \
  --binding openid4vp_verifier.verifier_base_url "${EXAMPLE_VERIFIER_BASE_URL}" \
  --binding openid4vp_verifier.verifier_launch_endpoint "${OIDF_VERIFIER_LAUNCH_ENDPOINT}" \
  --binding openid4vp_verifier.verifier_evidence_endpoint "${OIDF_VERIFIER_EVIDENCE_ENDPOINT}" \
  --binding openid4vp_verifier.verifier_health_endpoint "${OIDF_VERIFIER_HEALTH_ENDPOINT}" \
  --binding openid4vp_wallet.wallet_harness_endpoint "${OIDF_WALLET_HARNESS_ENDPOINT}" \
  --binding openid4vp_wallet.wallet_harness_health_endpoint "${OIDF_WALLET_HARNESS_HEALTH_ENDPOINT}"

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
  profile_expression verifier "${profile_id}" >/dev/null
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
    OIDF_VERIFIER_LAUNCH_TOKEN="${OIDF_VERIFIER_LAUNCH_TOKEN}" \
    OIDF_VERIFIER_EVIDENCE_TOKEN="${OIDF_VERIFIER_EVIDENCE_TOKEN}" \
    CONFORMANCE_API_TOKEN="${CONFORMANCE_API_TOKEN:-${CONFORMANCE_TOKEN}}" \
    OIDF_RUNNER_MODE=execute \
    OIDF_VERIFIER_FLOW_DRIVER_MODE=execute \
    conformance/scripts/run_oidf_verifier_plan.sh
  )
  require_validated_profile verifier "${profile_id}"
done
for profile_id in "${wallet_profiles[@]}"; do
  profile_expression wallet "${profile_id}" >/dev/null
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
    OIDF_WALLET_HARNESS_TOKEN="${OIDF_WALLET_HARNESS_TOKEN}" \
    CONFORMANCE_API_TOKEN="${CONFORMANCE_API_TOKEN:-${CONFORMANCE_TOKEN}}" \
    OIDF_WALLET_RUNNER_MODE=execute \
    OIDF_WALLET_FLOW_DRIVER_MODE=execute \
    conformance/scripts/run_oidf_wallet_plan.sh
  )
  require_validated_profile wallet "${profile_id}"
done

# Revalidate mutable local inputs after the long external run. Evidence must
# describe the exact checkout and configuration bytes that initiated it.
python3 scripts/verify_product_component_bom.py \
  --bom "${product_component_bom}" --plan plans/oidf/certification.json \
  --require-release-refs "${checkout_arguments[@]}"
scripts/verify_oidf_certification_parameters.py "${suite_dir}"
[[ "$(python3 scripts/hash_oidf_input.py "${verifier_config}")" == "${verifier_config_fingerprint}" ]] || \
  fail "verifier configuration changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${wallet_sd_jwt_config}")" == \
  "${wallet_sd_jwt_config_fingerprint}" ]] || \
  fail "SD-JWT wallet configuration changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${wallet_mdoc_config}")" == \
  "${wallet_mdoc_config_fingerprint}" ]] || \
  fail "mdoc wallet configuration changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${certification_plan}")" == "${plan_fingerprint}" ]] || \
  fail "certification plan changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${openid_profile_matrix}")" == \
  "${profile_matrix_fingerprint}" ]] || \
  fail "OpenID4VP profile matrix changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${result_root}/openid4vp-profile-matrix.json")" == \
  "${profile_matrix_fingerprint}" ]] || \
  fail "retained OpenID4VP profile matrix differs from the executed contract"

suite_revision="${checked_suite_revision}"
readonly suite_revision
printf '%s\n' "${suite_revision}" > "${result_root}/oidf-suite-revision.txt"
python3 scripts/assert_oidf_openid4vp_pre_submission.py \
  --result-root "${result_root}" \
  --certification-plan "${result_root}/certification-plan.json" \
  --profile-matrix "${result_root}/openid4vp-profile-matrix.json" \
  --product-component-bom "${result_root}/product-component-bom.json" \
  --deployment-manifest "${result_root}/deployment-manifest.json" \
  --openid4vp-source-dir "${openid4vp_root}" \
  --product-source-dir "${product_source_dir}" \
  --result-assertion "${openid_result_assertion}"
python3 scripts/build_oidf_evidence_index.py \
  --result-root "${result_root}" \
  --framework-revision "${CONFORMANCE_FRAMEWORK_COMMIT}" \
  --workflow-revision "${CONFORMANCE_WORKFLOW_COMMIT}" \
  --suite-revision "${suite_revision}" \
  --product-component-bom "${result_root}/product-component-bom.json" \
  --deployment-manifest "${result_root}/deployment-manifest.json" \
  --certification-plan "${result_root}/certification-plan.json" \
  --profile-matrix "${result_root}/openid4vp-profile-matrix.json" \
  --verifier-config "${verifier_config}" \
  --wallet-sd-jwt-config "${wallet_sd_jwt_config}" \
  --wallet-mdoc-config "${wallet_mdoc_config}" \
  --verifier-base-url "${EXAMPLE_VERIFIER_BASE_URL}" \
  --verifier-launch-endpoint "${OIDF_VERIFIER_LAUNCH_ENDPOINT}" \
  --verifier-evidence-endpoint "${OIDF_VERIFIER_EVIDENCE_ENDPOINT}" \
  --verifier-health-endpoint "${OIDF_VERIFIER_HEALTH_ENDPOINT}" \
  --wallet-harness-endpoint "${OIDF_WALLET_HARNESS_ENDPOINT}" \
  --wallet-harness-health-endpoint "${OIDF_WALLET_HARNESS_HEALTH_ENDPOINT}"
printf 'Validated six OpenID4VP certification profile exports under %s\n' "${result_root}"
