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
openid4vci_root="$(cd -- "${repository_root}/../openid4vci" && pwd)"
readonly openid4vci_root
suite_dir="${OIDF_CONFORMANCE_SUITE_DIR:-${repository_root}/upstream/oidf/openid-conformance-suite}"
default_result_root="${repository_root}/results/local/openid4vci-certification"
result_root="${OIDF_OPENID4VCI_RESULT_DIR:-${default_result_root}}"
readonly suite_dir default_result_root result_root

fail() {
  printf 'OIDF OpenID4VCI certification runner: %s\n' "$1" >&2
  exit 78
}

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
  local matches
  case "${role}" in
    issuer) plan_id="oid4vci-1_0-issuer-haip-test-plan" ;;
    wallet) plan_id="oid4vci-1_0-wallet-haip-test-plan" ;;
    *) fail "unsupported OpenID4VCI certification role" ;;
  esac
  matches="$(jq -er \
    --arg plan_id "${plan_id}" \
    --arg profile_id "${profile_id}" \
    '.plans[]
     | select(.protocol == "openid4vci" and .plan_id == $plan_id)
     | .certification_runs[]
     | select(.profile_id == $profile_id)
     | .expression' \
    "${certification_plan}")" || fail "certification profile is missing"
  case "${matches}" in
    "" | *$'\n'*) fail "certification profile is missing or duplicated" ;;
  esac
  jq -e \
    --arg profile_id "${profile_id}" \
    --arg expression "${matches}" \
    '.profiles
     | map(select(.profile_id == $profile_id and .plan_expression == $expression))
     | length == 1' \
    "${openid_profile_matrix}" >/dev/null || \
    fail "selected certification profile is unsupported by the locked OpenID4VCI component"
  printf '%s\n' "${matches}"
}

require_passed_profile() {
  local role="$1"
  local profile_id="$2"
  local summary_file="${result_root}/${role}/${profile_id}/summary.json"
  local export_dir="${result_root}/${role}/${profile_id}/suite-export"
  require_file "${summary_file}" "profile summary is missing"
  jq -e \
    --arg profile_id "${profile_id}" \
    --arg suite_commit "${suite_revision}" \
    '.profile_id == $profile_id and
     .suite_commit == $suite_commit and
     .result == "passed"' \
    "${summary_file}" >/dev/null || fail "profile result is not passed"
  [[ -d "${export_dir}" ]] || fail "profile export is missing"
  [[ -n "$(find "${export_dir}" -type f -print -quit)" ]] || fail "profile export is empty"
}

for command in git jq python3 curl find cp; do
  command -v "${command}" >/dev/null 2>&1 || fail "required command is unavailable"
done

require_variable CONFORMANCE_SERVER "CONFORMANCE_SERVER is required"
require_variable CONFORMANCE_SERVER_MTLS "CONFORMANCE_SERVER_MTLS is required"
require_variable CONFORMANCE_TOKEN "CONFORMANCE_TOKEN is required"
require_variable OIDF_VCI_ISSUER_CONFIG "OIDF_VCI_ISSUER_CONFIG is required"
require_variable OIDF_VCI_WALLET_CONFIG "OIDF_VCI_WALLET_CONFIG is required"
require_variable OIDF_DEPLOYMENT_MANIFEST "OIDF_DEPLOYMENT_MANIFEST is required"
require_variable OIDF_PRODUCT_COMPONENT_BOM "OIDF_PRODUCT_COMPONENT_BOM is required"
require_variable CONFORMANCE_FRAMEWORK_COMMIT "CONFORMANCE_FRAMEWORK_COMMIT is required"
require_variable CONFORMANCE_WORKFLOW_COMMIT "CONFORMANCE_WORKFLOW_COMMIT is required"
require_variable OPENID4VCI_ISSUER_BIN "OPENID4VCI_ISSUER_BIN is required"
require_variable OPENID4VCI_ISSUER_BASE_URL "OPENID4VCI_ISSUER_BASE_URL is required"
require_variable OPENID4VCI_WALLET_HARNESS_ENDPOINT \
  "OPENID4VCI_WALLET_HARNESS_ENDPOINT is required"
require_variable OPENID4VCI_WALLET_HARNESS_HEALTH_ENDPOINT \
  "OPENID4VCI_WALLET_HARNESS_HEALTH_ENDPOINT is required"
require_variable OPENID4VCI_WALLET_HARNESS_TOKEN \
  "OPENID4VCI_WALLET_HARNESS_TOKEN is required"
require_variable OPENID4VCI_WALLET_HARNESS_BINARY \
  "OPENID4VCI_WALLET_HARNESS_BINARY is required"
require_variable OPENID4VCI_WALLET_SOURCE_REPOSITORY_DIR \
  "OPENID4VCI_WALLET_SOURCE_REPOSITORY_DIR is required"

issuer_config="$(resolve_file "${OIDF_VCI_ISSUER_CONFIG}")"
wallet_config="$(resolve_file "${OIDF_VCI_WALLET_CONFIG}")"
deployment_manifest="$(resolve_file "${OIDF_DEPLOYMENT_MANIFEST}")"
product_component_bom="$(resolve_file "${OIDF_PRODUCT_COMPONENT_BOM}")"
issuer_binary="$(resolve_file "${OPENID4VCI_ISSUER_BIN}")"
wallet_binary="$(resolve_file "${OPENID4VCI_WALLET_HARNESS_BINARY}")"
wallet_source_repository_dir="$(cd -- "${OPENID4VCI_WALLET_SOURCE_REPOSITORY_DIR}" && pwd)" || \
  fail "wallet source repository is unavailable"
readonly issuer_config wallet_config deployment_manifest product_component_bom issuer_binary wallet_binary
readonly wallet_source_repository_dir
require_file "${issuer_config}" "issuer configuration is unavailable"
require_file "${wallet_config}" "wallet configuration is unavailable"
require_file "${deployment_manifest}" "deployment manifest is unavailable"
require_file "${product_component_bom}" "product component BOM is unavailable"
[[ -x "${issuer_binary}" && ! -L "${issuer_binary}" ]] || \
  fail "issuer binary is unavailable, symbolic, or not executable"
[[ -f "${wallet_binary}" && ! -L "${wallet_binary}" ]] || \
  fail "wallet harness binary is unavailable or symbolic"
[[ -d "${suite_dir}" ]] || fail "pinned conformance suite checkout is unavailable"
[[ ! -e "${result_root}" ]] || fail "result directory already exists"

require_public_https_endpoint "${CONFORMANCE_SERVER}" \
  "hosted conformance server must be a public HTTPS endpoint"
require_public_https_endpoint "${CONFORMANCE_SERVER_MTLS}" \
  "hosted mTLS conformance server must be a public HTTPS endpoint"
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
require_public_https_endpoint "${OPENID4VCI_ISSUER_BASE_URL}" \
  "issuer base URL must be a public HTTPS endpoint"
require_public_https_endpoint "${OPENID4VCI_WALLET_HARNESS_ENDPOINT}" \
  "wallet harness must be a public HTTPS endpoint"
require_public_https_endpoint "${OPENID4VCI_WALLET_HARNESS_HEALTH_ENDPOINT}" \
  "wallet harness health check must be a public HTTPS endpoint"

cd "${repository_root}"
python3 scripts/verify_product_component_bom.py \
  --bom "${product_component_bom}" --plan plans/oidf/certification.json \
  --require-release-refs --verify-checkouts
scripts/verify_oidf_manifests.py
scripts/verify_oidf_certification_parameters.py "${suite_dir}"
python3 scripts/verify_oidf_deployment_manifest.py \
  --manifest "${deployment_manifest}" \
  --product-component-bom "${product_component_bom}" \
  --binding openid4vci_issuer.issuer_base_url "${OPENID4VCI_ISSUER_BASE_URL}" \
  --binding openid4vci_wallet.wallet_harness_endpoint "${OPENID4VCI_WALLET_HARNESS_ENDPOINT}" \
  --binding openid4vci_wallet.wallet_harness_health_endpoint "${OPENID4VCI_WALLET_HARNESS_HEALTH_ENDPOINT}"

readonly certification_plan="${repository_root}/plans/oidf/certification.json"
readonly openid_profile_matrix="${openid4vci_root}/conformance/oidf/profile-matrix.json"
readonly suite_contract="${openid4vci_root}/conformance/oidf/suite-contract.json"
readonly module_inventory="${openid4vci_root}/conformance/oidf/certification-module-inventory.json"
readonly issuer_runner="${openid4vci_root}/scripts/conformance/run_oidf_oid4vci_issuer.sh"
readonly wallet_runner="${openid4vci_root}/scripts/conformance/run_oidf_oid4vci_wallet.sh"
require_file "${certification_plan}" "certification plan is unavailable"
require_file "${openid_profile_matrix}" "OpenID4VCI profile matrix is unavailable"
require_file "${suite_contract}" "OpenID4VCI suite contract is unavailable"
require_file "${module_inventory}" "OpenID4VCI module inventory is unavailable"
[[ -x "${issuer_runner}" ]] || fail "issuer certification runner is unavailable"
[[ -x "${wallet_runner}" ]] || fail "wallet certification runner is unavailable"
issuer_config_fingerprint="$(python3 scripts/hash_oidf_input.py "${issuer_config}")"
wallet_config_fingerprint="$(python3 scripts/hash_oidf_input.py "${wallet_config}")"
plan_fingerprint="$(python3 scripts/hash_oidf_input.py "${certification_plan}")"
profile_matrix_fingerprint="$(python3 scripts/hash_oidf_input.py "${openid_profile_matrix}")"
issuer_binary_fingerprint="$(python3 scripts/hash_oidf_input.py --artifact "${issuer_binary}")"
wallet_binary_fingerprint="$(python3 scripts/hash_oidf_input.py --artifact "${wallet_binary}")"
expected_issuer_binary_digest="$(jq -er \
  '.roles.openid4vci_issuer.artifact.sha256 | select(type == "string" and length == 64)' \
  "${deployment_manifest}")" || fail "issuer artifact digest is missing from the deployment manifest"
expected_wallet_binary_digest="$(jq -er \
  '.roles.openid4vci_wallet.artifact.sha256 | select(type == "string" and length == 64)' \
  "${deployment_manifest}")" || fail "wallet artifact digest is missing from the deployment manifest"
issuer_artifact_kind="$(jq -er '.roles.openid4vci_issuer.artifact.kind' \
  "${deployment_manifest}")" || fail "issuer artifact kind is missing from the deployment manifest"
wallet_artifact_kind="$(jq -er '.roles.openid4vci_wallet.artifact.kind' \
  "${deployment_manifest}")" || fail "wallet artifact kind is missing from the deployment manifest"
if [[ "${issuer_artifact_kind}" == "binary" ]]; then
  issuer_deployment_artifact="$(resolve_file \
    "${OPENID4VCI_ISSUER_DEPLOYMENT_ARTIFACT:-${issuer_binary}}")"
else
  require_variable OPENID4VCI_ISSUER_DEPLOYMENT_ARTIFACT \
    "OPENID4VCI_ISSUER_DEPLOYMENT_ARTIFACT is required for a non-binary deployment"
  issuer_deployment_artifact="$(resolve_file "${OPENID4VCI_ISSUER_DEPLOYMENT_ARTIFACT}")"
fi
if [[ "${wallet_artifact_kind}" == "binary" ]]; then
  wallet_deployment_artifact="$(resolve_file \
    "${OPENID4VCI_WALLET_DEPLOYMENT_ARTIFACT:-${wallet_binary}}")"
else
  require_variable OPENID4VCI_WALLET_DEPLOYMENT_ARTIFACT \
    "OPENID4VCI_WALLET_DEPLOYMENT_ARTIFACT is required for a non-binary deployment"
  wallet_deployment_artifact="$(resolve_file "${OPENID4VCI_WALLET_DEPLOYMENT_ARTIFACT}")"
fi
require_file "${issuer_deployment_artifact}" "issuer deployment artifact is unavailable"
require_file "${wallet_deployment_artifact}" "wallet deployment artifact is unavailable"
issuer_deployment_artifact_fingerprint="$(python3 scripts/hash_oidf_input.py \
  --artifact "${issuer_deployment_artifact}")"
wallet_deployment_artifact_fingerprint="$(python3 scripts/hash_oidf_input.py \
  --artifact "${wallet_deployment_artifact}")"
[[ "${issuer_deployment_artifact_fingerprint%%:*}" == \
  "${expected_issuer_binary_digest}" ]] || \
  fail "issuer deployment artifact does not match the deployment manifest"
[[ "${wallet_deployment_artifact_fingerprint%%:*}" == \
  "${expected_wallet_binary_digest}" ]] || \
  fail "wallet deployment artifact does not match the deployment manifest"
wallet_source_repository="$(jq -er \
  '.roles.openid4vci_wallet.source_repository | select(type == "string" and length > 0)' \
  "${deployment_manifest}")" || fail "wallet source repository is missing from the deployment manifest"
readonly issuer_config_fingerprint wallet_config_fingerprint plan_fingerprint
readonly profile_matrix_fingerprint issuer_binary_fingerprint wallet_binary_fingerprint
readonly expected_issuer_binary_digest expected_wallet_binary_digest
readonly issuer_artifact_kind wallet_artifact_kind
readonly issuer_deployment_artifact wallet_deployment_artifact
readonly issuer_deployment_artifact_fingerprint wallet_deployment_artifact_fingerprint
readonly wallet_source_repository

suite_revision="$(git -C "${suite_dir}" rev-parse HEAD)"
readonly suite_revision
mkdir -p "${result_root}/issuer" "${result_root}/wallet"
cp "${deployment_manifest}" "${result_root}/deployment-manifest.json"
cp "${product_component_bom}" "${result_root}/product-component-bom.json"
cp "${certification_plan}" "${result_root}/certification-plan.json"
cp "${openid_profile_matrix}" "${result_root}/openid4vci-profile-matrix.json"
cp "${suite_contract}" "${result_root}/openid4vci-suite-contract.json"
python3 scripts/verify_oidf_deployment_manifest.py \
  --manifest "${result_root}/deployment-manifest.json" \
  --product-component-bom "${result_root}/product-component-bom.json" \
  --binding openid4vci_issuer.issuer_base_url "${OPENID4VCI_ISSUER_BASE_URL}" \
  --binding openid4vci_wallet.wallet_harness_endpoint "${OPENID4VCI_WALLET_HARNESS_ENDPOINT}" \
  --binding openid4vci_wallet.wallet_harness_health_endpoint "${OPENID4VCI_WALLET_HARNESS_HEALTH_ENDPOINT}"

mapfile -t issuer_profiles < <(jq -er '
  .plans[]
  | select(.protocol == "openid4vci" and .role == "issuer")
  | .certification_runs[].profile_id
' "${certification_plan}")
mapfile -t wallet_profiles < <(jq -er '
  .plans[]
  | select(.protocol == "openid4vci" and .role == "wallet")
  | .certification_runs[].profile_id
' "${certification_plan}")
[[ "${#issuer_profiles[@]}" -eq 4 && "${#wallet_profiles[@]}" -eq 6 ]] || \
  fail "certification plan does not select the complete OpenID4VCI profile set"

for profile_id in "${issuer_profiles[@]}"; do
  plan_expression="$(profile_expression issuer "${profile_id}")"
  (
    cd "${openid4vci_root}"
    OIDF_CONFORMANCE_MODE=hosted \
    CONFORMANCE_RESULTS_DIR="${result_root}/issuer" \
    OIDF_PROFILE_MATRIX="${openid_profile_matrix}" \
    OIDF_ISSUER_PLAN_EXPRESSION="${plan_expression}" \
    OIDF_ALIAS="reallyme-${profile_id}" \
    OPENID4VCI_SOURCE_REPOSITORY_DIR="${openid4vci_root}" \
    "${issuer_runner}" "${suite_dir}" "${issuer_binary}" "${issuer_config}"
  )
  require_passed_profile issuer "${profile_id}"
done

for profile_id in "${wallet_profiles[@]}"; do
  plan_expression="$(profile_expression wallet "${profile_id}")"
  (
    cd "${openid4vci_root}"
    OIDF_CONFORMANCE_MODE=hosted \
    CONFORMANCE_RESULTS_DIR="${result_root}/wallet" \
    OIDF_PROFILE_MATRIX="${openid_profile_matrix}" \
    OIDF_WALLET_PLAN_EXPRESSION="${plan_expression}" \
    OIDF_WALLET_CONFIG_FILE="${wallet_config}" \
    OPENID4VCI_SOURCE_REPOSITORY_DIR="${openid4vci_root}" \
    OPENID4VCI_WALLET_SOURCE_REPOSITORY="${wallet_source_repository}" \
    OPENID4VCI_WALLET_SOURCE_REPOSITORY_DIR="${wallet_source_repository_dir}" \
    OPENID4VCI_WALLET_HARNESS_BINARY="${wallet_binary}" \
    OPENID4VCI_WALLET_HARNESS_TOKEN="${OPENID4VCI_WALLET_HARNESS_TOKEN}" \
    "${wallet_runner}" "${suite_dir}"
  )
  require_passed_profile wallet "${profile_id}"
done

# Revalidate mutable local inputs after the long external run. Evidence must
# describe the exact checkout, executable, and configuration bytes that were
# present when execution began.
python3 scripts/verify_product_component_bom.py \
  --bom "${product_component_bom}" --plan plans/oidf/certification.json \
  --require-release-refs --verify-checkouts
scripts/verify_oidf_certification_parameters.py "${suite_dir}"
[[ "$(python3 scripts/hash_oidf_input.py "${issuer_config}")" == "${issuer_config_fingerprint}" ]] || \
  fail "issuer configuration changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${wallet_config}")" == "${wallet_config_fingerprint}" ]] || \
  fail "wallet configuration changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${certification_plan}")" == "${plan_fingerprint}" ]] || \
  fail "certification plan changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py "${openid_profile_matrix}")" == "${profile_matrix_fingerprint}" ]] || \
  fail "OpenID4VCI profile matrix changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py --artifact "${issuer_binary}")" == "${issuer_binary_fingerprint}" ]] || \
  fail "issuer binary changed during execution"
[[ "$(python3 scripts/hash_oidf_input.py --artifact "${wallet_binary}")" == "${wallet_binary_fingerprint}" ]] || \
  fail "wallet harness binary changed during execution"

printf '%s\n' "${suite_revision}" > "${result_root}/oidf-suite-revision.txt"
python3 scripts/assert_oidf_openid4vci_pre_submission.py \
  --result-root "${result_root}" \
  --certification-plan "${result_root}/certification-plan.json" \
  --profile-matrix "${result_root}/openid4vci-profile-matrix.json" \
  --suite-contract "${result_root}/openid4vci-suite-contract.json" \
  --product-component-bom "${result_root}/product-component-bom.json" \
  --deployment-manifest "${result_root}/deployment-manifest.json" \
  --openid4vci-source-dir "${openid4vci_root}" \
  --wallet-source-dir "${wallet_source_repository_dir}" \
  --issuer-binary "${issuer_binary}" \
  --wallet-binary "${wallet_binary}" \
  --issuer-deployment-artifact "${issuer_deployment_artifact}" \
  --wallet-deployment-artifact "${wallet_deployment_artifact}" \
  --result-assertion "${openid4vci_root}/scripts/conformance/assert_oidf_results.sh" \
  --wallet-assertion "${openid4vci_root}/scripts/conformance/assert_oidf_wallet_implementation_evidence.py" \
  --module-inventory "${module_inventory}"
python3 scripts/build_oidf_openid4vci_evidence_index.py \
  --result-root "${result_root}" \
  --framework-revision "${CONFORMANCE_FRAMEWORK_COMMIT}" \
  --workflow-revision "${CONFORMANCE_WORKFLOW_COMMIT}" \
  --suite-revision "${suite_revision}" \
  --product-component-bom "${result_root}/product-component-bom.json" \
  --deployment-manifest "${result_root}/deployment-manifest.json" \
  --certification-plan "${result_root}/certification-plan.json" \
  --profile-matrix "${result_root}/openid4vci-profile-matrix.json" \
  --issuer-config "${issuer_config}" \
  --wallet-config "${wallet_config}" \
  --issuer-binary "${issuer_binary}" \
  --wallet-binary "${wallet_binary}" \
  --issuer-deployment-artifact "${issuer_deployment_artifact}" \
  --wallet-deployment-artifact "${wallet_deployment_artifact}" \
  --issuer-base-url "${OPENID4VCI_ISSUER_BASE_URL}" \
  --wallet-harness-endpoint "${OPENID4VCI_WALLET_HARNESS_ENDPOINT}" \
  --wallet-harness-health-endpoint "${OPENID4VCI_WALLET_HARNESS_HEALTH_ENDPOINT}"
printf 'Validated ten OpenID4VCI certification profile exports under %s\n' "${result_root}"
