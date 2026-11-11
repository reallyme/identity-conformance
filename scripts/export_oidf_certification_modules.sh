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

suite_dir="$(cd -- "${1:-upstream/oidf/openid-conformance-suite}" && pwd)"
readonly suite_dir
readonly manifest_path="${2:-plans/oidf/certification.json}"
readonly output_path="${3:-upstream/oidf/snapshots/certification-modules.json}"
readonly extractor_source="scripts/java/OidfCertificationModuleSnapshot.java"
readonly dependency_classpath_file="target/certification-snapshot-classpath.txt"
readonly maven_repository="${repository_root}/target/oidf-maven-repository"
readonly oidf_java_home="${OIDF_CONFORMANCE_JAVA_HOME:-/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home}"

if [[ ! -x "${oidf_java_home}/bin/java" || ! -x "${oidf_java_home}/bin/javac" ]]; then
    printf 'OIDF_CONFORMANCE_JAVA_HOME must point to a JDK 21 installation\n' >&2
    exit 78
fi

scripts/verify_oidf_certification_parameters.py "${suite_dir}" --manifest "${manifest_path}"

# Snapshot generation is an infrequent release operation. A clean compilation
# is intentional: a commit-only stamp cannot prove target/classes corresponds
# to the checkout when an earlier incremental build left newer stale bytecode.
(
    cd "${suite_dir}"
    JAVA_HOME="${oidf_java_home}" mvn -B -DskipTests \
        -Dmaven.repo.local="${maven_repository}" \
        clean test-compile dependency:build-classpath \
        -DincludeScope=test \
        -Dmdep.outputFile="${dependency_classpath_file}"
)

temporary_directory="$(mktemp -d)"
readonly temporary_directory
cleanup() {
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT INT TERM

dependency_classpath="$(<"${suite_dir}/${dependency_classpath_file}")"
readonly dependency_classpath
readonly suite_classpath="${suite_dir}/target/classes:${suite_dir}/target/test-classes:${dependency_classpath}"

"${oidf_java_home}/bin/javac" --release 21 -cp "${suite_classpath}" \
    -d "${temporary_directory}" "${extractor_source}"
"${oidf_java_home}/bin/java" -cp "${temporary_directory}:${suite_classpath}" \
    OidfCertificationModuleSnapshot "${manifest_path}" "${output_path}"

jq empty "${output_path}"
printf 'Wrote complete OIDF plan module inventory to %s\n' "${output_path}"
