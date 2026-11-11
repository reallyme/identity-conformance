# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
#
# SPDX-License-Identifier: MIT OR Apache-2.0

FROM maven@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320

ARG GUAVA_VERSION=33.8.0-jre
ARG GUAVA_SHA256=97b79ec3f2c0a6313a0c2df51ce1abdf8907e6531803467b81efcaaf99b35161

# The upstream image predates published fixes in its Noble base packages and
# Maven's bundled Guava. Exact package versions and an independently verified
# artifact digest make the security update fail closed if inputs drift.
RUN set -eux; \
    apt-get update; \
    apt-get install --yes --no-install-recommends \
        apt=2.8.4ubuntu0.1 \
        curl=8.5.0-2ubuntu10.16 \
        libapt-pkg6.0t64=2.8.4ubuntu0.1 \
        libbrotli1=1.1.0-2ubuntu0.1 \
        libcurl3t64-gnutls=8.5.0-2ubuntu10.16 \
        libcurl4t64=8.5.0-2ubuntu10.16 \
        libfreetype6=2.13.2+dfsg-1ubuntu0.2 \
        libpcre2-8-0=10.42-4ubuntu2.2 \
        libpng16-16t64=1.6.43-5ubuntu0.7 \
        libssl3t64=3.0.13-0ubuntu3.16 \
        openssh-client=1:9.6p1-3ubuntu13.20 \
        openssl=3.0.13-0ubuntu3.16 \
        libperl5.38t64=5.38.2-3.2ubuntu0.7 \
        perl=5.38.2-3.2ubuntu0.7 \
        perl-base=5.38.2-3.2ubuntu0.7 \
        perl-modules-5.38=5.38.2-3.2ubuntu0.7 \
        zlib1g=1:1.3.dfsg-3.1ubuntu2.3; \
    rm -rf /var/lib/apt/lists/*; \
    guava_path="$(find "${MAVEN_HOME}/lib" -maxdepth 1 -type f -name 'guava-*.jar' -print)"; \
    test -n "${guava_path}"; \
    test "$(printf '%s\n' "${guava_path}" | wc -l)" -eq 1; \
    curl --fail --silent --show-error --location \
        --output /tmp/guava.jar \
        "https://repo1.maven.org/maven2/com/google/guava/guava/${GUAVA_VERSION}/guava-${GUAVA_VERSION}.jar"; \
    printf '%s  %s\n' "${GUAVA_SHA256}" /tmp/guava.jar | sha256sum --check --strict; \
    rm -- "${guava_path}"; \
    install --mode=0644 /tmp/guava.jar "${MAVEN_HOME}/lib/guava-${GUAVA_VERSION}.jar"; \
    rm -- /tmp/guava.jar
