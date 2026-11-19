# fedlin-pqc-toolkit: portable, air-gappable PQC assessment toolkit.
# Bundles: python pipeline + CNSA 2.0 overlay, cyclonedx-cli, cdxgen, cbomkit-theia, oc, openssl, jq.
#
# Two images from one file (ADR-066):
#   default target  -> ghcr.io/fedlinllc/fedlin-pqc-toolkit        Red Hat certified: UBI crypto only
#   --target probe  -> ghcr.io/fedlinllc/fedlin-pqc-toolkit-probe  the same plus an Alpine OpenSSL 3.5 key-exchange
#                      probe, so a FIPS-mode host can still observe X25519MLKEM768; not certified

# --- stage 1: build cbomkit-theia from source (stripped static binary) ---
FROM docker.io/library/golang:1.26-alpine@sha256:30b1e546a9c7fa3b747c2bdba3a0c7bdf3a02ebb4c5b8405d2f948d7e8aac4ec AS theia
ARG THEIA_COMMIT=1ce8b4d946c699198efe95de287a61832c82dd74
RUN apk add --no-cache git ca-certificates
# Verified fetch: TLS + Go checksum-db verification left ON (this is a crypto-assurance tool).
ENV GOFLAGS=-buildvcs=false
RUN git clone https://github.com/PQCA/cbomkit-theia /src \
 && cd /src && git checkout ${THEIA_COMMIT} \
 && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -o /cbomkit-theia .

# --- stage 1b: key-exchange probe OpenSSL (same pinned Alpine + openssl as images/kex-probe; probe image only) ---
# UBI 9 OpenSSL follows the host's FIPS mode and crypto policy and may refuse X25519MLKEM768. The probe
# OpenSSL is used only to observe which group a server negotiates; it never touches the host's config.
FROM docker.io/library/alpine:3.22@sha256:9db2934886712d877c932e07249c75a59e6ca27adfbccc05261987a17bef2d63 AS kexprobe
RUN apk add --no-cache openssl=3.5.9-r0 \
 && mkdir -p /out/bin /out/lib \
 && cp /usr/bin/openssl /out/bin/ \
 && cp /lib/ld-musl-x86_64.so.1 /usr/lib/libssl.so.3 /usr/lib/libcrypto.so.3 /out/lib/ \
 && cp /etc/ssl/openssl.cnf /out/openssl.cnf

# --- stage 2: runtime core: MINIMAL UBI9 node image (node+npm present, microdnf-based) ---
FROM registry.access.redhat.com/ubi9/nodejs-22-minimal@sha256:0cc4ae118138dd07280d5abaa12b6a018e5bc82c048296f3c3676e62d3a1d8a8 AS core
# Our own identity labels. Without them the image inherits the UBI base's name/vendor/maintainer (Red Hat),
# which misstates who ships it and fails Red Hat's preflight trademark check. The release workflow passes
# VERSION; local builds are labelled "dev".
ARG VERSION=dev
ARG RELEASE=1
LABEL name="fedlin-pqc-toolkit" \
      vendor="FEDLIN LLC" \
      maintainer="FEDLIN LLC" \
      version="${VERSION}" \
      release="${RELEASE}" \
      summary="Post-quantum cryptography readiness assessment toolkit" \
      description="Builds a CycloneDX cryptographic bill of materials (CBOM) from repositories, clusters, hosts and TLS endpoints, then checks it against CNSA 2.0 and NIST IR 8547 timelines." \
      url="https://github.com/fedlinllc/fedlin-pqc-toolkit" \
      io.k8s.display-name="FEDLIN PQC Toolkit" \
      io.k8s.description="Post-quantum cryptography readiness assessment: CBOM generation and CNSA 2.0 / NIST IR 8547 policy checks." \
      io.openshift.tags="pqc,cbom,cyclonedx,cnsa,cryptography" \
      help="https://github.com/fedlinllc/fedlin-pqc-toolkit#readme" \
      io.openshift.expose-services="" \
      io.s2i.scripts-url=""
USER 0
# cyclonedx-cli is a self-contained .NET binary; libicu + invariant mode satisfy its globalization needs
ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

# One layer: OS deps + oc/kubectl + cyclonedx-cli, then purge caches. tar/gzip only needed to unpack oc.
RUN microdnf -y install python3 openssl jq libicu tar gzip \
 && curl -sSfL -o /tmp/oc.tgz https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.22.0/openshift-client-linux-4.22.0.tar.gz \
 && echo "b6e027b304678d55e89ea1e8fe5c89e832f9c1a73518a1846e8cf9601c647aef  /tmp/oc.tgz" | sha256sum -c - \
 && tar -xzf /tmp/oc.tgz -C /usr/local/bin oc kubectl \
 && curl -sSfL -o /usr/local/bin/cyclonedx https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.32.0/cyclonedx-linux-x64 \
 && echo "454879e6a4a405c8a13bff49b8982adcb0596f3019b26b0811c66e4d7f0783e1  /usr/local/bin/cyclonedx" | sha256sum -c - \
 && chmod +x /usr/local/bin/cyclonedx \
 && microdnf -y remove tar gzip \
 && microdnf clean all \
 && rm -rf /tmp/oc.tgz /var/cache/* /var/log/* /root/.cache

# cbomkit-theia (stripped binary from stage 1)
COPY --from=theia /cbomkit-theia /usr/local/bin/cbomkit-theia

WORKDIR /opt/toolkit
COPY package.json pnpm-lock.yaml ./
# ubi9/nodejs-22-minimal ships npm but NOT corepack, so bootstrap the pnpm CLI with npm (that only
# fetches the pnpm binary: pnpm still installs the project deps from pnpm-lock.yaml, off the lockfile).
# The pnpm tarball is checked against the sha512 pinned in package.json "packageManager".
RUN want="$(sed -n 's/.*"packageManager": *"pnpm@10.34.9+sha512\.\([0-9a-f]*\)".*/\1/p' package.json)" \
 && curl -sSfL -o /tmp/pnpm.tgz https://registry.npmjs.org/pnpm/-/pnpm-10.34.9.tgz \
 && echo "$want  /tmp/pnpm.tgz" | sha512sum -c - \
 && npm install -g /tmp/pnpm.tgz \
 && pnpm install --prod --frozen-lockfile \
 && pnpm store prune \
 && npm cache clean --force \
 && rm -rf /root/.npm /root/.cache /root/.local/share/pnpm/store /tmp/*
COPY scripts ./scripts
COPY data ./data
COPY third_party ./third_party
COPY README.md ./
# /licenses: our licence plus the licences of the third-party data we ship (Red Hat certification
# requirement). The public tree has LICENSE at the root; the source tree keeps it in public/.
RUN --mount=type=bind,target=/tmp/ctx \
    mkdir -p /licenses \
 && if [ -f /tmp/ctx/LICENSE ]; then src=/tmp/ctx/LICENSE; else src=/tmp/ctx/public/LICENSE; fi \
 && cp "$src" /licenses/fedlin-pqc-toolkit.LICENSE \
 && cp "$(dirname "$src")/NOTICE" /licenses/fedlin-pqc-toolkit.NOTICE \
 && for d in third_party/*/; do [ "$(basename "$d")" = musl ] && continue; \
      cp "$d/LICENSE" "/licenses/third_party-$(basename "$d").LICENSE"; done \
 && printf '%s\n' \
      'fedlin-pqc-toolkit: Apache-2.0 (fedlin-pqc-toolkit.LICENSE, notice in fedlin-pqc-toolkit.NOTICE).' \
      'third_party-*.LICENSE: licences of the vendored CycloneDX and PKI Consortium files.' \
      'Bundled tools (each under its own licence): oc/kubectl (Apache-2.0), cyclonedx-cli (Apache-2.0),' \
      'cdxgen (Apache-2.0), cbomkit-theia (Apache-2.0). npm dependencies: licence files under' \
      '/opt/toolkit/node_modules. UBI packages: see /usr/share/licenses.' > /licenses/README
RUN mkdir -p /opt/toolkit/out && chmod -R a+rwX /opt/toolkit/out

ENV PATH="/opt/toolkit/node_modules/.bin:${PATH}"
# Run as the base image's unprivileged user.
USER 1001
# tool paths are baked; caller supplies --out/--name/--repo/--theia-dir/... plus KUBECONFIG
ENTRYPOINT ["python3", "scripts/tier2_pipeline.py", \
            "--cyclonedx", "/usr/local/bin/cyclonedx", \
            "--cdxgen", "/opt/toolkit/node_modules/.bin/cdxgen", \
            "--theia", "/usr/local/bin/cbomkit-theia"]
CMD ["--help"]

# --- probe image (--target probe): core + the Alpine OpenSSL 3.5 key-exchange probe; not Red Hat certified ---
FROM core AS probe
LABEL name="fedlin-pqc-toolkit-probe" \
      summary="Post-quantum cryptography readiness assessment toolkit, with a key-exchange probe OpenSSL" \
      description="fedlin-pqc-toolkit plus an Alpine OpenSSL 3.5 used only to observe which key-exchange group a TLS server negotiates, so a FIPS-mode host can see X25519MLKEM768. Not Red Hat certified: use fedlin-pqc-toolkit for the certified image." \
      io.k8s.display-name="FEDLIN PQC Toolkit (with key-exchange probe)"
USER 0
# Key-exchange probe OpenSSL (stage 1b), run through its own musl loader; it never reads the host's config.
COPY --from=kexprobe /out /opt/kex-probe
RUN --mount=type=bind,target=/tmp/ctx \
    printf '%s\n' '#!/bin/sh' \
      'OPENSSL_CONF=/opt/kex-probe/openssl.cnf exec /opt/kex-probe/lib/ld-musl-x86_64.so.1 --library-path /opt/kex-probe/lib /opt/kex-probe/bin/openssl "$@"' \
      > /usr/local/bin/kex-probe-openssl \
 && chmod 0755 /usr/local/bin/kex-probe-openssl \
 && cp /tmp/ctx/third_party/musl/LICENSE /licenses/third_party-musl.LICENSE \
 && printf '%s\n' \
      'This image adds an OpenSSL 3.5 key-exchange probe (Apache-2.0) from Alpine Linux, run through' \
      'musl libc (MIT, third_party-musl.LICENSE).' >> /licenses/README
ENV FEDLIN_KEX_PROBE_OPENSSL=/usr/local/bin/kex-probe-openssl
USER 1001

# --- default target: the Red Hat certified image (UBI crypto only) ---
FROM core AS certified
