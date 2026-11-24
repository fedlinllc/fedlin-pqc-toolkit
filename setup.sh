#!/usr/bin/env bash
# Reproducible setup for fedlin-pqc-toolkit: fetch the cyclonedx-cli binary and
# install node deps (cdxgen). Run once after cloning.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p bin out
# Pinned downloads: exact version + SHA-256 (keep in sync with toolkit.lock). A mismatch aborts.
CYCLONEDX_URL=https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.32.0/cyclonedx-linux-x64
CYCLONEDX_SHA256=454879e6a4a405c8a13bff49b8982adcb0596f3019b26b0811c66e4d7f0783e1
if [ ! -x bin/cyclonedx ] || ! echo "$CYCLONEDX_SHA256  bin/cyclonedx" | sha256sum -c --quiet - 2>/dev/null; then
  echo "fetching cyclonedx-cli v0.32.0 ..."
  curl -sSfL -o bin/cyclonedx.tmp "$CYCLONEDX_URL"
  echo "$CYCLONEDX_SHA256  bin/cyclonedx.tmp" | sha256sum -c --quiet - \
    || { echo "cyclonedx-cli SHA-256 mismatch; refusing to install" >&2; rm -f bin/cyclonedx.tmp; exit 1; }
  mv bin/cyclonedx.tmp bin/cyclonedx
  chmod +x bin/cyclonedx
fi
bin/cyclonedx --version

# Podman builds the key-exchange probe image and cbomkit-theia. Both are optional: without podman,
# endpoint scans still run (unobserved key exchange is reported as unknown) and --theia-dir is unavailable.
HAVE_PODMAN=0; command -v podman >/dev/null 2>&1 && HAVE_PODMAN=1
if [ "$HAVE_PODMAN" = 1 ] && ! podman image exists localhost/fedlin-kex-probe:0.1; then
  echo "building the key-exchange probe image (pinned Alpine + openssl 3.5.9-r1) ..."
  podman build -q -t localhost/fedlin-kex-probe:0.1 images/kex-probe
fi

THEIA_COMMIT=1ce8b4d946c699198efe95de287a61832c82dd74   # keep in sync with toolkit.lock
GO_IMAGE=docker.io/library/golang:1.26-alpine@sha256:30b1e546a9c7fa3b747c2bdba3a0c7bdf3a02ebb4c5b8405d2f948d7e8aac4ec   # same as Containerfile
if [ "$HAVE_PODMAN" = 0 ]; then
  echo "[warn] podman not found: skipping the key-exchange probe image and cbomkit-theia" >&2
elif [ ! -x bin/cbomkit-theia ]; then
  echo "building cbomkit-theia (static Go binary via podman) ..."
  tmp="$(mktemp -d)"
  git clone -q https://github.com/PQCA/cbomkit-theia "$tmp/theia"
  git -C "$tmp/theia" -c advice.detachedHead=false checkout -q "$THEIA_COMMIT"
  # Build in the same digest-pinned Go image as the Containerfile (not upstream's unpinned Dockerfile).
  # Go module checksums stay verified against go.sum and the Go checksum database.
  podman run --rm -v "$tmp/theia:/src:Z" -w /src \
    -e CGO_ENABLED=0 -e GOOS=linux -e GOFLAGS=-buildvcs=false \
    "$GO_IMAGE" go build -ldflags="-s -w" -trimpath -o /src/cbomkit-theia .
  install -m 0755 "$tmp/theia/cbomkit-theia" bin/cbomkit-theia
  podman unshare rm -rf "$tmp"
fi
[ -x bin/cbomkit-theia ] && bin/cbomkit-theia --help >/dev/null && echo "cbomkit-theia: ok"

echo "installing node deps from pnpm-lock.yaml via pnpm ..."
# pnpm is pinned in package.json "packageManager" (exact version + sha512). Nothing is installed
# globally, so setup needs no root. Install strictly from pnpm-lock.yaml; no unfrozen fallback.
if command -v corepack >/dev/null 2>&1; then
  # corepack fetches the pinned pnpm into its own cache and checks the sha512.
  export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
  PNPM="corepack pnpm"
else
  # No corepack: fetch the same pnpm tarball, check it against package.json, and run it from bin/.
  want="$(sed -n 's/.*"packageManager": *"pnpm@10.34.9+sha512\.\([0-9a-f]*\)".*/\1/p' package.json)"
  if [ ! -f bin/pnpm-10.34.9/bin/pnpm.cjs ]; then
    tmp="$(mktemp -d)"
    curl -sSfL -o "$tmp/pnpm.tgz" https://registry.npmjs.org/pnpm/-/pnpm-10.34.9.tgz
    echo "$want  $tmp/pnpm.tgz" | sha512sum -c --quiet - \
      || { echo "pnpm sha512 mismatch; refusing to install" >&2; rm -rf "$tmp"; exit 1; }
    mkdir -p bin/pnpm-10.34.9
    tar -xzf "$tmp/pnpm.tgz" -C bin/pnpm-10.34.9 --strip-components=1
    rm -rf "$tmp"
  fi
  PNPM="node bin/pnpm-10.34.9/bin/pnpm.cjs"
fi
$PNPM install --prod --frozen-lockfile
./node_modules/.bin/cdxgen --version

echo "ready. Example:"
echo "  python3 scripts/tier2_pipeline.py --no-runtime --endpoints example.com \\"
echo "    --name example.com --report --out out/cbom.json"
