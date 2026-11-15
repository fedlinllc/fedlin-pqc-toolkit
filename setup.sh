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

THEIA_COMMIT=1ce8b4d946c699198efe95de287a61832c82dd74   # keep in sync with toolkit.lock
if [ ! -x bin/cbomkit-theia ]; then
  echo "building cbomkit-theia (static Go binary via podman) ..."
  tmp="$(mktemp -d)"
  git clone https://github.com/PQCA/cbomkit-theia "$tmp/theia"
  git -C "$tmp/theia" checkout "$THEIA_COMMIT"
  podman build -t cbomkit-theia:local "$tmp/theia"
  cid="$(podman create cbomkit-theia:local)"
  podman cp "$cid:/app/cbomkit-theia" bin/cbomkit-theia
  podman rm "$cid" >/dev/null
  chmod +x bin/cbomkit-theia
  rm -rf "$tmp"
fi
bin/cbomkit-theia --help >/dev/null && echo "cbomkit-theia: ok"

if command -v podman >/dev/null 2>&1 && ! podman image exists localhost/fedlin-kex-probe:0.1; then
  echo "building the key-exchange probe image (pinned Alpine + openssl 3.5.9-r0) ..."
  podman build -q -t localhost/fedlin-kex-probe:0.1 images/kex-probe
fi

echo "installing node deps (cdxgen + @noble/post-quantum signer) via pnpm ..."
# pnpm is pinned in package.json "packageManager" (exact version + sha512, verified by corepack).
# Install strictly from pnpm-lock.yaml; no unfrozen fallback.
if command -v corepack >/dev/null 2>&1; then
  corepack enable pnpm
  PNPM="corepack pnpm"
else
  npm install -g pnpm@10.34.9
  PNPM="pnpm"
fi
$PNPM install --prod --frozen-lockfile
./node_modules/.bin/cdxgen --version

echo "ready. Example:"
echo "  export KUBECONFIG=\$HOME/.kube/config"
echo "  python3 scripts/tier2_pipeline.py --out out/cbom.json --name <system> [--repo <path>] --validate"
