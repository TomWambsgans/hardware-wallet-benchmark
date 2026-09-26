#!/usr/bin/env bash
# Build Trezor's production-test firmware (prodtest) for the Trezor Safe 3 (T3B1) with the
# SPHINCS+ benchmark commands of trezor/prodtest_sphincs.c and the crypto of
# ledger-app/src/crypto (same C scheme, same Thumb-2 compressions).
#
# 1. clones trezor-firmware at a pinned commit into trezor/trezor-firmware/ (gitignored),
# 2. adds our files and build.rs patch on a local branch `sphincs-bench`,
# 3. runs Trezor's reproducible Docker build (Nix inside Docker; the first run builds the
#    environment and takes a while) for T3B1 prodtest, non-production: signed with the
#    public development keys, under the "unsafe" vendor header -- the combination an
#    unlocked bootloader accepts (it shows a red "UNSAFE" warning at boot).
#
# Output: trezor/trezor-firmware/build/core-T3B1/prodtest/prodtest.bin (path printed at the end)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF="$ROOT/trezor/trezor-firmware"
TREZOR_COMMIT="3227ea8110e2ca2a53439b123f3d764655e9f9ae"  # trezor-firmware main, 2026-09-26
PRODTEST="core/embed/projects/prodtest"

if [ ! -d "$TF/.git" ]; then
    git init -q "$TF"
    git -C "$TF" remote add origin https://github.com/trezor/trezor-firmware.git
fi
if ! git -C "$TF" cat-file -e "$TREZOR_COMMIT^{commit}" 2>/dev/null; then
    git -C "$TF" fetch -q --depth 1 origin "$TREZOR_COMMIT"
fi
git -C "$TF" checkout -q -f -B sphincs-bench "$TREZOR_COMMIT"
git -C "$TF" clean -q -dfx -e build -e ci

mkdir -p "$TF/$PRODTEST/cmd/sphincs"
cp "$ROOT"/ledger-app/src/crypto/{sphincs,hash,blake2s,sha256}.{c,h} \
   "$ROOT"/ledger-app/src/crypto/{blake2s,sha256}_thumb2.S "$TF/$PRODTEST/cmd/sphincs/"
cp "$ROOT/trezor/prodtest_sphincs.c" "$TF/$PRODTEST/cmd/"
git -C "$TF" apply "$ROOT/trezor/prodtest-build.patch"
git -C "$TF" add -A
git -C "$TF" -c user.name=build -c user.email=build@localhost commit -q -m "prodtest: SPHINCS+ benchmark"

cd "$TF"
PRODUCTION=0 \
VENDOR_HEADER=/reproducible-build/trezor-firmware/core/embed/models/T3B1/vendorheader/vendorheader_unsafe_signed_prod.bin \
    ./build-docker.sh --models T3B1 --targets prodtest --skip-bitcoinonly sphincs-bench
find "$TF/build" -name 'prodtest*.bin' -newer "$ROOT/trezor/build.sh" -print
