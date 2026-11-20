#!/usr/bin/env bash
# Reproducible release build of the `cybermesh` binary (docs/build-integrity.md).
#
#   scripts/build-release.sh [--docker] TARGET OUT_DIR
#
# --docker builds inside the Rust image pinned by digest in deploy/docker/Dockerfile, so a
# Linux binary can be rebuilt bit for bit anywhere Docker runs (linux/amd64 for
# x86_64-unknown-linux-gnu, linux/arm64 for aarch64-unknown-linux-gnu). Without it, the build
# uses the local toolchain (rust-toolchain.toml); macOS release binaries are built this way.
#
# What makes the build reproducible: the pinned toolchain and Cargo.lock (--locked), no
# incremental compilation, one codegen unit and stripped symbols (profile.release), path
# remapping for rustc and for C/assembly compiled by build scripts, and (macOS) a fixed
# target directory. Checked: rebuilds from another checkout path, toolchain location and
# Cargo home are byte-identical. The output is OUT_DIR/cybermesh-<version>-<target>.
set -euo pipefail
cd "$(dirname "$0")/.."

DOCKER=0
if [ "${1:-}" = "--docker" ]; then DOCKER=1; shift; fi
TARGET=${1:?usage: build-release.sh [--docker] TARGET OUT_DIR}
OUT=${2:?usage: build-release.sh [--docker] TARGET OUT_DIR}
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[ -n "$VERSION" ] || { echo "no workspace version in Cargo.toml" >&2; exit 1; }
TOOLCHAIN=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)

if [ "$DOCKER" = 1 ]; then
  IMAGE=$(sed -n 's/^FROM \(rust:[^ ]*@sha256:[0-9a-f]*\) .*/\1/p' deploy/docker/Dockerfile | head -1)
  [ -n "$IMAGE" ] || { echo "no pinned rust image in deploy/docker/Dockerfile" >&2; exit 1; }
  case "$TARGET" in
    x86_64-unknown-linux-gnu) PLATFORM=linux/amd64 ;;
    aarch64-unknown-linux-gnu) PLATFORM=linux/arm64 ;;
    *) echo "--docker supports only x86_64- and aarch64-unknown-linux-gnu" >&2; exit 1 ;;
  esac
  case "$OUT" in
    /*|..*) echo "with --docker, OUT_DIR must be inside the checkout (a relative path)" >&2; exit 1 ;;
  esac
  mkdir -p "$OUT"
  # Same paths inside the container on every host: /cybermesh and the image's Cargo home.
  docker run --rm --platform "$PLATFORM" \
    -v "$PWD":/cybermesh -w /cybermesh \
    -e RUSTUP_TOOLCHAIN="$TOOLCHAIN" \
    "$IMAGE" scripts/build-release.sh "$TARGET" "$OUT"
  exit 0
fi

CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
SYSROOT=$(rustc --print sysroot)
COMMIT=$(rustc -vV | sed -n 's/^commit-hash: //p')
# The standard library's sources: rustc maps its virtual /rustc/<commit> paths to the local
# rust-src component when that is installed; map them back so the result does not depend on it.
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$PWD=/cybermesh --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$SYSROOT/lib/rustlib/src/rust=/rustc/$COMMIT"
# The same for C and assembly compiled by build scripts (the `cc` crate, e.g. in `ring`).
PREFIX_MAP="-ffile-prefix-map=$PWD=/cybermesh -ffile-prefix-map=$CARGO_HOME_DIR=/cargo"
export CFLAGS="${CFLAGS:-} $PREFIX_MAP" ASMFLAGS="${ASMFLAGS:-} $PREFIX_MAP"
# The macOS linker derives LC_UUID from the object paths in its debug map before symbols are
# stripped: use a fixed target directory, and drop the toolchain's location from the paths
# of the standard library's objects.
export CARGO_TARGET_DIR=/tmp/cybermesh-release-target
case "$TARGET" in
  *-apple-darwin) RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-oso_prefix,$SYSROOT/" ;;
esac
cargo build --release --locked -p cybermesh-cli --target "$TARGET"
mkdir -p "$OUT"
DEST="$OUT/cybermesh-$VERSION-$TARGET"
cp "$CARGO_TARGET_DIR/$TARGET/release/cybermesh" "$DEST"
chmod 0755 "$DEST"
if command -v sha256sum > /dev/null; then sha256sum "$DEST"; else shasum -a 256 "$DEST"; fi
