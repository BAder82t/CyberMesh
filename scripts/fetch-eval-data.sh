#!/usr/bin/env bash
# Downloads evaluation-only data into eval-data/raw/ (git-ignored, never redistributed).
#   * Majestic Million (CC BY 3.0)            - benign sample and popularity list
#   * mitchellkrogza/Phishing.Database (MIT)  - two pinned snapshots of active phishing domains
# The phishing snapshots are pinned to commits so results are reproducible.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=eval-data/raw
mkdir -p "$OUT"
T0_SHA=4bf912033505180b0d0fd40c54ada55a907ae505   # 2026-07-29
T1_SHA=12a20bf8dd2b7e78d9d38fc12b3e5c970f79d1a7   # 2026-10-02
BASE=https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database
fetch() { [ -s "$2" ] || curl -fsSL --retry 3 -o "$2" "$1"; }
fetch "$BASE/$T0_SHA/phishing-domains-ACTIVE.txt" "$OUT/phishing-t0.txt"
fetch "$BASE/$T1_SHA/phishing-domains-ACTIVE.txt" "$OUT/phishing-t1.txt"
fetch https://downloads.majestic.com/majestic_million.csv "$OUT/majestic_million.csv"
# The phishing snapshots are pinned to commits, so their hashes are fixed. The Majestic list
# is a moving target: its hash is recorded, not checked.
verify() { echo "$2  $OUT/$1" | shasum -a 256 -c - >/dev/null || { echo "hash mismatch: $1" >&2; exit 1; }; }
verify phishing-t0.txt 0494746d15cf8e87ff3411df9cbde8fff61fd777fb9e877ae43dc25a10f29090
verify phishing-t1.txt 70c6c2e24e6b3484e7ace27b079723e55937bc1f4cbd98bea38a472ec8e37326
( cd "$OUT" && shasum -a 256 phishing-t0.txt phishing-t1.txt majestic_million.csv > SHA256SUMS )
cat "$OUT/SHA256SUMS"
