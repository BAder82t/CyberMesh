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
( cd "$OUT" && shasum -a 256 phishing-t0.txt phishing-t1.txt majestic_million.csv > SHA256SUMS )
cat "$OUT/SHA256SUMS"
