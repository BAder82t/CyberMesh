#!/usr/bin/env bash
# Local CyberMesh demonstration with separate OS processes on 127.0.0.1.
#   1. generate a demo network (5 operators, 6 workers incl. one simulated compromised worker,
#      and an independent verifier at org-b; releases need records from 2 verifier operators)
#   2. start workers and the independent verifier, run the coordinator until every task is
#      settled, wait for the independent verifier to finish
#   3. build the release independently twice from both verifiers' records, co-sign by two
#      organisations, verify offline
#   4. append to the transparency log, anchor on the local test chain, verify the proof
#   5. serve the release and the phishing test page for the browser extension
# Usage: scripts/demo-local.sh [--keep-serving]
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${OUT:-demo-out}
ADVERSARY=${ADVERSARY:-flip-verdicts}
# The demo binary includes the adversary simulation; keep it out of target/release so it can
# never be mistaken for a production build.
cargo build -q --release -p cybermesh-cli --features adversary-sim,dev-tools --target-dir target/demo
BIN="$PWD/target/demo/release/cybermesh"
case "$OUT" in ""|/|.|..|/*) echo "refusing OUT=$OUT" >&2; exit 1;; esac
rm -rf "$OUT"
"$BIN" demo init --out "$OUT" --evidence datasets/demo/evidence --domains datasets/demo/domains.txt --adversary "$ADVERSARY" \
  --ct-log demo-mock-log --ct-tiles 8
cd "$OUT"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
# Synthetic static CT log (real X.509 certificates) on loopback, pinned in ct-logs evidence.
"$BIN" dev mock-ct-log --addr 127.0.0.1:8090 --tiles 8 2> logs-mock-ct.log &
pids+=($!)
mkdir -p logs
vpids=()
for cfg in verifier-*.toml; do
  [ -e "$cfg" ] || continue
  name=${cfg%.toml}
  RUST_LOG=${RUST_LOG:-info,libp2p=warn} "$BIN" verifier run --config "$cfg" > "logs/$name-report.json" 2> "logs/$name.log" &
  vpids+=($!)
  pids+=($!)
done
for cfg in worker-*.toml; do
  name=${cfg%.toml}
  RUST_LOG=${RUST_LOG:-info,libp2p=warn} "$BIN" worker run --config "$cfg" > "logs/$name.json" 2> "logs/$name.log" &
  pids+=($!)
done
echo "== started ${#vpids[@]} independent verifier(s) and $(ls worker-*.toml | wc -l | tr -d ' ') workers; running coordinator"
"$BIN" coordinator run --config coordinator.toml > logs/coordinator-report.json 2> logs/coordinator.log
python3 -I -c "import json;r=json.load(open('logs/coordinator-report.json'));print('coordinator:', {k:r[k] for k in ['tasks_issued','verified','disputed','insufficient','reassignments','faults','results_rejected','ct_tiles_verified','ct_entries_verified','ct_matches','ct_tiles_rescanned']})"
# Independent verifiers exit on their own once idle (idle_exit_secs).
for p in "${vpids[@]:-}"; do [ -n "$p" ] && wait "$p"; done
for f in logs/verifier-*-report.json; do
  [ -e "$f" ] || continue
  python3 -I -c "import json,sys;r=json.load(open(sys.argv[1]));print('independent verifier', r['operator']+':', {k:r[k] for k in ['tasks_seen','verified','disputed','insufficient','faults','results_accepted','tasks_incompatible']})" "$f"
done
RECORDS=(--records state/coordinator/records)
for d in state/verifier-*/records; do [ -d "$d" ] && RECORDS+=(--records "$d"); done
echo "== CT investigation report (newly certified lookalike names per protected brand)"
"$BIN" ct report --records state/coordinator/records --manifest manifest.json --root governance-root.json --evidence evidence --out ct-report.json
echo "== worker status (resource usage measured by each worker)"
for cfg in worker-*.toml; do w=${cfg#worker-}; w=${w%.toml}; "$BIN" worker status --state-dir "state/$w" | python3 -I -c "import json,sys;s=json.load(sys.stdin);r=s['resources'];print(f\"  {s['operator']:6} state={s['state']:9} tasks={s['tasks_completed']} cpu_avg={r['cpu_percent_avg']:.3f}% rss={r['rss_bytes']/1048576:.1f}MiB net_out={s['net_bytes_out']}B\")"; done
NOW=$(date +%s)
echo "== quorum check: the coordinator's records alone (one verifier) publish nothing"
"$BIN" release build --records state/coordinator/records --manifest manifest.json --root governance-root.json --sequence 1 --issued-at "$NOW" --out release-1.coordinator-only.payload
echo "== building release independently at org-a and org-b from both verifiers' records (must be byte-identical)"
"$BIN" release build "${RECORDS[@]}" --manifest manifest.json --root governance-root.json --sequence 1 --issued-at "$NOW" --out release-1.org-a.payload
"$BIN" release build "${RECORDS[@]}" --manifest manifest.json --root governance-root.json --sequence 1 --issued-at "$NOW" --out release-1.org-b.payload
cmp release-1.org-a.payload release-1.org-b.payload && echo "   identical payloads"
"$BIN" release sign --payload release-1.org-a.payload --key keys/release-org-a.key.json --out release-1.json
"$BIN" release sign --payload release-1.org-b.payload --key keys/release-org-b.key.json --merge release-1.json --out release-1.json
"$BIN" release verify --release release-1.json --trust-root trust-root.json --state consumer-state.json --update-state
cp release-1.json public/release.json
echo "== transparency log + local test chain anchor (off the protection path)"
"$BIN" anchor append --log anchor-log.json --log-id cybermesh-demo --release release-1.json
"$BIN" anchor commit --log anchor-log.json --log-id cybermesh-demo --adapter local --chain anchor-chain.json --out anchor-receipt.json
"$BIN" anchor prove --log anchor-log.json --log-id cybermesh-demo --release release-1.json --out inclusion-proof.json
"$BIN" anchor verify --proof inclusion-proof.json --receipt anchor-receipt.json --release release-1.json --chain anchor-chain.json
echo "== release entries"
"$BIN" release show --release release-1.json | python3 -I -c "import json,sys;r=json.load(sys.stdin);[print(f\"  {e['action']:5} {e['confidence']:6} {e['risk_score_bp']:5} {e['indicator']}\") for e in r['entries']];print('  corrections:',len(r['corrections']))"
if [ "${1:-}" = "--keep-serving" ]; then
  echo "== serving $OUT/public on http://127.0.0.1:8088 (Ctrl-C to stop)"
  "$BIN" serve --dir public --addr 127.0.0.1:8088
fi
