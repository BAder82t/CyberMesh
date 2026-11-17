#!/usr/bin/env bash
# Docker Compose demonstration. Usage: deploy/docker/demo.sh [up|down]
set -euo pipefail
cd "$(dirname "$0")"
C="docker compose -f docker-compose.yml"
if [ "${1:-up}" = "down" ]; then $C --profile run --profile tools --profile web down -v; exit 0; fi
$C build init
echo "== independent verifier of organisation B (own key, own records)"
$C --profile run up -d verifier-org-b
$C up -d worker-a1 worker-b1 worker-b2 worker-c1 worker-d1 worker-m1
sleep 3
echo "== coordinator (runs until all tasks settle)"
$C --profile run run --rm coordinator | tail -n 30
echo "== waiting for the independent verifier to settle its last tasks"
code=$(docker wait "$($C --profile run ps -a -q verifier-org-b)")
if [ "$code" != "0" ]; then $C --profile run logs --tail 40 verifier-org-b; echo "verifier exited with $code" >&2; exit 1; fi
$C --profile tools run --rm status 'grep -E "\"(operator|tasks_seen|verified|insufficient|faults|results_accepted|tasks_incompatible|records_published|records_received|records_refused)\"" /state/verifier-org-b/verifier-report.json'
echo "== organisation A builds and signs the release (only its own release key is mounted)"
$C --profile tools run --rm release-org-a '
set -e; NOW=$(date +%s); echo "$NOW" > issued_at
echo "quorum check: the coordinator records alone (one verifier organisation) publish nothing"
cybermesh release build --records /demo/state/coordinator/records --manifest /demo/manifest.json --root /demo/governance-root.json --sequence 1 --issued-at "$NOW" --out release-1.coordinator-only
rm release-1.coordinator-only
echo "org-a builds from its own node only: own records + records received over the network"
cybermesh release build --records /demo/state/coordinator/records --records /demo/state/coordinator/received-records --manifest /demo/manifest.json --root /demo/governance-root.json --sequence 1 --issued-at "$NOW" --out release-1.a
cybermesh release sign --payload release-1.a --key /demo/keys/release-org-a.key.json --out release-1.json'
echo "== organisation B rebuilds independently, compares bytes, co-signs, verifies, anchors"
$C --profile tools run --rm release-org-b '
set -e; NOW=$(cat issued_at)
echo "org-b builds from its own node only: own records + records received over the network"
cybermesh release build --records /demo/state/verifier-org-b/records --records /demo/state/verifier-org-b/received-records --manifest /demo/manifest.json --root /demo/governance-root.json --sequence 1 --issued-at "$NOW" --out release-1.b
cmp release-1.a release-1.b && echo "identical payloads"
cybermesh release sign --payload release-1.b --key /demo/keys/release-org-b.key.json --merge release-1.json --out release-1.json
cybermesh release verify --release release-1.json --trust-root /demo/trust-root.json
cp release-1.json release.json
cybermesh anchor append --log anchor-log.json --log-id cybermesh-demo --release release-1.json
cybermesh anchor commit --log anchor-log.json --log-id cybermesh-demo --adapter local --chain anchor-chain.json --out anchor-receipt.json
cybermesh anchor prove --log anchor-log.json --log-id cybermesh-demo --release release-1.json --out inclusion-proof.json
cybermesh anchor verify --proof inclusion-proof.json --receipt anchor-receipt.json --release release-1.json --chain anchor-chain.json'
echo "== worker status (self-reported resource usage)"
$C --profile tools run --rm status 'for w in a1 b1 b2 c1 d1 m1; do cybermesh worker status --state-dir /state/$w | grep -E "\"(operator|state|tasks_completed|cpu_percent_avg|rss_bytes)\""; done'
echo "== resource usage reported by Docker"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" $($C ps -q)
$C --profile web up -d web
echo "Release and phishing test page served at http://127.0.0.1:8088 (stop with: deploy/docker/demo.sh down)"
