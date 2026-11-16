#!/usr/bin/env bash
# Docker Compose demonstration. Usage: deploy/docker/demo.sh [up|down]
set -euo pipefail
cd "$(dirname "$0")"
C="docker compose -f docker-compose.yml"
if [ "${1:-up}" = "down" ]; then $C --profile run --profile tools --profile web down -v; exit 0; fi
$C build init
$C up -d worker-a1 worker-b1 worker-b2 worker-c1 worker-d1 worker-m1
sleep 3
echo "== coordinator (runs until all tasks settle)"
$C --profile run run --rm coordinator | tail -n 30
echo "== release: built independently by org-a and org-b, co-signed, verified, anchored"
$C --profile tools run --rm cli '
set -e; NOW=$(date +%s)
cybermesh release build --records state/coordinator/records --manifest manifest.json --root governance-root.json --sequence 1 --issued-at $NOW --out release-1.a
cybermesh release build --records state/coordinator/records --manifest manifest.json --root governance-root.json --sequence 1 --issued-at $NOW --out release-1.b
cmp release-1.a release-1.b && echo "identical payloads"
cybermesh release sign --payload release-1.a --key keys/release-org-a.key.json --out release-1.json
cybermesh release sign --payload release-1.b --key keys/release-org-b.key.json --merge release-1.json --out release-1.json
cybermesh release verify --release release-1.json --trust-root trust-root.json
cp release-1.json public/release.json
cybermesh anchor append --log anchor-log.json --log-id cybermesh-demo --release release-1.json
cybermesh anchor commit --log anchor-log.json --log-id cybermesh-demo --adapter local --chain anchor-chain.json --out anchor-receipt.json
cybermesh anchor prove --log anchor-log.json --log-id cybermesh-demo --release release-1.json --out inclusion-proof.json
cybermesh anchor verify --proof inclusion-proof.json --receipt anchor-receipt.json --release release-1.json --chain anchor-chain.json
for w in a1 b1 b2 c1 d1 m1; do cybermesh worker status --state-dir state/$w | grep -E "\"(operator|state|tasks_completed|cpu_percent_avg|rss_bytes)\""; done'
echo "== resource usage reported by Docker"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" $($C ps -q)
$C --profile web up -d web
echo "Release and phishing test page served at http://127.0.0.1:8088 (stop with: deploy/docker/demo.sh down)"
