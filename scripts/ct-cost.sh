#!/usr/bin/env bash
# Cost of decentralising CT monitoring (docs/ct-evaluation.md §6). Scans the same fixed range
# of a live CT log twice and compares CPU, CT download and peer-to-peer traffic:
#   (a) one process: `cybermesh ct watch --start-tile --end-tile`;
#   (b) a local CyberMesh network: a coordinator, 5 workers in 4 organisations and one
#       independent verifier (replication 2, min_verifiers 2), as in the local demo.
# Both verify the log's checkpoint and prove every tile root they rely on.
#
#   scripts/ct-cost.sh [LOG_ID] [TILES]   (default: letsencrypt-willow-2027h1, 64 tiles)
#
# CT_COST_TILES_PER_TASK (default 8, the coordinator's default) sets the task size. Each
# verifier rescans 2 tiles per task, so with 2 tiles per task (the demo's setting)
# verification is a full recomputation; with 8 it rescans about a quarter.
#
# Downloads about 2.5 MB per tile (decompressed) in total; 64 tiles is about 160 MB.
# Output: eval-data/ct-cost/ (OUT overrides), summary on stdout and in summary.json.
set -euo pipefail
cd "$(dirname "$0")/.."
LOG=${1:-letsencrypt-willow-2027h1}
TILES=${2:-64}
TPT=${CT_COST_TILES_PER_TASK:-8}
EVIDENCE=${CT_COST_EVIDENCE:-eval-data/ct-evidence}
OUT=${OUT:-eval-data/ct-cost}
case "$OUT" in ""|/|.|..) echo "refusing OUT=$OUT" >&2; exit 1;; esac
cargo build -q --release -p cybermesh-cli
BIN="$PWD/target/release/cybermesh"
rm -rf "$OUT"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

FULL=$("$BIN" ct checkpoint --evidence "$EVIDENCE" --log "$LOG" | sed -E 's/.*full_tiles=([0-9]+).*/\1/')
[[ "$FULL" =~ ^[0-9]+$ ]] || { echo "could not read the log's checkpoint" >&2; exit 1; }
FIRST=$(( FULL - TILES ))
[ "$FIRST" -ge 0 ] || { echo "the log has only $FULL full tiles" >&2; exit 1; }
END=$FULL
echo "== $LOG: tiles $FIRST..$END ($TILES tiles, $(( TILES * 256 )) entries, $TPT tiles per task)"

echo "== (a) one process"
T0=$(date +%s)
"$BIN" ct watch --evidence "$EVIDENCE" --log "$LOG" --out "$OUT/single" \
  --start-tile "$FIRST" --end-tile "$END" --poll-secs 1 2> "$OUT/single.log"
echo $(( $(date +%s) - T0 )) > "$OUT/single.wall"

echo "== (b) CyberMesh network"
: > "$OUT/no-domains.txt"
"$BIN" demo init --out "$OUT/net" --evidence "$EVIDENCE" --domains "$OUT/no-domains.txt" \
  --base-port 4600 --ct-log "$LOG" --ct-tiles "$TILES" --independent-verifiers 1 > /dev/null
cd "$OUT/net"
# A fixed range instead of following the log.
sed -i.bak -e "s/^first_tile = 0$/first_tile = $FIRST/" -e 's/^follow = true$/follow = false/' \
  -e '/^poll_secs = /d' -e '/^until_tile = /d' -e "s/^tiles_per_task = 2$/tiles_per_task = $TPT/" coordinator.toml
need() { grep -q "$1" coordinator.toml || { echo "coordinator.toml patch failed: $1" >&2; exit 1; }; }
refuse() { if grep -q "$1" coordinator.toml; then echo "coordinator.toml patch failed: $1 still set" >&2; exit 1; fi; }
need "^first_tile = $FIRST$"
need '^follow = false$'
need "^tiles_per_task = $TPT$"
refuse '^poll_secs = '
refuse '^until_tile = '
mkdir -p logs
pids=()
vpids=()
cleanup() { for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
for cfg in verifier-*.toml; do
  [ -e "$cfg" ] || continue
  "$BIN" verifier run --config "$cfg" > "logs/${cfg%.toml}-report.json" 2> "logs/${cfg%.toml}.log" &
  vpids+=($!); pids+=($!)
done
wpids=()
for cfg in worker-*.toml; do
  "$BIN" worker run --config "$cfg" > "logs/${cfg%.toml}.json" 2> "logs/${cfg%.toml}.log" &
  wpids+=($!); pids+=($!)
done
T0=$(date +%s)
"$BIN" coordinator run --config coordinator.toml > logs/coordinator-report.json 2> logs/coordinator.log
echo $(( $(date +%s) - T0 )) > ../net.wall
for p in "${vpids[@]:-}"; do [ -n "$p" ] && wait "$p"; done
# Stop the workers cleanly: each writes a final status.json on exit.
for cfg in worker-*.toml; do
  w=${cfg#worker-}; w=${w%.toml}
  "$BIN" worker stop --control-dir "state/$w/control" > /dev/null
done
for p in "${wpids[@]:-}"; do [ -n "$p" ] && wait "$p" || true; done
for cfg in worker-*.toml; do
  w=${cfg#worker-}; w=${w%.toml}
  "$BIN" worker status --state-dir "state/$w" > "logs/status-$w.json"
done
cd "$OUT"

python3 -I - "$OUT" "$TILES" "$TPT" <<'EOF'
import glob, json, os, sys
out, tiles, tpt = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
entries = tiles * 256
def jl(p):
    with open(p) as f:
        return [json.loads(l) for l in f if l.strip()]
polls = jl(os.path.join(out, "single/polls.jsonl"))
proc = jl(os.path.join(out, "single/process.jsonl"))
# HTTP-level counts, as the network nodes report them.
single = {
    "processes": 1,
    "wall_s": int(open(os.path.join(out, "single.wall")).read()),
    "cpu_ms": proc[-1]["cpu_ms"],
    "ct_bytes": proc[-1]["ct_http_bytes"],
    "ct_requests": proc[-1]["ct_http_requests"],
    "p2p_bytes": 0,
    "tiles_scanned": sum(p["tiles"] for p in polls),
}
net_dir = os.path.join(out, "net")
coord = json.load(open(os.path.join(net_dir, "logs/coordinator-report.json")))
vers = [json.load(open(p)) for p in glob.glob(os.path.join(net_dir, "logs/verifier-*-report.json"))]
works = [json.load(open(p)) for p in glob.glob(os.path.join(net_dir, "logs/status-*.json"))]
nodes = [("coordinator", coord)] + [("verifier", v) for v in vers] + [("worker", w) for w in works]
by_role = {}
for role, n in nodes:
    r = by_role.setdefault(role, {"n": 0, "cpu_ms": 0, "ct_bytes": 0, "ct_requests": 0, "p2p_out": 0})
    r["n"] += 1
    r["cpu_ms"] += n.get("cpu_ms", 0)
    r["ct_bytes"] += n.get("ct_http_bytes", 0)
    r["ct_requests"] += n.get("ct_http_requests", 0)
    r["p2p_out"] += n.get("net_bytes_out", 0)
net = {
    "processes": len(nodes),
    "wall_s": int(open(os.path.join(out, "net.wall")).read()),
    "cpu_ms": sum(r["cpu_ms"] for r in by_role.values()),
    "ct_bytes": sum(r["ct_bytes"] for r in by_role.values()),
    "ct_requests": sum(r["ct_requests"] for r in by_role.values()),
    "p2p_bytes": sum(r["p2p_out"] for r in by_role.values()),
    "tiles_verified": coord["ct_tiles_verified"],
    "tiles_rescanned_by_coordinator": coord["ct_tiles_rescanned"],
    "tasks": {k: coord[k] for k in ["tasks_issued", "verified", "disputed", "insufficient", "faults"]},
    "independent_verifiers": [{k: v[k] for k in ["operator", "verified", "insufficient", "faults"]} for v in vers],
    "by_role": by_role,
}
ratio = {k: round(net[k] / single[k], 2) if single[k] else None for k in ["cpu_ms", "ct_bytes", "ct_requests", "wall_s"]}
summary = {"log_entries": entries, "tiles_per_task": tpt, "single": single, "network": net, "network_over_single": ratio}
json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=2)
print(f"single process: {single['cpu_ms']/1000:.1f} s CPU, {single['ct_bytes']/1e6:.1f} MB from the log "
      f"({single['ct_requests']} requests), {single['wall_s']} s wall, {single['tiles_scanned']} tiles")
print(f"network ({net['processes']} processes): {net['cpu_ms']/1000:.1f} s CPU, {net['ct_bytes']/1e6:.1f} MB from the log "
      f"({net['ct_requests']} requests), {net['p2p_bytes']/1e6:.2f} MB peer-to-peer, {net['wall_s']} s wall, "
      f"{net['tiles_verified']} tiles verified, coordinator rescanned {net['tiles_rescanned_by_coordinator']}")
for role, r in sorted(by_role.items()):
    print(f"  {role:11} x{r['n']}: {r['cpu_ms']/1000:6.1f} s CPU, {r['ct_bytes']/1e6:7.1f} MB from the log, {r['p2p_out']/1e6:6.2f} MB p2p out")
print("network / single:", ratio)
print("per entry: single", round(single["cpu_ms"] * 1000 / entries), "us CPU,", round(single["ct_bytes"] / entries), "B;",
      "network", round(net["cpu_ms"] * 1000 / entries), "us CPU,", round(net["ct_bytes"] / entries), "B +",
      round(net["p2p_bytes"] / entries), "B p2p")
print("tasks:", net["tasks"], "independent verifiers:", net["independent_verifiers"])
EOF
