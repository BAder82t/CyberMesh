#!/usr/bin/env bash
# Measures worker resource usage externally (ps sampling) while the local demo network
# assesses a larger domain list. Usage: scripts/measure-resources.sh [domains-file] [idle-seconds]
# Writes a summary to stdout; raw samples to $OUT/logs/samples.csv.
set -euo pipefail
cd "$(dirname "$0")/.."
DOMAINS=${1:-datasets/demo/domains.txt}
IDLE=${2:-120}
OUT=${OUT:-measure-out}
cargo build -q --release -p cybermesh-cli
BIN="$PWD/target/release/cybermesh"
rm -rf "$OUT"
"$BIN" demo init --out "$OUT" --evidence datasets/demo/evidence --domains "$DOMAINS" --base-port 4300 >/dev/null
cd "$OUT"; mkdir -p logs
sed -i.bak 's/^batch_size = 8/batch_size = 32/' coordinator.toml
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
for cfg in worker-*.toml; do
  "$BIN" worker run --config "$cfg" > /dev/null 2> "logs/${cfg%.toml}.log" & pids+=($!)
done
echo "t,pid,cpu_pct,rss_kib" > logs/samples.csv
sample() { local t=0; while true; do for p in "${pids[@]}"; do ps -o pid=,%cpu=,rss= -p "$p" 2>/dev/null | awk -v t="$t" '{print t","$1","$2","$3}' >> logs/samples.csv; done; sleep 2; t=$((t+2)); done; }
sample & SP=$!
START=$(date +%s)
"$BIN" coordinator run --config coordinator.toml > logs/report.json 2> logs/coordinator.log
END=$(date +%s)
echo "== busy phase: $((END-START)) s for $(python3 -I -c "import json;print(json.load(open('logs/report.json'))['domains_total'])") domains"
echo "== idle phase: ${IDLE} s (connected, heartbeats only)"
sleep "$IDLE"
kill $SP 2>/dev/null || true
for cfg in worker-*.toml; do w=${cfg#worker-}; w=${w%.toml}; "$BIN" worker status --state-dir "state/$w"; done > logs/status.jsonl
python3 -I - <<'PY'
import csv, json, re
rows=list(csv.DictReader(open("logs/samples.csv")))
by={}
for r in rows: by.setdefault(r["pid"],[]).append((float(r["cpu_pct"]), int(r["rss_kib"])))
cpu=[sum(c for c,_ in v)/len(v) for v in by.values()]
rss=[max(m for _,m in v)/1024 for v in by.values()]
print(f"ps sampling: {len(rows)} samples over {len(by)} workers")
print(f"  mean CPU per worker (ps %cpu, decaying average): min {min(cpu):.3f}%  max {max(cpu):.3f}%")
print(f"  peak RSS per worker: min {min(rss):.1f} MiB  max {max(rss):.1f} MiB")
txt=open("logs/status.jsonl").read()
objs=[json.loads(o) for o in re.split(r"\n(?=\{)", txt.strip()) if o.strip()]
for s in objs:
    r=s["resources"]
    print(f"  self-report {s['operator']:6} tasks={s['tasks_completed']:3} cpu_avg={r['cpu_percent_avg']:.3f}% over {r['wall_seconds']:.0f}s rss={r['rss_bytes']/1048576:.1f}MiB out={s['net_bytes_out']/1024:.1f}KiB in={s['net_bytes_in']/1024:.1f}KiB")
rep=json.load(open("logs/report.json"))
print("coordinator:", {k: rep[k] for k in ["tasks_issued","verified","insufficient","reassignments","faults"]})
PY
