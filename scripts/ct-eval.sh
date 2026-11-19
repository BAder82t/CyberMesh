#!/usr/bin/env bash
# Live CT detection evaluation (docs/ct-evaluation.md): follows public CT logs with
# `cybermesh ct watch` for a fixed window, and snapshots a phishing feed every hour until a
# grace period after it.
#
#   scripts/ct-eval.sh start    [RUN_DIR]   start, or resume after a reboot (same end time)
#   scripts/ct-eval.sh stop     [RUN_DIR]   stop both processes cleanly
#   scripts/ct-eval.sh status   [RUN_DIR]   processes, progress, disk use, recent events
#   scripts/ct-eval.sh history  [RUN_DIR]   clone OpenPhish's public feed history and export
#                                           each commit since a day before the run as a
#                                           snapshot for `cybermesh ct evaluate`
#
# Environment:
#   CT_EVAL_LOGS  space-separated log ids (default: Willow, Sycamore, ParcelYard: about 13 GB a
#                 day of download each; Sycamore + ParcelYard alone carry about 98 % of the names)
#   CT_EVAL_DAYS  CT window of a new run (default 7); CT_EVAL_SECS overrides it in seconds
#   CT_EVAL_FEED_GRACE_SECS  feed snapshots continue this long after the CT window, so late
#                 confirmations of the last days' detections are seen (default 3 days)
#
# Data goes to eval-data/ (git-ignored). Feeds are research data under their own terms and are
# never redistributed: phishunt (CC0), OpenPhish community feed (non-commercial use only).
set -euo pipefail
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
CALLER=$PWD
cd "$(dirname "$SELF")/.."

CMD=${1:-status}
RUN=${2:-eval-data/ct-run}
# A RUN_DIR given on the command line is relative to the caller, not the repository.
case "$RUN" in /*) ;; *) [ -n "${2:-}" ] && RUN="$CALLER/$RUN" ;; esac
BIN=target/release/cybermesh
EVIDENCE=eval-data/ct-evidence
LOGS=${CT_EVAL_LOGS:-letsencrypt-willow-2027h1 letsencrypt-sycamore-2027h1 google-parcelyard-2027h1}
DAYS=${CT_EVAL_DAYS:-7}
SECS=${CT_EVAL_SECS:-$(( DAYS * 86400 ))}
GRACE=${CT_EVAL_FEED_GRACE_SECS:-$(( 3 * 86400 ))}
PHISHUNT=https://phishunt.io/feed.csv

# A pid file is live only if its process is still ours (pids are reused after a reboot).
alive() {
  [ -f "$1" ] || return 1
  local pid; pid=$(cat "$1")
  kill -0 "$pid" 2>/dev/null || return 1
  ps -p "$pid" -o args= 2>/dev/null | grep -qE 'cybermesh ct watch|ct-eval\.sh feeds'
}
now() { date -u +%s; }
utc() { date -u -r "$1" 2>/dev/null || date -u -d "@$1"; }
stamp() { date -u -r "$1" +%Y%m%dT%H%M%SZ 2>/dev/null || date -u -d "@$1" +%Y%m%dT%H%M%SZ; }

fetch_feeds() {
  local ts tmp
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  tmp="$RUN/feeds/.phishunt.tmp"
  # Never let one failure end the loop; only a complete, plausible CSV gets a final name.
  if curl -fsS --max-time 120 --retry 2 -o "$tmp" "$PHISHUNT" \
    && [ -s "$tmp" ] && head -c 11 "$tmp" | grep -q '^url,domain' \
    && gzip -c "$tmp" > "$tmp.gz" \
    && mv "$tmp.gz" "$RUN/feeds/phishunt/$ts.csv.gz"; then
    echo "$ts phishunt ok $(wc -l < "$tmp") lines"
  else
    echo "$ts phishunt FAILED"
  fi
  rm -f "$tmp" "$tmp.gz"
}

case "$CMD" in
  start)
    [ -x "$BIN" ] || { echo "build first: cargo build --release -p cybermesh-cli" >&2; exit 1; }
    "$BIN" evidence verify --dir "$EVIDENCE" > /dev/null
    if alive "$RUN/watch.pid" || alive "$RUN/feeds.pid"; then
      echo "already running ($RUN)" >&2; exit 1
    fi
    mkdir -p "$RUN/feeds/phishunt"
    rm -f "$RUN/STOP"
    [ -f "$RUN/until" ] || echo $(( $(now) + SECS )) > "$RUN/until"
    [ -f "$RUN/feeds_until" ] || echo $(( $(cat "$RUN/until") + GRACE )) > "$RUN/feeds_until"
    [ -f "$RUN/logs" ] || echo "$LOGS" > "$RUN/logs"
    LEFT=$(( $(cat "$RUN/until") - $(now) ))
    FLEFT=$(( $(cat "$RUN/feeds_until") - $(now) ))
    [ "$FLEFT" -gt 0 ] || { echo "run already ended at $(utc "$(cat "$RUN/feeds_until")")" >&2; exit 1; }
    if [ "$LEFT" -gt 0 ]; then
      ARGS=()
      for l in $(cat "$RUN/logs"); do ARGS+=(--log "$l"); done
      nohup "$BIN" ct watch --evidence "$EVIDENCE" "${ARGS[@]}" --out "$RUN" \
        --poll-secs 15 --duration-secs "$LEFT" >> "$RUN/watch.log" 2>&1 &
      echo $! > "$RUN/watch.pid"
      # macOS: keep the machine from idle-sleeping while the watcher runs (not lid-close sleep).
      if command -v caffeinate > /dev/null; then
        nohup caffeinate -i -w "$(cat "$RUN/watch.pid")" > /dev/null 2>&1 &
      fi
      echo "watch: pid $(cat "$RUN/watch.pid"), logs: $(cat "$RUN/logs")"
      echo "CT window ends: $(utc "$(cat "$RUN/until")") (in $(( LEFT / 3600 )) h)"
    else
      echo "CT window ended at $(utc "$(cat "$RUN/until")"); resuming the feed snapshots only"
    fi
    nohup "$SELF" feeds "$RUN" >> "$RUN/feeds.log" 2>&1 &
    echo $! > "$RUN/feeds.pid"
    echo "feeds: pid $(cat "$RUN/feeds.pid"), until $(utc "$(cat "$RUN/feeds_until")")"
    ;;
  feeds)
    # Internal: hourly feed snapshots until the run ends or is stopped.
    while [ ! -e "$RUN/STOP" ] && [ "$(now)" -lt "$(cat "$RUN/feeds_until")" ]; do
      fetch_feeds
      next=$(( $(now) + 3600 ))
      while [ ! -e "$RUN/STOP" ] && [ "$(now)" -lt "$next" ]; do sleep 10; done
    done
    echo "$(date -u +%Y%m%dT%H%M%SZ) feeds stopped"
    ;;
  stop)
    touch "$RUN/STOP"
    for p in watch feeds; do
      for _ in $(seq 1 60); do alive "$RUN/$p.pid" || break; sleep 1; done
      alive "$RUN/$p.pid" && echo "$p still running (pid $(cat "$RUN/$p.pid"))" >&2
    done
    echo "stopped"
    ;;
  status)
    for p in watch feeds; do
      if alive "$RUN/$p.pid"; then echo "$p: running (pid $(cat "$RUN/$p.pid"))"; else echo "$p: not running"; fi
    done
    [ -f "$RUN/until" ] && echo "CT window ends: $(utc "$(cat "$RUN/until")")"
    [ -f "$RUN/feeds_until" ] && echo "feed snapshots end: $(utc "$(cat "$RUN/feeds_until")")"
    if [ -f "$RUN/polls.jsonl" ]; then
      python3 -I - "$RUN" <<'EOF'
import json, os, sys, collections
d = sys.argv[1]
last, tiles = {}, collections.Counter()
with open(os.path.join(d, "polls.jsonl")) as f:
    for line in f:
        try:
            p = json.loads(line)
        except ValueError:
            continue
        last[p["log"]] = p
        tiles[p["log"]] += p["tiles"]
for log, p in sorted(last.items()):
    print(f"{log}: {tiles[log]} tiles scanned, next tile {p['next_tile']}, lag {p['lag_tiles']} tiles")
n = sum(1 for _ in open(os.path.join(d, "matches.jsonl"))) if os.path.exists(os.path.join(d, "matches.jsonl")) else 0
snaps = len(os.listdir(os.path.join(d, "feeds", "phishunt"))) if os.path.isdir(os.path.join(d, "feeds", "phishunt")) else 0
print(f"brand-signal lines: {n}; feed snapshots: {snaps}")
EOF
    fi
    du -sh "$RUN" 2>/dev/null | awk '{print "disk: " $1}'
    if [ -s "$RUN/events.jsonl" ]; then
      echo "events by kind:"
      python3 -I -c 'import json,sys,collections; c=collections.Counter()
for l in open(sys.argv[1]):
    try: e=json.loads(l)
    except ValueError: continue
    c[(e["log"],e["kind"])]+=1
for (l,k),n in sorted(c.items()): print(f"  {l} {k}: {n}")' "$RUN/events.jsonl"
      echo "latest:"; tail -1 "$RUN/events.jsonl"
    fi
    true
    ;;
  history)
    mkdir -p "$RUN/feeds"
    dst="$RUN/feeds/public_feed.git"
    if [ -d "$dst" ]; then
      git -C "$dst" fetch -q origin '+refs/heads/*:refs/heads/*'
    else
      git clone -q --bare https://github.com/openphish/public_feed.git "$dst"
    fi
    echo "openphish/public_feed: $(git -C "$dst" rev-list --count HEAD) commits"
    start=$(python3 -I -c 'import json,sys; print(min(json.loads(l)["started_ms"] for l in open(sys.argv[1]) if l.strip()) // 1000)' "$RUN/runs.jsonl")
    since=$(( start - 86400 ))
    mkdir -p "$RUN/feeds/openphish"
    n=0
    while read -r sha ct; do
      [ "$ct" -ge "$since" ] || continue
      f="$RUN/feeds/openphish/$(stamp "$ct").txt.gz"
      if [ ! -s "$f" ]; then
        if ! git -C "$RUN/feeds/public_feed.git" show "$sha:feed.txt" | gzip > "$f.tmp"; then
          rm -f "$f.tmp"; echo "export of OpenPhish commit $sha failed" >&2; exit 1
        fi
        mv "$f.tmp" "$f"
      fi
      n=$((n + 1))
    done < <(git -C "$RUN/feeds/public_feed.git" log --format='%H %ct' HEAD -- feed.txt)
    echo "openphish: $n snapshots since $(utc "$since")"
    ;;
  *)
    echo "usage: $0 start|stop|status|history [RUN_DIR]" >&2; exit 2 ;;
esac
