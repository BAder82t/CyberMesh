#!/usr/bin/env bash
# Runs every TLC configuration and checks it gives the EXPECTED result.
# Usage: TLA2TOOLS=/path/to/tla2tools.jar formal/tla/run.sh   (needs Java)
set -u
here="$(cd "$(dirname "$0")" && pwd)"
jar="${TLA2TOOLS:?set TLA2TOOLS to the path of tla2tools.jar}"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
fail=0
# config:expectation   (pass, or the name of the invariant that must be violated)
for item in safe:pass unauth:NoForgery unauth_overrun:NoOverrun restore:NoAuthReuse \
            restore_pad:NoPadReuse discipline:NoAuthReuse discipline_pad:NoPadReuse reach:NotHealed; do
  cfg="${item%%:*}"; want="${item#*:}"
  out="$work/$cfg.txt"
  (cd "$work" && java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -nowarning -config "$here/$cfg.cfg" \
      -workers auto -metadir "$work/m_$cfg" "$here/TrustFabricResync.tla" >"$out" 2>&1)
  if [ "$want" = pass ]; then
    grep -q "No error has been found" "$out" && r=ok || r=WRONG
  else
    grep -q "Invariant $want is violated" "$out" && r=ok || r=WRONG
  fi
  printf '%-16s expect %-12s %s\n' "$cfg" "$want" "$r"
  [ "$r" = ok ] || fail=1
done
exit $fail
