#!/bin/bash
# SPDX-License-Identifier: MIT
# omamobile-torch against a fake brightnessctl: without TORCH_* keys it runs
# exactly the commands the tile ran before (white:torch, 100%), and a device
# descriptor's TORCH_LED and TORCH_LEVEL replace them.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }
pass() { printf 'ok - %s\n' "$1"; }
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
F=$t/fakes; mkdir -p "$F"
printf '#!/bin/bash\necho "$*" >>"$T/log"\n[[ $2 == get ]] && cat "$T/level"\nexit 0\n' >"$F/brightnessctl"
chmod +x "$F/brightnessctl"
torch() { : >"$t/log"; env T="$t" OMAMOBILE_DEVICE_CONF="$conf" PATH="$F:/usr/bin:/bin" bash bin/omamobile-torch "$@" >"$t/out" 2>"$t/err"; }
log() { cat "$t/log"; }

conf=$t/missing.conf
torch info; [[ $(log) == '--device=white:torch --machine-readable info' ]] || fail "info without a descriptor: $(log)"
torch on; [[ $(log) == '--device=white:torch --quiet set 100%' ]] || fail "on without a descriptor: $(log)"
torch off; [[ $(log) == '--device=white:torch --quiet set 0' ]] || fail "off without a descriptor: $(log)"
pass "without a descriptor the torch is white:torch at 100%, as before"

conf=$t/cheetah.conf
printf 'CODENAME=cheetah\nPANEL_SIZE=1440x3120\n' >"$conf"
torch on; [[ $(log) == '--device=white:torch --quiet set 100%' ]] || fail "a descriptor without TORCH_* keys: $(log)"
pass "a descriptor without TORCH_* keys keeps the defaults"

conf=$t/ingot.conf
printf 'CODENAME=ingot\nTORCH_LED=white:flash\nTORCH_LEVEL=128\n' >"$conf"
torch on; [[ $(log) == '--device=white:flash --quiet set 128' ]] || fail "TORCH_LED and TORCH_LEVEL: $(log)"
echo 0 >"$t/level"; torch toggle
[[ $(log) == $'--device=white:flash get\n--device=white:flash --quiet set 128' ]] || fail "toggle from off: $(log)"
echo 128 >"$t/level"; torch toggle
[[ $(log) == $'--device=white:flash get\n--device=white:flash --quiet set 0' ]] || fail "toggle from on: $(log)"
torch get; [[ $(log) == '--device=white:flash get' && $(cat "$t/out") == 128 ]] || fail "get: $(log)"
pass "TORCH_LED and TORCH_LEVEL pick the LED and the on level"

printf 'TORCH_LED="white:flash"\nTORCH_LEVEL="50%%"\n' >"$conf"
torch on; [[ $(log) == '--device=white:flash --quiet set 50%' ]] || fail "quoted values: $(log)"
pass "quoted values and percentages"

printf 'TORCH_LED=../../x; rm\nTORCH_LEVEL=max\n' >"$conf"
torch on; [[ $(log) == '--device=white:torch --quiet set 100%' ]] || fail "bad values are ignored: $(log)"
grep -c 'ignoring TORCH_LEVEL' "$t/err" >/dev/null || fail "a bad value is reported"
pass "values that aren't an LED name or a level are ignored"

if torch bogus; then fail "an unknown command fails"; fi
pass "an unknown command fails"
