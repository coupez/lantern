#!/bin/sh
# Interoperate with Samba's real node-status server inside the disposable Linux
# test container. No SMB daemon, shares, host mounts, or published ports.
set -eu
binary=${1:-/tmp/lantern}
lantern_samba_tmp=$(mktemp -d)
lantern_samba_pid=
cleanup() {
  if [ -n "$lantern_samba_pid" ]; then
    kill "$lantern_samba_pid" 2>/dev/null || true
    wait "$lantern_samba_pid" 2>/dev/null || true
  fi
  rm -rf "$lantern_samba_tmp"
}
trap cleanup EXIT HUP INT TERM
lantern_samba_interface=$(ip -4 route show default | awk 'NR == 1 {print $5}')
lantern_samba_ip=$(ip -4 -o address show dev "$lantern_samba_interface" | awk 'NR == 1 {split($4,a,"/");print a[1]}')
test -n "$lantern_samba_ip"
cat > "$lantern_samba_tmp/smb.conf" <<CONFIG
[global]
  netbios name = LANTERN-SAMBA
  workgroup = LANTERN-LAB
  interfaces = $lantern_samba_ip
  bind interfaces only = yes
  local master = no
  preferred master = no
  domain master = no
  wins support = no
  disable netbios = no
  private dir = $lantern_samba_tmp
  state directory = $lantern_samba_tmp
  cache directory = $lantern_samba_tmp
  lock directory = $lantern_samba_tmp
  pid directory = $lantern_samba_tmp
CONFIG
nmbd --foreground --no-process-group --debug-stdout --configfile="$lantern_samba_tmp/smb.conf" > "$lantern_samba_tmp/nmbd.log" 2>&1 &
lantern_samba_pid=$!
# Probe the known live child until its registered names are ready. Startup
# registers names asynchronously, so socket readiness alone is insufficient.
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if ! kill -0 "$lantern_samba_pid" 2>/dev/null; then cat "$lantern_samba_tmp/nmbd.log"; exit 1; fi
  "$binary" scan "$lantern_samba_ip" --netbios --ports none --no-icmp --no-multicast --no-dns --json > "$lantern_samba_tmp/report.json"
  if python3 - "$lantern_samba_tmp/report.json" 2> "$lantern_samba_tmp/check.log" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert len(r['devices'])==1
host=r['devices'][0]
assert 'netbios' in host['evidence']
assert host['identity']['name']=='LANTERN-SAMBA'
assert not host.get('ports'), 'name registration is not a verified open TCP port'
assert any(a['protocol']=='netbios' and a['service']=='workgroup' and a['properties']['name']=='LANTERN-LAB' for a in host['advertisements'])
PY
  then ready=1; break; fi
  sleep 1
done
if [ "$ready" != 1 ]; then cat "$lantern_samba_tmp/nmbd.log"; cat "$lantern_samba_tmp/report.json"; cat "$lantern_samba_tmp/check.log"; exit 1; fi
"$binary" inspect "$lantern_samba_ip" --ports none --banners=false --no-icmp --no-multicast --no-dns --json > "$lantern_samba_tmp/inspect.json"
"$binary" inspect "$lantern_samba_ip" --netbios=false --ports none --banners=false --no-icmp --no-multicast --no-dns --json > "$lantern_samba_tmp/disabled.json"
python3 - "$lantern_samba_tmp/inspect.json" "$lantern_samba_tmp/disabled.json" <<'PY'
import json,sys
inspect=json.load(open(sys.argv[1]))
disabled=json.load(open(sys.argv[2]))
assert inspect['devices'][0]['identity']['name']=='LANTERN-SAMBA'
assert all('netbios' not in d['evidence'] for d in disabled['devices'])
PY
nmbd --version
cat "$lantern_samba_tmp/report.json"
echo 'PASS NetBIOS interoperability: real Samba name table, workgroup, provenance, no inferred open ports'
