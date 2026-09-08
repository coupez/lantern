#!/bin/sh
set -eu
go version
go vet ./...
go test -race ./...
# The bridge gateway is a known peer in this container's own network namespace.
LANTERN_ARP_TARGET=$(ip -4 route show default | awk 'NR == 1 {print $3}')
LANTERN_ARP_INTERFACE=$(ip -4 route show default | awk 'NR == 1 {print $5}')
export LANTERN_ARP_TARGET LANTERN_ARP_INTERFACE LANTERN_NETWORK_TESTS=1
test -n "$LANTERN_ARP_TARGET"
go test -race ./pkg/scanner -run NetworkIntegration -v
python3 scripts/test-install.py
go build -trimpath -o /tmp/lantern ./cmd/lantern
python3 /usr/local/bin/test-event-stream.py /tmp/lantern
python3 /usr/local/bin/test-doctor.py /tmp/lantern --expect-arp available
python3 /usr/local/bin/test-watch-pty.py /tmp/lantern
python3 /usr/local/bin/test-snapshot-cli.py /tmp/lantern
sh /usr/local/bin/test-netbios-samba.sh /tmp/lantern
/tmp/lantern version
/tmp/lantern demo --no-color
/tmp/lantern scan "$LANTERN_ARP_TARGET" --interface "$LANTERN_ARP_INTERFACE" --arp --ports none --no-icmp --no-multicast --no-dns --json
