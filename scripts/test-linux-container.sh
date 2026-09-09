#!/bin/sh
set -eu
go version
if [ -n "${LANTERN_EXPECT_GOARCH:-}" ]; then
    test "$(go env GOOS)" = linux
    test "$(go env GOARCH)" = "$LANTERN_EXPECT_GOARCH"
    case "$LANTERN_EXPECT_GOARCH" in
        amd64) test "$(uname -m)" = x86_64 ;;
        arm64) test "$(uname -m)" = aarch64 ;;
        *) exit 2 ;;
    esac
    printf 'Verified container architecture: linux/%s (%s)\n' "$LANTERN_EXPECT_GOARCH" "$(uname -m)"
fi
go vet ./...
go test -race ./...
# The bridge gateway is a known peer in this container's own network namespace.
LANTERN_ARP_TARGET=$(ip -4 route show default | awk 'NR == 1 {print $3}')
LANTERN_ARP_INTERFACE=$(ip -4 route show default | awk 'NR == 1 {print $5}')
export LANTERN_ARP_TARGET LANTERN_ARP_INTERFACE LANTERN_NETWORK_TESTS=1 LANTERN_WSD_MULTICAST_TESTS=1
test -n "$LANTERN_ARP_TARGET"
go test -race ./pkg/scanner -run NetworkIntegration -v
python3 scripts/test-install.py
go build -trimpath -o /tmp/lantern ./cmd/lantern
python3 /usr/local/bin/test-event-stream.py /tmp/lantern
python3 /usr/local/bin/test-full-ports.py /tmp/lantern
python3 /usr/local/bin/test-doctor.py /tmp/lantern --expect-arp available
python3 /usr/local/bin/test-watch-pty.py /tmp/lantern
python3 /usr/local/bin/test-snapshot-cli.py /tmp/lantern
python3 /usr/local/bin/test-banner-fingerprints.py /tmp/lantern
python3 /usr/local/bin/test-ethernet-fixture.py /tmp/lantern
sh /usr/local/bin/test-netbios-samba.sh /tmp/lantern
/tmp/lantern version
/tmp/lantern demo --no-color
/tmp/lantern scan "$LANTERN_ARP_TARGET" --interface "$LANTERN_ARP_INTERFACE" --arp --ports none --no-icmp --no-multicast --no-dns --json
