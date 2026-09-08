#!/bin/sh
# Use a distinct image per architecture and pin every run to the requested one.
set -eu
platform=${LINUX_PLATFORM:-}
if [ -n "$platform" ]; then
    case "$platform" in
        linux/amd64|linux/arm64) ;;
        *) printf '%s\n' 'LINUX_PLATFORM must be linux/amd64 or linux/arm64' >&2; exit 2 ;;
    esac
fi
daemon=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')
platform=${platform:-$daemon}
case "$platform" in
    linux/amd64|linux/arm64) ;;
    *) printf 'Unsupported Linux test platform: %s\n' "$platform" >&2; exit 2 ;;
esac
arch=${platform#linux/}
image="lantern-linux-test:$arch"
printf 'Linux runtime target: %s; Docker daemon: %s\n' "$platform" "$daemon"
docker build --platform "$platform" -f scripts/Dockerfile.linux-test -t "$image" .
docker run --rm --platform "$platform" -e "LANTERN_EXPECT_GOARCH=$arch" --cap-drop ALL --cap-add NET_RAW "$image"
docker run --rm --platform "$platform" -e "LANTERN_EXPECT_GOARCH=$arch" --cap-drop ALL "$image" sh -c 'go build -o /tmp/lantern ./cmd/lantern && python3 /usr/local/bin/test-doctor.py /tmp/lantern --expect-arp unavailable && python3 /usr/local/bin/test-wsdd.py /tmp/lantern'
docker run --rm --platform "$platform" -e "LANTERN_EXPECT_GOARCH=$arch" --cap-drop ALL --cap-add NET_ADMIN "$image" sh -c 'go build -o /tmp/lantern ./cmd/lantern && python3 /usr/local/bin/test-neighbor-interfaces.py /tmp/lantern && python3 /usr/local/bin/test-ndp-linux.py /tmp/lantern --without-raw && python3 /usr/local/bin/test-wsdd.py /tmp/lantern --ipv6 --unavailable-source'
docker run --rm --platform "$platform" -e "LANTERN_EXPECT_GOARCH=$arch" --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW "$image" sh -c 'go build -o /tmp/lantern ./cmd/lantern && python3 /usr/local/bin/test-ndp-linux.py /tmp/lantern'
