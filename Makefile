.PHONY: build install test check demo clean linux-test terminal-test install-test release
PREFIX ?= $(HOME)/.local
DESTDIR ?=
VERSION ?= dev
export PREFIX DESTDIR VERSION
build:
	go build -trimpath -ldflags='-s -w' -o bin/lantern ./cmd/lantern
install: build
	install -d "$$DESTDIR$$PREFIX/bin"
	install -m 755 bin/lantern "$$DESTDIR$$PREFIX/bin/lantern"
test:
	go test -race ./...
check:
	go vet ./...
	go test -race ./...
demo: build
	./bin/lantern demo
clean:
	rm -f bin/lantern

linux-test:
	docker build -f scripts/Dockerfile.linux-test -t lantern-linux-test:local .
	docker run --rm --cap-drop ALL --cap-add NET_RAW lantern-linux-test:local
	docker run --rm --cap-drop ALL lantern-linux-test:local sh -c 'go build -o /tmp/lantern ./cmd/lantern && python3 /usr/local/bin/test-doctor.py /tmp/lantern --expect-arp unavailable'
	docker run --rm --cap-drop ALL --cap-add NET_ADMIN lantern-linux-test:local sh -c 'go build -o /tmp/lantern ./cmd/lantern && python3 /usr/local/bin/test-neighbor-interfaces.py /tmp/lantern'

terminal-test: build
	python3 scripts/test-watch-pty.py

install-test:
	python3 scripts/test-install.py

release:
	sh scripts/release.sh "$$VERSION"
