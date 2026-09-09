.PHONY: build install test check demo clean linux-test terminal-test install-test release
PREFIX ?= $(HOME)/.local
DESTDIR ?=
VERSION ?= dev
LINUX_PLATFORM ?=
export PREFIX DESTDIR VERSION LINUX_PLATFORM
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
	sh scripts/test-linux.sh

terminal-test: build
	python3 scripts/test-watch-pty.py

install-test:
	python3 scripts/test-install.py

release:
	sh scripts/release.sh "$$VERSION"
