.PHONY: build test check demo clean linux-test terminal-test
build:
	go build -trimpath -ldflags='-s -w' -o bin/lantern ./cmd/lantern
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

terminal-test: build
	python3 scripts/test-watch-pty.py
