.PHONY: build test check demo clean linux-test
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
