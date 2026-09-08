.PHONY: build test check demo clean
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
