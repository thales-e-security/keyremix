all: check keyremix

check:
	go test ./...

keyremix: $(wildcard *.go) $(wildcard cmd/keyremix/*.go)
	go build -o $@ ./cmd/keyremix

clean:
	rm -f keyremix
