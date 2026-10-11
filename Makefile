.PHONY: build demo test fuzz vuln lint clean

build:
	go build -trimpath -o bin/free-as-a-bird ./cmd/free-as-a-bird

demo:
	go run ./cmd/free-as-a-bird demo

test:
	go test -race -count=1 ./...

fuzz:
	go test -run='^$$' -fuzz=FuzzParse$$ -fuzztime=30s ./internal/manifest/
	go test -run='^$$' -fuzz=FuzzParsePost -fuzztime=30s ./internal/board/
	go test -run='^$$' -fuzz=FuzzRenderBody -fuzztime=30s ./internal/web/
	go test -run='^$$' -fuzz=FuzzParseCell -fuzztime=30s ./internal/route/
	go test -run='^$$' -fuzz=FuzzParse$$ -fuzztime=30s ./internal/land/

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

lint:
	gofmt -l .
	go vet ./...

clean:
	rm -rf bin free-as-a-bird-demo
