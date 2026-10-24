VERSION ?= 0.1.0-dev
LDFLAGS := -s -w -X trove.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build test vet fmt cross docker clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/trove ./cmd/trove

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

cross:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "building $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/trove-$$os-$$arch$$ext ./cmd/trove || exit 1; \
	done

docker:
	docker build --build-arg VERSION=$(VERSION) -t trove:$(VERSION) .

clean:
	rm -rf dist
