NAME = vault-auth-slack
GOOSES = darwin linux windows
GOARCHES = amd64

export GO111MODULE = on
export GOFLAGS = -mod=vendor
export CGO_ENABLED = 0

deps:
	@go get -mod="" -u -t ./...
	@go mod tidy
	@go mod vendor
.PHONY: deps

dev:
	@go install -i .
.PHONY: dev

build:
	@rm -rf build/
	@for GOOS in ${GOOSES}; do \
		for GOARCH in ${GOARCHES}; do \
			echo "Building $${GOOS}/$${GOARCH}" ; \
			GOOS=$${GOOS} GOARCH=$${GOARCH} go build \
				-a \
				-ldflags "-s -w -extldflags 'static'" \
				-installsuffix cgo \
				-tags netgo \
				-o build/$${GOOS}_$${GOARCH}/${NAME} \
				. ; \
		done ; \
	done
.PHONY: build

compress:
	@for dir in $$(find build/* -type d); do \
		f=$$(basename $$dir) ; \
		tar -C build -czf build/$$f.tgz $$f ; \
	done
.PHONY: compress

test:
	@go test -parallel=40 ./...
.PHONY: test
