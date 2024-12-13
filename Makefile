.PHONY: clean build

default: build

clean:
	@rm -f dmwg

build: clean
	@go mod tidy
	@docker build --target export --output . .
