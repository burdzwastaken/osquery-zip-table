.PHONY: all build osqueryd osqueryi vendor tidy clean test
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
WORKDIR=$(shell pwd)
TESTARGS?=./...

all: test build

build:
	echo "$(shell pwd)/build/osquery-zip-table-extension.ext" > /tmp/extensions.load
	$(GOBUILD) -o build/osquery-zip-table-extension.ext .

test:
	$(GOTEST) $(TESTARGS)

osqueryd: build
	osqueryd \
		--extensions_autoload=/tmp/extensions.load \
		--pidfile=/tmp/osquery.pid \
		--database_path=/tmp/osquery.db \
		--extensions_socket=/tmp/osquery.sock \

osqueryi: build
	osqueryi --extension=./build/osquery-zip-table-extension.ext

vendor:
	$(GOMOD) vendor

tidy:
	$(GOMOD) tidy

clean:
	rm -rf /tmp/extensions.load
	rm -rf /tmp/osquery.*
	rm -rf build
