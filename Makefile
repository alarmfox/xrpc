CC ?= gcc

CFLAGS = -Wall -Wextra -std=c99
CFLAGS += -Iinclude/

LDFLAGS = -static

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g
else
CFLAGS += -O2
endif

## all: build all executables
all: build/rpc_server_unix build/rpc_server_tcp

## build/rpc_server_tcp: builds tcp implementation
build/rpc_server_tcp: build/server_tcp.o build/transport_tcp.o build/protocol.o build/log.o
	$(CC) $(LDFLAGS) -o $@ $^

## build/rpc_server_unix: builds unix implementation
build/rpc_server_unix: build/server_unix.o build/transport_unix.o build/protocol.o build/log.o
	$(CC) $(LDFLAGS) -o $@ $^

## build/server_unix.o: builds server.c defining the TRANSPORT_UNIX symbol
build/server_unix.o: src/server.c | build
	$(CC) $(CFLAGS) -DTRANSPORT_UNIX -c -o $@ $<

## build/server_tcp.o: builds server.c defining the TRANSPORT_TCP symbol
build/server_tcp.o: src/server.c | build
	$(CC) $(CFLAGS) -DTRANSPORT_TCP -c -o $@ $<

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

## clean: remove builds artifacts
clean:
	rm -rf build/*.o build/rpc_server_unix build/rpc_server_tcp

.PHONY: help
## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
