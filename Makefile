CC ?= gcc

# TLS-only flags
MBEDTLS_INC = -Iexternal/mbedtls/include
MBEDTLS_LIBS = lib/libmbedtls.a lib/libmbedx509.a lib/libmbedcrypto.a

# Classig CFLAGS
CFLAGS = -Wall -Wextra -std=c99
CFLAGS += -Iinclude/

LDFLAGS = -static

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g -DDEBUG $(MBEDTLS_INC)
else
CFLAGS += -O2
endif

## all: build all executables
all: build/rpc_server_unix build/rpc_server_tcp build/rpc_server_tcp_tls

## build/rpc_server_unix: builds unix implementation
build/rpc_server_unix: build/server_unix.o build/transport_unix.o build/protocol.o
	$(CC) $(LDFLAGS) -o $@ $^

## build/rpc_server_tcp: builds tcp implementation
build/rpc_server_tcp: build/server_tcp.o build/transport_tcp.o build/protocol.o
	$(CC) $(LDFLAGS) -o $@ $^

## build/rpc_server_tcp: builds TLS over TCP implementation with mbedtls library
build/rpc_server_tcp_tls: build/server_tcp_tls.o build/transport_tcp_tls.o build/protocol.o 
	$(CC) $(LDFLAGS) -o $@ $^ $(MBEDTLS_LIBS)

## build/server_unix.o: builds server.c defining the TRANSPORT_UNIX symbol
build/server_unix.o: src/server.c | build
	$(CC) $(CFLAGS) -DTRANSPORT_UNIX -c -o $@ $<

## build/server_tcp.o: builds server.c defining the TRANSPORT_TCP symbol
build/server_tcp.o: src/server.c | build
	$(CC) $(CFLAGS) -DTRANSPORT_TCP -c -o $@ $<

## build/server_tcp_tls.o: builds server.c defining the TRANSPORT_TCP_TLS symbol
build/server_tcp_tls.o: src/server.c | build
	$(CC) $(CFLAGS) -DTRANSPORT_TCP_TLS -c -o $@ $<

## build/transport_tcp_tls.o: build transport_tcp_tls with mbedtls include
build/transport_tcp_tls.o: src/transport_tcp_tls.c | build
	$(CC) $(MBEDTLS_INC) $(CFLAGS) -c -o $@ $<

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

## clean: remove builds artifacts
clean:
	rm -rf build/*.o build/rpc_server_unix build/rpc_server_tcp build/rpc_server_tcp_tls

.PHONY: help
## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
