CC = gcc
AR = ar

CFLAGS = -std=c99 -Wall -Wextra -fPIC
CFLAGS += -Iinclude/ $(MBEDTLS_INC)

LDFLAGS = -static

ARFLAGS = rcs

# TLS-only flags
# TODO: configure this dinamically
MBEDTLS_INC = -Iexternal/mbedtls/include
MBEDTLS_LIBS = lib/libmbedtls.a lib/libmbedx509.a lib/libmbedcrypto.a

BUILD_DIR = build

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g3 -DDEBUG
else
CFLAGS += -O2
endif

CORE_SRCS = $(wildcard src/core/*.c)
TRANSPORT_SRCS = $(wildcard src/transports/*.c)

ALL_SRCS = $(CORE_SRCS) $(TRANSPORT_SRCS)
ALL_OBJS = $(ALL_SRCS:.c=.o)

## libxrpc.a: builds the library
libxrpc.a: $(ALL_OBJS)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

## examples: builds examples
examples: libxrpc.a
	$(CC) $(CFLAGS) $(LDFLAGS) examples/tcp/server.c -o examples/tcp/server -L. -lxrpc
	$(CC) $(CFLAGS) $(LDFLAGS) examples/tcp/client.c -o examples/tcp/client -L. -lxrpc

clean:
	rm -f $(ALL_OBJS) libxrpc.a examples/*/server examples/*/client

.PHONY: examples clean help

## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
