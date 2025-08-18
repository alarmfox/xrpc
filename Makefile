CC = gcc
AR = ar

ARFLAGS = rcs

CFLAGS = -std=c99 -Wall -Wextra -fPIC
CFLAGS += -Iinclude/ 

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g3 -DDEBUG
else
CFLAGS += -O2
endif

CORE_SRCS = $(wildcard src/core/*.c)
TRANSPORT_SRCS = $(wildcard src/transports/*.c)
IO_SYSTEM_SRCS = $(wildcard src/io/*.c)

ALL_SRCS = $(CORE_SRCS) $(TRANSPORT_SRCS) $(IO_SYSTEM_SRCS)
ALL_OBJS = $(ALL_SRCS:.c=.o)

## libxrpc.a: builds the library
libxrpc.a: $(ALL_OBJS)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

## examples: builds examples
examples: libxrpc.a
	$(CC) $(CFLAGS) examples/tcp/server.c -o examples/tcp/server -L. -lxrpc

clean:
	rm -f $(ALL_OBJS) libxrpc.a examples/*/server examples/*/client

.PHONY: examples clean help

## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
