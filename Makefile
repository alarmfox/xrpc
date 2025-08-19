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

# Testing flags and src
TEST_CFLAGS = $(CFLAGS) -Itest/

TEST_SRCS = $(wildcard test/test_*.c)
CORE_SRCS = $(wildcard src/core/*.c)
TRANSPORT_SRCS = $(wildcard src/transports/*.c)
IO_SYSTEM_SRCS = $(wildcard src/io/*.c)

ALL_SRCS = $(CORE_SRCS) $(TRANSPORT_SRCS) $(IO_SYSTEM_SRCS)
ALL_OBJS = $(ALL_SRCS:.c=.o)
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_BINS = $(TEST_SRCS:.c=)


## all: buils the library examples and test
all: libxrpc.a examples

## libxrpc.a: builds the library
libxrpc.a: $(ALL_OBJS)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

## examples: builds examples
examples: libxrpc.a
	$(CC) $(CFLAGS) examples/tcp/server.c -o examples/tcp/server -L. -lxrpc

## test: builds and runs test
test: $(TEST_BINS)
	@for test in $(TEST_BINS); do \
		./$${test} || exit 1; \
	done

	@echo "Tests completed successfully"

# builds the test
test/%.o: test/%.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

# Test binary compilation
test/%: test/%.o libxrpc.a
	$(CC) $(TEST_CFLAGS) $< -o $@ -L. -lxrpc

## clean: remove all artifacts
clean:
	rm -f $(ALL_OBJS) libxrpc.a examples/*/server $(TEST_BINS)

.PHONY: examples clean help test

## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
