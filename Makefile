# Programs 
CC      = gcc
AR      = ar

# =========================
#  Compilation Flags
# =========================
ARFLAGS = rcs

CFLAGS  = -std=c11 -Wall -Wextra -Werror
CFLAGS += -Iinclude/ -Ibenchmark/

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g3 -DDEBUG
else
CFLAGS += -O2
endif

# Testing / Benchmark flags
TEST_CFLAGS  := -Itest/
BENCH_CFLAGS := -D_POSIX_C_SOURCE=199309L -DBENCHMARK

# =========================
#  Sources & Objects
# =========================
ALL_SRCS        := $(shell find src -name '*.c' -print)

ALL_OBJS        := $(patsubst %.c,%.o,$(ALL_SRCS))

CLI_OBJS        := $(filter src/client/%.o,$(ALL_OBJS))
LIB_OBJS        := $(filter-out $(CLI_OBJS), $(ALL_OBJS))
LIB_INSTR_OBJS  := $(patsubst %.o,%_bench.o,$(LIB_OBJS))

# Tests
TEST_SRCS := $(wildcard test/test_*.c)
TEST_OBJS := $(TEST_SRCS:.c=.o)
TEST_BINS := $(TEST_SRCS:.c=)

# Benchmarks
BENCH_SRCS       := $(shell find benchmark -name '*.c' -print)
BENCH_HELPER_SRC := benchmark/benchmark.c
BENCH_PROG_SRCS  := $(filter-out $(BENCH_HELPER_SRC),$(BENCH_SRCS))
BENCH_HELPER_OBJ := $(patsubst %.c,%.o, $(BENCH_HELPER_SRC))
BENCH_PROG_OBJS  := $(patsubst %.c,%.o,$(BENCH_PROG_SRCS))
BENCH_BINS       := $(patsubst %.c,%,$(BENCH_PROG_SRCS))

# =========================
#  Targets
# =========================
.PHONY: all clean help examples test benchmark

all: libxrpc.a examples test-build benchmark client

## libxrpc.a: builds the library
libxrpc.a: $(LIB_OBJS)
	$(AR) $(ARFLAGS) $@ $^

## examples: builds example applications
examples: $(LIB_OBJS)
	$(CC) $(CFLAGS) examples/simple/server.c -o examples/simple/server $^
	$(CC) $(CFLAGS) examples/simple/client.c -o examples/simple/client $^

## client: builds client applications
client: $(CLI_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o xrpc_client $^

## benchmark: builds the benchmark application
benchmark: $(BENCH_BINS)

test-build: $(TEST_BINS)

## test: builds and runs all the tests
test: test-build
	@for t in $(TEST_BINS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done

# =========================
#  Pattern Rules
# =========================
test/%.o: test/%.c
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -c -o $@ $<

test/%: test/%.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -o $@ $^

$(BENCH_BINS): %: %.o $(BENCH_HELPER_OBJ) $(LIB_INSTR_OBJS)
	$(CC) $(BENCH_CFLAGS) -o $@ $^

benchmark/%.o: benchmark/%.c
	$(CC) $(CFLAGS) $(BENCH_CFLAGS) -c -o $@ $<

%_bench.o: %.c
	$(CC) $(CFLAGS) $(BENCH_CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

## clean: remove all build artifacts
clean:
	$(RM) $(LIB_OBJS) $(CLI_OBJS) $(LIB_INSTR_OBJS) $(TEST_BINS) $(TEST_OBJS) $(BENCH_OBJS) $(BENCH_BINS) libxrpc.a examples/*/server examples/*/client xrpc_client

## help: prints this help message
help:
	@echo "Usage: make [target]\n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
