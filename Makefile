CC = gcc
AR = ar

ARFLAGS = rcs

CFLAGS = -std=c99 -Wall -Wextra
CFLAGS += -Iinclude/ -Ibenchmark/ -D_POSIX_C_SOURCE=199309L

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g3 -DDEBUG
else
CFLAGS += -O2
endif

# Testing / Benchmark flags
TEST_CFLAGS  := $(CFLAGS) -Itest/

# =========================
#  Sources & Objects
# =========================
CORE_SRCS       := $(wildcard src/core/*.c)
TRANSPORT_SRCS  := $(wildcard src/transports/*.c)
IO_SYSTEM_SRCS  := $(wildcard src/io/*.c)
ALL_SRCS        := $(CORE_SRCS) $(TRANSPORT_SRCS) $(IO_SYSTEM_SRCS)

ALL_OBJS        := $(ALL_SRCS:.c=.o)
ALL_INSTR_OBJS  := $(ALL_SRCS:.c=_bench.o)

# Tests
TEST_SRCS := $(wildcard test/test_*.c)
TEST_OBJS := $(TEST_SRCS:.c=.o)
TEST_BINS := $(TEST_SRCS:.c=)

# Benchmarks
BENCH_HELPER_SRC := benchmark/benchmark.c
BENCH_HELPER_OBJ := $(BENCH_HELPER_SRC:.c=.o)
BENCH_PROG_SRCS  := $(filter-out $(BENCH_HELPER_SRC), $(wildcard benchmark/*.c))
BENCH_OBJS       := $(BENCH_PROG_SRCS:.c=.o)
BENCH_BINS       := $(BENCH_PROG_SRCS:.c=)

# =========================
#  Targets
# =========================
.PHONY: all clean help examples test benchmark

all: libxrpc.a examples

## libxrpc.a: builds the library
libxrpc.a: $(ALL_OBJS)
	$(AR) $(ARFLAGS) $@ $^

## libxrpc_bench.a: builds the instrumented benchmark library
libxrpc_bench.a: CFLAGS += -DBENCHMARK
libxrpc_bench.a: $(ALL_INSTR_OBJS) $(BENCH_HELPER_OBJ)
	$(AR) $(ARFLAGS) $@ $^

## examples: builds example applications
examples: libxrpc.a
	$(CC) $(CFLAGS) examples/tcp/server.c -o examples/tcp/server -L. -lxrpc

## benchmark: builds the benchmark application
benchmark: $(BENCH_BINS) $(BENCH_HELPER_OBJ) libxrpc_bench.a

## test: builds and runs all tests
test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done
	@echo "All tests passed ✅"

# =========================
#  Pattern Rules
# =========================
test/%.o: test/%.c
	$(CC) $(TEST_CFLAGS) -c -o $@ $<

test/%: test/%.o libxrpc.a
	$(CC) $(TEST_CFLAGS) $< -o $@ -L. -lxrpc

benchmark/benchmark.o: benchmark/benchmark.c
	$(CC) $(CFLAGS) -c -o $@ $<

benchmark/%.o: benchmark/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

benchmark/%: benchmark/%.o libxrpc_bench.a
	$(CC) $(CFLAGS) $< -o $@ -L. -lxrpc_bench -lpthread

%_bench.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

## clean: remove all build artifacts
clean:
	$(RM) $(ALL_OBJS) $(ALL_INSTR_OBJS) \
	      $(TEST_OBJS) $(TEST_BINS) \
	      $(BENCH_OBJS) $(BENCH_BINS) $(BENCH_HELPER_OBJ) \
	      libxrpc.a libxrpc_bench.a \
	      examples/*/server

## help: prints this help message
help:
	@echo "Usage: make [target]\n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
