# Programs 
CC      = gcc
ARFLAGS = rcs

CFLAGS  = -std=c11 -Wall -Wextra -Werror
CFLAGS += -Iinclude/ -Ibenchmark/

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g3 -DDEBUG
else
CFLAGS += -O2
endif

# Testing / Benchmark flags
TEST_CFLAGS  := -Itest
BENCH_CFLAGS := -D_POSIX_C_SOURCE=199309L -DBENCHMARK

# =========================
#  Sources & Objects
# =========================
ALL_SRCS        := $(wildcard src/**/*.c)

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

## examples: builds example applications
examples: $(ALL_OBJS)
	$(CC) $(CFLAGS) examples/tcp/server.c -o examples/tcp/server $^

## benchmark: builds the benchmark application
benchmark: $(BENCH_BINS) $(BENCH_HELPER_OBJ) $(ALL_INSTR_OBJS)

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
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -c -o $@ $<

test/%: test/%.o $(ALL_OBJS)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -o $@ $^

$(BENCH_BINS): %: %.o $(BENCH_HELPER_OBJ) $(ALL_INSTR_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

benchmark/%.o: benchmark/%.c
	$(CC) $(CFLAGS) $(BENCH_CFLAGS) -c -o $@ $<

benchmark/benchmark.o: benchmark/benchmark.c
	$(CC) $(CFLAGS) $(BENCH_CFLAGS) -c -o $@ $<

%_bench.o: %.c
	$(CC) $(CFLAGS) $(BENCH_CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

## clean: remove all build artifacts
clean:
	$(RM) $(ALL_OBJS) $(ALL_INSTR_OBJS) $(TEST_BINS) $(TEST_OBJS) $(BENCH_OBJS) $(BENCH_BINS) $(BENCH_HELPER_OBJ) libxrpc.a examples/*/server

## help: prints this help message
help:
	@echo "Usage: make [target]\n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
