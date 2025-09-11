# Programs 
CC      = gcc
AR      = ar

# =========================
#  Compilation Flags
# =========================
ARFLAGS = rcs

CFLAGS  = -std=c11 -Wall -Wextra -Werror
CFLAGS += -Iinclude/ -Ibenchmark/

LDFLAGS = 

# Testing / Benchmark flags
TEST_CFLAGS  := -Itest/
BENCH_CFLAGS := -D_POSIX_C_SOURCE=199309L -DBENCHMARK

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g3 -DDEBUG
else
CFLAGS += -O2
endif

# Disable sanitizers by default since they are not supported everywhere.
# For example, on `musl` systems they are not available.
SANITIZE ?= 0

ifeq ($(SANITIZE),1)
CFLAGS += -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined
LDFLAGS += -fsanitize=address,undefined
endif

# =========================
#  Sources & Objects
# =========================
ALL_SRCS        := $(shell find src -name '*.c' -print)

ALL_OBJS        := $(patsubst %.c,%.o,$(ALL_SRCS))

CLI_OBJS        := $(filter src/client/%.o,$(ALL_OBJS))
LIB_OBJS        := $(filter-out $(CLI_OBJS), $(ALL_OBJS))
INSTR_OBJS      := $(patsubst %.o,%_bench.o,$(LIB_OBJS))

# Tests
TEST_SRCS := $(shell find test -name 'test_*.c' -print)
TEST_OBJS := $(patsubst %.c,%.o, $(TEST_SRCS))
TEST_BINS := $(patsubst %.c,%, $(TEST_SRCS))

# Benchmarks
BENCH_SRCS       := $(shell find benchmark -name '*.c' -print)
BENCH_HELPER_SRC := benchmark/benchmark.c
BENCH_PROG_SRCS  := $(filter-out $(BENCH_HELPER_SRC),$(BENCH_SRCS))
BENCH_OBJS       := $(patsubst %.c,%.o,$(BENCH_SRCS))
BENCH_BINS       := $(patsubst %.c,%,$(BENCH_PROG_SRCS))

# =========================
#  Targets
# =========================
.PHONY: all clean help examples test benchmark

all: libxrpc.a examples test

## libxrpc.a: builds the library
libxrpc.a: $(LIB_OBJS)
	$(AR) $(ARFLAGS) $@ $^

## examples: builds example applications
examples: $(LIB_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) examples/simple/server.c -o examples/simple/server $^
	$(CC) $(CFLAGS) $(LDFLAGS) examples/simple/client.c -o examples/simple/client $^

## client: builds client applications
client: $(CLI_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o xrpc_client $^

## benchmark: builds the benchmark application
benchmark: $(BENCH_BINS)

## test: builds all tests
test: $(TEST_BINS)

## test-run: runs all the tests
test-run: test
	@for t in $(TEST_BINS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done

## test-run-valgrind: runs all the tests with valgrind
test-run-valgrind: test
	@for t in $(TEST_BINS); do \
		echo "Running $$t with Valgrind..."; \
		valgrind --tool=memcheck \
		--leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--error-exitcode=1 \
		--quiet \
		./$$t || exit 1; \
	done

# =========================
#  Pattern Rules
# =========================
test/%.o: test/%.c
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -c -o $@ $<

test/%: test/%.o $(LIB_OBJS)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) $(LDFLAGS) -o $@ $^

$(BENCH_BINS): %: $(BENCH_OBJS) $(INSTR_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

benchmark/%.o: benchmark/%.c
	$(CC) $(CFLAGS) $(BENCH_CFLAGS) -c -o $@ $<

%_bench.o: %.c
	$(CC) $(CFLAGS) $(BENCH_CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

## clean: remove all build artifacts
clean:
	$(RM) $(LIB_OBJS) $(CLI_OBJS) $(INSTR_OBJS) $(TEST_BINS) $(TEST_OBJS) $(BENCH_OBJS) \
	$(BENCH_BINS) libxrpc.a examples/*/server examples/*/client xrpc_client

## help: prints this help message
help:
	@echo "Usage: make [target]\n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
