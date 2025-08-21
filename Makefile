CC = gcc
AR = ar

ARFLAGS = rcs

CFLAGS = -std=c99 -Wall -Wextra
CFLAGS += -Iinclude/ 

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g3 -DDEBUG
else
CFLAGS += -O2
endif

# Testing flags and src
TEST_EXTRA_CFLAGS = -Itest/
BENCH_EXTRA_CFLAGS = -D_POSIX_C_SOURCE=199309L -Ibenchmark/

# Library code and objects
CORE_SRCS = $(wildcard src/core/*.c)
TRANSPORT_SRCS = $(wildcard src/transports/*.c)
IO_SYSTEM_SRCS = $(wildcard src/io/*.c)

# Test code and objects
TEST_SRCS = $(wildcard test/test_*.c)
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_BINS = $(TEST_SRCS:.c=)

# Benchmark code and objects
BENCH_HELPER_SRC = benchmark/benchmark.c
BENCH_PROG_SRCS = $(filter-out $(BENCH_HELPER_SRC), $(wildcard benchmark/*.c))
BENCH_HELPER_OBJ = $(BENCH_HELPER_SRC:.c=.o)
BENCH_OBJS = $(BENCH_PROG_SRCS:.c=.o)
BENCH_BINS = $(BENCH_PROG_SRCS:.c=)

ALL_SRCS = $(CORE_SRCS) $(TRANSPORT_SRCS) $(IO_SYSTEM_SRCS)

# Non instrumented objects
ALL_OBJS = $(ALL_SRCS:.c=.o)
# Instrumented objects
ALL_INSTR_OBJS = $(ALL_SRCS:.c=_bench.o)

## libxrpc.a: builds the library
libxrpc.a: $(ALL_OBJS)
	$(AR) $(ARFLAGS) $@ $^

## libxrpc.a: builds the library
libxrpc_bench.a: CFLAGS+=-DBENCHMARK
libxrpc_bench.a: $(ALL_INSTR_OBJS) $(BENCH_HELPER_OBJ)
	$(AR) $(ARFLAGS) $@ $^

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
	$(CC) $(CFLAGS) $(TEST_EXTRA_CFLAGS) -c -o $@ $<

# test binary compilation
test/%: test/%.o libxrpc.a
	$(CC) $(CFLAGS) $(TEST_EXTRA_CFLAGS) $< -o $@ -L. -lxrpc

## benchmark: builds the benchmark application
benchmark: $(BENCH_BINS) $(BENCH_HELPER_OBJ)

benchmark/benchmark.o: benchmark/benchmark.c
	$(CC) $(CFLAGS) $(BENCH_EXTRA_CFLAGS) -c -o $@ $<

# builds the benchmark 
benchmark/%.o: benchmark/%.c
	$(CC) $(CFLAGS) $(BENCH_EXTRA_CFLAGS) -c -o $@ $<

# builds all the benchmark executables
benchmark/%: benchmark/%.o libxrpc_bench.a
	$(CC) $(CFLAGS) $(BENCH_EXTRA_CFLAGS) $< -o $@ -L. -lxrpc_bench -lpthread

# fallback to compile every C file
%_bench.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

# fallback to compile every C file
%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

## clean: remove all artifacts
clean:
	rm -f $(ALL_OBJS) $(TEST_BINS) $(ALL_INSTR_OBJS) libxrpc.a libxrpc_bench.a \
		examples/*/server $(BENCH_HELPER_OBJ) $(BENCH_BINS)

.PHONY: examples clean help test benchmark

## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
