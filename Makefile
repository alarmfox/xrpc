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
all: build/rpc_server_unix

build/rpc_server_unix: build/rpc_server_unix.o build/protocol.o build/log.o
	$(CC) $(LDFLAGS) -o $@ $^

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

## clean: remove artifacts
clean:
	rm -rf build/*.o build/rpc_server_unix

.PHONY: help
## help: prints this help message
help:
	@echo "Usage: \n"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
