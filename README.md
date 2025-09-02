# XRPC

> [!WARNING]
> `xrpc` is an early development project.

## Introduction
A small (but very fun) project to explore RPC in C.
The target of `xrpc` is to produce a `libxrpc` that users can use in their own projects.
The goal is to explore and compare different implementations: from raw TCP sockets to RDMA.

Protocol description can be found at [PROTOCOL.md](./PROTOCOL.md).

## Usage

The goal of the library is to provide a minimal API to integrate RPC functionalities into an existing project.
Build the library:

```sh
make
```

The build process outputs `libxrpc.a` in the root directory of the project. 
Link it in your projects and copy `include/` for API declaration.

```sh
cp -r include/ /path/to/project/include/
cp libxrpc.a /path/to/project/lib
```

For examples, refer to the [examples](./examples/) folder.


## Testing
Execute all the available tests in `test/` using:

```sh
make test-run
```

## Benchmarking

For now, microbenchmark traces connection and requests allocations.

Build benchmark server in `benchmark/tcp_echo_server.c` and run the server:

```sh
make benchmark

./benchmark/tcp_echo_server -h
Usage: ./benchmark/tcp_echo_server [options]
Options:
  -p <port>     Server port (default: 9000)
  -a <address>  Server address (default: 127.0.0.1)
  -r <seconds>  Print benchmark report every N seconds
  -h            Show this help
```

In another terminal (or a proper client machine), start the client using the `scripts/benchmark_client.py`
configuring the desidered parameters:

```sh
python scripts/benchmark_client.py -h
usage: benchmark_client.py [-h] [--host HOST] [--port PORT] [--duration DURATION]
                           [--connections CONNECTIONS] [--rate RATE] [--warmup WARMUP]
                           [--operation {ping,echo,sum,dot_product}] [--payload-size PAYLOAD_SIZE]
                           [--output OUTPUT] [--verbose]

XRPC Benchmark Client

options:
  -h, --help            show this help message and exit
  --host HOST           Server hostname
  --port PORT           Server port
  --duration DURATION   Benchmark duration in seconds
  --connections CONNECTIONS
                        Number of concurrent connections
  --rate RATE           Request rate limit per connection (req/s)
  --warmup WARMUP       Warmup duration in seconds
  --operation {ping,echo,sum,dot_product}
                        Operation to benchmark
  --payload-size PAYLOAD_SIZE
                        Payload size in bytes
  --output OUTPUT       Output file for JSON results
  --verbose             Verbose output
```

## Development
To get a working LSP, you can use [Bear](https://github.com/rizsotto/Bear) to generate a `compile_commands.json`.

```sh
bear -- make
```
