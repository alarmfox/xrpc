# XRPC

> [!WARNING]
> `xrpc` is an early development project.

## Introduction
A small (but very fun) project to explore RPC in C.
The target of `xrpc` is to produce a `libxrpc` that users can use in their own projects allowing
to choose different transport implementations: from raw TCP sockets to RDMA.

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

If you have Valgrind installed and in your `$PATH` you can run the tests with:
```sh
make test-run-valgrind
```

You can build and run tests and library with sanitizers using `make SANITIZE=1 ...`.
If your platform does not support sanitizers (ie. you use musl), you can use the 
Dockerfile to build an image with glibc.

```sh
docker build -t xrpc-sanitizers .
docker run --rm -v $(pwd):/workspace -w /workspace xrpc-build sh -c "make SANITIZE=1 clean test-run && make clean test-run-valgrind"
```

## Development
To get a working LSP, you can use [Bear](https://github.com/rizsotto/Bear) to generate a `compile_commands.json`.

```sh
bear -- make
```
