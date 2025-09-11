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

If you have Valgrind installed and in your `$PATH` you can run the tests with:
```sh
make test-run-valgrind
```

If your platform support sanitizers, you can build tests and run them with `SANITIZE=1`

## Development
To get a working LSP, you can use [Bear](https://github.com/rizsotto/Bear) to generate a `compile_commands.json`.

```sh
bear -- make
```
