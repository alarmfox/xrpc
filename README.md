# XRPC

> [!WARNING]
> `xrpc` is an early development project.

## Introduction
A small (yet fun) project to get familiar with RPC in C. The goal is to explore and compare different 
implementations: from UNIX sockets to RDMA.

## Development
To get a working LSP, you can use [Bear](https://github.com/rizsotto/Bear) to generate a `compile_commands.json`.
The `.clangd` file will assume the `compile_commands.json` is in the `build/` directory.

```sh
bear -- make
mv compile_commands.json build/
```
