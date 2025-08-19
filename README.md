# XRPC

> [!WARNING]
> `xrpc` is an early development project.

## Introduction
A small (but very fun) project to explore RPC in C.
The goal is to explore and compare different implementations: from raw TCP sockets to RDMA.

## Usage (server only)

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

### Example
The following example is based from [server.c](./examples/tcp/server.c).
```c
// include library
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

#define OP_DUMMY 0

// declare an handler (response data will be freed after being sent by the caller)
static int dummy_handler(const struct xrpc_request *req,
                         struct xrpc_response *res) {

  res->hdr->status = XRPC_RESPONSE_SUCCESS;
  res->hdr->sz = sizeof(uint64_t);

  res->data = malloc(sizeof(uint64_t));
  memcpy(res->data, req->data, sizeof(uint64_t));

  return XRPC_SUCCESS;
}

int main(void) {
  // declare a server with TCP transport and blocking I/O system.
  struct xrpc_server *srv = NULL;
  struct xrpc_transport_config tcfg =
      XRPC_TCP_SERVER_DEFAULT_CONFIG(INADDR_LOOPBACK, 9000);
  struct xrpc_io_system_config iocfg = {.type = XRPC_IO_SYSTEM_BLOCKING};
  struct xrpc_server_config cfg = {.tcfg = &tcfg, .iocfg = &iocfg};

  // set non blocking to false
  tcfg.config.tcp.nonblocking = false;
  // wait for 100ms
  tcfg.config.tcp.accept_timeout_ms = 100;

  // create the server
  if (xrpc_server_create(&srv, &cfg) != XRPC_SUCCESS) {
    printf("cannot create xrpc_server\n");
    goto exit;
  }

  // register the handler 
  if (xrpc_server_register(srv, OP_DUMMY, dummy_handler, XRPC_RF_OVERWRITE) !=
      XRPC_SUCCESS) {
    printf("cannot register dummy handler\n");
    goto exit;
  }

  // run the server
  xrpc_server_run(srv);

// free resources
exit:
  xrpc_server_free(srv);
  free(srv);
  srv = NULL;

  return 0;
}

```


## Testing
Execute all the available tests in `test/` using:

```sh
make test
```

## Development
To get a working LSP, you can use [Bear](https://github.com/rizsotto/Bear) to generate a `compile_commands.json`.

```sh
bear -- make
```
