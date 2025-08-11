#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "transport.h"

#define UNIX_SOCKET_PATH "/tmp/rpc.sock"

#define OP_SUM 0x0

#define DEBUG 1

uint64_t op_sum(uint64_t a, uint64_t b) { return a + b; }

struct unix_transport_args {
  char unix_socket_path[108];
};

int main() {
  int ret;
  struct transport *t = NULL;
  struct unix_transport_args args = {.unix_socket_path = UNIX_SOCKET_PATH};
  struct rpc_server *rs = NULL;
  struct request *req = malloc(sizeof(struct request));
  struct response *res = malloc(sizeof(struct response));

  log_init("rpc_server_unix");
  if (DEBUG)
    log_set_minimum_level(LOG_LV_DEBUG);

  rpc_server_init(&rs);
  ret = rpc_server_register_handler(rs, OP_SUM, op_sum, RF_OVERWRITE);

  if (ret < 0)
    bail("cannot register handler");

  transport_init(&t, (void *)&args);

  log_message(LOG_LV_INFO, "waiting for connections");
  while (transport_recv(t, req) == 0) {
    rpc_server_handle_req(rs, req, res);
    dbg_request((*req), (*res));
    transport_send(t, res);
  }

  rpc_server_free(rs);
  transport_free(t);
  free(req);
  free(res);
  log_free();

  return 0;
}
