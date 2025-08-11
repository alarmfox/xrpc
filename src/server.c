#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "transport.h"

#define OP_SUM 0x0

#define DEBUG 1

uint64_t op_sum(uint64_t a, uint64_t b) { return a + b; }

#ifdef TRANSPORT_UNIX
#define UNIX_SOCKET_PATH "/tmp/rpc.sock"
struct transport_args {
  char unix_socket_path[108];
} args = {.unix_socket_path = UNIX_SOCKET_PATH};
const char *log_prefix = "rpc_server_unix";
#endif /* if TRANSPORT_UNIX */

#ifdef TRANSPORT_TCP
struct transport_args {
  uint32_t saddr;
  uint16_t sport;
} args = {.saddr = INADDR_ANY, .sport = 9000};
const char *log_prefix = "rpc_server_tcp";
#endif /* if TRANSPORT_UNIX */

int main() {
  int ret;
  struct transport *t = NULL;
  struct rpc_server *rs = NULL;
  struct request *req = malloc(sizeof(struct request));
  struct response *res = malloc(sizeof(struct response));

  if (DEBUG)
    log_set_minimum_level(LOG_LV_DEBUG);

  log_init(log_prefix);

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

    memset(req, 0, sizeof(struct request));
    memset(res, 0, sizeof(struct response));
  }

  rpc_server_free(rs);
  transport_free(t);
  free(req);
  free(res);
  log_free();

  return 0;
}
