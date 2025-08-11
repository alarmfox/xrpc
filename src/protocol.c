#include "protocol.h"
#include <stdlib.h>

#define MAX_HANDLERS 256

struct rpc_server {
  void *handlers[MAX_HANDLERS];
};

void rpc_server_init(struct rpc_server **s) {
  *s = malloc(sizeof(struct rpc_server));
  for (int i = 0; i < MAX_HANDLERS; ++i) {
    (*s)->handlers[i] = NULL;
  }
}

int rpc_server_register_handler(struct rpc_server *s, const int opcode,
                                uint64_t (*op)(uint64_t, uint64_t),
                                const int flags) {

  if (opcode >= MAX_HANDLERS) {
    return RPC_EINVOPCODE;
  }

  void *fn = s->handlers[opcode];

  if (fn != NULL && !(flags & RF_OVERWRITE)) {
    return RPC_EINVAL;
  }

  s->handlers[opcode] = (void *)op;

  return RPC_SUCCESS;
}

void rpc_server_handle_req(const struct rpc_server *s,
                           const struct request *req, struct response *res) {

  if (req->opcode >= MAX_HANDLERS) {
    // TODO: return invalid opcode
    return;
  }

  uint64_t (*fn)(uint64_t, uint64_t) = s->handlers[req->opcode];

  if (fn == NULL) {
    // TODO: return unimplemented code
    return;
  }

  res->res = fn(req->op1, req->op2);
  res->opcode = req->opcode;
  res->req_id = req->req_id;
}

void rpc_server_free(struct rpc_server *s) {
  for (int i = 0; i < MAX_HANDLERS; ++i) {
    s->handlers[i] = NULL;
  }
  free(s);
  s = NULL;
}
