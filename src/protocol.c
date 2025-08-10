#include "protocol.h"
#include <stdlib.h>

void server_init(struct server **s) {
  *s = malloc(sizeof(struct server));
  for (int i = 0; i < MAX_HANDLERS; ++i) {
    (*s)->handlers[i] = NULL;
  }
}

int server_register_handler(struct server *s, const int opcode,
                            uint64_t (*op)(uint64_t, uint64_t), int flags) {

  if (opcode >= MAX_HANDLERS) {
    return RPC_EINVOPCODE;
  }

  uint64_t (*fn)(uint64_t, uint64_t) = s->handlers[opcode];

  if (fn != NULL && !(flags & RF_OVERWRITE)) {
    return RPC_EINVAL;
  }

  s->handlers[opcode] = (void *)op;

  return RPC_SUCCESS;
}

void server_handle_req(const struct server *s, const struct msg_req *req,
                       struct msg_res *res) {

  if (req->opcode > MAX_HANDLERS) {
    // TODO: return invalid opcode
    return;
  }

  uint64_t (*fn)(uint64_t, uint64_t) = s->handlers[req->opcode];

  if (fn == NULL) {
    // TODO: return unimplemented code
    return;
  }

  res->res = fn(req->op_a, req->op_b);
  res->opcode = req->opcode;
  res->req_id = req->req_id;
}

void server_destroy(struct server *s) {
  for (int i = 0; i < MAX_HANDLERS; ++i) {
    s->handlers[i] = NULL;
  }
  free(s);
  s = NULL;
}
