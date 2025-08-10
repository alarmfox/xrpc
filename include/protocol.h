#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#include <arpa/inet.h>
#include <stdint.h>

#define MAX_HANDLERS 255

#define RPC_SUCCESS 0
#define RPC_EINVAL -1
#define RPC_EINVHANDLER -2
#define RPC_EINVOPCODE -3

struct __attribute__((packed)) msg_req {
  uint16_t opcode;
  uint64_t req_id;
  uint64_t op_a;
  uint64_t op_b;
};

struct __attribute__((packed)) msg_res {
  uint16_t opcode;
  uint64_t req_id;
  uint64_t res;
};

// Register handler flags
enum REGISTER_FLAGS {
  RF_OVERWRITE = 1 << 0,
};

struct server {
  void *handlers[MAX_HANDLERS];
};

void server_init(struct server **s);
int server_register_handler(struct server *s, int opcode,
                            uint64_t (*op)(uint64_t, uint64_t), int flags);

void server_handle_req(const struct server *s, const struct msg_req *req,
                       struct msg_res *res);
void server_destroy(struct server *s);

/*  Utility functions to marshal and unmarshal uint64_t */
static inline uint64_t htonll(uint64_t x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap64(x);
#else
  return x;
#endif
}

static inline uint64_t ntohll(uint64_t x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return __builtin_bswap64(x);
#else
  return x;
#endif
}

static inline void marshal_res(struct msg_res *res) {
  res->opcode = htons(res->opcode);
  res->res = htonll(res->res);
  res->req_id = htonll(res->req_id);
}

static inline void unmarshal_req(struct msg_req *req) {
  req->op_a = ntohll(req->op_a);
  req->op_b = ntohll(req->op_b);
  req->opcode = ntohs(req->opcode);
  req->req_id = ntohll(req->req_id);
}
#endif // !__PROTOCOL_H
