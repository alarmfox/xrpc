#ifndef __PROTOCOL_H
#define __PROTOCOL_H

#include <arpa/inet.h>
#include <stdint.h>

#define RPC_SUCCESS 0
#define RPC_EINVAL -1
#define RPC_EINVHANDLER -2
#define RPC_EINVOPCODE -3

struct __attribute__((packed)) request {
  uint16_t opcode;
  uint64_t req_id;
  uint64_t op1;
  uint64_t op2;
};

struct __attribute__((packed)) response {
  uint16_t opcode;
  uint64_t req_id;
  uint64_t res;
};

// Register handler flags
enum REGISTER_FLAGS {
  RF_OVERWRITE = 1 << 0,
};

struct rpc_server;

void rpc_server_init(struct rpc_server **s);
int rpc_server_register_handler(struct rpc_server *s, const int opcode,
                                uint64_t (*op)(uint64_t, uint64_t),
                                const int flags);

void rpc_server_handle_req(const struct rpc_server *s,
                           const struct request *req, struct response *res);
void rpc_server_free(struct rpc_server *s);

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

static inline void marshal_res(struct response *res) {
  res->opcode = htons(res->opcode);
  res->res = htonll(res->res);
  res->req_id = htonll(res->req_id);
}

static inline void unmarshal_req(struct request *req) {
  req->op1 = ntohll(req->op1);
  req->op2 = ntohll(req->op2);
  req->opcode = ntohs(req->opcode);
  req->req_id = ntohll(req->req_id);
}
#endif // !__PROTOCOL_H
