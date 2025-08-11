#ifndef __SERVER_H

#include "protocol.h"
#include <stdint.h>

// Register handler flags
enum REGISTER_FLAGS {
  RF_OVERWRITE = 1 << 0,
};

struct rpc_server;
void transport_init(struct rpc_server **s);
void trasport_free(struct rpc_server *s);

#endif // !__SERVER_H
