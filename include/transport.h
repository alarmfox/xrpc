#ifndef __SERVER_H

#include "protocol.h"

struct transport;
void transport_init(struct transport **t, const void *args);
int transport_poll_client(struct transport *t);
int transport_recv(struct transport *t, struct request *r);
int transport_send(struct transport *t, struct response *r);
void transport_free(struct transport *t);

#endif // !__SERVER_H
