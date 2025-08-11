#ifndef __SERVER_H

#include "protocol.h"

struct transport;
void transport_init(struct transport **s, const void *args);
int transport_recv(struct transport *s, struct request *r);
int transport_send(struct transport *s, struct response *r);
void transport_free(struct transport *s);

#endif // !__SERVER_H
