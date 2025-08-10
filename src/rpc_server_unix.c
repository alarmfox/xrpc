#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "protocol.h"

#define BACKLOG 10
#define UNIX_SOCKET_PATH "/tmp/rpc.sock"

#define OP_SUM 0x0

uint64_t op_sum(uint64_t a, uint64_t b) { return a + b; }

#define bail(msg)                                                              \
  {                                                                            \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  }

int read_all(int fd, void *buf, ssize_t len) {
  ssize_t tot_read = 0, n;
  char *tmp = (char *)buf;

  do {
    n = read(fd, tmp + tot_read, len - tot_read);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }

    tot_read += n;
  } while ((tot_read < len) && n != EOF);

  return tot_read == len ? len : -1;
}

void handle_conn(int fd, const struct server *s) {
  struct msg_req req;
  struct msg_res res;
  printf("got connection\n");

  if (read_all(fd, (void *)&req, sizeof(struct msg_req)) < 0) {
    perror("error in receiving request");
    goto CLEANUP;
  }

  unmarshal_req(&req);

  printf("id: %lu\n", req.req_id);
  printf("opa: %lu\n", req.op_a);
  printf("opb: %lu\n", req.op_b);
  printf("opcode: %d\n", (int)req.opcode);

  server_handle_req(s, &req, &res);
  marshal_res(&res);

  if (write(fd, (const void *)&res, sizeof(struct msg_res)) < 0) {
    perror("cannot send result");
  }

CLEANUP:
  close(fd);
}

int main() {
  int ret, fd, client_fd;
  struct sockaddr_un addr = {.sun_family = AF_UNIX,
                             .sun_path = UNIX_SOCKET_PATH};
  struct server *srv = NULL;

  if (fd = socket(AF_UNIX, SOCK_STREAM, 0), fd < 0)
    bail("socket error");

  ret = unlink(UNIX_SOCKET_PATH);
  if (ret < 0 && errno != ENOENT)
    bail("cannot unlink");

  ret = bind(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
  if (ret < 0)
    bail("bind error");

  if (ret = listen(fd, BACKLOG), ret < 0)
    bail("listen error");

  // build and configure server before accept
  server_init(&srv);
  ret = server_register_handler(srv, OP_SUM, op_sum, 0);

  if (ret != RPC_SUCCESS) {
    perror("cannot register handler");
    goto CLEANUP;
  }

  while (client_fd = accept(fd, 0, 0), client_fd > 0) {
    handle_conn(client_fd, srv);
  }

CLEANUP:
  printf("closing server");
  server_destroy(srv);
  close(fd);

  return EXIT_SUCCESS;
}
