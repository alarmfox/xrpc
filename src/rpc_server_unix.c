#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "log.h"
#include "protocol.h"

#define BACKLOG 10
#define UNIX_SOCKET_PATH "/tmp/rpc.sock"

#define OP_SUM 0x0

#define DEBUG 1

uint64_t op_sum(uint64_t a, uint64_t b) { return a + b; }

#define bail(MSG, ERR)                                                         \
  {                                                                            \
    char msg[512];                                                             \
    if (ERR != 0) {                                                            \
      snprintf(msg, sizeof(msg), "%s (errno=%d %s)", MSG, errno,               \
               strerror(errno));                                               \
    }                                                                          \
    log_message(LOG_LV_ERROR, ERR != 0 ? msg : MSG);                           \
    exit(EXIT_FAILURE);                                                        \
  }

#define dbg_params(REQ, RES)                                                   \
  {                                                                            \
    char msg[256];                                                             \
    snprintf(                                                                  \
        msg, sizeof(msg),                                                      \
        "req(id=%lu opcode=%d op1=%lu op2=%lu) res(id=%lu opcode=%d res=%lu)", \
        REQ.req_id, REQ.opcode, REQ.op1, REQ.op2, RES.req_id, RES.opcode,      \
        RES.res);                                                              \
    log_message(LOG_LV_DEBUG, msg);                                            \
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
  struct msg_res res = {
      .opcode = 0,
      .req_id = 0,
      .res = 0,
  };

  if (read_all(fd, (void *)&req, sizeof(struct msg_req)) < 0) {
    perror("error in receiving request");
    goto CLEANUP;
  }

  unmarshal_req(&req);

  server_handle_req(s, &req, &res);

  dbg_params(req, res);
  marshal_res(&res);

  // TODO: implement a write_all function
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
  char buf[64];
  memset(buf, 0, sizeof(buf));

  log_init("rpc_server_unix");

  if (DEBUG)
    log_set_minimum_level(LOG_LV_DEBUG);

  if (fd = socket(AF_UNIX, SOCK_STREAM, 0), fd < 0)
    bail("socket error", errno);

  ret = unlink(UNIX_SOCKET_PATH);
  if (ret < 0 && errno != ENOENT)
    bail("cannot unlink", errno);

  ret = bind(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
  if (ret < 0)
    bail("bind error", errno);

  if (ret = listen(fd, BACKLOG), ret < 0)
    bail("listen error", errno);

  sprintf(buf, "listening on %s", UNIX_SOCKET_PATH);

  // build and configure server before accept
  server_init(&srv);
  ret = server_register_handler(srv, OP_SUM, op_sum, 0);

  if (ret != RPC_SUCCESS) {
    perror("cannot register handler");
    goto CLEANUP;
  }

  log_message(LOG_LV_INFO, buf);
  while (client_fd = accept(fd, 0, 0), client_fd > 0) {
    log_message(DEBUG, "got a new connection");
    handle_conn(client_fd, srv);
  }

CLEANUP:
  printf("closing server");
  server_destroy(srv);
  close(fd);
  log_free();

  return EXIT_SUCCESS;
}
