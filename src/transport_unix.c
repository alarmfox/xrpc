#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "log.h"
#include "transport.h"

#define BACKLOG 10

struct transport {
  int fd;
  int client_fd;
};

struct transport_args {
  struct sockaddr_un sa;
};

int read_all(int fd, void *buf, ssize_t len);
int write_all(int fd, const void *buf, ssize_t len);

void transport_init(struct transport **s, const void *_args) {
  int ret, fd;
  struct transport_args *args = (struct transport_args *)_args;
  // alloc the server
  *s = malloc(sizeof(struct transport));
  struct transport *t = *s;

  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  strncpy(addr.sun_path, args->sa.sun_path, 108);

  if (fd = socket(AF_UNIX, SOCK_STREAM, 0), fd < 0) bail("socket");

  ret = unlink(args->sa.sun_path);
  if (ret < 0 && errno != ENOENT) bail("unlink");

  ret = bind(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
  if (ret < 0) bail("bind");

  if (ret = listen(fd, BACKLOG), ret < 0) bail("listen");

  t->fd = fd;
  t->client_fd = -1;
}

int transport_poll_client(struct transport *t) {

  int client_fd;

  client_fd = accept(t->fd, 0, 0);
  if (client_fd < 0) return -1;

  t->client_fd = client_fd;
  return 0;
}

int transport_recv(struct transport *s, struct request *r) {

  int ret;
  if (ret = read_all(s->client_fd, (void *)r, sizeof(struct request)),
      ret < 0) {
    close(s->client_fd);
    return ret;
  }

  unmarshal_req(r);
  return 0;
}

int transport_send(struct transport *s, struct response *r) {
  int ret = 0;

  marshal_res(r);
  if (write_all(s->client_fd, (const void *)r, sizeof(struct response)) < 0) {
    log_error("error in sending request");
    ret = -1;
  }

  return ret;
}

void transport_free(struct transport *s) {
  if (s->client_fd > 0) { close(s->client_fd); }
  close(s->fd);
  free(s);
  s = NULL;
}

int read_all(int fd, void *buf, ssize_t len) {
  ssize_t tot_read = 0, n;
  unsigned char *tmp = (unsigned char *)buf;

  do {
    n = read(fd, tmp + tot_read, len - tot_read);
    if (n == 0) return -1;
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }

    tot_read += n;
  } while (tot_read < len);

  return tot_read == len ? len : -1;
}

int write_all(int fd, const void *buf, ssize_t len) {
  ssize_t tot_write = 0, n;
  char *tmp = (char *)buf;

  do {
    n = write(fd, tmp + tot_write, len - tot_write);
    if (n <= 0) return -1;

    tot_write += n;
  } while (tot_write < len);

  return 0;
}
