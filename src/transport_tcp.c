#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "debug.h"
#include "error.h"
#include "transport.h"

#define BACKLOG 10

struct transport {
  int server_fd;
  int client_fd;
};

struct transport_args {
  struct sockaddr_in sa;
};

int transport_server_init(struct transport **s, const void *_args) {
  int ret, fd;
  struct transport_args *args = (struct transport_args *)_args;
  struct transport *t = NULL;
  args->sa.sin_addr.s_addr = htonl(args->sa.sin_addr.s_addr);
  args->sa.sin_port = htons(args->sa.sin_port);

  *s = malloc(sizeof(struct transport));
  if (!*s) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);

  t = *s;

  if (fd = socket(AF_INET, SOCK_STREAM, 0), fd < 0)
    _print_syscall_err_and_return("socket", XRPC_TRANSPORT_ERR_SOCKET);

  ret = bind(fd, (const struct sockaddr *)&(args->sa),
             sizeof(struct sockaddr_in));

  if (ret < 0) _print_syscall_err_and_return("bind", XRPC_TRANSPORT_ERR_BIND);

  if (ret = listen(fd, BACKLOG), ret < 0)
    _print_syscall_err_and_return("listen", XRPC_TRANSPORT_ERR_LISTEN);

  t->server_fd = fd;
  t->client_fd = -1;

  return XRPC_SUCCESS;
}

int transport_poll_client(struct transport *t) {

  int client_fd;
  struct sockaddr_in client;
  socklen_t client_len = sizeof(struct sockaddr_in);

  client_fd = accept(t->server_fd, (struct sockaddr *)&client, &client_len);
  if (client_fd < 0)
    _print_syscall_err_and_return("accept", XRPC_TRANSPORT_ERR_ACCEPT);

  t->client_fd = client_fd;

  return XRPC_SUCCESS;
}

int transport_recv(struct transport *t, void *b, size_t s) {
  size_t tot_read = 0;
  ssize_t n;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = read(t->client_fd, tmp + tot_read, s - tot_read);
    if (n == 0) return XRPC_TRANSPORT_ERR_READ_CONN_CLOSED;
    if (n < 0) {
      if (errno == EINTR) continue;
      _print_syscall_err_and_return("read", XRPC_TRANSPORT_ERR_READ);
    }
    tot_read += n;
  } while (tot_read < s);

  return XRPC_SUCCESS;
}

int transport_send(struct transport *t, const void *b, size_t l) {
  size_t tot_write = 0;
  ssize_t n;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = write(t->client_fd, tmp + tot_write, l - tot_write);
    if (n <= 0)
      _print_syscall_err_and_return("write", XRPC_TRANSPORT_ERR_WRITE);

    tot_write += n;
  } while (tot_write < l);

  return XRPC_SUCCESS;
}

void transport_release_client(struct transport *t) { close(t->client_fd); }

void transport_free(struct transport *s) {
  if (!s) return;
  close(s->server_fd);
  free(s);
}
