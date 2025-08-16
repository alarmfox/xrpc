#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "internal/debug.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

#define BACKLOG 10

struct xrpc_transport {
  int server_fd;
  int client_fd;
};

int xrpc_transport_server_init_tcp(struct xrpc_transport **s,
                                   const struct xrpc_tcp_server_config *args) {
  int ret, fd;
  struct xrpc_transport *t = NULL;

  t = malloc(sizeof(struct xrpc_transport));
  if (!t) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);

  if (fd = socket(AF_INET, SOCK_STREAM, 0), fd < 0)
    _print_syscall_err_and_return("socket", XRPC_TRANSPORT_ERR_SOCKET);

  ret = bind(fd, (const struct sockaddr *)&(args->addr),
             sizeof(struct sockaddr_in));

  if (ret < 0) _print_syscall_err_and_return("bind", XRPC_TRANSPORT_ERR_BIND);

  if (ret = listen(fd, BACKLOG), ret < 0)
    _print_syscall_err_and_return("listen", XRPC_TRANSPORT_ERR_LISTEN);

  t->server_fd = fd;
  t->client_fd = -1;

  *s = t;
  return XRPC_SUCCESS;
}

int xrpc_transport_client_init_tcp(struct xrpc_transport **s,
                                   const struct xrpc_tcp_client_config *args) {

  int ret, fd;
  struct xrpc_transport *t = malloc(sizeof(struct xrpc_transport));

  if (!t) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);

  if (fd = socket(AF_INET, SOCK_STREAM, 0), fd < 0)
    _print_syscall_err_and_return("socket", XRPC_TRANSPORT_ERR_SOCKET);

  ret = connect(fd, (const struct sockaddr *)&(args->addr),
                sizeof(struct sockaddr_in));

  if (ret < 0)
    _print_syscall_err_and_return("connect", XRPC_TRANSPORT_ERR_CONNECT);

  t->client_fd = fd;
  t->server_fd = -1;

  *s = t;
  return XRPC_SUCCESS;
}

int transport_poll_client(struct xrpc_transport *t) {

  int client_fd;
  struct sockaddr_in client;
  socklen_t client_len = sizeof(struct sockaddr_in);

  client_fd = accept(t->server_fd, (struct sockaddr *)&client, &client_len);
  if (client_fd < 0)
    _print_syscall_err_and_return("accept", XRPC_TRANSPORT_ERR_ACCEPT);

  t->client_fd = client_fd;

  return XRPC_SUCCESS;
}

int transport_recv(struct xrpc_transport *t, void *b, size_t s) {
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

int transport_send(struct xrpc_transport *t, const void *b, size_t l) {
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

void transport_release_client(struct xrpc_transport *t) { close(t->client_fd); }

void __transport_free(struct xrpc_transport *t) {
  if (!t) return;
  if (t->server_fd > 0) close(t->server_fd);
  if (t->client_fd > 0) close(t->client_fd);
  free(t);
}

void xrpc_transport_server_free_tcp(struct xrpc_transport *t) {
  __transport_free(t);
}

void xrpc_transport_client_free_tcp(struct xrpc_transport *t) {
  __transport_free(t);
  ;
}
