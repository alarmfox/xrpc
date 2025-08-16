#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

#define BACKLOG 10

// Exported VTable
const struct xrpc_transport_ops xrpc_transport_tcp_ops;

struct xrpc_transport_data {
  int fd;
};

struct xrpc_connection {
  int fd;
};

int xrpc_transport_server_tcp_accept_connection(struct xrpc_transport *t,
                                                struct xrpc_connection **c) {

  int client_fd;
  struct sockaddr_in client;
  socklen_t client_len = sizeof(struct sockaddr_in);
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  struct xrpc_connection *conn = NULL;

  client_fd = accept(data->fd, (struct sockaddr *)&client, &client_len);
  if (client_fd < 0)
    _print_syscall_err_and_return("accept", XRPC_TRANSPORT_ERR_ACCEPT);

  conn = malloc(sizeof(struct xrpc_connection));

  if (!conn) _print_syscall_err_and_return("malloc", XRPC_API_ERR_ALLOC);

  conn->fd = client_fd;

  *c = conn;
  return XRPC_SUCCESS;
}

int xrpc_transport_server_tcp_recv(struct xrpc_connection *conn, void *b,
                                   size_t s) {
  size_t tot_read = 0;
  ssize_t n;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = read(conn->fd, tmp + tot_read, s - tot_read);
    if (n == 0) return XRPC_TRANSPORT_ERR_READ_CONN_CLOSED;
    if (n < 0) {
      if (errno == EINTR) continue;
      _print_syscall_err_and_return("read", XRPC_TRANSPORT_ERR_READ);
    }
    tot_read += n;
  } while (tot_read < s);

  return XRPC_SUCCESS;
}

int xrpc_transport_server_tcp_send(struct xrpc_connection *conn, const void *b,
                                   size_t l) {
  size_t tot_write = 0;
  ssize_t n;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = write(conn->fd, tmp + tot_write, l - tot_write);
    if (n <= 0)
      _print_syscall_err_and_return("write", XRPC_TRANSPORT_ERR_WRITE);

    tot_write += n;
  } while (tot_write < l);

  return XRPC_SUCCESS;
}

void xrpc_transport_server_tcp_close_connection(struct xrpc_connection *conn) {

  if (conn->fd > 0) close(conn->fd);
}

int xrpc_transport_server_tcp_init(struct xrpc_transport **s,
                                   const struct xrpc_server_config *config) {
  int ret, fd;
  const struct xrpc_server_tcp_config *args = &config->config.tcp;

  struct xrpc_transport *t = malloc(sizeof(struct xrpc_transport));
  struct xrpc_transport_data *data = malloc(sizeof(struct xrpc_transport_data));

  if (!t) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);
  if (!data) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);

  if (fd = socket(AF_INET, SOCK_STREAM, 0), fd < 0)
    _print_syscall_err_and_return("socket", XRPC_TRANSPORT_ERR_SOCKET);

  ret = bind(fd, (const struct sockaddr *)&(args->addr),
             sizeof(struct sockaddr_in));

  if (ret < 0) _print_syscall_err_and_return("bind", XRPC_TRANSPORT_ERR_BIND);

  if (ret = listen(fd, BACKLOG), ret < 0)
    _print_syscall_err_and_return("listen", XRPC_TRANSPORT_ERR_LISTEN);

  data->fd = fd;
  t->ops = &xrpc_transport_tcp_ops;
  t->data = data;

  *s = t;
  return XRPC_SUCCESS;
}

void xrpc_transport_server_tcp_free(struct xrpc_transport *t) {
  if (!t) return;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  if (data->fd > 0) close(data->fd);
  free(data);
  free(t);
}

// VTable for TCP operations
const struct xrpc_transport_ops xrpc_transport_tcp_ops = {
    .init = xrpc_transport_server_tcp_init,
    .free = xrpc_transport_server_tcp_free,
    .accept_connection = xrpc_transport_server_tcp_accept_connection,
    .close_connection = xrpc_transport_server_tcp_close_connection,
    .send = xrpc_transport_server_tcp_send,
    .recv = xrpc_transport_server_tcp_recv,
};
