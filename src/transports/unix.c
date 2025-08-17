#include <errno.h>
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
const struct xrpc_transport_ops xrpc_transport_unix_ops;

struct xrpc_transport_data {
  int fd;
};

struct xrpc_transport_connection {
  int fd;
};

static int
xrpc_transport_server_unix_init(struct xrpc_transport **s,
                                const struct xrpc_server_config *conf) {
  int ret, fd;

  const struct xrpc_server_unix_config *args = &conf->config.unix;
  struct xrpc_transport *t = malloc(sizeof(struct xrpc_transport));
  struct xrpc_transport_data *data = malloc(sizeof(struct xrpc_transport_data));

  if (!t) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);
  if (!data) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);

  if (fd = socket(AF_UNIX, SOCK_STREAM, 0), fd < 0)
    _print_syscall_err_and_return("socket", XRPC_TRANSPORT_ERR_SOCKET);

  ret = unlink(args->addr.sun_path);
  if (ret < 0 && errno != ENOENT)
    _print_syscall_err_and_return("unlink", XRPC_TRANSPORT_ERR_UNLINK);

  ret = bind(fd, (const struct sockaddr *)&args->addr,
             sizeof(struct sockaddr_un));
  if (ret < 0) _print_syscall_err_and_return("bind", XRPC_TRANSPORT_ERR_BIND);

  if (ret = listen(fd, BACKLOG), ret < 0)
    _print_syscall_err_and_return("listen", XRPC_TRANSPORT_ERR_LISTEN);

  // Populate the struct with ops and transport specific values
  data->fd = fd;

  t->ops = &xrpc_transport_unix_ops;
  t->data = data;

  *s = t;

  return XRPC_SUCCESS;
}

static int xrpc_transport_server_unix_accept_connection(
    struct xrpc_transport *t, struct xrpc_transport_connection **conn) {

  int fd;
  struct xrpc_transport_connection *c = NULL;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;

  fd = accept(data->fd, 0, 0);
  if (fd < 0)
    _print_syscall_err_and_return("accept", XRPC_TRANSPORT_ERR_ACCEPT);

  c = malloc(sizeof(struct xrpc_transport_connection));

  if (!c) _print_syscall_err_and_return("malloc", XRPC_API_ERR_ALLOC);

  c->fd = fd;

  *conn = c;
  return XRPC_SUCCESS;
}

static int
xprc_transport_server_unix_recv(struct xrpc_transport_connection *conn, void *b,
                                size_t l) {

  size_t tot_read = 0;
  ssize_t n;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = read(conn->fd, tmp + tot_read, l - tot_read);
    if (n == 0) return XRPC_TRANSPORT_ERR_READ_CONN_CLOSED;
    if (n < 0) {
      if (errno == EINTR) continue;
      _print_syscall_err_and_return("read", XRPC_TRANSPORT_ERR_READ);
    }

    tot_read += n;
  } while (tot_read < l);

  return XRPC_SUCCESS;
}

static int
xprc_transport_server_unix_send(struct xrpc_transport_connection *conn,
                                const void *b, size_t l) {
  size_t tot_write = 0, n;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = write(conn->fd, tmp + tot_write, l - tot_write);
    if (n <= 0)
      _print_syscall_err_and_return("write", XRPC_TRANSPORT_ERR_WRITE);

    tot_write += n;
  } while (tot_write < l);

  return XRPC_SUCCESS;
}

static void xrpc_transport_server_unix_close_connection(
    struct xrpc_transport_connection *conn) {
  if (!conn || conn->fd < 0) return;
  close(conn->fd);
  conn->fd = -1;
}

static void xrpc_transport_server_unix_free(struct xrpc_transport *t) {
  if (!t) return;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  if (data->fd > 0) close(data->fd);
  free(data);
  data = NULL;
}

const struct xrpc_transport_ops xrpc_transport_unix_ops = {
    .init = xrpc_transport_server_unix_init,
    .free = xrpc_transport_server_unix_free,
    .accept_connection = xrpc_transport_server_unix_accept_connection,
    .close_connection = xrpc_transport_server_unix_close_connection,
    .send = xprc_transport_server_unix_send,
    .recv = xprc_transport_server_unix_recv,

};
