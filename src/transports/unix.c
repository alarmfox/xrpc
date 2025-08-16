#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "internal/debug.h"
#include "internal/transport.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

#define BACKLOG 10

struct xrpc_transport_data {
  int server_fd;
  int client_fd;
};

int xrpc_transport_server_unix_poll_client(struct xrpc_transport *t) {

  int client_fd;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;

  client_fd = accept(data->server_fd, 0, 0);
  if (client_fd < 0)
    _print_syscall_err_and_return("accept", XRPC_TRANSPORT_ERR_ACCEPT);

  data->client_fd = client_fd;
  return XRPC_SUCCESS;
}

int xprc_transport_server_unix_recv(struct xrpc_transport *t, void *b,
                                    size_t l) {

  size_t tot_read = 0;
  ssize_t n;
  unsigned char *tmp = (unsigned char *)b;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;

  do {
    n = read(data->client_fd, tmp + tot_read, l - tot_read);
    if (n == 0) return XRPC_TRANSPORT_ERR_READ_CONN_CLOSED;
    if (n < 0) {
      if (errno == EINTR) continue;
      _print_syscall_err_and_return("read", XRPC_TRANSPORT_ERR_READ);
    }

    tot_read += n;
  } while (tot_read < l);

  return XRPC_SUCCESS;
}

int xprc_transport_server_unix_send(struct xrpc_transport *t, const void *b,
                                    size_t l) {
  size_t tot_write = 0, n;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = write(data->client_fd, tmp + tot_write, l - tot_write);
    if (n <= 0)
      _print_syscall_err_and_return("write", XRPC_TRANSPORT_ERR_WRITE);

    tot_write += n;
  } while (tot_write < l);

  return XRPC_SUCCESS;
}

void xrpc_transport_server_unix_release_client(struct xrpc_transport *t) {
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  if (data->client_fd > 0) {
    close(data->client_fd);
    data->client_fd = -1;
  }
}

void xrpc_transport_server_free(struct xrpc_transport *t) {
  if (!t) return;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  if (data->server_fd > 0) close(data->server_fd);
  if (data->client_fd > 0) close(data->client_fd);
  free(data);
  free(t);
}

// VTable for Unix backend
static const struct xrpc_transport_ops unix_ops = {
    .poll_client = xrpc_transport_server_unix_poll_client,
    .release_client = xrpc_transport_server_unix_release_client,
    .send = xprc_transport_server_unix_send,
    .recv = xprc_transport_server_unix_recv,

};

int xrpc_transport_server_init_unix(
    struct xrpc_transport **s, const struct xrpc_server_unix_config *args) {
  int ret, fd;

  // alloc the server
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
  data->server_fd = fd;
  data->client_fd = -1;
  t->ops = &unix_ops;
  t->data = data;

  *s = t;

  return XRPC_SUCCESS;
}
