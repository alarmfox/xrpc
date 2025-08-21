#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "benchmark.h"
#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/pool.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

// Exported VTable
const struct xrpc_transport_ops xrpc_transport_tcp_ops;
const struct xrpc_connection_ops xrpc_connection_tcp_ops;

struct xrpc_transport_data {
  struct xrpc_pool *pool;
  uint64_t current_id;
  int fd;
  int accept_timeout_ms;
  bool nonblocking;
};

struct xrpc_connection_data {
  int fd;
};

static int
xrpc_tcp_configure_socket(int fd, const struct xrpc_transport_tcp_config *c) {

  int ret, opt;
  struct timeval timeout;

  // set nodelay
  if (c->nodelay) {
    opt = 1;
    if (ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(int)),
        ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt TCP_NODELAY",
                                        XRPC_TRANSPORT_ERR_SOCKET);

    XRPC_DEBUG_PRINT("TCP_NODELAY enabled");
  }

  if (c->reuseaddr) {
    opt = 1;
    if (ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)),
        ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt SO_REUSEADDR",
                                        XRPC_TRANSPORT_ERR_SOCKET);

    XRPC_DEBUG_PRINT("SO_REUSEADDR enabled");
  }

  if (c->reuseport) {
    opt = 1;
    if (ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(int)),
        ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt SO_REUSEPORT",
                                        XRPC_TRANSPORT_ERR_SOCKET);

    XRPC_DEBUG_PRINT("SO_REUSEPORT enabled");
  }

  if (c->keepalive) {
    opt = 1;
    if (ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(int)),
        ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt SO_KEEPALIVE",
                                        XRPC_TRANSPORT_ERR_SOCKET);

    if (c->keepalive_idle > 0) {
      opt = c->keepalive_idle;
      if (ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(int)),
          ret < 0)
        XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt TCP_KEEPIDLE",
                                          XRPC_TRANSPORT_ERR_SOCKET);
    }

    if (c->keepalive_interval > 0) {
      opt = c->keepalive_interval;
      if (ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(int)),
          ret < 0)
        XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt TCP_KEEPINTVL",
                                          XRPC_TRANSPORT_ERR_SOCKET);
    }

    if (c->keepalive_probes > 0) {
      opt = c->keepalive_probes;
      if (ret = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(int)),
          ret < 0)
        XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt TCP_KEEPCNT",
                                          XRPC_TRANSPORT_ERR_SOCKET);

      XRPC_DEBUG_PRINT("Keepalive enabled: idle=%ds, interval=%ds, probes=%d",
                       c->keepalive_idle, c->keepalive_interval,
                       c->keepalive_probes);
    }
  }

  if (c->send_timeout_ms > 0) {
    timeout.tv_sec = c->send_timeout_ms / 1000;
    timeout.tv_usec = (c->send_timeout_ms % 1000) * 1000;

    if (ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                         sizeof(struct timeval)),
        ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt SO_SNDTIMEO",
                                        XRPC_TRANSPORT_ERR_SOCKET);

    XRPC_DEBUG_PRINT("SO_SNDTIMEO set to %d ms", c->send_timeout_ms);
  }

  if (c->recv_timeout_ms > 0) {
    timeout.tv_sec = c->recv_timeout_ms / 1000;
    timeout.tv_usec = (c->recv_timeout_ms % 1000) * 1000;

    if (ret = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                         sizeof(struct timeval)),
        ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt SO_RCVTIMEO",
                                        XRPC_TRANSPORT_ERR_SOCKET);

    XRPC_DEBUG_PRINT("SO_RCVTIMEO set to %d ms", c->recv_timeout_ms);
  }

  if (c->send_buffer_size > 0) {
    opt = c->send_buffer_size;

    if (ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(int)), ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt SO_SNDBUF",
                                        XRPC_TRANSPORT_ERR_SOCKET);

    XRPC_DEBUG_PRINT("SO_SNDBUF set to %d bytes", c->send_buffer_size);
  }

  if (c->recv_buffer_size > 0) {
    opt = c->recv_buffer_size;

    if (ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int)), ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("setsockopt SO_RCVBUF",
                                        XRPC_TRANSPORT_ERR_SOCKET);

    XRPC_DEBUG_PRINT("SO_RCVBUF set to %d bytes", c->recv_buffer_size);
  }

  if (c->nonblocking) {
    int flags = fcntl(fd, F_GETFL);
    if (ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK), ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("fcntl O_NONBLOCK",
                                        XRPC_TRANSPORT_ERR_SOCKET);

    XRPC_DEBUG_PRINT("O_NONBLOCK enabled");
  }
  return XRPC_SUCCESS;
}

static int
xrpc_transport_server_tcp_init(struct xrpc_transport **s,
                               const struct xrpc_transport_config *config) {
  int ret, fd;
  const struct xrpc_transport_tcp_config *args = &config->config.tcp;

  struct xrpc_transport *t = malloc(sizeof(struct xrpc_transport));
  struct xrpc_transport_data *data = malloc(sizeof(struct xrpc_transport_data));
  struct xrpc_pool *pool = NULL;
  const size_t conn_size =
      sizeof(struct xrpc_connection) + sizeof(struct xrpc_connection_data);

  if (!t) XRPC_PRINT_ERR_AND_RETURN("malloc error", XRPC_API_ERR_ALLOC);
  if (!data) XRPC_PRINT_ERR_AND_RETURN("malloc error", XRPC_API_ERR_ALLOC);

  if (fd = socket(AF_INET, SOCK_STREAM, 0), fd < 0)
    XRPC_PRINT_SYSCALL_ERR_AND_RETURN("socket", XRPC_TRANSPORT_ERR_SOCKET);

  if (ret = xrpc_tcp_configure_socket(fd, args), ret < 0)
    XRPC_PRINT_SYSCALL_ERR_AND_RETURN("socket", XRPC_TRANSPORT_ERR_SOCKET);

  ret = bind(fd, (const struct sockaddr *)&(args->addr),
             sizeof(struct sockaddr_in));

  if (ret < 0)
    XRPC_PRINT_SYSCALL_ERR_AND_RETURN("bind", XRPC_TRANSPORT_ERR_BIND);

  if (ret = listen(fd, args->listen_backlog), ret < 0)
    XRPC_PRINT_SYSCALL_ERR_AND_RETURN("listen", XRPC_TRANSPORT_ERR_LISTEN);

  if (ret = xrpc_pool_init(&pool, args->connection_pool_size, conn_size),
      ret != XRPC_SUCCESS)
    XRPC_PRINT_ERR_AND_RETURN("connection poll init error", ret);

  data->fd = fd;
  data->accept_timeout_ms = args->accept_timeout_ms;
  data->nonblocking = args->nonblocking;
  data->pool = pool;
  // make id atomic
  __atomic_store_n(&data->current_id, 0, __ATOMIC_SEQ_CST);

  t->ops = &xrpc_transport_tcp_ops;
  t->data = data;

  *s = t;
  return XRPC_SUCCESS;
}

static int xrpc_transport_server_tcp_accept(struct xrpc_transport *t,
                                            struct xrpc_connection **c) {

  int client_fd;
  int ret;
  struct sockaddr_in client;
  socklen_t client_len = sizeof(struct sockaddr_in);
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  struct xrpc_connection *conn = NULL;
  struct xrpc_connection_data *cdata = NULL;

  // If the socket is blocking and `accept_timeout > 0`, we
  //  need to use `poll` to exit after a certain `accept_timeout`. Otherwise we
  //  can use the normal accept.

  if (!data->nonblocking && data->accept_timeout_ms > 0) {
    struct pollfd pfds[1];

    pfds[0].fd = data->fd;
    pfds[0].events = POLLIN;

    // susped for at most data->accept_timeout
    ret = poll(pfds, 1, data->accept_timeout_ms);
    if (ret < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("poll", XRPC_TRANSPORT_ERR_ACCEPT);
    if (pfds[0].revents & POLLIN) {
      // normally accept -> we have been told that there is data
      client_fd = accept(data->fd, (struct sockaddr *)&client, &client_len);
    } else
      return XRPC_TRANSPORT_WOULD_BLOCK;
  } else {
    client_fd = accept(data->fd, (struct sockaddr *)&client, &client_len);

    if (client_fd < 0 && (errno == EWOULDBLOCK || errno == EAGAIN))
      return XRPC_TRANSPORT_WOULD_BLOCK;
    else if (client_fd < 0)
      XRPC_PRINT_SYSCALL_ERR_AND_RETURN("accept", XRPC_TRANSPORT_ERR_ACCEPT);
  }

  // get a connection from the pool
  xrpc_pool_get(data->pool, (void **)&conn);
  if (!conn) return XRPC_API_ERR_ALLOC;

  // the pool gets a block to a contigous memory region. First part of the
  // memory is for connection and than to the xrpc_connetion
  conn->data = (uint8_t *)conn + sizeof(struct xrpc_connection);

  cdata = conn->data;

  cdata->fd = client_fd;

  // setup connection
  conn->data = (void *)cdata;
  conn->ops = &xrpc_connection_tcp_ops;
  conn->is_closed = false;
  conn->is_closing = false;

  // get connection id atomically
  conn->id = __atomic_fetch_add(&data->current_id, 1, __ATOMIC_RELAXED);
  __atomic_store_n(&conn->ref_count, 0, __ATOMIC_SEQ_CST);

  XRPC_DEBUG_PRINT("tcp connection accepted from %s:%d (id=%lu)",
                   inet_ntoa(client.sin_addr), ntohs(client.sin_port),
                   conn->id);

  XRPC_BENCH_CONN_ACCEPT(conn->id);
  *c = conn;
  return XRPC_SUCCESS;
}

static int xrpc_transport_server_tcp_send(struct xrpc_connection *conn,
                                          const void *b, size_t len,
                                          size_t *bytes_written) {
  ssize_t n;
  struct xrpc_connection_data *cdata =
      (struct xrpc_connection_data *)conn->data;

  n = write(cdata->fd, b, len);
  if (n <= 0)
    XRPC_PRINT_SYSCALL_ERR_AND_RETURN("write", XRPC_TRANSPORT_ERR_WRITE);

  *bytes_written = n;

  return XRPC_SUCCESS;
}

static int xrpc_transport_server_tcp_recv(struct xrpc_connection *conn, void *b,
                                          size_t len, size_t *bytes_read) {
  ssize_t n;
  struct xrpc_connection_data *cdata =
      (struct xrpc_connection_data *)conn->data;

  n = read(cdata->fd, b, len);

  if (n == 0) return XRPC_TRANSPORT_ERR_CONN_CLOSED;
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return XRPC_TRANSPORT_WOULD_BLOCK;
    XRPC_PRINT_SYSCALL_ERR_AND_RETURN("read", XRPC_TRANSPORT_ERR_READ);
  }

  *bytes_read = n;

  return XRPC_SUCCESS;
}

static void xrpc_transport_server_tcp_close(struct xrpc_transport *t,
                                            struct xrpc_connection *conn) {
  (void)t;
  if (!conn) return;

  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  struct xrpc_connection_data *cdata =
      (struct xrpc_connection_data *)conn->data;

  XRPC_DEBUG_PRINT("closing tcp connection (id=%lu)", conn->id);

  if (cdata && cdata->fd > 0) {
    close(cdata->fd);
    cdata->fd = -1;
    // zero out the memory
    memset(conn, 0,
           sizeof(struct xrpc_connection) +
               sizeof(struct xrpc_connection_data));
    // should never fail
    assert(xrpc_pool_put(data->pool, conn) == XRPC_SUCCESS);
    XRPC_BENCH_CONN_CLOSE(conn->id);
  }
}

static void xrpc_transport_server_tcp_free(struct xrpc_transport *t) {
  if (!t) return;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  if (data) {
    if (data->fd > 0) close(data->fd);
    if (data->pool) {
      xrpc_pool_free(data->pool);
      data->pool = NULL;
    }
    free(data);
    t->data = NULL;
  }

  free(t);
}

// TCP operations
const struct xrpc_transport_ops xrpc_transport_tcp_ops = {
    .init = xrpc_transport_server_tcp_init,
    .free = xrpc_transport_server_tcp_free,
    .accept = xrpc_transport_server_tcp_accept,
    .close = xrpc_transport_server_tcp_close,
};

const struct xrpc_connection_ops xrpc_connection_tcp_ops = {
    .send = xrpc_transport_server_tcp_send,
    .recv = xrpc_transport_server_tcp_recv,
};
