#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "xrpc/error.h"
#include "xrpc/xrpc.h"

#define OP_ECHO 0x0
#define OP_SUM 0x1
#define OP_DOT_PROD 0x2

static struct xrpc_server *srv = NULL;

#define PRINT_OPT_OR_DISABLED(opt, buf, v, unit)                               \
  do {                                                                         \
    strncpy(buf, "disabled", 8 + 1);                                           \
    if (v > 0) {                                                               \
      sprintf(buf, "%d", v);                                                   \
      printf("  " opt " %s %s\n", buf, unit);                                  \
    } else                                                                     \
      printf("  " opt " %s\n", buf);                                           \
  } while (0)

// Signal handler for clean shutdown
static void signal_handler(int sig) {
  (void)sig;
  xrpc_server_stop(srv);
  printf("\nShutting down server...\n");
}

static int echo_handler(const struct xrpc_request *req,
                        struct xrpc_response *res) {

  res->hdr->status = XRPC_RESPONSE_SUCCESS;
  res->hdr->sz = sizeof(uint64_t);

  res->data = malloc(sizeof(uint64_t));
  memcpy(res->data, req->data, sizeof(uint64_t));

  return XRPC_SUCCESS;
}

/*
 * For demonstration purposes this sums just 2 uint64_t.
 */
static int sum_handler(const struct xrpc_request *req,
                       struct xrpc_response *res) {
  if (req->hdr->sz != 16) {
    res->hdr->status = XRPC_RESPONSE_INVALID_PARAMS;
    res->hdr->sz = 0;
    return XRPC_SUCCESS;
  }
  uint64_t *p = (uint64_t *)req->data;

  uint64_t op1 = *p++;
  uint64_t op2 = *p;
  uint64_t c = op1 + op2;

  // write the header and populate the result
  res->hdr->status = XRPC_RESPONSE_SUCCESS;
  res->hdr->sz = sizeof(uint64_t);
  res->data = malloc(res->hdr->sz);

  memcpy(res->data, &c, sizeof(uint64_t));

  return XRPC_SUCCESS;
}

/*
 * Performs the dot product between two arrays.
 * Arrays are sent one after the other. The array size must req->hdr->sz / 2
 * For now assume uint64_t arrays. Since req->hdr->sz is bytes, to get the
 * number of elements we need to divide by the sizeof(type)
 */
static int dot_product_handler(const struct xrpc_request *req,
                               struct xrpc_response *res) {

  // We cannot construct 2 arrays from an odd size
  if (req->hdr->sz % (2 * sizeof(uint64_t)) != 0) {
    res->hdr->status = XRPC_RESPONSE_INVALID_PARAMS;
    res->hdr->sz = 0;

    return XRPC_SUCCESS;
  }

  size_t arr_sz = req->hdr->sz / (2 * sizeof(uint64_t));
  uint64_t *p = (uint64_t *)req->data;
  uint64_t prod = 0;

  for (size_t i = 0; i < arr_sz; i++) {
    prod += p[i] * p[i + arr_sz];
  }

  res->hdr->status = XRPC_RESPONSE_SUCCESS;
  res->hdr->sz = sizeof(uint64_t);
  res->data = malloc(res->hdr->sz);

  memcpy(res->data, &prod, sizeof(uint64_t));

  return XRPC_SUCCESS;
}

static void print_config(const struct xrpc_server_config *cfg) {
  const struct xrpc_transport_tcp_config *c = &cfg->tcfg->config.tcp;
  char buf[64];

  printf("\n========================================\n");
  printf(" XRPC TCP Server Configuration ");
  printf("\n========================================\n");

  printf("  TCP_NODELAY            : %s\n",
         c->nodelay ? "enabled" : "disabled");
  printf("  SO_REUSEADDR           : %s\n",
         c->reuseaddr ? "enabled" : "disabled");
  printf("  SO_REUSEPORT           : %s\n",
         c->reuseport ? "enabled" : "disabled");
  printf("  SO_KEEPALIVE           : %s\n",
         c->keepalive ? "enabled" : "disabled");
  printf("  O_NONBLOCK             : %s\n",
         c->nonblocking ? "enabled" : "disabled");

  PRINT_OPT_OR_DISABLED("TCP_KEEPIDLE           :", buf, c->keepalive_idle,
                        "s");
  PRINT_OPT_OR_DISABLED("TCP_KEEPINTVL          :", buf, c->keepalive_interval,
                        "s");
  PRINT_OPT_OR_DISABLED("TCP_KEEPCNT            :", buf, c->keepalive_probes,
                        "");
  PRINT_OPT_OR_DISABLED("SO_SNDTIMEO            :", buf, c->send_timeout_ms,
                        "ms");
  PRINT_OPT_OR_DISABLED("SO_RCVTIMEO            :", buf, c->recv_timeout_ms,
                        "ms");
  PRINT_OPT_OR_DISABLED("SO_RCVBUF              :", buf, c->recv_buffer_size,
                        "bytes");
  PRINT_OPT_OR_DISABLED("SO_SNDBUF              :", buf, c->send_buffer_size,
                        "bytes");

  printf("  Connections pool size  : %d\n", c->connection_pool_size);
  printf("  Requests pool size     : %lu\n", cfg->max_concurrent_requests);
  printf("  Max concurrent I/O ops : %lu\n",
         cfg->iocfg->max_concurrent_operations);

  printf("========================================\n\n");
}

int main(void) {
  struct xrpc_transport_config tcfg =
      XRPC_TCP_SERVER_DEFAULT_CONFIG(INADDR_LOOPBACK, 9000);
  struct xrpc_io_system_config iocfg = {.type = XRPC_IO_SYSTEM_BLOCKING,
                                        .max_concurrent_operations = 128};
  struct xrpc_server_config cfg = {
      .tcfg = &tcfg, .iocfg = &iocfg, .max_concurrent_requests = 1024};

  tcfg.config.tcp.nonblocking = false;
  tcfg.config.tcp.accept_timeout_ms = 100;
  tcfg.config.tcp.recv_timeout_ms = 100;
  tcfg.config.tcp.connection_pool_size = 1024;

  // Set up signal handling for clean shutdown
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  if (xrpc_server_create(&srv, &cfg) != XRPC_SUCCESS) {
    printf("cannot create xrpc_server\n");
    goto exit;
  }

  printf("Creating XRPC Server on %s:%d\n", "127.0.0.1", 9000);
  if (xrpc_server_register(srv, OP_ECHO, echo_handler, XRPC_RF_OVERWRITE) !=
      XRPC_SUCCESS) {
    printf("cannot register dummy handler\n");
    goto exit;
  }

  if (xrpc_server_register(srv, OP_SUM, sum_handler, XRPC_RF_OVERWRITE) !=
      XRPC_SUCCESS) {
    printf("cannot register sum handler\n");
    goto exit;
  }

  if (xrpc_server_register(srv, OP_DOT_PROD, dot_product_handler,
                           XRPC_RF_OVERWRITE) != XRPC_SUCCESS) {
    printf("cannot register dot product handler\n");
    goto exit;
  }

  printf("\nServer started successfully!\n");
  print_config(&cfg);

  printf("Available operations:\n");
  printf("  0x%02X - Echo (mirror input data)\n", OP_ECHO);
  printf("  0x%02X - Sum (sums 2 uint64_t)\n", OP_SUM);
  printf("  0x%02X - Dot Product (performs dot product on equally size "
         "uint64_t vectors)\n",
         OP_DOT_PROD);
  xrpc_server_run(srv);

exit:
  if (srv) {
    xrpc_server_free(srv);
    srv = NULL;
  }

  return 0;
}
