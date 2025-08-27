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

static int vector_add_handler(const struct xrpc_request_frame *rq,
                              struct xrpc_response_frame *rs) {
  (void)rq;
  (void)rs;
  return XRPC_SUCCESS;
}

static void print_config(const struct xrpc_server_config *config) {
  const struct xrpc_transport_tcp_config *tcp_config =
      &config->transport.config.tcp;
  char buf[64];

  printf("\n========================================\n");
  printf(" XRPC TCP Server Configuration ");
  printf("\n========================================\n");

  printf("  TCP_NODELAY            : %s\n",
         tcp_config->nodelay ? "enabled" : "disabled");
  printf("  SO_REUSEADDR           : %s\n",
         tcp_config->reuseaddr ? "enabled" : "disabled");
  printf("  SO_REUSEPORT           : %s\n",
         tcp_config->reuseport ? "enabled" : "disabled");
  printf("  SO_KEEPALIVE           : %s\n",
         tcp_config->keepalive ? "enabled" : "disabled");
  printf("  O_NONBLOCK             : %s\n",
         tcp_config->nonblocking ? "enabled" : "disabled");

  PRINT_OPT_OR_DISABLED("TCP_KEEPIDLE           :", buf,
                        tcp_config->keepalive_idle, "s");
  PRINT_OPT_OR_DISABLED("TCP_KEEPINTVL          :", buf,
                        tcp_config->keepalive_interval, "s");
  PRINT_OPT_OR_DISABLED("TCP_KEEPCNT            :", buf,
                        tcp_config->keepalive_probes, "");
  PRINT_OPT_OR_DISABLED("SO_SNDTIMEO            :", buf,
                        tcp_config->send_timeout_ms, "ms");
  PRINT_OPT_OR_DISABLED("SO_RCVTIMEO            :", buf,
                        tcp_config->recv_timeout_ms, "ms");
  PRINT_OPT_OR_DISABLED("SO_RCVBUF              :", buf,
                        tcp_config->recv_buffer_size, "bytes");
  PRINT_OPT_OR_DISABLED("SO_SNDBUF              :", buf,
                        tcp_config->send_buffer_size, "bytes");

  printf("  Connections pool size  : %d\n", tcp_config->connection_pool_size);
  printf("  Requests pool size     : %lu\n", config->max_concurrent_requests);
  printf("  Max concurrent I/O ops : %lu\n",
         config->io.max_concurrent_operations);

  printf("========================================\n\n");
}

int main(void) {

  const char address[] = "127.0.0.1";
  uint16_t port = 9000;

  struct xrpc_server_config config = {0};
  struct xrpc_io_system_config iocfg = {.type = XRPC_IO_SYSTEM_BLOCKING,
                                        .max_concurrent_operations = 128};

  config.io = iocfg;
  xrpc_tcpv4_server_build_default_config(address, port, &config);
  config.max_concurrent_requests = 128;

  // Set up signal handling for clean shutdown
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  if (xrpc_server_init(&srv, &config) != XRPC_SUCCESS) {
    printf("cannot create xrpc_server\n");
    goto exit;
  }

  print_config(&config);

  printf("Creating XRPC Server on %s:%d\n", address, port);
  if (xrpc_server_register(srv, OP_ECHO, vector_add_handler,
                           XRPC_RF_OVERWRITE) != XRPC_SUCCESS) {
    printf("cannot register dummy handler\n");
    goto exit;
  }

  printf("\nServer started successfully!\n");

  printf("Available operations:\n");
  printf("  0x%02X - Echo (mirror input payload)\n", OP_ECHO);
  xrpc_server_run(srv);

exit:
  if (srv) {
    xrpc_server_free(srv);
    srv = NULL;
  }

  return 0;
}
