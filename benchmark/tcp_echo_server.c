#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "benchmark.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

#define OP_ECHO 0x0

#define PRINT_STR_OPT_OR_DISABLED(opt, buf, v)                                 \
  do {                                                                         \
    strncpy(buf, "disabled", 8 + 1);                                           \
    if (v > 0) sprintf(buf, "%d", v);                                          \
    printf("  " opt " %s\n", buf);                                             \
  } while (0)

static struct xrpc_server *srv = NULL;
static pthread_t report_thread_id;
static volatile int g_running = 0;

// Signal handler for clean shutdown
static void signal_handler(int sig) {
  (void)sig;
  __atomic_store_n(&g_running, 0, __ATOMIC_SEQ_CST);
  xrpc_server_stop(srv);
  printf("\nShutting down server...\n");
}

static void *report_handler(void *params) {
  int *args = (int *)params;
  int sleep_interval = *args;
  struct xrpc_benchmark_stats stats = {0};
  while (__atomic_load_n(&g_running, __ATOMIC_RELAXED)) {
    xrpc_benchmark_stats_get(&stats);
    xrpc_benchmark_stats_print(&stats);
    sleep(sleep_interval);
    printf("\033c");
  }

  xrpc_benchmark_stats_get(&stats);
  xrpc_benchmark_stats_print(&stats);
  pthread_exit(0);
}

static int echo_handler(const struct xrpc_request *req,
                        struct xrpc_response *res) {

  res->hdr->status = XRPC_RESPONSE_SUCCESS;
  res->hdr->sz = sizeof(uint64_t);

  res->data = malloc(sizeof(uint64_t));
  memcpy(res->data, req->data, sizeof(uint64_t));

  return XRPC_SUCCESS;
}

static void print_usage(const char *program) {
  printf("Usage: %s [options]\n", program);
  printf("Options:\n");
  printf("  -p <port>     Server port (default: 9000)\n");
  printf("  -a <address>  Server address (default: 127.0.0.1)\n");
  printf("  -r <seconds>  Print benchmark report every N seconds\n");
  printf("  -h            Show this help\n");
}

static void print_config(const struct xrpc_server_config *cfg) {
  const struct xrpc_transport_tcp_config *c = &cfg->tcfg->config.tcp;
  char buf[64];

  printf("\n========================================\n");
  printf(" XRPC TCP Server Benchmark Configuration ");
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

  PRINT_STR_OPT_OR_DISABLED("TCP_KEEPIDLE           :", buf, c->keepalive_idle);
  PRINT_STR_OPT_OR_DISABLED("TCP_KEEPINTVL          :", buf,
                            c->keepalive_interval);
  PRINT_STR_OPT_OR_DISABLED("TCP_KEEPCNT            :", buf,
                            c->keepalive_probes);
  PRINT_STR_OPT_OR_DISABLED("SO_SNDTIMEO            :", buf,
                            c->send_timeout_ms);
  PRINT_STR_OPT_OR_DISABLED("SO_RCVTIMEO            :", buf,
                            c->recv_timeout_ms);
  PRINT_STR_OPT_OR_DISABLED("SO_RCVBUF              :", buf,
                            c->recv_buffer_size);
  PRINT_STR_OPT_OR_DISABLED("SO_SNDBUF              :", buf,
                            c->send_buffer_size);

  printf("  Connections pool size  : %d\n", c->connection_pool_size);
  printf("  Requests pool size     : %lu\n", cfg->max_concurrent_requests);
  printf("  Max concurrent I/O ops : %lu\n", cfg->max_concurrent_requests);

  printf("========================================\n\n");
}

int main(int argc, char **argv) {

  int report_interval = 2;
  int port = 9000;
  uint32_t address = INADDR_LOOPBACK;

  int opt;
  while ((opt = getopt(argc, argv, "p:a:tr:j:h")) != -1) {
    switch (opt) {
    case 'p':
      port = (uint16_t)atoi(optarg);
      break;
    case 'a':
      if (strcmp(optarg, "0.0.0.0") == 0) {
        address = INADDR_ANY;
      } else {
        address = INADDR_LOOPBACK; // For simplicity, could parse properly
      }
      break;
    case 'r':
      report_interval = atoi(optarg);
      break;
    case 'h':
      print_usage(argv[0]);
      return 0;
    default:
      print_usage(argv[0]);
      return 1;
    }
  }
  // Set up signal handling for clean shutdown
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  struct xrpc_io_system_config iocfg = {.type = XRPC_IO_SYSTEM_BLOCKING,
                                        .max_concurrent_operations = 128};

  struct xrpc_transport_config tcfg =
      XRPC_TCP_SERVER_DEFAULT_CONFIG(address, port);

  struct xrpc_server_config cfg = {.tcfg = &tcfg, .iocfg = &iocfg};

  // Optimize for benchmarking
  tcfg.config.tcp.nonblocking = false;
  tcfg.config.tcp.accept_timeout_ms = 100;     // Allow periodic reports
  tcfg.config.tcp.nodelay = true;              // Minimize latency
  tcfg.config.tcp.connection_pool_size = 1000; // Handle many connections
  cfg.max_concurrent_requests = 1024;

  printf("Creating XRPC Server for benchmarking on %s:%d\n",
         inet_ntoa(tcfg.config.tcp.addr.sin_addr), port);

  print_config(&cfg);

  if (xrpc_server_create(&srv, &cfg) != XRPC_SUCCESS) {
    printf("cannot create xrpc_server\n");
    goto exit;
  }

  if (xrpc_server_register(srv, OP_ECHO, echo_handler, XRPC_RF_OVERWRITE) !=
      XRPC_SUCCESS) {
    printf("cannot register dummy handler\n");
    goto exit;
  }

  printf("\nServer started successfully!\n");
  printf("Available operations:\n");
  printf("  0x%02X - Echo (mirror input data)\n", OP_ECHO);

  xrpc_benchmark_stats_init();

  __atomic_store_n(&g_running, 1, __ATOMIC_SEQ_CST);

  if (report_interval > 0) {
    printf("Benchmark reports every %d seconds\n", report_interval);
    pthread_create(&report_thread_id, 0, report_handler,
                   (void *)&report_interval);
  }

  xrpc_server_run(srv);
  if (report_interval > 0) pthread_join(report_thread_id, 0);
exit:
  if (srv) {
    xrpc_server_free(srv);
    srv = NULL;
  }
  xrpc_benchmark_stats_free();

  printf("Server shutdown complete\n");

  return 0;
}
