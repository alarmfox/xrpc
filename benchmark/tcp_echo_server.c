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

#define PRINT_OPT_OR_DISABLED(opt, buf, v, unit)                               \
  do {                                                                         \
    strncpy(buf, "disabled", 8 + 1);                                           \
    if (v > 0) {                                                               \
      sprintf(buf, "%d", v);                                                   \
      printf("  " opt " %s %s\n", buf, unit);                                  \
    } else                                                                     \
      printf("  " opt " %s\n", buf);                                           \
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

static int echo_handler(const struct xrpc_request_frame *req,
                        struct xrpc_response_frame *res) {

  memcpy(res->data, req->data, req->header->size_params);
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

static void print_config(const struct xrpc_server_config *config) {
  const struct xrpc_transport_tcp_config *tcp_config =
      &config->transport.config.tcp;
  char buf[64];

  printf("\n========================================\n");
  printf(" Benchmark XRPC TCP Server Configuration ");
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
                        tcp_config->keepalive_idle_sec, "s");
  PRINT_OPT_OR_DISABLED("TCP_KEEPINTVL          :", buf,
                        tcp_config->keepalive_interval_sec, "s");
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

  printf("  Connections pool size  : %lu\n",
         config->transport.connection_pool_size);
  printf("  Requests pool size     : %lu\n", config->max_concurrent_requests);
  printf("  Max concurrent I/O ops : %lu\n",
         config->io.max_concurrent_operations);

  printf("========================================\n\n");
}

int main(int argc, char **argv) {

  // Set up signal handling for clean shutdown
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  struct xrpc_benchmark_stats stats = {0};
  // Default params
  uint16_t port = 9000;
  const char *address = "127.0.0.1";
  int report_interval = 2, opt;

  struct xrpc_server_config config = {0};

  config.max_concurrent_requests = 10;
  config.io = (struct xrpc_io_system_config){
      .type = XRPC_IO_SYSTEM_BLOCKING,
      .max_concurrent_operations = 128,

  };

  assert(xrpc_tcpv4_server_build_default_config(
             address, port, &config.transport) == XRPC_SUCCESS);

  while ((opt = getopt(argc, argv, "p:a:tr:j:h")) != -1) {
    switch (opt) {
    case 'p':
      config.transport.config.tcp.addr.sin_port = htons((uint16_t)atoi(optarg));
      break;
    case 'a':
      inet_aton(optarg, &config.transport.config.tcp.addr.sin_addr);
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

  printf("Creating XRPC Server for benchmarking on %s:%d\n", address, port);

  print_config(&config);

  if (xrpc_server_init(&srv, &config) != XRPC_SUCCESS) {
    printf("cannot create xrpc_server\n");
    goto exit;
  }

  if (xrpc_server_register(srv, OP_ECHO, echo_handler, XRPC_RF_OVERWRITE) !=
      XRPC_SUCCESS) {
    printf("cannot register echo handler\n");
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

  print_config(&config);
  xrpc_benchmark_stats_get(&stats);
  xrpc_benchmark_stats_print(&stats);

  xrpc_benchmark_stats_free();

  printf("Server shutdown complete\n");

  return 0;
}
