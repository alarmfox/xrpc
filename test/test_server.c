#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "test.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

// Test configuration
#define TEST_SERVER_PORT 9001
#define TEST_SERVER_ADDR "127.0.0.1"
#define CLIENT_TIMEOUT_SEC 5

// Global test state
static struct xrpc_server *g_test_server = NULL;
static pthread_t g_server_thread;

#define XRPC_TEST_BLOCKING_IO

// Mock operation IDs
#define OP_VECTOR_ADD 1
#define OP_ECHO 2
#define OP_INVALID 99

// Mock handlers for testing
static int mock_vector_add_handler(const struct xrpc_request_frame *req,
                                   struct xrpc_response_frame *resp) {
  if (!req || !resp || !req->data || !resp->data) {
    return XRPC_API_ERR_INVALID_ARGS;
  }

  // Extract data from request (assuming uint16_t vector)
  uint16_t *input = (uint16_t *)req->data;
  uint16_t size_params = req->header->size_params;

  // Calculate sum
  uint64_t sum = 0;
  for (int i = 0; i < size_params; i++) {
    sum += input[i];
  }

  // Set response data
  *(uint64_t *)resp->data = sum;

  return XRPC_SUCCESS;
}

static int mock_echo_handler(const struct xrpc_request_frame *req,
                             struct xrpc_response_frame *resp) {

  if (!req || !resp) return XRPC_API_ERR_INVALID_ARGS;

  // Simple echo - copy request to response
  if (req->data && resp->data) {
    memcpy(resp->data, req->data, req->header->size_params * sizeof(uint32_t));
  }

  return XRPC_SUCCESS;
}

// Server thread function
static void *server_thread_func(void *arg) {
  (void)arg;
  struct xrpc_server_config config = {0};
  int ret;

  ret = xrpc_tcpv4_server_build_default_config(TEST_SERVER_ADDR,
                                               TEST_SERVER_PORT, &config);

  config.transport.config.tcp.reuseaddr = true;
  config.transport.config.tcp.accept_timeout_ms = 10;
  config.io.type = XRPC_IO_SYSTEM_BLOCKING;
  config.max_concurrent_requests = 10;
  config.io.max_concurrent_operations = 10;

  // Initialize server
  ret = xrpc_server_init(&g_test_server, &config);
  if (ret != XRPC_SUCCESS) { return NULL; }

  // Register handlers
  xrpc_server_register(g_test_server, OP_VECTOR_ADD, mock_vector_add_handler,
                       0);
  xrpc_server_register(g_test_server, OP_ECHO, mock_echo_handler, 0);

  // Run server (this blocks)
  xrpc_server_run(g_test_server);

  return NULL;
}

// Helper to start test server
static int start_test_server() {

  int ret = pthread_create(&g_server_thread, NULL, server_thread_func, NULL);
  if (ret != 0) { return 1; }

  // Wait for server to start
  int timeout = 5; // 5 seconds
  while (!xrpc_server_running(g_test_server) && timeout > 0) {
    sleep(1); // 1s
    timeout--;
  }

  if (!xrpc_server_running(g_test_server)) { return 1; }

  return XRPC_SUCCESS;
}

// Helper to stop test server
static void stop_test_server() {
  if (g_test_server) {
    xrpc_server_stop(g_test_server);
    pthread_join(g_server_thread, NULL);
    xrpc_server_free(g_test_server);
    g_test_server = NULL;
  }
}

// Helper to check if server port is available
static int is_port_available(int port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) return 0;

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, TEST_SERVER_ADDR, &addr.sin_addr);

  int ret = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
  close(sockfd);

  return ret == 0;
}

// Test: Basic server startup and shutdown
static int test_server_startup_shutdown() {
  TEST_CASE("server_startup_shutdown");

  // Check if port is available
  TEST_ASSERT(is_port_available(TEST_SERVER_PORT),
              "Test port should be available");

  int ret = start_test_server();
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Server should start successfully");

  // Server should be running
  TEST_ASSERT(xrpc_server_running(g_test_server),
              "Server should be marked as running");
  TEST_ASSERT_NOT_NULL(g_test_server, "Server instance should exist");

  stop_test_server();

  // Server should be stopped
  TEST_ASSERT(!xrpc_server_running(g_test_server), "Server should be stopped");

  TEST_SUCCESS();
}

// Test: Client connection and disconnection
static int test_client_connection() {
  TEST_CASE("client_connection");

  int ret = start_test_server();
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Server should start");

  // Test client connection
  struct xrpc_client *client = NULL;
  ret = xrpc_client_init(&client);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client init should succeed");
  TEST_ASSERT_NOT_NULL(client, "Client should be initialized");

  struct xrpc_client_config config = {0};
  xrpc_tcpv4_client_build_default_config(&config);
  config.transport_config.tcp.addr.sin_family = AF_INET;
  config.transport_config.tcp.addr.sin_port = htons(TEST_SERVER_PORT);
  inet_pton(AF_INET, TEST_SERVER_ADDR,
            &config.transport_config.tcp.addr.sin_addr);

  ret = xrpc_client_connect(client, &config);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client should connect to server");

  // Clean up
  xrpc_client_disconnect(client);
  xrpc_client_free(client);
  stop_test_server();

  TEST_SUCCESS();
}

// Test: Simple RPC call - vector addition
static int test_simple_rpc_call() {
  TEST_CASE("simple_rpc_call");

  int ret = start_test_server();
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Server should start");

  // Initialize client
  struct xrpc_client *client = NULL;
  ret = xrpc_client_init(&client);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client init should succeed");

  struct xrpc_client_config config = {0};
  xrpc_tcpv4_client_build_default_config(&config);
  config.transport_config.tcp.addr.sin_family = AF_INET;
  config.transport_config.tcp.addr.sin_port = htons(TEST_SERVER_PORT);
  inet_pton(AF_INET, TEST_SERVER_ADDR,
            &config.transport_config.tcp.addr.sin_addr);

  ret = xrpc_client_connect(client, &config);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client should connect");

  // Prepare test data
  uint16_t test_vector[] = {100, 200, 300, 400}; // Sum = 1000
  uint16_t vector_size = sizeof(test_vector) / sizeof(test_vector[0]);
  uint64_t result = 0;

  // Prepare response
  struct xrpc_response_frame resp = {0};
  struct xrpc_response_frame_header resp_header = {0};
  resp.header = &resp_header;
  resp.data = &result;

  // Make RPC call
  ret = xrpc_client_call_sync(client, OP_VECTOR_ADD, test_vector, vector_size,
                              XRPC_BASE_UINT16, XRPC_DTYPE_CAT_VECTOR, &resp);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "RPC call should succeed");

  // Verify result
  TEST_ASSERT_EQ(1000, result, "Vector sum should be 1000");

  // Clean up
  xrpc_client_disconnect(client);
  xrpc_client_free(client);
  stop_test_server();

  TEST_SUCCESS();
}

// Test: Multiple sequential RPC calls
static int test_multiple_rpc_calls() {
  TEST_CASE("multiple_rpc_calls");

  int ret = start_test_server();
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Server should start");

  // Initialize client
  struct xrpc_client *client = NULL;
  ret = xrpc_client_init(&client);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client init should succeed");

  struct xrpc_client_config config = {0};
  xrpc_tcpv4_client_build_default_config(&config);
  config.transport_config.tcp.addr.sin_family = AF_INET;
  config.transport_config.tcp.addr.sin_port = htons(TEST_SERVER_PORT);
  inet_pton(AF_INET, TEST_SERVER_ADDR,
            &config.transport_config.tcp.addr.sin_addr);

  ret = xrpc_client_connect(client, &config);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client should connect");

  // Test multiple calls with different data
  struct {
    uint16_t data[4];
    size_t size;
    uint64_t expected_sum;
  } test_cases[] = {{{1, 2, 3, 4}, 4, 10},
                    {{10, 20, 30}, 3, 60},
                    {{100, 200}, 2, 300},
                    {{1000}, 1, 1000}};

  for (int i = 0; i < 4; i++) {
    uint64_t result = 0;
    struct xrpc_response_frame resp = {0};
    struct xrpc_response_frame_header resp_header = {0};
    resp.header = &resp_header;
    resp.data = &result;

    ret = xrpc_client_call_sync(client, OP_VECTOR_ADD, test_cases[i].data,
                                test_cases[i].size, XRPC_BASE_UINT16,
                                XRPC_DTYPE_CAT_VECTOR, &resp);
    TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "RPC call should succeed");
    TEST_ASSERT_EQ(test_cases[i].expected_sum, result,
                   "Sum should match expected value");
  }

  // Clean up
  xrpc_client_disconnect(client);
  xrpc_client_free(client);
  stop_test_server();

  TEST_SUCCESS();
}

// Test: Invalid operation ID
static int test_invalid_operation() {
  TEST_CASE("invalid_operation");

  int ret = start_test_server();
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Server should start");

  // Initialize client
  struct xrpc_client *client = NULL;
  ret = xrpc_client_init(&client);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client init should succeed");

  struct xrpc_client_config config = {0};
  xrpc_tcpv4_client_build_default_config(&config);
  config.transport_config.tcp.addr.sin_family = AF_INET;
  config.transport_config.tcp.addr.sin_port = htons(TEST_SERVER_PORT);
  inet_pton(AF_INET, TEST_SERVER_ADDR,
            &config.transport_config.tcp.addr.sin_addr);

  ret = xrpc_client_connect(client, &config);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client should connect");

  // Try to call invalid operation
  uint16_t dummy_data[] = {1, 2, 3};
  uint64_t result = 0;
  struct xrpc_response_frame resp = {0};
  struct xrpc_response_frame_header resp_header = {0};
  resp.header = &resp_header;
  resp.data = &result;

  ret = xrpc_client_call_sync(client, OP_INVALID, dummy_data, 3,
                              XRPC_BASE_UINT16, XRPC_DTYPE_CAT_VECTOR, &resp);

  // Should receive error response
  TEST_ASSERT(ret != XRPC_SUCCESS, "Invalid operation should fail");

  // Clean up
  xrpc_client_disconnect(client);
  xrpc_client_free(client);
  stop_test_server();

  TEST_SUCCESS();
}

#ifndef XRPC_TEST_BLOCKING_IO
// Test: Connection handling under load
static int test_connection_load() {
  TEST_CASE("connection_load");

  int ret = start_test_server();
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Server should start");

  const int num_clients = 5;
  struct xrpc_client *clients[num_clients];

  // Initialize multiple clients
  for (int i = 0; i < num_clients; i++) {
    ret = xrpc_client_init(&clients[i]);
    TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client init should succeed");

    struct xrpc_client_config config = {0};
    xrpc_tcpv4_client_build_default_config(&config);
    config.transport_config.tcp.addr.sin_family = AF_INET;
    config.transport_config.tcp.addr.sin_port = htons(TEST_SERVER_PORT);
    inet_pton(AF_INET, TEST_SERVER_ADDR,
              &config.transport_config.tcp.addr.sin_addr);

    ret = xrpc_client_connect(clients[i], &config);
    TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client should connect");
  }

  // Make calls from all clients
  for (int i = 0; i < num_clients; i++) {
    uint16_t test_data[] = {(uint16_t)(i + 1), (uint16_t)(i + 2)};
    uint64_t expected = (i + 1) + (i + 2);
    uint64_t result = 0;

    struct xrpc_response_frame resp = {0};
    struct xrpc_response_frame_header resp_header = {0};
    resp.header = &resp_header;
    resp.data = &result;

    ret = xrpc_client_call_sync(clients[i], OP_VECTOR_ADD, test_data, 2,
                                XRPC_BASE_UINT16, XRPC_DTYPE_CAT_VECTOR, &resp);
    TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "RPC call should succeed");
    TEST_ASSERT_EQ(expected, result, "Result should match expected value");
  }

  // Clean up all clients
  for (int i = 0; i < num_clients; i++) {
    xrpc_client_disconnect(clients[i]);
    xrpc_client_free(clients[i]);
  }

  stop_test_server();

  TEST_SUCCESS();
}
#endif

// Test: Server info request
static int test_server_info() {
  TEST_CASE("server_info");

  int ret = start_test_server();
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Server should start");

  struct xrpc_client *client = NULL;
  ret = xrpc_client_init(&client);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client init should succeed");

  struct xrpc_client_config config = {0};
  xrpc_tcpv4_client_build_default_config(&config);
  config.transport_config.tcp.addr.sin_family = AF_INET;
  config.transport_config.tcp.addr.sin_port = htons(TEST_SERVER_PORT);
  inet_pton(AF_INET, TEST_SERVER_ADDR,
            &config.transport_config.tcp.addr.sin_addr);

  ret = xrpc_client_connect(client, &config);
  TEST_ASSERT_EQ(XRPC_SUCCESS, ret, "Client should connect");

  // TODO: implement server info

  xrpc_client_disconnect(client);
  xrpc_client_free(client);
  stop_test_server();

  TEST_SUCCESS();
}

// Main test runner
int main() {
  // Ignore SIGPIPE to handle broken connections gracefully
  signal(SIGPIPE, SIG_IGN);

  TEST_SUITE("XRPC Server Integration Tests");

  while (!is_port_available(TEST_SERVER_PORT)) {
    printf("waiting for port %d to become available...\n", TEST_SERVER_PORT);
    sleep(1);
  }

#ifndef XRPC_TEST_BLOCKING_IO
  RUN_TEST(test_connection_load);
#endif
  RUN_TEST(test_server_startup_shutdown);
  RUN_TEST(test_client_connection);
  RUN_TEST(test_simple_rpc_call);
  RUN_TEST(test_multiple_rpc_calls);
  RUN_TEST(test_invalid_operation);
  RUN_TEST(test_server_info);
  return 0;

  TEST_REPORT();
  return 0;
}
