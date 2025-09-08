#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "benchmark.h"
#include "xrpc/xrpc.h"

#define OP_ECHO 0x0

int main(void) {
  int result = XRPC_SUCCESS;
  struct xrpc_client *client = NULL;
  struct xrpc_client_config config = {0};

  // Default server connection
  const char *server_address = "127.0.0.1";
  uint16_t server_port = 9000;

  // Test payload
  uint16_t test_data[] = {1, 2, 3, 4, 5};
  size_t data_len = sizeof(test_data) / sizeof(test_data[0]);

  // Response storage
  struct xrpc_response_frame resp = {0};
  struct xrpc_response_frame_header resp_header = {0};
  uint16_t response_buffer[10] = {0};

  resp.header = &resp_header;
  resp.data = response_buffer;

  // Initialize client
  if (xrpc_client_init(&client) != XRPC_SUCCESS) {
    fprintf(stderr, "Failed to initialize client\n");
    return 1;
  }

  // Configure connection
  xrpc_tcpv4_client_build_default_config(&config);
  config.transport_config.tcp.addr.sin_family = AF_INET;
  config.transport_config.tcp.addr.sin_port = htons(server_port);
  inet_pton(AF_INET, server_address,
            &config.transport_config.tcp.addr.sin_addr);

  // Connect
  if (xrpc_client_connect(client, &config) != XRPC_SUCCESS) {
    fprintf(stderr, "Failed to connect to server\n");
    goto cleanup;
  }

  printf("Connected to %s:%d\n", server_address, server_port);

  // Single synchronous call
  uint64_t start_time = xrpc_benchmark_timestamp_ns();

  result =
      xrpc_client_call_sync(client, OP_ECHO, test_data, data_len,
                            XRPC_BASE_UINT16, XRPC_DTYPE_CAT_VECTOR, &resp);

  uint64_t end_time = xrpc_benchmark_timestamp_ns();
  uint64_t latency_ns = end_time - start_time;

  if (result == XRPC_SUCCESS) {
    printf("Request successful!\n");
    printf("Latency: %lu ns (%.3f ms)\n", latency_ns, latency_ns / 1000000.0);
    printf("Response data: ");
    for (int i = 0; i < resp.header->size_params; i++) {
      printf("%u ", response_buffer[i]);
    }
    printf("\n");
  } else {
    printf("Request failed with error: %d\n", result);
  }

cleanup:
  if (client) {
    xrpc_client_disconnect(client);
    xrpc_client_free(client);
  }

  return (result == XRPC_SUCCESS) ? 0 : 1;
}
