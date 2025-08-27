#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "api.h"
#include "xrpc/xrpc.h"

// global variables
static const char server_address[] = "127.0.0.1";
static const uint16_t server_port = 9000;
static struct xrpc_client *g_client = NULL;

/*
 * Ensure client connected
 */
static int client_ensure_connected() {
  if (g_client != NULL) return 0;

  struct xrpc_client_config config = {0};
  int ret;

  ret = xrpc_client_init(&g_client);
  if (ret != XRPC_SUCCESS) {
    fprintf(stderr, "xrpc_client_init() failed\n");
    return ret;
  }

  xrpc_tcpv4_client_build_default_config(&config);

  config.transport_config.tcp.addr.sin_family = AF_INET;
  config.transport_config.tcp.addr.sin_port = htons(server_port);
  ret = inet_pton(AF_INET, server_address,
                  &config.transport_config.tcp.addr.sin_addr);

  if (ret <= 0) return XRPC_API_ERR_INVALID_ARGS;

  ret = xrpc_client_connect(g_client, &config);
  if (ret != 0) {
    fprintf(stderr, "xrpc_client_connect() failed\n");
    xrpc_client_free(g_client);
    g_client = NULL;
    return ret;
  }

  return XRPC_SUCCESS;
}

/*
 * client_vector_add:
 *  - packs a single frame request containing a vector of uint16_t values
 *  - sends it synchronously using xrpc_client_call_sync
 *  - expects the server to reply with a uint64_t (sum) in network byte-order
 *
 * Returns 0 on success and writes result into *out_sum.
 * Returns -1 on error.
 */
static int client_vector_add(uint16_t *vec, uint16_t nelems,
                             uint64_t *out_sum) {
  if (!g_client) {
    fprintf(stderr, "client not connected\n");
    return -1;
  }
  if (!vec || nelems == 0 || !out_sum) return -1;

  /* Call the RPC synchronously */
  struct xrpc_response_frame resp = {0};
  struct xrpc_response_frame_header response_fr_header = {0};
  int rc;

  resp.header = &response_fr_header;
  resp.data = out_sum;

  rc = xrpc_client_call_sync(g_client, OP_VECTOR_ADD, vec, nelems,
                             XRPC_BASE_UINT16, XRPC_DTYPE_CAT_VECTOR, &resp);

  if (rc != XRPC_SUCCESS) return rc;
  return 0;
}

int main(void) {

  /* example vector */
  uint16_t v[] = {1000, 2000, 3000, 4000}; /* sum = 10000 */
  uint16_t n = (uint16_t)(sizeof(v) / sizeof(v[0]));
  uint64_t sum = 0;
  int ret;

  ret = client_ensure_connected();

  if (ret != 0) goto exit;

  ret = client_vector_add(v, n, &sum);
  if (ret != 0) {
    fprintf(stderr, "vector_add RPC failed\n");
    goto exit;
  }

  printf("vector_add returned: %" PRIu64 "\n", sum);

exit:
  /* Cleanup */
  xrpc_client_disconnect(g_client);
  xrpc_client_free(g_client);
  g_client = NULL;

  return 0;
}
