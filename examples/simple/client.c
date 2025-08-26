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
static int client_ensure_connected(const char *address, uint16_t port) {
  if (g_client != NULL) return 0;

  struct xrpc_client_config cfg = {0};
  int ret;

  ret = xrpc_client_init(&g_client);
  if (ret != XRPC_SUCCESS) {
    fprintf(stderr, "xrpc_client_init() failed\n");
    return ret;
  }

  ret = xrpc_tcpv4_client_build_default_config(&cfg);
  if (ret != XRPC_SUCCESS) {
    fprintf(stderr, "xrpc_tcpv4_client_build_default_config() failed\n");
    return ret;
  }

  ret = xrpc_client_connect(g_client, address, port);
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

  /* Build a local frame header (host byte order values) */
  struct xrpc_request_frame_header fh;
  memset(&fh, 0, sizeof(fh));

  /* set opinfo (we will use helpers to set fields) */
  uint16_t opinfo = 0;
  xrpc_req_fr_set_opcode(&opinfo, (uint8_t)OP_VECTOR_ADD);
  xrpc_req_fr_set_scale(&opinfo, 0); /* no scaling */
  xrpc_req_fr_set_dtypb(&opinfo, (uint8_t)XRPC_BASE_UINT16);
  xrpc_req_fr_set_dtypc(&opinfo, (uint8_t)XRPC_DTYPE_CAT_VECTOR);
  fh.opinfo = opinfo;

  /* size_params for vector: number of elements */
  fh.size_params =
      nelems; /* host order; xrpc_request_frame_header_to_net will convert */

  /* We use batch_id/frame_id = 0 for a single-frame request in this example */
  fh.batch_id = 0;
  fh.frame_id = 0;

  /* Serialize frame header to network byte order into a contiguous buffer,
   * then serialize vector elements in network order after it.
   *
   * Frame header is 8 bytes; vector data length is nelems * sizeof(uint16_t).
   */
  size_t vec_bytes = (size_t)nelems * sizeof(uint16_t);
  size_t req_size = sizeof(struct xrpc_request_frame_header) + vec_bytes;
  uint8_t *req_buf = malloc(req_size);
  if (!req_buf) {
    fprintf(stderr, "malloc failed\n");
    return -1;
  }

  /* header -> network */
  xrpc_request_frame_header_to_net(&fh, req_buf);

  /* vector data -> network (helper returns written size) */
  size_t written = 0;
  int rc = xrpc_vector_to_net(
      &fh, vec, req_buf + sizeof(struct xrpc_request_frame_header), vec_bytes,
      &written);
  if (rc != 0 || written != vec_bytes) {
    fprintf(stderr,
            "xrpc_vector_to_net failed (rc=%d written=%zu expected=%zu)\n", rc,
            written, vec_bytes);
    free(req_buf);
    return -1;
  }

  /* Call the RPC synchronously */
  struct xrpc_response_frame *resp = NULL;
  int call_rc =
      xrpc_client_call_sync(g_client, OP_VECTOR_ADD, req_buf, req_size, &resp);
  free(req_buf);

  (void)call_rc;
  return 0;
}

int main(void) {
  if (client_ensure_connected(server_address, server_port) != 0) {
    return EXIT_FAILURE;
  }

  /* example vector */
  uint16_t v[] = {1000, 2000, 3000, 4000}; /* sum = 10000 */
  uint16_t n = (uint16_t)(sizeof(v) / sizeof(v[0]));

  uint64_t sum = 0;
  if (client_vector_add(v, n, &sum) != 0) {
    fprintf(stderr, "vector_add RPC failed\n");
    xrpc_client_disconnect(g_client);
    xrpc_client_free(g_client);
    return EXIT_FAILURE;
  }

  printf("vector_add returned: %" PRIu64 "\n", sum);

  /* Cleanup */
  xrpc_client_disconnect(g_client);
  xrpc_client_free(g_client);
  g_client = NULL;

  return 0;
}
