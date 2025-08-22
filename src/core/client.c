#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

struct xrpc_client {
  struct xrpc_client_connection *conn;
  enum xrpc_client_state state;
  uint64_t next_reqid;
  int last_error;
};

// This map stores different transports. For now this is only for supported
// transport of this library. In future, a "register" method could be provided.
static const struct xrpc_client_connection_ops *connection_ops_map[] = {
    [XRPC_TRANSPORT_TCP] = &xrpc_client_connection_tcp_ops,
};

/*
 * Helper function to send exactly n bytes
 */
static int send_exact_n(struct xrpc_client_connection *conn, const void *buf,
                        size_t len) {
  if (!conn || !buf || len == 0) { return XRPC_CLIENT_ERR_INVALID_CONFIG; }

  size_t bytes_written = 0, total_written = 0;
  int ret = XRPC_SUCCESS;
  const uint8_t *data = (const uint8_t *)buf;

  while (total_written < len) {
    ret = conn->ops->send(conn, data + total_written, len - total_written,
                          &bytes_written);

    if (ret == XRPC_TRANSPORT_ERR_WOULD_BLOCK) {
      // For blocking client, we should not get this, but handle gracefully
      continue;
    } else if (ret != XRPC_SUCCESS) {
      XRPC_DEBUG_PRINT("send failed: %d", ret);
      return ret;
    }

    total_written += bytes_written;
    bytes_written = 0; // Reset for next iteration
  }

  return XRPC_SUCCESS;
}

/*
 * Helper function to receive exactly n bytes
 */
static int recv_exact_n(struct xrpc_client_connection *conn, void *buf,
                        size_t len) {
  if (!conn || !buf || len == 0) { return XRPC_CLIENT_ERR_INVALID_CONFIG; }

  size_t bytes_read = 0, total_read = 0;
  int ret = XRPC_SUCCESS;
  uint8_t *data = (uint8_t *)buf;

  while (total_read < len) {
    ret =
        conn->ops->recv(conn, data + total_read, len - total_read, &bytes_read);

    if (ret == XRPC_TRANSPORT_ERR_WOULD_BLOCK) {
      // For blocking client, we should not get this, but handle gracefully
      continue;
    } else if (ret != XRPC_SUCCESS) {
      XRPC_DEBUG_PRINT("recv failed: %d", ret);
      return ret;
    }

    total_read += bytes_read;
    bytes_read = 0; // Reset for next iteration
  }

  return XRPC_SUCCESS;
}

/*
 * @brief Connect to an XRPC server.
 *
 * @param[out] cli  Pointer to allocated client instance.
 * @param[in]  cfg  Pointer to client configuration
 * @return XRPC_SUCCESS on success,
 */
int xrpc_client_init(struct xrpc_client **cli) {
  if (!cli) return XRPC_CLIENT_ERR_INVALID_CONFIG;

  struct xrpc_client *c = malloc(sizeof(struct xrpc_client));

  if (!c) return XRPC_INTERNAL_ERR_ALLOC;

  c->conn = NULL;
  c->last_error = XRPC_SUCCESS;
  c->next_reqid = 1;
  c->state = XRPC_CLIENT_DISCONNECTED;

  *cli = c;
  return XRPC_SUCCESS;
}

/*
 * @brief Connect to an XRPC server.
 *
 * @param[out] cli  Pointer to the client instance.
 * @param[in]  cfg  Pointer to client configuration
 * @return 0 on success, -1 on error.
 */
int xrpc_client_connect(struct xrpc_client *cli,
                        const struct xrpc_client_config *cfg) {
  if (!cli || !cfg || !cfg->ccfg) { return XRPC_CLIENT_ERR_INVALID_CONFIG; }

  // Check if already connected
  if (cli->state == XRPC_CLIENT_CONNECTED) {
    XRPC_DEBUG_PRINT("client already connected");
    return XRPC_SUCCESS;
  }

  // Validate transport type
  if ((size_t)cfg->ccfg->type >=
          sizeof(connection_ops_map) / sizeof(connection_ops_map[0]) ||
      !connection_ops_map[cfg->ccfg->type]) {
    cli->last_error = XRPC_CLIENT_ERR_INVALID_TRANSPORT;
    cli->state = XRPC_CLIENT_ERROR;
    return XRPC_CLIENT_ERR_INVALID_TRANSPORT;
  }

  // Get transport operations
  const struct xrpc_client_connection_ops *ops =
      connection_ops_map[cfg->ccfg->type];

  // Attempt connection
  int ret = ops->connect(&cli->conn, cfg->ccfg);
  if (ret != XRPC_SUCCESS) {
    cli->last_error = ret;
    cli->state = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("connection failed: %d", ret);
    return ret;
  }

  cli->state = XRPC_CLIENT_CONNECTED;
  cli->last_error = XRPC_SUCCESS;

  XRPC_DEBUG_PRINT("client connected successfully");
  return XRPC_SUCCESS;
}

/*
 * @brief Perform a synchronous RPC call.
 *
 * @param[in] cli           Client instance.
 * @param[in] op            Operation ID
 * @param[in] request_data  Pointer to request payload (can be NULL)
 * @param[in] request_size  Size of request payload
 * @param[out] response     Pointer to allocated response (caller must free)
 * @return XRPC_SUCCESS on success, error code on failure.
 */
int xrpc_client_call_sync(struct xrpc_client *cli, uint32_t op,
                          const void *request_data, size_t request_size,
                          struct xrpc_response **response) {

  if (!cli || !response) return XRPC_CLIENT_ERR_INVALID_CONFIG;

  *response = NULL; // Initialize output parameter

  // Check client state
  if (cli->state != XRPC_CLIENT_CONNECTED || !cli->conn) {
    cli->last_error = XRPC_CLIENT_ERR_NOT_CONNECTED;
    return XRPC_CLIENT_ERR_NOT_CONNECTED;
  }

  // Prepare request header
  struct xrpc_request_header req_hdr = {
      .reqid = __atomic_fetch_add(&cli->next_reqid, 1, __ATOMIC_ACQ_REL),
      .op = op,
      .sz = (uint32_t)request_size};

  int ret;

  XRPC_DEBUG_PRINT("sending request: op=%u, size=%zu, reqid=%lu", op,
                   request_size, req_hdr.reqid);

  // Send request header
  ret = send_exact_n(cli->conn, &req_hdr, sizeof(struct xrpc_request_header));
  if (ret != XRPC_SUCCESS) {
    cli->last_error = ret;
    cli->state = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("failed to send request header: %d", ret);
    return ret;
  }

  // Send request body if present
  if (request_size > 0 && request_data) {
    ret = send_exact_n(cli->conn, request_data, request_size);
    if (ret != XRPC_SUCCESS) {
      cli->last_error = ret;
      cli->state = XRPC_CLIENT_ERROR;
      XRPC_DEBUG_PRINT("failed to send request body: %d", ret);
      return ret;
    }
  }

  // Receive response header
  struct xrpc_response_header resp_hdr = {0};
  ret = recv_exact_n(cli->conn, &resp_hdr, sizeof(struct xrpc_response_header));
  if (ret != XRPC_SUCCESS) {
    cli->last_error = ret;
    cli->state = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("failed to receive response header: %d", ret);
    return ret;
  }

  // Validate response header
  if (resp_hdr.reqid != req_hdr.reqid) {
    cli->last_error = XRPC_CLIENT_ERR_PROTOCOL;
    cli->state = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("request ID mismatch: sent=%lu, received=%lu",
                     req_hdr.reqid, resp_hdr.reqid);
    return XRPC_CLIENT_ERR_PROTOCOL;
  }

  if (resp_hdr.op != req_hdr.op) {
    cli->last_error = XRPC_CLIENT_ERR_PROTOCOL;
    cli->state = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("operation ID mismatch: sent=%u, received=%u", req_hdr.op,
                     resp_hdr.op);
    return XRPC_CLIENT_ERR_PROTOCOL;
  }

  // Allocate response structure
  size_t total_size = sizeof(struct xrpc_response) + resp_hdr.sz;
  struct xrpc_response *resp = malloc(total_size);
  if (!resp) {
    cli->last_error = XRPC_INTERNAL_ERR_ALLOC;
    cli->state = XRPC_CLIENT_ERROR;
    return XRPC_INTERNAL_ERR_ALLOC;
  }

  // Set up response structure
  resp->hdr = (struct xrpc_response_header *)((uint8_t *)resp +
                                              sizeof(struct xrpc_response));
  memcpy(resp->hdr, &resp_hdr, sizeof(struct xrpc_response_header));

  if (resp_hdr.sz > 0) {
    resp->data = (uint8_t *)resp->hdr + sizeof(struct xrpc_response_header);

    // Receive response body
    ret = recv_exact_n(cli->conn, resp->data, resp_hdr.sz);
    if (ret != XRPC_SUCCESS) {
      cli->last_error = ret;
      cli->state = XRPC_CLIENT_ERROR;
      free(resp);
      XRPC_DEBUG_PRINT("failed to receive response body: %d", ret);
      return ret;
    }
  } else {
    resp->data = NULL;
  }

  cli->last_error = XRPC_SUCCESS;
  *response = resp;

  XRPC_DEBUG_PRINT("request completed successfully: status=%u, size=%u",
                   resp_hdr.status, resp_hdr.sz);
  return XRPC_SUCCESS;
}

int xrpc_client_disconnect(struct xrpc_client *cli) {
  if (!cli) { return XRPC_CLIENT_ERR_INVALID_CONFIG; }

  if (cli->state != XRPC_CLIENT_CONNECTED || !cli->conn) {
    return XRPC_CLIENT_ERR_NOT_CONNECTED;
  }

  if (cli->conn->ops && cli->conn->ops->disconnect) {
    cli->conn->ops->disconnect(cli->conn);
  }

  cli->conn = NULL;
  cli->state = XRPC_CLIENT_DISCONNECTED;
  cli->last_error = XRPC_SUCCESS;

  XRPC_DEBUG_PRINT("client disconnected");
  return XRPC_SUCCESS;
}

/*
 * @brief Close client and free resources.
 *
 * @param[in] cli Client instance
 */
void xrpc_client_free(struct xrpc_client *cli) {
  if (!cli) return;

  // Disconnect if still connected
  if (cli->state == XRPC_CLIENT_CONNECTED) xrpc_client_disconnect(cli);

  free(cli);
  XRPC_DEBUG_PRINT("client freed");
}
