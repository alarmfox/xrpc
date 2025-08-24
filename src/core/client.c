#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/protocol.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

struct xrpc_client {
  struct xrpc_client_connection *conn;
  enum xrpc_client_status status;
  uint64_t next_reqid;
  char server_name[128];
  int last_error;
};

// This map stores different transports. For now this is only for supported
// transport of this library. In future, a "register" method could be provided.
static const struct xrpc_client_connection_ops *connection_ops_map[] = {
    [XRPC_TRANSPORT_TCP] = &xrpc_client_connection_tcp_ops,
};

static void set_server_name(struct xrpc_client *cli,
                            const struct xrpc_client_config *cfg) {
  switch (cfg->type) {
  case XRPC_TRANSPORT_TCP:
    snprintf(cli->server_name, sizeof(cli->server_name), "%s://%s:%d", "tcp",
             inet_ntoa(cfg->config.tcp.addr.sin_addr),
             ntohs(cfg->config.tcp.addr.sin_port));
  }
}

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
int xrpc_client_init(struct xrpc_client **out_client) {
  if (!out_client) return XRPC_CLIENT_ERR_INVALID_CONFIG;

  struct xrpc_client *client = malloc(sizeof(struct xrpc_client));

  if (!client) return XRPC_INTERNAL_ERR_ALLOC;

  client->conn = NULL;
  client->last_error = XRPC_SUCCESS;
  client->next_reqid = 1;
  client->status = XRPC_CLIENT_DISCONNECTED;
  memset(client->server_name, 0, sizeof(client->server_name));

  *out_client = client;
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
  if (!cli || !cfg) return XRPC_CLIENT_ERR_INVALID_CONFIG;

  // Check if already connected
  if (cli->status == XRPC_CLIENT_CONNECTED) {
    XRPC_DEBUG_PRINT("client already connected");
    return XRPC_SUCCESS;
  }

  // Validate transport type
  if ((size_t)cfg->type >=
          sizeof(connection_ops_map) / sizeof(connection_ops_map[0]) ||
      !connection_ops_map[cfg->type]) {
    cli->last_error = XRPC_CLIENT_ERR_INVALID_TRANSPORT;
    cli->status = XRPC_CLIENT_ERROR;
    return XRPC_CLIENT_ERR_INVALID_TRANSPORT;
  }

  // Get transport operations
  const struct xrpc_client_connection_ops *ops = connection_ops_map[cfg->type];

  // Attempt connection
  int ret = ops->connect(&cli->conn, cfg);
  if (ret != XRPC_SUCCESS) {
    cli->last_error = ret;
    cli->status = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("connection failed: %d", ret);
    return ret;
  }

  cli->status = XRPC_CLIENT_CONNECTED;
  cli->last_error = XRPC_SUCCESS;
  set_server_name(cli, cfg);

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
                          struct xrpc_response **out_resp) {

  if (!cli || !out_resp) return XRPC_CLIENT_ERR_INVALID_CONFIG;

  // Check client state
  if (cli->status != XRPC_CLIENT_CONNECTED || !cli->conn) {
    cli->last_error = XRPC_CLIENT_ERR_NOT_CONNECTED;
    return XRPC_CLIENT_ERR_NOT_CONNECTED;
  }

  // Convenies variable to avoid ugly &(*response-><field>)
  struct xrpc_response *resp = NULL;

  // Prepare request header
  struct xrpc_request_header req_hdr = {
      .request_id = __atomic_fetch_add(&cli->next_reqid, 1, __ATOMIC_ACQ_REL),
      .operation_id = op,
      .payload_size = (uint32_t)request_size};

  // Received response header
  struct xrpc_response_header resp_hdr = {0};
  int ret;

  XRPC_DEBUG_PRINT("sending request: op=%u, size=%zu, reqid=%lu", op,
                   request_size, req_hdr.request_id);
  // init out_resp = NULL so that if we fail the user will always read NULL.
  *out_resp = NULL;

  // Send request header
  ret = send_exact_n(cli->conn, &req_hdr, sizeof(struct xrpc_request_header));
  if (ret != XRPC_SUCCESS) {
    cli->last_error = ret;
    cli->status = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("failed to send request header: %d", ret);
    return ret;
  }

  // Send request body if present
  if (request_size > 0) {
    ret = send_exact_n(cli->conn, request_data, request_size);
    if (ret != XRPC_SUCCESS) {
      cli->last_error = ret;
      cli->status = XRPC_CLIENT_ERROR;
      XRPC_DEBUG_PRINT("failed to send request body: %d", ret);
      return ret;
    }
  }

  ret = recv_exact_n(cli->conn, &resp_hdr, sizeof(struct xrpc_response_header));
  if (ret != XRPC_SUCCESS) {
    cli->last_error = ret;
    cli->status = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("failed to receive response header: %d", ret);
    return ret;
  }

  // Validate response header
  if (resp_hdr.request_id != req_hdr.request_id) {
    cli->last_error = XRPC_CLIENT_ERR_PROTOCOL;
    cli->status = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("request ID mismatch: sent=%lu, received=%lu",
                     req_hdr.request_id, resp_hdr.request_id);
    return XRPC_CLIENT_ERR_PROTOCOL;
  }

  if (resp_hdr.operation_id != req_hdr.operation_id) {
    cli->last_error = XRPC_CLIENT_ERR_PROTOCOL;
    cli->status = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("operation ID mismatch: sent=%u, received=%u",
                     req_hdr.operation_id, resp_hdr.operation_id);
    return XRPC_CLIENT_ERR_PROTOCOL;
  }

  /*
   * Setup the response structure.
   * - Alloc the correct amount of memory for the response
   * - Copy the header in the response
   * - Read the body if any
   */
  resp = malloc(XRPC_RESPONSE_MSG_SIZE(resp_hdr.payload_size));

  if (!resp) {
    cli->last_error = XRPC_INTERNAL_ERR_ALLOC;
    cli->status = XRPC_CLIENT_ERROR;
    return XRPC_INTERNAL_ERR_ALLOC;
  }

  // Copy the header in the response
  memcpy(&resp->hdr, &resp_hdr, sizeof(struct xrpc_response_header));
  if (resp_hdr.payload_size > 0) {

    // Receive response body
    ret = recv_exact_n(cli->conn, &resp->payload, resp_hdr.payload_size);
    if (ret != XRPC_SUCCESS) {
      cli->last_error = ret;
      cli->status = XRPC_CLIENT_ERROR;
      free(resp);
      XRPC_DEBUG_PRINT("failed to receive response body: %d", ret);
      return ret;
    }
  }

  *out_resp = resp;
  cli->last_error = XRPC_SUCCESS;

  XRPC_DEBUG_PRINT("request completed successfully: status=%u, size=%u",
                   resp_hdr.status, resp_hdr.payload_size);
  return XRPC_SUCCESS;
}

int xrpc_client_disconnect(struct xrpc_client *cli) {
  if (!cli) return XRPC_CLIENT_ERR_INVALID_CONFIG;

  if (cli->status != XRPC_CLIENT_CONNECTED || !cli->conn) {
    return XRPC_SUCCESS;
  }

  if (cli->conn->ops && cli->conn->ops->disconnect) {
    cli->conn->ops->disconnect(cli->conn);
  }

  cli->conn = NULL;
  cli->status = XRPC_CLIENT_DISCONNECTED;
  cli->last_error = XRPC_SUCCESS;
  memset(cli->server_name, 0, sizeof(cli->server_name));

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
  if (cli->status == XRPC_CLIENT_CONNECTED) xrpc_client_disconnect(cli);

  free(cli);
}

/*
 * @brief Get the current client status
 *
 * @param[in] cli Client instance
 */
enum xrpc_client_status xrpc_client_status_get(const struct xrpc_client *cli) {
  if (!cli) return XRPC_CLIENT_DISCONNECTED;

  return cli->status;
}

/*
 * @brief Check if a client is connected
 *
 * @param[in] cli Client instance
 * @param[out] true if the server is connected, false otherwise
 */
bool xrpc_client_is_connected(const struct xrpc_client *cli) {
  if (!cli) return false;
  return cli->status == XRPC_CLIENT_CONNECTED;
}

/*
 * @brief Return the server name
 *
 * @param[in] cli Client instance
 * @param[out] Server name if connected. "" otherwise.
 */
const char *xrpc_client_get_server_name(const struct xrpc_client *cli) {
  if (!cli) return "";
  return cli->server_name;
}
