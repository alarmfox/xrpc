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
// static int send_exact_n(struct xrpc_client_connection *conn, const void *buf,
//                         size_t len) {
//   if (!conn || !buf || len == 0) { return XRPC_CLIENT_ERR_INVALID_CONFIG; }
//
//   size_t bytes_written = 0, total_written = 0;
//   int ret = XRPC_SUCCESS;
//   const uint8_t *data = (const uint8_t *)buf;
//
//   while (total_written < len) {
//     ret = conn->ops->send(conn, data + total_written, len - total_written,
//                           &bytes_written);
//
//     if (ret == XRPC_TRANSPORT_ERR_WOULD_BLOCK) {
//       // For blocking client, we should not get this, but handle gracefully
//       continue;
//     } else if (ret != XRPC_SUCCESS) {
//       XRPC_DEBUG_PRINT("send failed: %d", ret);
//       return ret;
//     }
//
//     total_written += bytes_written;
//     bytes_written = 0; // Reset for next iteration
//   }
//
//   return XRPC_SUCCESS;
// }
//
// /*
//  * Helper function to receive exactly n bytes
//  */
// static int recv_exact_n(struct xrpc_client_connection *conn, void *buf,
//                         size_t len) {
//   if (!conn || !buf || len == 0) { return XRPC_CLIENT_ERR_INVALID_CONFIG; }
//
//   size_t bytes_read = 0, total_read = 0;
//   int ret = XRPC_SUCCESS;
//   uint8_t *data = (uint8_t *)buf;
//
//   while (total_read < len) {
//     ret =
//         conn->ops->recv(conn, data + total_read, len - total_read,
//         &bytes_read);
//
//     if (ret == XRPC_TRANSPORT_ERR_WOULD_BLOCK) {
//       // For blocking client, we should not get this, but handle gracefully
//       continue;
//     } else if (ret != XRPC_SUCCESS) {
//       XRPC_DEBUG_PRINT("recv failed: %d", ret);
//       return ret;
//     }
//
//     total_read += bytes_read;
//     bytes_read = 0; // Reset for next iteration
//   }
//
//   return XRPC_SUCCESS;
// }
//
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
                        const struct xrpc_client_config *config) {
  if (!cli || !config) return XRPC_CLIENT_ERR_INVALID_CONFIG;

  // Check if already connected
  if (cli->status == XRPC_CLIENT_CONNECTED) { return XRPC_SUCCESS; }

  // Validate transport type
  if ((size_t)config->type >=
          sizeof(connection_ops_map) / sizeof(connection_ops_map[0]) ||
      !connection_ops_map[config->type]) {
    cli->last_error = XRPC_CLIENT_ERR_INVALID_TRANSPORT;
    cli->status = XRPC_CLIENT_ERROR;
    return XRPC_CLIENT_ERR_INVALID_TRANSPORT;
  }

  // Get transport operations
  const struct xrpc_client_connection_ops *ops =
      connection_ops_map[config->type];

  // Attempt connection
  int ret = ops->connect(&cli->conn, config);
  if (ret != XRPC_SUCCESS) {
    cli->last_error = ret;
    cli->status = XRPC_CLIENT_ERROR;
    XRPC_DEBUG_PRINT("connection failed: %d", ret);
    return ret;
  }

  cli->status = XRPC_CLIENT_CONNECTED;
  cli->last_error = XRPC_SUCCESS;

  return XRPC_SUCCESS;
}

/*
 * @brief Perform a synchronous RPC call. Since the protocol is batch-aware a
 * synchronous request means creating a batch with size 1, send a single frame
 * request and wait for the repsonse.
 *
 * @param[in] cli           Client instance.
 * @param[in] op            Operation ID
 * @param[in] request_data  Pointer to request payload (can be NULL)
 * @param[in] request_size  Size of request payload
 * @param[out] response     Pointer to allocated response (caller must free)
 * @return XRPC_SUCCESS on success, error code on failure.
 */
int xrpc_client_call_sync(struct xrpc_client *cli, uint8_t op,
                          const void *request_data, size_t request_size,
                          struct xrpc_response_frame **out_resp) {
  (void)cli;
  (void)op;
  (void)request_data;
  (void)request_size;
  (void)out_resp;
  if (!cli) return XRPC_API_ERR_INVALID_ARGS;

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

  return XRPC_SUCCESS;
}
