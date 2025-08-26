#ifndef XRPC_H
#define XRPC_H

#include <netinet/in.h>
#include <stdbool.h>

#include "xrpc/config.h"
#include "xrpc/protocol.h"

/*
 * Request and response frame wrappers to be used in handlers
 */
struct xrpc_request_frame {
  struct xrpc_request_frame_header *header;
  const void *data;
};

struct xrpc_response_frame {
  struct xrpc_response_frame_header *header;
  void *data;
};

/*
 * ==================================================================
 * Server API
 * ==================================================================
 */
struct xrpc_server;

/**
 * @brief RPC handler function signature.
 *
 * @param req  Pointer to the incoming request data.
 * @return 0 on success, nonzero on error.
 */
typedef int (*xrpc_handler_fn)(const struct xrpc_request_frame *rq,
                               struct xrpc_response_frame *rs);

/**
 * @brief Creates and initializes an xrpc server including the underlying
 * transport.
 *
 * @param[out] srv       Pointer to allocated server instance.
 * @param[in]  cfg       Pointer to a valid xrpc_server_config
 *
 * @return 0 on success, -1 on error.
 */
int xrpc_server_init(struct xrpc_server **srv,
                     const struct xrpc_server_config *cfg);

// Register handler flags
enum xrpc_handler_register_flags {
  // Allows user to overwrite an existing handler without giving errors.
  XRPC_RF_OVERWRITE = 1 << 0,
};

/**
 * @brief Register an RPC handler for a given method name.
 *
 * @param srv       Server instance.
 * @param method    Identifier of the operation
 * @param handler   Function pointer to call when method is invoked.
 * @return 0 on success, -1 on error.
 */
int xrpc_server_register(struct xrpc_server *srv, const size_t op,
                         xrpc_handler_fn handler, const int flags);

/**
 * @brief Poll the server for new clients and requests, dispatch handlers, send
 * responses.
 *
 * This call processes one iteration of the server loop: it accepts new clients
 * if available, reads incoming requests, queues them, executes handlers,
 * and sends responses.
 *
 * @param srv         Server instance.
 * @return 0 on success, -1 on fatal error.
 */
int xrpc_server_run(struct xrpc_server *srv);

/**
 * @brief Flags the server to stop if running
 *
 * TODO: make user to choice between a graceful shutdown or to force
 *
 * @param srv         Server instance.
 * @return 0 on success, -1 on fatal error.
 */
void xrpc_server_stop(struct xrpc_server *srv);

/**
 * @brief Release server resources.
 *
 * @param srv  Server instance to free.
 */
void xrpc_server_free(struct xrpc_server *srv);

/*
 * ==================================================================
 * Client API
 * ==================================================================
 * These are the core functions to be used by the client.
 */
struct xrpc_client;

enum xrpc_client_status {
  XRPC_CLIENT_CONNECTED,
  XRPC_CLIENT_DISCONNECTED,
  XRPC_CLIENT_ERROR,
};

/*
 * @brief Creates a client but not does not connect to anything.
 *
 * @param[out] cli  Pointer to allocated client instance.
 * @return 0 on success, -1 on error.
 */
int xrpc_client_init(struct xrpc_client **cli);

/*
 * @brief Connect to an XRPC server.
 *
 * @param[out] cli      Pointer to the client instance.
 * @param[in]  address  Address of the server
 * @param[in]  port     Port of the server
 * @return 0 on success, -1 on error.
 */
int xrpc_client_connect(struct xrpc_client *cli,
                        const struct xrpc_client_config *config);

/*
 * @brief Connect to an XRPC server.
 *
 * @param[in] cli  The client instance.
 * @return 0 on success, -1 on error.
 */
int xrpc_client_disconnect(struct xrpc_client *cli);

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
struct xrpc_response;
int xrpc_client_call_sync(struct xrpc_client *cli, uint8_t op,
                          const void *request_data, size_t request_size,
                          struct xrpc_response_frame **response);

/*
 * @brief Close client and free resources.
 *
 * @param[in] cli Client instance
 */
void xrpc_client_free(struct xrpc_client *cli);

/*
 * @brief Get the current client status
 *
 * @param[in] cli Client instance
 */
enum xrpc_client_status xrpc_client_status_get(const struct xrpc_client *cli);

/*
 * @brief Check if a client is connected
 *
 * @param[in] cli Client instance
 * @param[out] true if the server is connected, false otherwise
 */
bool xrpc_client_is_connected(const struct xrpc_client *cli);

#endif // XRPC_H
