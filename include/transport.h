#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#include <stddef.h>

struct transport;

/**
 * @brief Initialize a transport instance.
 *
 * This function allocates and initializes the transport backend for a given
 * implementation (TCP, UNIX socket, TLS, etc.). It sets up the listening
 * socket and prepares the transport for accepting client connections.
 *
 * @param[out] t     Pointer to a transport pointer to be allocated and
 * initialized.
 * @param[in]  args  Pointer to a transport-specific configuration struct.
 *                   The type of this struct depends on the transport backend
 *                   (e.g., struct transport_args for TCP/UNIX).
 *
 * @retval  0   Success
 * @retval -1   Error
 */
int transport_init(struct transport **t, const void *args);

/**
 * @brief Accept a new client connection if available.
 *
 * This function checks for an incoming connection on the listening socket.
 * If a new client is waiting, it accepts the connection and stores its state
 * inside the transport object.
 *
 * This call may block depending on the transport implementation and socket
 * mode.
 *
 * @param[in,out] t  Pointer to the transport instance.
 *
 * @retval  0  A new client was successfully accepted.
 * @retval -1  No new client available or an error occurred.
 */
int transport_poll_client(struct transport *t);

/*
 * @brief Release the client
 *
 * Frees the current client. Must be called after every connection
 *
 * @param[in,out] t  Pointer to the transport instance.
 */
void transport_release_client(struct transport *t);

/**
 * @brief Receive a request from the connected client.
 *
 * Reads a complete `struct request` from the currently connected client.
 * This function blocks until the full request is received or an error occurs.
 *
 * @param[in,out] t   Pointer to the transport instance.
 * @param[out] buf    Pointer to buffer to store received bytes.
 * @param[in]  len    Number of bytes to read.
 *
 * @retval  0  Request successfully received.
 * @retval -1  An error occurred (including client disconnection).
 */
int transport_recv(struct transport *t, void *buf, size_t len);

/**
 * @brief Send a response to the connected client.
 *
 * Writes a complete `struct response` to the currently connected client.
 * The function will marshal the response into network byte order before
 * sending.
 *
 * @param[in,out] t  Pointer to the transport instance.
 * @param[in]  buf   Pointer to buffer containing data to send.
 * @param[in]  len   Number of bytes to send.
 *
 * @retval  0  Response successfully sent.
 * @retval -1  An error occurred while sending.
 */
int transport_send(struct transport *t, const void *buf, size_t len);

/**
 * @brief Free transport resources.
 *
 * Closes any active client and listening sockets, releases all allocated
 * memory, and resets the transport pointer.
 *
 * @param[in,out] t  Pointer to the transport instance to free. Will be set to
 * NULL.
 *
 * @return void
 */
void transport_free(struct transport *t);

#endif // !__TRANSPORT_H
