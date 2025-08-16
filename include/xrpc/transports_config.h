#ifndef __TRANSPORTS_CONFIG__
#define __TRANSPORTS_CONFIG__

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

/**
 * @brief Unix transport configuration struct.
 *
 * Unix transport configuration struct. Contains sockaddr_un which contains the
 * path for the socket.
 *
 */
struct xrpc_unix_server_config {
  struct sockaddr_un addr;
};

/**
 * @brief TCP transport configuration struct.
 *
 * TCP transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port.
 */
struct xrpc_tcp_server_config {
  struct sockaddr_in addr;
};

/**
 * @brief TLS transport configuration struct.
 *
 * TLS transport configuration struct. Contains sockaddr_in which contains IPv4
 * and port and the path to the certificate and the private key.
 */
struct xrpc_tls_server_config {
  const char *address;
  const char *port;
  const char *crt_path;
  const char *key_path;
};

#endif // !__TRANSPORTS_CONFIG__
