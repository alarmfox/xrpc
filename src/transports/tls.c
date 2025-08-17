#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/transport.h"
#include "xrpc/xrpc.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

const struct xrpc_transport_ops xrpc_transport_tls_ops;

struct xrpc_transport_data {
  // Replaces classic Linux sockets
  mbedtls_net_context fd;

  // Random number
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  // SSL context
  mbedtls_ssl_config conf;

  // Cert and key
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
};

struct xrpc_transport_connection {
  mbedtls_ssl_context ssl;
  mbedtls_net_context fd;
};

static int
xrpc_transport_server_tls_init(struct xrpc_transport **s,
                               const struct xrpc_server_config *conf) {
  int ret;
  const char *pers = "ssl_server";
  const struct xrpc_server_tls_config *args = &conf->config.tls;
  struct xrpc_transport *t = malloc(sizeof(struct xrpc_transport));
  struct xrpc_transport_data *data = malloc(sizeof(struct xrpc_transport_data));

  if (!t) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);

  // init block
  mbedtls_net_init(&data->fd);
  mbedtls_ssl_config_init(&data->conf);
  mbedtls_x509_crt_init(&data->srvcert);
  mbedtls_pk_init(&data->pkey);
  mbedtls_ctr_drbg_init(&data->ctr_drbg);
  mbedtls_entropy_init(&data->entropy);
  t->ops = &xrpc_transport_tls_ops;

  ret = mbedtls_ctr_drbg_seed(&data->ctr_drbg, mbedtls_entropy_func,
                              &data->entropy,

                              (unsigned char *)pers, strlen(pers));

  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_ctr_drbg_seed", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_SEED);

  ret = mbedtls_x509_crt_parse_file(&data->srvcert, args->crt_path);
  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_x509_crt_parse_file", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_CERTIFICATE);

  ret = mbedtls_pk_parse_keyfile(&data->pkey, args->key_path, NULL, 0, 0);
  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_pk_parse_keyfile", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_KEY);

  ret = mbedtls_net_bind(&data->fd, args->address, args->port,
                         MBEDTLS_NET_PROTO_TCP);

  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_net_bind", ret,
                                  XRPC_TRANSPORT_ERR_BIND);

  ret = mbedtls_ssl_config_defaults(&data->conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);

  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_config_defaults", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_SSL_CONFIG);

  mbedtls_ssl_conf_rng(&data->conf, mbedtls_ctr_drbg_random, &data->ctr_drbg);
  mbedtls_ssl_conf_ca_chain(&data->conf, data->srvcert.next, NULL);

  if ((ret = mbedtls_ssl_conf_own_cert(&data->conf, &data->srvcert,
                                       &data->pkey)) != 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_conf_own_cert", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_CERTIFICATE);

  t->data = data;
  *s = t;
  return XRPC_SUCCESS;
}

static int xrpc_transport_server_tls_accept_connection(
    struct xrpc_transport *t, struct xrpc_transport_connection **conn) {

  int ret;
  mbedtls_net_context fd;
  mbedtls_ssl_context ssl;
  struct xrpc_transport_connection *c = NULL;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;

  if ((ret = mbedtls_ssl_setup(&ssl, &data->conf)) != 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_setup", ret,
                                  XRPC_TRANSPORT_ERR_SSL_SETUP_FAILED);
  mbedtls_net_init(&fd);
  mbedtls_ssl_init(&ssl);

  ret = mbedtls_net_accept(&data->fd, &fd, NULL, 0, NULL);

  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_net_accept", ret,
                                  XRPC_TRANSPORT_ERR_ACCEPT);

  mbedtls_ssl_set_bio(&ssl, &fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      _print_mbedtls_err_and_return("mbedtls_ssl_handshake", ret,
                                    XRPC_TRANSPORT_ERR_HANDSHAKE_FAILED);
    }
  }

  c = malloc(sizeof(struct xrpc_transport_connection));
  c->fd = fd;
  c->ssl = ssl;

  *conn = c;

  return XRPC_SUCCESS;
}

static int
xrpc_transport_server_tls_recv(struct xrpc_transport_connection *conn, void *b,
                               size_t l) {
  size_t tot_read = 0;
  ssize_t n;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = mbedtls_ssl_read(&conn->ssl, tmp, l - tot_read);
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }
    if (n <= 0) {
      switch (n) {
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        _print_err_and_return("connection closed by the peer",
                              XRPC_TRANSPORT_ERR_READ_CONN_CLOSED);

      case MBEDTLS_ERR_NET_CONN_RESET:
        _print_err_and_return("connection reset by the peer",
                              XRPC_TRANSPORT_ERR_READ_CONN_CLOSED);

      case 0:
        _print_err_and_return("connection closed",
                              XRPC_TRANSPORT_ERR_READ_CONN_CLOSED);

      default:
        _print_mbedtls_err_and_return("mbedtls_ssl_read", (int)n,
                                      XRPC_TRANSPORT_ERR_READ);
      }

      break;
    }

    tot_read += n;
  } while (tot_read < l);

  return XRPC_SUCCESS;
}

static int
xrpc_transport_server_tls_send(struct xrpc_transport_connection *conn,
                               const void *b, size_t l) {
  int n = 0;
  unsigned char *tmp = (unsigned char *)b;

  while ((n = mbedtls_ssl_write(&conn->ssl, tmp, l)) <= 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_write", n,
                                  XRPC_TRANSPORT_ERR_WRITE);

  return XRPC_SUCCESS;
}

static void xrpc_transport_server_tls_close_connection(
    struct xrpc_transport_connection *conn) {
  int n;

  while ((n = mbedtls_ssl_close_notify(&conn->ssl)) < 0) {
    if (n != MBEDTLS_ERR_SSL_WANT_READ && n != MBEDTLS_ERR_SSL_WANT_WRITE &&
        n != MBEDTLS_ERR_NET_CONN_RESET) {
      XRPC_DEBUG_PRINT("mbedtls_ssl_close_notify: %d", n);
    }
  }
  mbedtls_net_free(&conn->fd);
  mbedtls_ssl_session_reset(&conn->ssl);

  free(conn);
}

static void xrpc_transport_server_tls_free(struct xrpc_transport *t) {
  if (!t) return;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;

  mbedtls_net_free(&data->fd);
  mbedtls_ssl_config_free(&data->conf);
  mbedtls_ctr_drbg_free(&data->ctr_drbg);
  mbedtls_entropy_free(&data->entropy);

  free(data);
  free(t);
}

const struct xrpc_transport_ops xrpc_transport_tls_ops = {
    .init = xrpc_transport_server_tls_init,
    .free = xrpc_transport_server_tls_free,
    .accept_connection = xrpc_transport_server_tls_accept_connection,
    .close_connection = xrpc_transport_server_tls_close_connection,
    .recv = xrpc_transport_server_tls_recv,
    .send = xrpc_transport_server_tls_send,
};
