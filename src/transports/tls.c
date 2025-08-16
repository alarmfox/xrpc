#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal/debug.h"
#include "internal/transport.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

struct xrpc_transport_data {
  // Replaces classic Linux sockets
  mbedtls_net_context server_fd;
  mbedtls_net_context client_fd;

  // Random number
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  // SSL context
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;

  // Cert and key
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
};

int xrpc_transport_server_tls_poll_client(struct xrpc_transport *t) {

  int ret;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;

  ret = mbedtls_net_accept(&data->server_fd, &data->client_fd, NULL, 0, NULL);

  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_net_accept", ret,
                                  XRPC_TRANSPORT_ERR_ACCEPT);

  mbedtls_ssl_set_bio(&data->ssl, &data->client_fd, mbedtls_net_send,
                      mbedtls_net_recv, NULL);

  while ((ret = mbedtls_ssl_handshake(&data->ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      _print_mbedtls_err_and_return("mbedtls_ssl_handshake", ret,
                                    XRPC_TRANSPORT_ERR_HANDSHAKE_FAILED);
    }
  }

  return XRPC_SUCCESS;
}

int xrpc_transport_server_tls_recv(struct xrpc_transport *t, void *b,
                                   size_t l) {
  size_t tot_read = 0;
  ssize_t n;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = mbedtls_ssl_read(&data->ssl, tmp, l - tot_read);
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

int xrpc_transport_server_tls_send(struct xrpc_transport *t, const void *b,
                                   size_t l) {
  int n = 0;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;
  unsigned char *tmp = (unsigned char *)b;

  while ((n = mbedtls_ssl_write(&data->ssl, tmp, l)) <= 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_write", n,
                                  XRPC_TRANSPORT_ERR_WRITE);

  return XRPC_SUCCESS;
}

void xrpc_transport_server_tls_release_client(struct xrpc_transport *t) {
  int n;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;

  while ((n = mbedtls_ssl_close_notify(&data->ssl)) < 0) {
    if (n != MBEDTLS_ERR_SSL_WANT_READ && n != MBEDTLS_ERR_SSL_WANT_WRITE &&
        n != MBEDTLS_ERR_NET_CONN_RESET) {
      XRPC_DEBUG_PRINT("mbedtls_ssl_close_notify: %d", n);
    }
  }
  mbedtls_net_free(&data->client_fd);
  mbedtls_ssl_session_reset(&data->ssl);
}

void xrpc_transport_server_free_tls(struct xrpc_transport *t) {
  if (!t) return;
  struct xrpc_transport_data *data = (struct xrpc_transport_data *)t->data;

  mbedtls_net_free(&data->server_fd);
  mbedtls_net_free(&data->client_fd);
  mbedtls_ssl_free(&data->ssl);
  mbedtls_ssl_config_free(&data->conf);
  mbedtls_ctr_drbg_free(&data->ctr_drbg);
  mbedtls_entropy_free(&data->entropy);

  free(data);
  free(t);
}

static const struct xrpc_transport_ops tls_ops = {
    .poll_client = xrpc_transport_server_tls_poll_client,
    .release_client = xrpc_transport_server_tls_release_client,
    .recv = xrpc_transport_server_tls_recv,
    .send = xrpc_transport_server_tls_send,
};

int xrpc_transport_server_init_tls(struct xrpc_transport **s,
                                   const struct xrpc_server_tls_config *args) {
  int ret;
  const char *pers = "ssl_server";
  struct xrpc_transport *t = malloc(sizeof(struct xrpc_transport));
  struct xrpc_transport_data *data = malloc(sizeof(struct xrpc_transport_data));

  if (!t) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);

  // init block
  mbedtls_net_init(&data->server_fd);
  mbedtls_ssl_init(&data->ssl);
  mbedtls_ssl_config_init(&data->conf);
  mbedtls_x509_crt_init(&data->srvcert);
  mbedtls_pk_init(&data->pkey);
  mbedtls_ctr_drbg_init(&data->ctr_drbg);
  mbedtls_entropy_init(&data->entropy);
  t->ops = &tls_ops;

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

  ret = mbedtls_net_bind(&data->server_fd, args->address, args->port,
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

  if ((ret = mbedtls_ssl_setup(&data->ssl, &data->conf)) != 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_setup", ret,
                                  XRPC_TRANSPORT_ERR_SSL_SETUP_FAILED);

  t->data = data;
  *s = t;
  return XRPC_SUCCESS;
}
