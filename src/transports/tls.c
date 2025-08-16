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

struct xrpc_transport {
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

int xrpc_transport_server_init_tls(struct xrpc_transport **s,
                                   const struct xrpc_tls_server_config *args) {
  int ret;
  const char *pers = "ssl_server";
  struct xrpc_transport *t = NULL;

  *s = malloc(sizeof(struct xrpc_transport));

  if (!*s) _print_err_and_return("malloc error", XRPC_API_ERR_ALLOC);

  t = *s;

  // init block
  mbedtls_net_init(&t->server_fd);
  mbedtls_ssl_init(&t->ssl);
  mbedtls_ssl_config_init(&t->conf);
  mbedtls_x509_crt_init(&t->srvcert);
  mbedtls_pk_init(&t->pkey);
  mbedtls_ctr_drbg_init(&t->ctr_drbg);
  mbedtls_entropy_init(&t->entropy);

  ret = mbedtls_ctr_drbg_seed(&t->ctr_drbg, mbedtls_entropy_func, &t->entropy,

                              (unsigned char *)pers, strlen(pers));

  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_ctr_drbg_seed", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_SEED);

  ret = mbedtls_x509_crt_parse_file(&t->srvcert, args->crt_path);
  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_x509_crt_parse_file", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_CERTIFICATE);

  ret = mbedtls_pk_parse_keyfile(&t->pkey, args->key_path, NULL, 0, 0);
  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_pk_parse_keyfile", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_KEY);

  ret = mbedtls_net_bind(&t->server_fd, args->address, args->port,
                         MBEDTLS_NET_PROTO_TCP);

  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_net_bind", ret,
                                  XRPC_TRANSPORT_ERR_BIND);

  ret = mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);

  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_config_defaults", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_SSL_CONFIG);

  mbedtls_ssl_conf_rng(&t->conf, mbedtls_ctr_drbg_random, &t->ctr_drbg);
  mbedtls_ssl_conf_ca_chain(&t->conf, t->srvcert.next, NULL);

  if ((ret = mbedtls_ssl_conf_own_cert(&t->conf, &t->srvcert, &t->pkey)) != 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_conf_own_cert", ret,
                                  XRPC_TRANSPORT_ERR_INVALID_CERTIFICATE);

  if ((ret = mbedtls_ssl_setup(&t->ssl, &t->conf)) != 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_setup", ret,
                                  XRPC_TRANSPORT_ERR_SSL_SETUP_FAILED);

  return XRPC_SUCCESS;
}

int transport_poll_client(struct xrpc_transport *t) {

  int ret;

  ret = mbedtls_net_accept(&t->server_fd, &t->client_fd, NULL, 0, NULL);

  if (ret != 0)
    _print_mbedtls_err_and_return("mbedtls_net_accept", ret,
                                  XRPC_TRANSPORT_ERR_ACCEPT);

  mbedtls_ssl_set_bio(&t->ssl, &t->client_fd, mbedtls_net_send,
                      mbedtls_net_recv, NULL);

  while ((ret = mbedtls_ssl_handshake(&t->ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      _print_mbedtls_err_and_return("mbedtls_ssl_handshake", ret,
                                    XRPC_TRANSPORT_ERR_HANDSHAKE_FAILED);
    }
  }

  return XRPC_SUCCESS;
}

int transport_recv(struct xrpc_transport *t, void *b, size_t l) {
  size_t tot_read = 0;
  ssize_t n;
  unsigned char *tmp = (unsigned char *)b;

  do {
    n = mbedtls_ssl_read(&t->ssl, tmp, l - tot_read);
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

int transport_send(struct xrpc_transport *t, const void *b, size_t l) {
  int n = 0;

  unsigned char *tmp = (unsigned char *)b;

  while ((n = mbedtls_ssl_write(&t->ssl, tmp, l)) <= 0)
    _print_mbedtls_err_and_return("mbedtls_ssl_write", n,
                                  XRPC_TRANSPORT_ERR_WRITE);

  return XRPC_SUCCESS;
}

void transport_release_client(struct xrpc_transport *t) {
  int n;

  while ((n = mbedtls_ssl_close_notify(&t->ssl)) < 0) {
    if (n != MBEDTLS_ERR_SSL_WANT_READ && n != MBEDTLS_ERR_SSL_WANT_WRITE &&
        n != MBEDTLS_ERR_NET_CONN_RESET) {
      XRPC_DEBUG_PRINT("mbedtls_ssl_close_notify: %d", n);
    }
  }
  mbedtls_net_free(&t->client_fd);

  mbedtls_ssl_session_reset(&t->ssl);
}

void xrpc_transport_server_free_tls(struct xrpc_transport *t) {
  if (!t) return;
  mbedtls_net_free(&t->server_fd);
  mbedtls_net_free(&t->client_fd);
  mbedtls_ssl_free(&t->ssl);
  mbedtls_ssl_config_free(&t->conf);
  mbedtls_ctr_drbg_free(&t->ctr_drbg);
  mbedtls_entropy_free(&t->entropy);

  free(t);
}
