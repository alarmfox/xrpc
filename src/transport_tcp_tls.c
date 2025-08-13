#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "transport.h"

#define BACKLOG 5
static void my_debug(void *ctx, int level, const char *file, int line,
                     const char *str) {
  char msg[256];
  ((void)level);
  snprintf(msg, sizeof(msg), "%s:%04d: %s", file, line, str);

  log_message(LOG_LV_DEBUG, msg);
  fflush((FILE *)ctx);
}

#define log_mbedtls_error(MSG, ERR)                                            \
  {                                                                            \
    char msg[256];                                                             \
    char err[100];                                                             \
    mbedtls_strerror(ERR, err, 100);                                           \
    snprintf(msg, sizeof(msg), "mbedtls: %s (%s)", MSG, err);                  \
    log_message(LOG_LV_ERROR, msg);                                            \
  }

struct transport_args {
  struct sockaddr_in sa;
  char *cert_path;
  char *key_path;
};

struct transport {
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

int read_all(mbedtls_ssl_context *ssl, void *buf, ssize_t len);
int write_all(mbedtls_ssl_context *ssl, const void *buf, ssize_t len);

void transport_init(struct transport **s, const void *_args) {
  int ret;
  const char *pers = "ssl_server";
  struct transport_args *args = (struct transport_args *)_args;

  char addr[INET_ADDRSTRLEN];
  char port[6];
  char msg[256];

  // we support IPV4 only for now
  assert(args->sa.sin_family == AF_INET);

  args->sa.sin_addr.s_addr = ntohl(args->sa.sin_addr.s_addr);

  *s = malloc(sizeof(struct transport));
  struct transport *t = *s;

  // convert address and port to string
  if (!inet_ntop(AF_INET, &(args->sa.sin_addr), addr, INET_ADDRSTRLEN)) {
    log_message(LOG_LV_ERROR, "cannot convert ip address to char*");
    goto exit;
  }

  snprintf(port, sizeof(port), "%d", args->sa.sin_port);

  snprintf(msg, sizeof(msg), "binding on %s:%s", addr, port);
  log_message(LOG_LV_INFO, msg);

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

  if (ret != 0) {
    log_mbedtls_error("mbedtls_ctr_drbg_seed", ret);
    goto exit;
  }

  ret = mbedtls_x509_crt_parse_file(&t->srvcert, args->cert_path);
  if (ret != 0) {
    log_mbedtls_error("mbedtls_x509_crt_parse_file", ret);
    goto exit;
  }

  ret = mbedtls_pk_parse_keyfile(&t->pkey, args->key_path, NULL, 0, 0);
  if (ret != 0) {
    log_mbedtls_error("mbedtls_pk_parse_keyfile", ret);
    goto exit;
  }

  ret = mbedtls_net_bind(&t->server_fd, addr, port, MBEDTLS_NET_PROTO_TCP);

  if (ret != 0) {
    log_mbedtls_error("mbedtls_net_bind", ret);
    goto exit;
  }

  ret = mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_SERVER,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);

  if (ret != 0) {
    log_mbedtls_error("mbedtls_ssl_config_defaults", ret);
    goto exit;
  }

  mbedtls_ssl_conf_rng(&t->conf, mbedtls_ctr_drbg_random, &t->ctr_drbg);
  mbedtls_ssl_conf_ca_chain(&t->conf, t->srvcert.next, NULL);
  mbedtls_ssl_conf_dbg(&t->conf, my_debug, stdout);

  if ((ret = mbedtls_ssl_conf_own_cert(&t->conf, &t->srvcert, &t->pkey)) != 0) {
    log_mbedtls_error("mbedtls_ssl_conf_own_cert", ret);
    goto exit;
  }
  if ((ret = mbedtls_ssl_setup(&t->ssl, &t->conf)) != 0) {
    log_mbedtls_error("mbedtls_ssl_setup", ret);
    goto exit;
  }

  return;

exit:
  mbedtls_net_free(&t->server_fd);
  mbedtls_net_free(&t->server_fd);
  mbedtls_ssl_free(&t->ssl);
  mbedtls_ssl_config_free(&t->conf);
  mbedtls_ctr_drbg_free(&t->ctr_drbg);
  mbedtls_entropy_free(&t->entropy);

  exit(EXIT_FAILURE);
}

int transport_recv(struct transport *s, struct request *r) {
  int ret;

  ret = mbedtls_net_accept(&s->server_fd, &s->client_fd, NULL, 0, NULL);

  if (ret != 0) {
    log_mbedtls_error("mbedtls_net_accept", ret);
    return ret;
  }

  mbedtls_ssl_set_bio(&s->ssl, &s->client_fd, mbedtls_net_send,
                      mbedtls_net_recv, NULL);

  while ((ret = mbedtls_ssl_handshake(&s->ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      log_mbedtls_error("mbedtls_ssl_handshake", ret);
      return ret;
    }
  }

  if (read_all(&s->ssl, (void *)r, sizeof(struct request)) < 0) {
    log_message(LOG_LV_ERROR, "error during receive");
    return -1;
  }

  unmarshal_req(r);
  return 0;
}

int transport_send(struct transport *s, struct response *r) {
  int n = 0;

  marshal_res(r);

  if (write_all(&s->ssl, (const void *)r, sizeof(struct response)) < 0) {
    log_error("error in sending request");
    return -1;
  }

  while ((n = mbedtls_ssl_close_notify(&s->ssl)) < 0) {
    if (n != MBEDTLS_ERR_SSL_WANT_READ && n != MBEDTLS_ERR_SSL_WANT_WRITE &&
        n != MBEDTLS_ERR_NET_CONN_RESET) {
      char msg[128];
      snprintf(msg, sizeof(msg), "mbedtls_ssl_close_notify: 0x%x",
               (unsigned int)n);
      log_message(LOG_LV_ERROR, msg);
      return -1;
    }
  }
  mbedtls_net_free(&s->client_fd);

  mbedtls_ssl_session_reset(&s->ssl);
  return 0;
}

void transport_free(struct transport *s) {
  mbedtls_net_free(&s->server_fd);
  mbedtls_net_free(&s->client_fd);
  mbedtls_ssl_free(&s->ssl);
  mbedtls_ssl_config_free(&s->conf);
  mbedtls_ctr_drbg_free(&s->ctr_drbg);
  mbedtls_entropy_free(&s->entropy);

  free(s);
  s = NULL;
}

int read_all(mbedtls_ssl_context *fd, void *buf, ssize_t len) {
  ssize_t tot_read = 0, n;
  unsigned char *tmp = (unsigned char *)buf;
  char msg[128];

  do {
    n = mbedtls_ssl_read(fd, tmp + tot_read, len - tot_read);
    if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }
    if (n <= 0) {
      switch (n) {
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
        log_message(LOG_LV_DEBUG, " connection was closed gracefully");
        break;

      case MBEDTLS_ERR_NET_CONN_RESET:
        log_message(LOG_LV_DEBUG, " connection was reset by peer");
        break;

      default:
        snprintf(msg, sizeof(msg), "mbedtls_ssl_read error: -0x%x",
                 (unsigned int)n);
        log_message(LOG_LV_ERROR, msg);
        break;
      }

      break;
    }

    tot_read += n;
  } while ((tot_read < len) && n != EOF);

  return tot_read == len ? len : -1;
}

int write_all(mbedtls_ssl_context *fd, const void *buf, ssize_t len) {
  int ret;
  unsigned char *tmp = (unsigned char *)buf;

  while ((ret = mbedtls_ssl_write(fd, tmp, len)) <= 0) {
    if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
      log_message(LOG_LV_ERROR,
                  "mbedtls_ssl_write: peer closed the connection");
      return ret;
    }

    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      char msg[128];
      snprintf(msg, sizeof(msg), "mbedtls_ssl_write: %d", (int)ret);
      log_message(LOG_LV_ERROR, msg);
      return ret;
    }
  }

  return 0;
}
