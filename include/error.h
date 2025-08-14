#ifndef __ERROR_H
#define __ERROR_H

/*
 * Every call returns 0 as success
 */
#define XRPC_SUCCESS 0

/*
 * Generic errors can be returned from any backend
 * From -1 to -99
 */
#define XRPC_ERR_SOCKET -1
#define XRPC_ERR_BIND -2
#define XRPC_ERR_LISTEN -3
#define XRPC_ERR_ACCEPT -4
#define XRPC_ERR_READ_CONN_CLOSED -5
#define XRPC_ERR_READ -5
#define XRPC_ERR_WRITE -6
#define XRPC_ERR_ALLOC -7
#define XRPC_ERR_ADDRESS -8

/*
 * Unix socket specific errors
 *
 * From -100 to -199
 */
#define XRPC_ERR_UNLINK -100

/*
 * TCP socket specific errors
 *
 * From -200 to -299
 */

/*
 * (mbed)TLS specific errors
 *
 * From -300 to -399
 */
#define XRPC_ERR_HANDSHAKE_FAILED -300
#define XRPC_ERR_INVALID_CERTIFICATE -301
#define XRPC_ERR_INVALID_KEY -302
#define XRPC_ERR_INVALID_SEED -303
#define XRPC_ERR_INVALID_SSL_CONFIG -304
#define XRPC_ERR_SSL_SETUP_FAILED -304

#endif // !__ERROR_H
