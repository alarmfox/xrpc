#ifndef XRPC_ERROR_H
#define XRPC_ERROR_H

/*
 * Every call returns 0 as success
 */

#define XRPC_SUCCESS 0
#define XRPC_TRANSPORT_WOULD_BLOCK 1

/*
 * RPC API Server errors
 *
 * From -1 to - 99
 */

#define XRPC_API_ERR_ALLOC -1
#define XRPC_API_ERR_BAD_OPID -2
#define XRPC_API_ERR_HANDLER_ALREADY_REGISTERED -3
#define XRPC_API_ERR_INVALID_TRANSPORT -4
#define XRPC_API_ERR_INVALID_ARGS -5

/*
 * Transport related errors
 */

/*
 * Generic errors can be returned from any transport backend
 * From -100 to -199
 */
#define XRPC_TRANSPORT_ERR_SOCKET -100
#define XRPC_TRANSPORT_ERR_BIND -101
#define XRPC_TRANSPORT_ERR_LISTEN -102
#define XRPC_TRANSPORT_ERR_ACCEPT -103
#define XRPC_TRANSPORT_ERR_CONN_CLOSED -104
#define XRPC_TRANSPORT_ERR_READ -105
#define XRPC_TRANSPORT_ERR_WRITE -106
#define XRPC_TRANSPORT_ERR_ADDRESS -107
#define XRPC_TRANSPORT_ERR_CONNECT -108

/*
 * Unix socket specific errors
 *
 * From -200  to -299
 */
#define XRPC_TRANSPORT_ERR_UNLINK -200

/*
 * TCP socket specific errors
 *
 * From -300 to -399
 */

/*
 * (mbed)TLS specific errors
 *
 * From -400 to -499
 */
#define XRPC_TRANSPORT_ERR_HANDSHAKE_FAILED -400
#define XRPC_TRANSPORT_ERR_INVALID_CERTIFICATE -401
#define XRPC_TRANSPORT_ERR_INVALID_KEY -402
#define XRPC_TRANSPORT_ERR_INVALID_SEED -403
#define XRPC_TRANSPORT_ERR_INVALID_SSL_CONFIG -404
#define XRPC_TRANSPORT_ERR_SSL_SETUP_FAILED -405

/*
 * Blocking I/O system specific errors
 *
 * From -500 to -599
 *
 */
#define XRPC_IO_SYSTEM_ERR_UNSUPPORTED_OPERATION -500

/*
 * Internal errors. These are from ringbuffer, workers and other components non
 * exposed to the user
 *
 * From -600 to -699
 */
#define XRPC_INTERNAL_ERR_ALLOC -600
#define XRPC_INTERNAL_ERR_RINGBUF_FULL -601
#define XRPC_INTERNAL_ERR_RINGBUF_EMPTY -602
#define XRPC_INTERNAL_ERR_RINGBUF_INVALID_ARG -603
#define XRPC_INTERNAL_ERR_POOL_INVALID_ARG -604
#define XRPC_INTERNAL_ERR_POOL_FULL -605
#define XRPC_INTERNAL_ERR_POOL_EMPTY -606
#define XRPC_INTERNAL_ERR_INVALID_CONN -607

#endif // !XRPC_ERROR_H
