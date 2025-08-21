#ifndef XRPC_BENCHMARK_H
#define XRPC_BENCHMARK_H

#include <stdint.h>
#include <time.h>

/*
 * This module define tools to perform microbenchmark to get internal insight on
 * the server. It defines tools and macros to instrument the code. The main idea
 * is to record different metrics like:
 *
 * - memory allocations;
 * - I/O system performance
 * - transport system performance
 *
 * System performance (eg. Linux, CPU) will be evauluated using eBPF and perf
 * tools.
 */

enum xrpc_benchmark_event_type {
  XRPC_BENCH_EV_CONN_ACCEPT = 0,
  XRPC_BENCH_EV_CONN_CLOSE,
  XRPC_BENCH_EV_REQ_START,
  XRPC_BENCH_EV_REQ_END,

};

struct xrpc_benchmark_event {
  enum xrpc_benchmark_event_type type;
  uint64_t timestamp_ns;
  uint64_t request_id;
  uint64_t connection_id;
  uint32_t thread_id;

  union {

    uint64_t raw[2];
  } data;
};

struct xrpc_benchmark_stats {
  // Requests metrics
  uint64_t total_requests;
  uint64_t completed_requests;
  uint64_t failed_requests;

  // Timing metrics
  uint64_t total_request_time_ns;
  uint64_t total_request_processing_time_ns;
  uint64_t total_request_io_time_ns;

  // Connection metrics
  uint64_t total_connections;
  uint64_t active_connections;

  // I/O operation metrics
  uint64_t total_io_operations;
};

extern struct xrpc_benchmark_stats g_xrpc_bench_stats;

/*
 * Benchmark Core API
 *
 * These are functions to access and manipulate the g_xrpc_bench_stats struct.
 */

/*
 * @brief Init an empty `g_xrpc_bench_stats` struct instance.
 *
 * @return XRPC_SUCCESS if succesfull
 * @return XRPC_INTERAL_ERR_ALLOC on failure
 */
int xrpc_benchmark_stats_init(void);

/*
 * @brief Free `g_xrpc_bench_stats` struct instance.
 */
void xrpc_benchmark_stats_free(void);

/*
 * @brief Reset `g_xrpc_bench_stats` struct instance.
 */
void xrpc_benchmark_stats_reset(void);

/*
 * @brief Record a new event
 *
 * @param[in] type    Type of the event to be recorded
 * @param[in] conn_id Connection id
 * @param[in] req_id  Request id
 * @param[in] data    Data of the event (changes based on event type)
 */
void xrpc_benchmark_event_record(enum xrpc_benchmark_event_type type,
                                 const uint64_t conn_id, const uint64_t req_id,
                                 const void *data);
/*
 * @brief Copy `g_xrpc_bench_stats` in `s`.
 *
 * @param[in,out]s  The pointer to the target struct.
 */
void xrpc_benchmark_stats_get(struct xrpc_benchmark_stats *s);

/*
 * @brief Prints stats in s;

 * @param[in]s      The pointer to the target struct.
 */

void xrpc_benchmark_stats_print(const struct xrpc_benchmark_stats *s);
/*
 * @brief Get current high-resolution timestamp in nanoseconds
 *
 * @return Timestamp in nanoseconds
 */
static inline uint64_t xrpc_benchmark_timestamp_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Function implementation based on the -DBENCHMARK.
 */
#ifdef BENCHMARK

#define XRPC_BENCH_COUNTER_INC(c)                                              \
  do {                                                                         \
    __atomic_fetch_add(&g_xrpc_bench_stats.c, 1, __ATOMIC_RELAXED);            \
  } while (0)
#define XRPC_BENCH_COUNTER_SUB(c)                                              \
  do {                                                                         \
    __atomic_fetch_sub(&g_xrpc_bench_stats.c, 1, __ATOMIC_RELAXED);            \
  } while (0)

#define XRPC_BENCH_EV_RECORD(type, connid, reqid, data)                        \
  do {                                                                         \
    xrpc_benchmark_event_record(type, connid, reqid, data);                    \
  } while (0)

#else

#define XRPC_BENCH_COUNTER_INC(c) ((void)0);
#define XRPC_BENCH_COUNTER_SUB(c) ((void)0);

#define XRPC_BENCH_EV_RECORD(type, connid, reqid, data)                        \
  do {                                                                         \
  } while (0)

#endif // BENCHMARK

/*
 * Utilities to benchmark particular events
 */
#define XRPC_BENCH_CONN_ACCEPT(connid)                                         \
  XRPC_BENCH_COUNTER_INC(total_connections);                                   \
  XRPC_BENCH_COUNTER_INC(active_connections);                                  \
  XRPC_BENCH_EV_RECORD(XRPC_BENCH_EV_CONN_ACCEPT, connid, 0, 0);

#define XRPC_BENCH_CONN_CLOSE(connid)                                          \
  XRPC_BENCH_COUNTER_SUB(active_connections);                                  \
  XRPC_BENCH_EV_RECORD(XRPC_BENCH_EV_CONN_CLOSE, connid, 0, 0);

#define XRPC_BENCH_REQ_START(connid, reqid)                                    \
  XRPC_BENCH_COUNTER_INC(total_requests);                                      \
  XRPC_BENCH_EV_RECORD(XRPC_BENCH_EV_REQ_START, connid, reqid, 0);

#define XRPC_BENCH_REQ_CLOSE_SUCC(connid, reqid)                               \
  do {                                                                         \
    XRPC_BENCH_COUNTER_INC(total_requests);                                    \
    XRPC_BENCH_COUNTER_INC(completed_requests);                                \
    XRPC_BENCH_EV_RECORD(XRPC_BENCH_EV_REQ_END, connid, reqid, 0);             \
  } while (0)

#define XRPC_BENCH_REQ_CLOSE_ERR(connid, reqid)                                \
  do {                                                                         \
    XRPC_BENCH_COUNTER_INC(total_requests);                                    \
    XRPC_BENCH_COUNTER_INC(failed_requests);                                   \
    XRPC_BENCH_EV_RECORD(XRPC_BENCH_EV_REQ_END, connid, reqid, 0);             \
  } while (0)

#define XRPC_BENCH_IO_OP_TRACE(connid, reqid)                                  \
  do {                                                                         \
    XRPC_BENCH_COUNTER_INC(total_io_operations);                               \
  } while (0)
#endif // !XRPC_BENCHMARK_H
