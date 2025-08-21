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
 * -  I/O system performance
 * - transport system performance
 *
 * System performance (eg. Linux, CPU) will be evauluated using eBPF and perf
 * tools.
 */

enum xrpc_benchmark_event_type {
  XRPC_BENCH_EV_CONN_ACCEPT = 0,
  XRPC_BENCH_EV_CONN_CLOSE,

};

struct xrpc_benchmark_event {
  enum xrpc_benchmark_event_type type;
  uint64_t request_id;
  uint64_t connection_id;
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
 * @brief Init an empty `g_xrpc_bench_stats`.
 *
 */
void xrpc_benchmark_stats_init(void);

/*
 * @brief Clean up the `g_xrpc_bench_stats` struct.
 */
void xrpc_benchmark_stats_free(void);

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

#endif // !XRPC_BENCHMARK_H
