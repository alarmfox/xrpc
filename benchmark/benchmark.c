#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "benchmark.h"
#include "xrpc/error.h"

struct xrpc_benchmark_stats g_xrpc_bench_stats = {0};

/*
 * @bried Get thread ID
 */
static inline uint32_t get_thread_id(void) { return gettid(); }

#define MAX_EVENTS 100000000
static struct xrpc_benchmark_event *g_trace_events;
static bool g_bench_initialized = false;
static size_t g_trace_event_index;

/*
 * @brief Init an empty `g_xrpc_bench_stats` struct instance.
 */
int xrpc_benchmark_stats_init(void) {
  if (g_bench_initialized) return XRPC_SUCCESS;

  memset(&g_xrpc_bench_stats, 0, sizeof(struct xrpc_benchmark_stats));

  g_trace_events = malloc(sizeof(struct xrpc_benchmark_event) * MAX_EVENTS);

  if (!g_trace_events) return XRPC_INTERNAL_ERR_ALLOC;

  __atomic_store_n(&g_trace_event_index, 0, __ATOMIC_SEQ_CST);
  g_bench_initialized = true;

  return XRPC_SUCCESS;
}

/*
 * @brief Free `g_xrpc_bench_stats` struct instance.
 */
void xrpc_benchmark_stats_free(void) {
  if (!g_bench_initialized) return;
  if (g_trace_events) {
    free(g_trace_events);
    g_trace_events = NULL;
  }

  g_bench_initialized = false;
}

/*
 * @brief Reset `g_xrpc_bench_stats` struct instance.
 */
void xrpc_benchmark_stats_reset(void) {
  if (!g_bench_initialized) return;

  memset(&g_xrpc_bench_stats, 0, sizeof(struct xrpc_benchmark_stats));
  __atomic_store_n(&g_trace_event_index, 0, __ATOMIC_SEQ_CST);
}

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
                                 const void *data) {

  if (!g_bench_initialized || !g_trace_events) return;

  size_t pos = __atomic_fetch_add(&g_trace_event_index, 1, __ATOMIC_RELAXED);
  uint64_t now = xrpc_benchmark_timestamp_ns();
  struct xrpc_benchmark_event *e = &g_trace_events[pos];

  // dropping event
  if (pos >= MAX_EVENTS) return;

  e->type = type;
  e->timestamp_ns = now;
  e->request_id = req_id;
  e->connection_id = conn_id;
  e->thread_id = get_thread_id();

  // Copy eventual request data
  if (data) {
    memcpy(&e->data, data, sizeof(e->data));
  } else {
    memset(&e->data, 0, sizeof(e->data));
  }
}

/*
 * @brief Copy `g_xrpc_bench_stats` in `s`.
 *
 * @param[in,out] The pointer to the target struct.
 */
void xrpc_benchmark_stats_get(struct xrpc_benchmark_stats *s) {
  if (!s) return;

  // zero out memory
  memset(s, 0, sizeof(struct xrpc_benchmark_stats));

  // Requests metrics
  s->total_requests =
      __atomic_load_n(&g_xrpc_bench_stats.total_requests, __ATOMIC_RELAXED);
  s->completed_requests =
      __atomic_load_n(&g_xrpc_bench_stats.completed_requests, __ATOMIC_RELAXED);
  s->failed_requests =
      __atomic_load_n(&g_xrpc_bench_stats.failed_requests, __ATOMIC_RELAXED);

  // Timing metrics
  s->total_request_time_ns = __atomic_load_n(
      &g_xrpc_bench_stats.total_request_time_ns, __ATOMIC_RELAXED);
  s->total_request_processing_time_ns =
      g_xrpc_bench_stats.total_request_processing_time_ns;
  s->total_request_io_time_ns = __atomic_load_n(
      &g_xrpc_bench_stats.total_request_io_time_ns, __ATOMIC_RELAXED);

  // Connection metrics
  s->total_connections =
      __atomic_load_n(&g_xrpc_bench_stats.total_connections, __ATOMIC_RELAXED);
  s->active_connections =
      __atomic_load_n(&g_xrpc_bench_stats.active_connections, __ATOMIC_RELAXED);

  // I/O operation metrics
  s->total_io_operations = __atomic_load_n(
      &g_xrpc_bench_stats.total_io_operations, __ATOMIC_RELAXED);
}

void xrpc_benchmark_stats_print(const struct xrpc_benchmark_stats *s) {
  if (!s) return;

  printf("\n========================================\n");
  printf("       XRPC Server Benchmark Report     ");
  printf("\n========================================\n");
  printf("  Total requests       : %lu\n", s->total_requests);
  printf("  Completed requests   : %lu\n", s->completed_requests);
  printf("  Failed requests      : %lu\n", s->failed_requests);
  printf("  Total connections    : %lu\n", s->total_connections);
  printf("  Active connections   : %lu\n", s->active_connections);
  printf("  Total I/O operations : %lu\n", s->total_io_operations);
  printf("\n========================================\n");
}
