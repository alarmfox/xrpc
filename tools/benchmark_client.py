"""
XRPC Benchmark Client

This script benchmarks the XRPC server with various workloads and measures:
- Request latency (p50, p95, p99, max)
- Throughput (requests per second)
- Connection performance
- Memory usage patterns
"""

import argparse
import json
import random
import socket
import struct
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional, Tuple

# Operation IDs (must match server)
OP_ECHO = 0x0

# Response status codes
XRPC_RESPONSE_SUCCESS = 1 << 0
XRPC_RESPONSE_INTERNAL_ERROR = 1 << 1
XRPC_RESPONSE_UNSUPPORTED_HANDLER = 1 << 2
XRPC_RESPONSE_INVALID_PARAMS = 1 << 3


@dataclass
class BenchmarkConfig:
    """Benchmark configuration parameters."""

    server_host: str = "localhost"
    server_port: int = 9000
    duration_seconds: int = 30
    num_connections: int = 10
    request_rate_per_connection: Optional[int] = None  # None = unlimited
    warmup_seconds: int = 5
    operation: str = "ping"
    payload_size: int = 64
    output_file: Optional[str] = None
    verbose: bool = False


@dataclass
class RequestResult:
    """Result of a single request."""

    latency_ns: int
    success: bool
    error_msg: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0


class XRPCClient:
    """High-performance XRPC client for benchmarking."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None

    def connect(self) -> bool:
        """Connect to the XRPC server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from the server."""
        if self.socket:
            self.socket.close()
            self.socket = None

    def _recvall(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes or return None if EOF."""
        data = bytearray()
        while len(data) < n:
            try:
                packet = self.socket.recv(n - len(data))
                if not packet:
                    return None
                data.extend(packet)
            except Exception:
                return None
        return bytes(data)

    def call(
        self, operation: int, data: bytes = b"", request_id: int = 0
    ) -> RequestResult:
        """Make a synchronous RPC call and measure latency."""
        start_time = time.time_ns()

        try:
            # Send request header + data
            header = struct.pack("=IIQ", operation, len(data), request_id)
            self.socket.sendall(header + data)
            bytes_sent = len(header) + len(data)

            # Receive response header
            response_header = self._recvall(4 + 4 + 8 + 1)  # op + sz + reqid + status
            if not response_header:
                return RequestResult(0, False, "Connection closed", bytes_sent, 0)

            resp_op, resp_sz, resp_reqid, resp_status = struct.unpack(
                "=IIQB", response_header
            )
            bytes_received = len(response_header)

            # Receive response data if any
            response_data = b""
            if resp_sz > 0:
                response_data = self._recvall(resp_sz)
                if response_data is None:
                    return RequestResult(
                        0, False, "Incomplete response", bytes_sent, bytes_received
                    )
                bytes_received += len(response_data)

            end_time = time.time_ns()
            latency_ns = end_time - start_time

            # Validate response
            if resp_reqid != request_id:
                return RequestResult(
                    latency_ns,
                    False,
                    f"Request ID mismatch: {resp_reqid} != {request_id}",
                    bytes_sent,
                    bytes_received,
                )

            if resp_status != XRPC_RESPONSE_SUCCESS:
                return RequestResult(
                    latency_ns,
                    False,
                    f"Server error: status={resp_status}",
                    bytes_sent,
                    bytes_received,
                )

            return RequestResult(latency_ns, True, None, bytes_sent, bytes_received)

        except Exception as e:
            end_time = time.time_ns()
            return RequestResult(end_time - start_time, False, str(e), 0, 0)


def generate_payload(operation: str, size: int) -> bytes:
    """Generate test payload for the given operation."""
    if operation == "ping":
        return b""  # No payload for ping
    elif operation == "echo":
        return b"A" * size
    elif operation == "sum":
        # Generate array of uint64_t numbers
        count = max(1, size // 8)
        numbers = [random.randint(1, 1000) for _ in range(count)]
        return struct.pack(f"={count}Q", *numbers)
    elif operation == "dot_product":
        # Generate two arrays of equal size
        count = max(1, size // 16)  # Two arrays of uint64_t
        array1 = [random.randint(1, 100) for _ in range(count)]
        array2 = [random.randint(1, 100) for _ in range(count)]
        return struct.pack(f"={count * 2}Q", *(array1 + array2))
    else:
        return b"X" * size


def benchmark_worker(
    config: BenchmarkConfig, worker_id: int, results_queue: List[RequestResult]
) -> None:
    """Worker thread that performs benchmark requests."""
    client = XRPCClient(config.server_host, config.server_port)

    if not client.connect():
        print(f"Worker {worker_id}: Failed to connect")
        return

    try:
        operation_id = OP_ECHO
        payload = generate_payload(config.operation, config.payload_size)

        # Warmup phase
        print(f"Worker {worker_id}: Warming up for {config.warmup_seconds}s...")
        warmup_end = time.time() + config.warmup_seconds
        request_id = 0

        while time.time() < warmup_end:
            client.call(operation_id, payload, request_id)
            request_id += 1
            if config.request_rate_per_connection:
                time.sleep(1.0 / config.request_rate_per_connection)

        # Benchmark phase
        print(
            f"Worker {worker_id}: Starting benchmark for {config.duration_seconds}s..."
        )
        benchmark_end = time.time() + config.duration_seconds
        local_results = []

        while time.time() < benchmark_end:
            result = client.call(operation_id, payload, request_id)
            local_results.append(result)
            request_id += 1

            if config.request_rate_per_connection:
                time.sleep(1.0 / config.request_rate_per_connection)

        # Add results to shared queue (thread-safe append)
        results_queue.extend(local_results)

        print(f"Worker {worker_id}: Completed {len(local_results)} requests")

    finally:
        client.disconnect()


def analyze_results(results: List[RequestResult]) -> dict:
    """Analyze benchmark results and compute statistics."""
    if not results:
        return {"error": "No results to analyze"}

    successful_results = [r for r in results if r.success]
    failed_results = [r for r in results if not r.success]

    if not successful_results:
        return {"error": "No successful requests"}

    latencies_us = [r.latency_ns / 1000.0 for r in successful_results]
    total_bytes_sent = sum(r.bytes_sent for r in successful_results)
    total_bytes_received = sum(r.bytes_received for r in successful_results)

    analysis = {
        "total_requests": len(results),
        "successful_requests": len(successful_results),
        "failed_requests": len(failed_results),
        "success_rate": len(successful_results) / len(results) * 100,
        "latency_us": {
            "min": min(latencies_us),
            "max": max(latencies_us),
            "mean": statistics.mean(latencies_us),
            "median": statistics.median(latencies_us),
            "p95": statistics.quantiles(latencies_us, n=20)[18],  # 95th percentile
            "p99": statistics.quantiles(latencies_us, n=100)[98],  # 99th percentile
            "stdev": statistics.stdev(latencies_us) if len(latencies_us) > 1 else 0,
        },
        "throughput": {
            "requests_per_second": len(successful_results)
            / (max(r.latency_ns for r in successful_results) / 1e9),
            "bytes_per_second_sent": total_bytes_sent
            / (max(r.latency_ns for r in successful_results) / 1e9),
            "bytes_per_second_received": total_bytes_received
            / (max(r.latency_ns for r in successful_results) / 1e9),
        },
        "data_transfer": {
            "total_bytes_sent": total_bytes_sent,
            "total_bytes_received": total_bytes_received,
            "avg_request_size": total_bytes_sent / len(successful_results),
            "avg_response_size": total_bytes_received / len(successful_results),
        },
    }

    if failed_results:
        error_summary = {}
        for result in failed_results:
            error = result.error_msg or "Unknown error"
            error_summary[error] = error_summary.get(error, 0) + 1
        analysis["errors"] = error_summary

    return analysis


def print_results(analysis: dict, config: BenchmarkConfig):
    """Print benchmark results in a human-readable format."""
    if "error" in analysis:
        print(f"Error: {analysis['error']}")
        return

    print("\n" + "=" * 60)
    print("XRPC Benchmark Results")
    print("=" * 60)

    print("Configuration:")
    print(f"  Server: {config.server_host}:{config.server_port}")
    print(f"  Operation: {config.operation}")
    print(f"  Payload Size: {config.payload_size} bytes")
    print(f"  Connections: {config.num_connections}")
    print(f"  Duration: {config.duration_seconds}s (+ {config.warmup_seconds}s warmup)")
    if config.request_rate_per_connection:
        print(
            f"  Rate Limit: {config.request_rate_per_connection} req/s per connection"
        )

    print("\nRequest Summary:")
    print(f"  Total Requests: {analysis['total_requests']:,}")
    print(
        f"  Successful: {analysis['successful_requests']:,} ({analysis['success_rate']:.1f}%)"
    )
    print(f"  Failed: {analysis['failed_requests']:,}")

    lat = analysis["latency_us"]
    print("\nLatency (microseconds):")
    print(f"  Min: {lat['min']:.1f} μs")
    print(f"  Mean: {lat['mean']:.1f} μs")
    print(f"  Median: {lat['median']:.1f} μs")
    print(f"  P95: {lat['p95']:.1f} μs")
    print(f"  P99: {lat['p99']:.1f} μs")
    print(f"  Max: {lat['max']:.1f} μs")
    print(f"  StdDev: {lat['stdev']:.1f} μs")

    tput = analysis["throughput"]
    print("Throughput:")
    print(f"  Requests/sec: {tput['requests_per_second']:.1f}")
    print(f"  MB/sec sent: {tput['bytes_per_second_sent'] / (1024 * 1024):.2f}")
    print(f"  MB/sec received: {tput['bytes_per_second_received'] / (1024 * 1024):.2f}")

    data = analysis["data_transfer"]
    print("\nData Transfer:")
    print(
        f"  Total sent: {data['total_bytes_sent']:,} bytes ({data['total_bytes_sent'] / (1024 * 1024):.2f} MB)"
    )
    print(
        f"  Total received: {data['total_bytes_received']:,} bytes ({data['total_bytes_received'] / (1024 * 1024):.2f} MB)"
    )
    print(f"  Avg request: {data['avg_request_size']:.1f} bytes")
    print(f"  Avg response: {data['avg_response_size']:.1f} bytes")

    if "errors" in analysis:
        print("\nErrors:")
        for error, count in analysis["errors"].items():
            print(f"  {error}: {count}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="XRPC Benchmark Client")
    parser.add_argument("--host", default="localhost", help="Server hostname")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument(
        "--duration", type=int, default=30, help="Benchmark duration in seconds"
    )
    parser.add_argument(
        "--connections", type=int, default=10, help="Number of concurrent connections"
    )
    parser.add_argument(
        "--rate", type=int, help="Request rate limit per connection (req/s)"
    )
    parser.add_argument(
        "--warmup", type=int, default=5, help="Warmup duration in seconds"
    )
    parser.add_argument(
        "--operation",
        choices=["ping", "echo", "sum", "dot_product"],
        default="ping",
        help="Operation to benchmark",
    )
    parser.add_argument(
        "--payload-size", type=int, default=64, help="Payload size in bytes"
    )
    parser.add_argument("--output", help="Output file for JSON results")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = BenchmarkConfig(
        server_host=args.host,
        server_port=args.port,
        duration_seconds=args.duration,
        num_connections=args.connections,
        request_rate_per_connection=args.rate,
        warmup_seconds=args.warmup,
        operation=args.operation,
        payload_size=args.payload_size,
        output_file=args.output,
        verbose=args.verbose,
    )

    print("Starting XRPC benchmark...")
    print(f"Target: {config.server_host}:{config.server_port}")

    # Test connection
    test_client = XRPCClient(config.server_host, config.server_port)
    if not test_client.connect():
        print("Error: Cannot connect to server")
        sys.exit(1)
    test_client.disconnect()

    # Run benchmark with multiple worker threads
    results_queue = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=config.num_connections) as executor:
        futures = []
        for i in range(config.num_connections):
            future = executor.submit(benchmark_worker, config, i, results_queue)
            futures.append(future)

        # Wait for all workers to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Worker error: {e}")

    end_time = time.time()
    total_time = end_time - start_time

    print(f"\nBenchmark completed in {total_time:.1f} seconds")

    # Analyze and print results
    analysis = analyze_results(results_queue)
    analysis["benchmark_duration_seconds"] = total_time
    analysis["config"] = config.__dict__

    print_results(analysis, config)

    # Export to JSON if requested
    if config.output_file:
        try:
            with open(config.output_file, "w") as f:
                json.dump(analysis, f, indent=2, default=str)
            print(f"\nResults exported to {config.output_file}")
        except Exception as e:
            print(f"Error exporting results: {e}")


if __name__ == "__main__":
    main()
