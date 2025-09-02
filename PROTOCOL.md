# XRPC Protocol Specification

## Overview

XRPC is a small binary RPC protocol for exchange of typed data structures (vectors, matrices, and tensors) between clients and servers. The protocol supports batching operations to reduce network overhead and provides strong typing for mathematical operations.

**Protocol Version:** 0x0  
**Endianness:** Network byte order (big-endian) for all multi-byte fields

## Core Concepts

### Batching
The protocol is built around the concept of **batches** - sequences of operations that share common parameters (such as security settings) and are processed together by the server. This reduces the overhead of parameter negotiation for multiple related operations.

### Data Types
XRPC supports three categories of data structures:
- **Vectors** (1D arrays)
- **Matrices** (2D arrays) 
- **Tensors** (N-dimensional arrays) (Not implemented yet)

Each can contain elements of various base types (integers, floats, etc.) with scaling factors.

## Message Flow

1. Client initiates a batch with `XRPC_REQUEST_BATCH_INIT`
2. Server responds with the assigned batch id
2. Client sends batch initialization with `XRPC_REQUEST_BATCH_START`
3. Client sends individual operation frames within the batch
4. Server processes the batch and responds with results
5. Server sends batch completion notification

## Request Types

| Type | Value | Description |
|------|-------|-------------|
| `XRPC_REQUEST_BATCH_START` | 1 | Initialize a new batch |
| `XRPC_REQUEST_SERVER_INFO` | 2 | Query server information |
| `XRPC_REQUEST_SERVER_PING` | 3 | Server connectivity test |
| `XRPC_REQUEST_BATCH_INIT` | 4 | Begin batch operations |

## Data Type System

### Base Types

| Type | Value | Size (bytes) | Description |
|------|-------|--------------|-------------|
| `XRPC_BASE_UINT8` | 1 | 1 | Unsigned 8-bit integer |
| `XRPC_BASE_UINT16` | 2 | 2 | Unsigned 16-bit integer |
| `XRPC_BASE_UINT32` | 3 | 4 | Unsigned 32-bit integer |
| `XRPC_BASE_UINT64` | 4 | 8 | Unsigned 64-bit integer |
| `XRPC_BASE_INT8` | 5 | 1 | Signed 8-bit integer |
| `XRPC_BASE_INT16` | 6 | 2 | Signed 16-bit integer |
| `XRPC_BASE_INT32` | 7 | 4 | Signed 32-bit integer |
| `XRPC_BASE_INT64` | 8 | 8 | Signed 64-bit integer |
| `XRPC_BASE_FLOAT32` | 9 | 4 | 32-bit floating point |
| `XRPC_BASE_FLOAT64` | 10 | 8 | 64-bit floating point |
| `XRPC_BASE_DOUBLE32` | 11 | 4 | 32-bit double precision |
| `XRPC_BASE_DOUBLE64` | 12 | 8 | 64-bit double precision |

### Categories

| Category | Value | Description |
|----------|-------|-------------|
| `XRPC_DTYPE_CAT_VECTOR` | 0 | 1D array |
| `XRPC_DTYPE_CAT_MATRIX` | 1 | 2D array |
| `XRPC_DTYPE_CAT_TENSOR` | 2 | Multi-dimensional array |

### Scaling
The SCALE field allows for dynamic sizing where the actual element size is `sizeof(base_type) * 2^scale`.

## Message Formats

### Request Header (12 bytes)

```
 4bit 4bit   8 bit          16 bit
+----+----+----+----+----+----+----+----+
|VER |TYPE|RESP MODE|      BATCH ID     | (32 bit)
+----+----+----+----+----+----+----+----+
+----+----+----+----+----+----+----+----+
|     BATCH SIZE    |      RESERVED     | (32 bit)
+----+----+----+----+----+----+----+----+
+----+----+----+----+----+----+----+----+
|             SEQUENCE NUMBER           | (32 bit)
+----+----+----+----+----+----+----+----+
```

**Fields:**
- **VER** (4 bits): Protocol version (currently 0x0)
- **TYPE** (4 bits): Request type from `xrpc_request_type`
- **RESP MODE** (8 bits): Response behavior mode (reserved for future use)
- **BATCH ID** (16 bits): Unique identifier for the batch 
- **BATCH SIZE** (16 bits): Number of frames (operations) in the batch
- **RESERVED** (16 bits): Must be zero
- **SEQUENCE NUMBER** (32 bits): Unique message identifier

### Request Frame Header (8 bytes)

```
  6 bit 4bit  6 bit         16 bit
+----+----+----+-----+----+----+----+-----+
|OPCOD|SCALE|DTYPB|DC|     SIZE PARAMS    |  (32 bit)
+----+----+----+-----+----+----+----+-----+
+----+----+----+-----+----+----+----+-----+
|      BATCH_ID      |      FRAME ID      |  (32 bit)
+----+----+----+-----+----+----+----+-----+
```

**Fields:**
- **OPCODE** (6 bits): Operation identifier
- **SCALE** (4 bits): Scaling factor (operand_size = base_size * 2^scale)
- **DTYPB** (4 bits): Base data type from `xrpc_dtype_base`
- **DC** (2 bits): Data category from `xrpc_dtype_category`
- **SIZE PARAMS** (16 bits): Dimension parameters
  - For vectors: number of elements
  - For matrices: upper 8 bits = rows, lower 8 bits = columns
  - For tensors: total number of elements
- **BATCH_ID** (16 bits): Associated batch identifier
- **FRAME_ID** (16 bits): Unique frame identifier within batch

### Response Header (12 bytes)

```
 4bit 4 bit  8 bit          16 bit
+----+----+----+----+----+----+----+----+
|VER | TYP|   RSV   |      BATCH ID     | (32 bit)
+----+----+----+----+----+----+----+----+
+----+----+----+----+----+----+----+----+
|       STATUS      |    PAYLOAD SIZE   | (32 bit)
+----+----+----+----+----+----+----+----+
+----+----+----+----+----+----+----+----+
|             SEQUENCE NUMBER           | (32 bit)
+----+----+----+----+----+----+----+----+
```

**Fields:**
- **VER** (4 bits): Protocol version
- **TYPE** (4 bits): Response type from `xrpc_response_type`
- **RSV** (8 bits): Reserved, must be zero
- **BATCH ID** (16 bits): Corresponding batch identifier
- **STATUS** (16 bits): Operation status
- **PAYLOAD SIZE** (16 bits): Size of additional payload data
- **SEQUENCE NUMBER** (32 bits): Unique message identifier

### Response Types

| Type | Value | Description |
|------|-------|-------------|
| `XRPC_RESP_TYPE_BATCH_INIT` | 1 | Batch initialization response |
| `XRPC_RESP_TYPE_BATCH_REPORT` | 2 | Batch completion report |
| `XRPC_RESP_TYPE_ACK` | 3 | Acknowledgment |

### Response Frame Header (8 bytes)

Similar structure to request frame header, but the first 6 bits represent STATUS instead of OPCODE:

```
 6 bit 4bit  6 bit         16 bit
+----+----+----+-----+----+----+----+-----+
|STATU|SCALE|DTYPB|DC|     SIZE PARAMS    |  (32 bit)
+----+----+----+-----+----+----+----+-----+
+----+----+----+-----+----+----+----+-----+
|      BATCH_ID      |      FRAME ID      |  (32 bit)
+----+----+----+-----+----+----+----+-----+
```

### Response Status Codes

| Status | Value | Description |
|--------|-------|-------------|
| `XRPC_FR_RESPONSE_SUCCESS` | 0 | Operation completed successfully |
| `XRPC_FR_RESPONSE_INTERNAL_ERROR` | 1 | Server internal error |
| `XRPC_FR_RESPONSE_INVALID_OP` | 2 | Invalid operation code |
| `XRPC_FR_RESPONSE_INVALID_PARAMS` | 3 | Invalid parameters |

## Data Serialization

### Frame Data Size Calculation

The size of data following a frame header is calculated as:

```
data_size = sizeof(base_type) * (dimension_factor * 2^scale)
```

Where `dimension_factor` depends on the data category:
- **Vector**: `size_params` (number of elements)
- **Matrix**: `rows * cols` (from size_params encoding)
- **Tensors** (N-dimensional arrays) (Not implemented yet)
