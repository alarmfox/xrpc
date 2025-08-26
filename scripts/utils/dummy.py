#!/usr/bin/env python3
"""
Minimal client to test the xrpc server.
Sends:
  - one request header (batch_size=1)
  - one frame header (vector of 4 float32)
  - payload: 4 float32 values (1.0, 2.0, 3.0, 4.0)
Usage:
  python3 xrpc_test_client.py [host] [port]
Default: host=127.0.0.1 port=9000
"""

import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9000

# Protocol constants (match your protocol.h)
XRPC_PROTO_VERSION = 0x0
XRPC_REQUEST_BATCH_START = 1
XRPC_REQUEST_SERVER_PING = 3

# dtype base values from your protocol.h:
# (counting from the enum in your header: UINT8=1 ... FLOAT32=9 ...)
XRPC_BASE_FLOAT32 = 9
XRPC_DTYPE_CAT_VECTOR = 0


def make_request_header(version, req_type, resp_mode, batch_id, batch_size, reserved=0):
    # PREAMBLE: 8 bits = (VER << 4) | TYPE
    preamble = (((version & 0x0F) << 4) | (req_type & 0x0F)) & 0xFF
    # word1 = preamble(8) | resp_mode(8) | batch_id(16)  as 32-bit word (host-order to be network-ordered)
    w1 = (preamble << 24) | ((resp_mode & 0xFF) << 16) | (batch_id & 0xFFFF)
    # word2 = batch_size(16) << 16 | reserved(16)
    w2 = ((batch_size & 0xFFFF) << 16) | (reserved & 0xFFFF)
    # pack as network-order unsigned ints
    return struct.pack("!II", w1, w2)


def make_frame_header(opcode, scale, dtypb, dtypc, size_params, batch_id, frame_id):
    # opinfo (16 bits) layout:
    # bits  0-1 : DC (2 bits)
    # bits  2-5 : DTYPB (4 bits)
    # bits  6-9 : SCALE (4 bits)
    # bits 10-15: OPCODE (6 bits)
    opinfo = (
        ((opcode & 0x3F) << 10)
        | ((scale & 0x0F) << 6)
        | ((dtypb & 0x0F) << 2)
        | (dtypc & 0x03)
    )
    # word1: opinfo (16) << 16 | size_params (16)
    w1 = ((opinfo & 0xFFFF) << 16) | (size_params & 0xFFFF)
    # word2: batch_id (16) << 16 | frame_id (16)
    w2 = ((batch_id & 0xFFFF) << 16) | (frame_id & 0xFFFF)
    return struct.pack("!II", w1, w2)


def main():
    # Test values
    version = XRPC_PROTO_VERSION
    req_type = XRPC_REQUEST_BATCH_START
    resp_mode = 0
    batch_id = 1
    batch_size = 1

    opcode = 1
    scale = 0
    dtypb = XRPC_BASE_FLOAT32
    dtypc = XRPC_DTYPE_CAT_VECTOR
    vector_len = 4
    frame_batch_id = batch_id
    frame_id = 1

    # payload: 4 float32
    payload_floats = (1.0, 2.0, 3.0, 4.0)
    payload = struct.pack("!4f", *payload_floats)  # network-order float32

    # sanity: payload length should match computed size: 4 * 4 = 16 bytes
    assert len(payload) == 4 * 4

    req_hdr = make_request_header(
        version, req_type, resp_mode, batch_id, batch_size, reserved=0
    )
    fr_hdr = make_frame_header(
        opcode, scale, dtypb, dtypc, vector_len, frame_batch_id, frame_id
    )

    print("Connecting to {}:{}...".format(HOST, PORT))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print(
        "Connected, sending request header (8 bytes), frame header (8 bytes) and {}-byte payload...".format(
            len(payload)
        )
    )

    # send header, frame header, payload
    s.sendall(req_hdr)
    s.sendall(fr_hdr)
    s.sendall(payload)

    print(
        "Sent. Now reading up to 4096 bytes of server response (if any) with 2s timeout."
    )
    try:
        data = s.recv(4096)
        if data:
            print("Received {} bytes:".format(len(data)))
            # print hex dump
            print(data.hex())
        else:
            print("Connection closed by server or no data received.")
    except socket.timeout:
        print(
            "No response received (timeout). That's OK if server does not reply immediately."
        )
    except Exception as e:
        print("Recv error:", e)

    s.close()
    print("Done.")


if __name__ == "__main__":
    main()
