import random
import socket
import struct

SERVER_ADDRESS: str = "localhost"
SERVER_PORT_TCP: int = 9000
OP_DUMMY: int = 0x0


def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


def do_dummy(s: socket.socket, id: int) -> None:
    a = random.randint(0, 10)
    header = struct.pack("=IIQ", OP_DUMMY, 8, id)
    data = struct.pack("Q", a)

    s.sendall(header + data)

    res = recvall(s, 4 + 4 + 8 + 1 + 8)
    res = struct.unpack("=IIQBQ", res)

    assert res[0] == OP_DUMMY, (
        "request operation does not match. expected {OP_DUMMY}; got {res[0]}"
    )
    assert res[1] == 8, f"response size must be 8; got {res[1]}"
    assert res[2] == id, f"request id expected {id}; got {res[2]}"
    assert res[3] == 0x1, f"response status expected 0x1; got {res[3]}"
    assert res[4] == a, f"expected {a}; got {res[4]}"


with socket.create_connection((SERVER_ADDRESS, SERVER_PORT_TCP)) as s:
    do_dummy(s, 1)

