import random
import socket
import struct
import sys
import ssl

UNIX_SOCKET_PATH: str = "/tmp/xrpc.sock"
SERVER_ADDRESS: str = "localhost"
SERVER_PORT_TCP: int = 9000
SERVER_PORT_TLS: int = 9001
MAX_REPETITONS: int = 100

OP_SUM: int = 0
OP_DOT_PROD: int = 1


def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


def do_sum(s: socket.socket) -> None:
    a = random.randint(0, 10)
    b = random.randint(0, 10)
    id = random.randint(0, 100000)

    # send header
    header = struct.pack("=IIQ", OP_SUM, 8 + 8, id)

    # send packet
    data = struct.pack("QQ", a, b)

    s.sendall(header + data)

    # receive response header
    res = recvall(s, 4 + 4 + 8 + 1 + 8)
    res = struct.unpack("=IIQBQ", res)
    assert res[0] == OP_SUM, "request operation does not math"
    assert res[1] == 8, "response size must be 8"
    assert res[2] == id, "request id does not match"
    assert res[3] == 0x1, "response status must be 0x1 (SUCCESS)"
    assert res[4] == a + b, f"sum is not correct: {a}+{b} = {a + b}; got {res[4]}"


def do_dot_prod(s: socket.socket) -> None:
    a1 = []
    a2 = []
    n = 4096 * 32
    id = random.randint(0, 1000)

    for _ in range(n):
        a1.append(random.randint(0, 1000000))
        a2.append(random.randint(0, 1000000))

    # send header
    header = struct.pack("=IIQ", OP_DOT_PROD, 2 * n * 8, id)

    # send packet
    data = struct.pack("QQ" * n, *a1, *a2)

    s.sendall(header + data)

    res = recvall(s, 4 + 4 + 8 + 1 + 8)
    res = struct.unpack("=IIQBQ", res)

    p = 0
    for a, b in zip(a1, a2):
        p += a * b

    assert res[0] == OP_DOT_PROD, "request operation does not math"
    assert res[1] == 8, "response size must be 8"
    assert res[2] == id, "request id does not match"
    assert res[3] == 0x1, "response status must be 0x1 (SUCCESS)"
    assert res[4] == p, f"dot is not {p}; got {res[4]}"


def test(s: socket.socket) -> None:
    for _ in range(MAX_REPETITONS):
        op = random.choice([OP_SUM, OP_DOT_PROD])
        if op == OP_SUM:
            do_sum(s)
        else:
            do_dot_prod(s)


def unix() -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0) as s:
        s.connect(UNIX_SOCKET_PATH)
        test(s)


def tcp() -> None:
    with socket.create_connection((SERVER_ADDRESS, SERVER_PORT_TCP)) as s:
        test(s)


def tls() -> None:
    context = ssl.create_default_context(cafile="certs/certificate.crt")
    context.check_hostname = False

    with socket.create_connection((SERVER_ADDRESS, SERVER_PORT_TLS)) as sock:
        with context.wrap_socket(sock, server_hostname="localhost") as ssock:
            test(ssock)


def all() -> None:
    unix()
    tcp()
    tls()


SUPPORTED_TRANSPORTS: dict[str, callable] = {
    "tcp": tcp,
    "unix": unix,
    "tls": tls,
    "all": all,
}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: <script>", "|".join(SUPPORTED_TRANSPORTS.keys()))
        sys.exit(1)

    fn = SUPPORTED_TRANSPORTS.get(sys.argv[1])

    if fn is None:
        print("unsupported transport:", sys.argv[1])
        sys.exit(1)

    fn()
