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


def test(s: socket.socket) -> None:
    for _ in range(MAX_REPETITONS):
        a = random.randint(0, 10)
        b = random.randint(0, 10)
        id = random.randint(0, 100000)

        # send header
        header = struct.pack("iiQ", OP_SUM, 8 + 8, id)
        s.sendall(header)

        # send packet
        data = struct.pack("QQ", a, b)

        s.sendall(data)

        # receive response header
        res = s.recv(4 + 4 + 8 + 1)
        res = struct.unpack("iiQB", res)
        assert res[0] == 0, "request operation does not math"
        assert res[1] == 8, "response size must be 8"
        assert res[2] == id, "request id does not match"
        assert res[3] == 0x1, "response status must be 0x1 (SUCCESS)"

        # receive the response packet
        res = s.recv(8)
        res = struct.unpack("Q", res)
        assert res[0] == a + b, f"sum is not correct: {a}+{b} = {a + b}; got {res[0]}"


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
