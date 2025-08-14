import random
import socket
import struct
import sys
import ssl

UNIX_SOCKET_PATH: str = "/tmp/rpc.sock"
SERVER_ADDRESS: str = "localhost"
SERVER_PORT_TCP: int = 9000
SERVER_PORT_TLS: int = 9001
MAX_REPETITONS: int = 2

OP_SUM: int = 0


def test(s: socket.socket, reps: int = 100) -> None:
    for _ in range(MAX_REPETITONS):
        a = random.randint(0, 10)
        b = random.randint(0, 10)
        id = random.randint(0, 100000)
        data = struct.pack("!HQQQ", OP_SUM, id, a, b)

        s.sendall(data)

        res = s.recv(8 + 8 + 2)
        res = struct.unpack("!HQQ", res)
        assert res[1] == id, "request id does not match"
        assert res[2] == a + b, "sum is not correct"


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
            print(ssock.version)
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
