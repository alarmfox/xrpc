import random
import socket
import struct
import sys
import ssl

UNIX_SOCKET_PATH: str = "/tmp/rpc.sock"
SERVER_ADDRESS: str = "localhost"
SERVER_PORT: int = 9000

OP_SUM: int = 0


def test(s) -> None:
    a = random.randint(0, 10)
    b = random.randint(0, 10)
    id = random.randint(0, 100000)
    data = struct.pack("!HQQQ", OP_SUM, id, a, b)

    s.sendall(data)

    res = s.recv(8 + 8 + 2)
    res = struct.unpack("!HQQ", res)
    assert res[1] == id, "request id does not match"
    assert res[2] == a + b, "sum is not correct"


def unix(path: str) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0) as s:
        s.connect(UNIX_SOCKET_PATH)
        test(s)


def tcp(address: str, port: int) -> None:
    with socket.create_connection((address, port)) as s:
        s.connect((address, port))
        test(s)


def tls(address: str, port: int) -> None:
    context = ssl.create_default_context(cafile="certs/certificate.crt")
    context.check_hostname = False

    with socket.create_connection((address, port)) as sock:
        with context.wrap_socket(sock, server_hostname="localhost") as ssock:
            print(ssock.version)
            test(ssock)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: <script> tcp/unix/tls")
        sys.exit(1)

    transport = sys.argv[1]
    if transport == "unix":
        unix(UNIX_SOCKET_PATH)
    elif transport == "tcp":
        tcp(SERVER_ADDRESS, SERVER_PORT)
    elif transport == "tls":
        tls(SERVER_ADDRESS, SERVER_PORT)
    else:
        print("unsupported transport:", transport)
        sys.exit(1)
