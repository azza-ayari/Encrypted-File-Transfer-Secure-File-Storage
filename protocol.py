import struct
import json

# Message types
MSG_UPLOAD_INIT = 1
MSG_UPLOAD_CHUNK = 2
MSG_UPLOAD_DONE = 3
MSG_DOWNLOAD_REQ = 4
MSG_DOWNLOAD_CHUNK = 5
MSG_RESUME_QUERY = 6
MSG_RESUME_RESP = 7
MSG_ACK = 8
MSG_ERROR = 9


def send_msg(sock, msg_type: int, payload: bytes):
    header = struct.pack(">BI", msg_type, len(payload))
    sock.sendall(header + payload)


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


def recv_msg(sock) -> tuple[int, bytes]:
    header = recv_exact(sock, 5)
    msg_type, length = struct.unpack(">BI", header)
    payload = recv_exact(sock, length) if length else b""
    return msg_type, payload


def encode_json(obj) -> bytes:
    return json.dumps(obj).encode()


def decode_json(data: bytes):
    return json.loads(data.decode())
