import os
import ssl
import socket
import threading
import hashlib
import json
from crypto_utils import (
    encrypt_chunk, decrypt_chunk, compute_hmac, verify_hmac,
    CHUNK_SIZE, NONCE_SIZE, HMAC_SIZE, KEY_SIZE
)
from protocol import *

STORAGE_DIR = "server_storage"
META_DIR = "server_meta"
os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(META_DIR, exist_ok=True)

# Server-side master key (in production: use HSM / KMS)
SERVER_MASTER_KEY = b"REPLACE_WITH_SECURELY_SHARED_KEY_32B!!"[:32]  # persist safely!


def storage_path(file_id: str) -> str:
    return os.path.join(STORAGE_DIR, file_id + ".enc")


def meta_path(file_id: str) -> str:
    return os.path.join(META_DIR, file_id + ".json")


def handle_upload(conn):
    # Init
    _, init_payload = recv_msg(conn)
    meta = decode_json(init_payload)
    file_id = meta["file_id"]
    total_chunks = meta["total_chunks"]
    filename = meta["filename"]

    fpath = storage_path(file_id)
    mpath = meta_path(file_id)

    # Resume support: check existing chunks
    existing = 0
    if os.path.exists(mpath):
        with open(mpath) as f:
            saved = json.load(f)
        existing = saved.get("chunks_received", 0)

    send_msg(conn, MSG_RESUME_RESP, encode_json({"resume_from": existing}))

    mode = "ab" if existing > 0 else "wb"
    with open(fpath, mode) as f:
        for i in range(existing, total_chunks):
            msg_type, payload = recv_msg(conn)
            if msg_type != MSG_UPLOAD_CHUNK:
                send_msg(conn, MSG_ERROR, b"expected chunk")
                return

            # Payload = nonce(12) || hmac(32) || ciphertext
            nonce = payload[:NONCE_SIZE]
            mac = payload[NONCE_SIZE:NONCE_SIZE + HMAC_SIZE]
            ct = payload[NONCE_SIZE + HMAC_SIZE:]

            # Verify HMAC (transport-level integrity, in addition to GCM tag)
            if not verify_hmac(SERVER_MASTER_KEY, nonce + ct, mac):
                send_msg(conn, MSG_ERROR, b"hmac mismatch")
                return

            # Write encrypted chunk to disk AS-IS (already encrypted with user key).
            # Prefix each stored chunk with nonce for later retrieval.
            f.write(len(payload).to_bytes(4, "big"))
            f.write(payload)

            send_msg(conn, MSG_ACK, b"")

    # Save metadata
    with open(mpath, "w") as f:
        json.dump({
            "file_id": file_id,
            "filename": filename,
            "total_chunks": total_chunks,
            "chunks_received": total_chunks,
        }, f)

    send_msg(conn, MSG_UPLOAD_DONE, b"ok")
    print(f"[+] Upload complete: {filename} ({file_id})")


def handle_download(conn, file_id):
    fpath = storage_path(file_id)
    mpath = meta_path(file_id)
    if not os.path.exists(fpath):
        send_msg(conn, MSG_ERROR, b"not found")
        return

    with open(mpath) as f:
        meta = json.load(f)
    send_msg(conn, MSG_RESUME_RESP, encode_json(meta))

    with open(fpath, "rb") as f:
        while True:
            size_bytes = f.read(4)
            if not size_bytes:
                break
            size = int.from_bytes(size_bytes, "big")
            payload = f.read(size)
            send_msg(conn, MSG_DOWNLOAD_CHUNK, payload)
            # Wait for ACK
            recv_msg(conn)

    send_msg(conn, MSG_UPLOAD_DONE, b"ok")
    print(f"[+] Download complete: {file_id}")


def client_thread(conn, addr):
    print(f"[+] Client connected: {addr}")
    try:
        msg_type, payload = recv_msg(conn)
        if msg_type == MSG_UPLOAD_INIT:
            # Re-inject the init message via a small wrapper
            # (easier: handle_upload expects init as first)
            _handle_upload_with_init(conn, payload)
        elif msg_type == MSG_DOWNLOAD_REQ:
            req = decode_json(payload)
            handle_download(conn, req["file_id"])
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()


def _handle_upload_with_init(conn, init_payload):
    meta = decode_json(init_payload)
    file_id = meta["file_id"]
    total_chunks = meta["total_chunks"]
    filename = meta["filename"]

    fpath = storage_path(file_id)
    mpath = meta_path(file_id)

    existing = 0
    if os.path.exists(mpath):
        with open(mpath) as f:
            saved = json.load(f)
        existing = saved.get("chunks_received", 0)
        if existing >= total_chunks:
            existing = 0  # already complete, overwrite

    send_msg(conn, MSG_RESUME_RESP, encode_json({"resume_from": existing}))

    mode = "ab" if existing > 0 else "wb"
    with open(fpath, mode) as f:
        for i in range(existing, total_chunks):
            msg_type, payload = recv_msg(conn)
            nonce = payload[:NONCE_SIZE]
            mac = payload[NONCE_SIZE:NONCE_SIZE + HMAC_SIZE]
            ct = payload[NONCE_SIZE + HMAC_SIZE:]

            if not verify_hmac(SERVER_MASTER_KEY, nonce + ct, mac):
                send_msg(conn, MSG_ERROR, b"hmac mismatch")
                return

            f.write(len(payload).to_bytes(4, "big"))
            f.write(payload)

            # Update progress
            with open(mpath, "w") as mf:
                json.dump({
                    "file_id": file_id,
                    "filename": filename,
                    "total_chunks": total_chunks,
                    "chunks_received": i + 1,
                }, mf)

            send_msg(conn, MSG_ACK, b"")

    send_msg(conn, MSG_UPLOAD_DONE, b"ok")
    print(f"[+] Upload complete: {filename}")


def main(host="0.0.0.0", port=8443):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[*] Server listening on {host}:{port}")

        with ctx.wrap_socket(sock, server_side=True) as ssock:
            while True:
                conn, addr = ssock.accept()
                t = threading.Thread(target=client_thread, args=(conn, addr))
                t.daemon = True
                t.start()


if __name__ == "__main__":
    main()
