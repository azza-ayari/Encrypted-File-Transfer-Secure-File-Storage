import os
import ssl
import socket
import hashlib
import getpass
from crypto_utils import (
    derive_key, encrypt_chunk, decrypt_chunk, compute_hmac,
    CHUNK_SIZE, NONCE_SIZE, HMAC_SIZE, SALT_SIZE
)
from protocol import *

# Shared HMAC key with server (in real deployments: negotiated via mutual TLS + KDF)
SHARED_HMAC_KEY = b"REPLACE_WITH_SECURELY_SHARED_KEY_32B!!"[:32]


def make_file_id(filename: str, key: bytes) -> str:
    return hashlib.sha256(filename.encode() + key[:8]).hexdigest()[:32]


def connect(host, port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False           # For self-signed testing
    ctx.verify_mode = ssl.CERT_NONE      # In production: verify CA properly
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    sock = socket.create_connection((host, port))
    return ctx.wrap_socket(sock, server_hostname=host)


def upload_file(host, port, filepath, password):
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    total_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE

    # Derive per-file key from password + salt (salt stored client-side; here embedded in filename hash for demo)
    salt = hashlib.sha256(filename.encode()).digest()[:SALT_SIZE]
    key = derive_key(password.encode(), salt)
    file_id = make_file_id(filename, key)

    conn = connect(host, port)
    try:
        send_msg(conn, MSG_UPLOAD_INIT, encode_json({
            "file_id": file_id,
            "filename": filename,
            "total_chunks": total_chunks,
            "filesize": filesize,
        }))

        _, resp = recv_msg(conn)
        resume_from = decode_json(resp).get("resume_from", 0)
        print(f"[*] Uploading {filename} ({total_chunks} chunks), resuming from {resume_from}")

        with open(filepath, "rb") as f:
            f.seek(resume_from * CHUNK_SIZE)
            for i in range(resume_from, total_chunks):
                chunk = f.read(CHUNK_SIZE)
                # AAD binds chunk index -> prevents reorder attacks
                aad = i.to_bytes(8, "big")
                nonce, ct = encrypt_chunk(key, chunk, aad)
                mac = compute_hmac(SHARED_HMAC_KEY, nonce + ct)
                payload = nonce + mac + ct
                send_msg(conn, MSG_UPLOAD_CHUNK, payload)
                recv_msg(conn)  # ACK
                print(f"  chunk {i+1}/{total_chunks}", end="\r")

        _, _ = recv_msg(conn)
        print(f"\n[+] Upload finished: {file_id}")
    finally:
        conn.close()


def download_file(host, port, filename, out_path, password):
    salt = hashlib.sha256(filename.encode()).digest()[:SALT_SIZE]
    key = derive_key(password.encode(), salt)
    file_id = make_file_id(filename, key)

    conn = connect(host, port)
    try:
        send_msg(conn, MSG_DOWNLOAD_REQ, encode_json({"file_id": file_id}))
        _, meta_payload = recv_msg(conn)
        meta = decode_json(meta_payload)
        total_chunks = meta["total_chunks"]
        print(f"[*] Downloading {meta['filename']} ({total_chunks} chunks)")

        with open(out_path, "wb") as f:
            for i in range(total_chunks):
                msg_type, payload = recv_msg(conn)
                if msg_type != MSG_DOWNLOAD_CHUNK:
                    raise RuntimeError("unexpected message")

                nonce = payload[:NONCE_SIZE]
                mac = payload[NONCE_SIZE:NONCE_SIZE + HMAC_SIZE]
                ct = payload[NONCE_SIZE + HMAC_SIZE:]

                # Verify HMAC (transport integrity)
                if not compute_hmac(SHARED_HMAC_KEY, nonce + ct) == mac:
                    raise RuntimeError(f"HMAC mismatch on chunk {i}")

                aad = i.to_bytes(8, "big")
                plaintext = decrypt_chunk(key, nonce, ct, aad)
                f.write(plaintext)
                send_msg(conn, MSG_ACK, b"")
                print(f"  chunk {i+1}/{total_chunks}", end="\r")

        recv_msg(conn)
        print(f"\n[+] Downloaded to {out_path}")
    finally:
        conn.close()


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python client.py upload <path>")
        print("  python client.py download <filename> <output>")
        sys.exit(1)

    action = sys.argv[1]
    pw = getpass.getpass("Password: ")
    if action == "upload":
        upload_file("localhost", 8443, sys.argv[2], pw)
    elif action == "download":
        download_file("localhost", 8443, sys.argv[2], sys.argv[3], pw)

