import hashlib
import socket
import struct
import sys
import threading
import base64
import readline
from datetime import datetime, timedelta
from typing import Optional

import requests
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad

COMMON_PHRASE = "MyGame"
DEFAULT_PORT = 5001
BACKLOG = 5
MSG_MAX = 4096

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"

def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"

def info(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\r{_c(DIM, ts)} {_c(CYAN, '·')} {msg}")

def warn(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\r{_c(DIM, ts)} {_c(YELLOW, '!')} {msg}")

def err(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\r{_c(DIM, ts)} {_c(RED, '✗')} {msg}")

def recv_msg(label: str, text: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\r{_c(DIM, ts)} {_c(MAGENTA, label):30s} {text}")

def sent_msg(label: str, text: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\r{_c(DIM, ts)} {_c(GREEN, label):30s} {text}")

def reprint_prompt():
    sys.stdout.write(f"{_c(BOLD + GREEN, 'you')} » ")
    sys.stdout.flush()

def _sha256_fold_xor(data: str, byte_num: int) -> bytes:
    if 32 % byte_num != 0:
        raise ValueError(f"byte_num must divide 32 evenly, got {byte_num}")
    digest = hashlib.sha256(data.encode()).digest()
    folded = bytearray(byte_num)
    for i, b in enumerate(digest):
        folded[i % byte_num] ^= b
    return bytes(folded)

def _round_hash(min_start: Optional[int], byte_num: int):
    now = datetime.utcnow()
    if min_start is None:
        anchor = now.replace(second=0, microsecond=0)
    else:
        if now.minute >= min_start:
            anchor = now.replace(minute=min_start, second=0, microsecond=0)
        else:
            anchor = (now - timedelta(hours=1)).replace(
                minute=min_start,
                second=0,
                microsecond=0
            )
    stamp = int(anchor.strftime("%Y%m%d%H%M%S"))
    return _sha256_fold_xor(str(stamp), byte_num), now.minute

def _make_des3_key(raw_key: bytes) -> bytes:
    combined = raw_key + COMMON_PHRASE.encode("utf-8")
    padded = pad(combined, 8)
    return padded[:24]

def _ip_port_to_bytes(ipv4: str, port: int) -> bytes:
    return socket.inet_aton(ipv4) + struct.pack("!H", port) + b"\x00\x00"

def _bytes_to_ip_port(data: bytes):
    return socket.inet_ntoa(data[:4]), struct.unpack("!H", data[4:6])[0]

def _find_public_ipv4() -> str:
    try:
        return requests.get("https://api.ipify.org", timeout=6).text.strip()
    except Exception:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

def generate_token(port: int) -> str:
    public_ip = _find_public_ipv4()
    plain = _ip_port_to_bytes(public_ip, port)
    key, start = _round_hash(None, 16)
    cipher = DES3.new(_make_des3_key(key), DES3.MODE_ECB)
    cipher_bytes = cipher.encrypt(plain)
    token = base64.b85encode(cipher_bytes).decode() + str(start)
    return token

def decode_token(token: str):
    b85_part = token[:10]
    min_part = int(token[10:])
    ciphertext = base64.b85decode(b85_part)

    for delta in (0, -1, 1):
        try:
            probe_min = (min_part + delta) % 60
            key, _ = _round_hash(probe_min, 16)
            cipher = DES3.new(_make_des3_key(key), DES3.MODE_ECB)
            plain = cipher.decrypt(ciphertext)
            ip, port = _bytes_to_ip_port(plain)
            if 1 <= port <= 65535:
                return ip, port
        except Exception:
            continue

    raise ValueError("Could not decode token – it may have expired (> 1 min old)")

def _send_frame(sock: socket.socket, text: str):
    payload = text.encode("utf-8")
    header = struct.pack("!I", len(payload))
    sock.sendall(header + payload)

def _recv_frame(sock: socket.socket) -> Optional[str]:
    def _read_exactly(n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    header = _read_exactly(4)
    if header is None:
        return None

    (length,) = struct.unpack("!I", header)

    if length > MSG_MAX:
        return None

    payload = _read_exactly(length)

    if payload is None:
        return None

    return payload.decode("utf-8", errors="replace")

class PeerManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._peers: dict[str, socket.socket] = {}

    def add(self, label: str, sock: socket.socket):
        with self._lock:
            self._peers[label] = sock

    def remove(self, label: str):
        with self._lock:
            self._peers.pop(label, None)

    def broadcast(self, text: str, exclude: Optional[str] = None):
        with self._lock:
            dead = []

            for label, sock in self._peers.items():
                if label == exclude:
                    continue

                try:
                    _send_frame(sock, text)
                except Exception:
                    dead.append(label)

            for label in dead:
                del self._peers[label]

    def list_peers(self) -> list[str]:
        with self._lock:
            return list(self._peers.keys())

    def count(self) -> int:
        with self._lock:
            return len(self._peers)

def _peer_reader(
    sock: socket.socket,
    label: str,
    peers: PeerManager,
    nickname: str
):
    try:
        while True:
            msg = _recv_frame(sock)

            if msg is None:
                break

            recv_msg(f"←  {label}", msg)
            reprint_prompt()
            peers.broadcast(f"[{label}] {msg}", exclude=label)

    except Exception:
        pass

    finally:
        peers.remove(label)
        warn(f"Peer disconnected: {label}")
        reprint_prompt()

        try:
            sock.close()
        except Exception:
            pass

def _accept_loop(server_sock: socket.socket, peers: PeerManager, nickname: str):
    while True:
        try:
            client_sock, addr = server_sock.accept()
        except OSError:
            break

        label = f"{addr[0]}:{addr[1]}"

        info(f"Incoming connection from {_c(YELLOW, label)}")
        reprint_prompt()

        peers.add(label, client_sock)

        t = threading.Thread(
            target=_peer_reader,
            args=(client_sock, label, peers, nickname),
            daemon=True
        )

        t.start()

def _connect_to_peer(token: str, peers: PeerManager, nickname: str):
    try:
        ip, port = decode_token(token.strip())
    except ValueError as e:
        err(str(e))
        return

    label = f"{ip}:{port}"

    if label in peers.list_peers():
        warn(f"Already connected to {label}")
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, port))
        sock.settimeout(None)
    except Exception as e:
        err(f"Could not connect to {label}: {e}")
        return

    peers.add(label, sock)

    info(f"Connected to {_c(GREEN, label)}")

    t = threading.Thread(
        target=_peer_reader,
        args=(sock, label, peers, nickname),
        daemon=True
    )

    t.start()

def _banner(port: int, token: str):
    w = 60

    print(_c(BOLD + CYAN, "─" * w))
    print(_c(BOLD + CYAN, "  ◈  P2P TERMINAL MESSENGER"))
    print(_c(CYAN, f"  listening on port {port}"))
    print(_c(CYAN, "─" * w))
    print(_c(BOLD, "  Your token (share this with a peer):"))
    print(_c(YELLOW + BOLD, f"  {token}"))
    print(_c(CYAN, "─" * w))
    print(_c(DIM, "  Commands:"))
    print(_c(DIM, "    /connect <token>  — connect to a peer"))
    print(_c(DIM, "    /token             — re-print your token"))
    print(_c(DIM, "    /peers             — list active peers"))
    print(_c(DIM, "    /quit  or  Ctrl-C  — exit"))
    print(_c(CYAN, "─" * w))

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Serverless P2P terminal messenger"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP port to listen on (default {DEFAULT_PORT})"
    )

    parser.add_argument(
        "--nick",
        type=str,
        default="you",
        help="Display nickname for your outgoing messages"
    )

    args = parser.parse_args()

    port = args.port
    nickname = args.nick

    info("Resolving public IP…")

    try:
        token = generate_token(port)
    except Exception as e:
        err(f"Failed to generate token: {e}")
        sys.exit(1)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    try:
        server_sock.bind(("0.0.0.0", port))
    except OSError as e:
        err(f"Cannot bind to port {port}: {e}")
        sys.exit(1)

    server_sock.listen(BACKLOG)

    peers = PeerManager()

    accept_thread = threading.Thread(
        target=_accept_loop,
        args=(server_sock, peers, nickname),
        daemon=True
    )

    accept_thread.start()

    _banner(port, token)

    try:
        while True:
            sys.stdout.write(f"{_c(BOLD + GREEN, nickname)} » ")
            sys.stdout.flush()

            line = sys.stdin.readline()

            if not line:
                break

            line = line.rstrip("\n")

            if not line:
                continue

            if line.startswith("/connect "):
                tok = line[9:].strip()

                if not tok:
                    warn("Usage: /connect <token>")
                else:
                    _connect_to_peer(tok, peers, nickname)

            elif line == "/token":
                print(_c(YELLOW + BOLD, f"  {token}"))

            elif line == "/peers":
                pl = peers.list_peers()

                if pl:
                    info(f"{len(pl)} peer(s) connected:")

                    for p in pl:
                        print(f"    {_c(GREEN, p)}")
                else:
                    info("No peers connected yet.")

            elif line in ("/quit", "/exit", "/q"):
                break

            elif line.startswith("/"):
                warn(f"Unknown command: {line}")

            else:
                if peers.count() == 0:
                    warn("No peers connected. Use /connect <token> first.")
                else:
                    peers.broadcast(line)
                    sent_msg(f"→  {nickname}", line)

    except KeyboardInterrupt:
        pass

    finally:
        info("Shutting down…")
        server_sock.close()

if __name__ == "__main__":
    main()
