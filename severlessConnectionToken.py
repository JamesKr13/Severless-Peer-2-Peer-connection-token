import hashlib
from datetime import datetime, timedelta
import base64
import socket
import requests
import struct
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# limit 8
COMMON_PHRASE = "MyGame"

def round_hash(min_start: int, byte_num: int) -> str:
    now = datetime.utcnow()
    one_hour_back = now
    if min_start != None: 
        if now.minute >= min_start:
            one_hour_back = now.replace(minute=min_start, second=0, microsecond=0)
        else:
            one_hour_back = now - timedelta(hours=1)
            one_hour_back.replace(minute=min_start, second=0, microsecond=0)

    est_start_int = int(one_hour_back.strftime("%Y%m%d%H%M%S"))

    return sha256_fold_xor(str(est_start_int),byte_num), now.minute


def sha256_fold_xor(data: str, byte_num: int) -> str:
    if 32%byte_num != 0:
        return ""
    digest = hashlib.sha256(data.encode()).digest()

    folded = [0]*byte_num
    for i,b in enumerate(digest):
        folded[i % byte_num] ^= b

    folded_bytes = bytes(folded)

    return folded_bytes


def find_public_ipv4():
    return requests.get("https://api.ipify.org").text

def ip_port_to_code(ipv4: str, port: int) -> str:
    ip_bytes = socket.inet_aton(ipv4)
    port_bytes = struct.pack("!H", port)
    data = ip_bytes + port_bytes + bytes(2)
    return data

def generate_severless_connection_token():
    public_ipv4 = find_public_ipv4()
    inital_code = ip_port_to_code(public_ipv4, 5000)
    print(len(inital_code))
    key, start_mins = round_hash(None,16)
    cipher = DES3.new(pad(key+COMMON_PHRASE.encode("utf-8"), 8), DES3.MODE_ECB)
    ciphertext = cipher.encrypt(inital_code)
    data = bytes.fromhex(str(ciphertext.hex()))
    return base64.b85encode(data).decode()+str(start_mins)


def find_peer_information(base85_str: str) -> str:
    seed_min = base85_str[10:]
    ciphertext = base64.b85decode(base85_str[:10])
    key, min = round_hash(int(seed_min), 16)
    cipher = DES3.new(pad(key+COMMON_PHRASE.encode("utf-8"), 24), DES3.MODE_ECB)
    print(len(ciphertext))
    plaintext = cipher.decrypt(ciphertext)
    print(code_to_ip_port(plaintext))

def code_to_ip_port(data: str) -> str:
    ip_bytes = data[:4]
    ipv4 = socket.inet_ntoa(ip_bytes)
    port_bytes = data[4:6]
    port = struct.unpack("!H", port_bytes)[0]

    return ipv4, port

token = generate_severless_connection_token()
print(token)
find_peer_information(token)
