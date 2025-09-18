# Severless-Peer-2-Peer-connection-token
For communicating inital public ipv4 and port for peer-2-peer connection without a intermediate third party server.
Is not secure, would be very simple to break as it uses timestamp and a common phrase to encrypt the token. 

## Abstract 
This script implements a serverless peer-to-peer connection token system, combining time-based hashing, DES3 encryption, and IP/port encoding to securely share connection information. 
Requires both paries are aware of a shared phrase or code, i.e. both parties are using the same client which uses a phrase "MYCLIENT" to seed the key derivation. 
Which acts as a miniscule extra layer of protection but also ensures both parties are communicating via the same program whether it be a game or a chat client.  


### Serverless Peer-to-Peer Connection Token System

1. **Time-based key derivation (`round_hash`)**
    - Computes a hash based on the current UTC time, rounding to the last `:17` minute.
    - Uses SHA-256 and a folding XOR technique to produce a fixed-length byte key.
    - Returns the key along with the current minute for freshness.

2. **IP and port encoding (`ip_port_to_code` / `code_to_ip_port`)**
    - Encodes the public IPv4 address and port into bytes for encryption.
    - Supports reversible decoding to retrieve the original IP and port.

3. **Public IP discovery (`find_public_ipv4`)**
    - Fetches the client’s public IPv4 via an external service (`api.ipify.org`).

4. **Token generation (`generate_severless_connection_token`)**
    - Combines the encoded IP/port with a time-derived key and a constant phrase (`COMMON_PHRASE`).
    - Pads and encrypts the data with DES3 in ECB mode.
    - Encodes the ciphertext using Base85 for compact representation and appends the time seed for token freshness.

5. **Token decryption (`find_peer_information`)**
    - Decodes the Base85 string, extracts the time seed, and reconstructs the DES3 key.
    - Decrypts the ciphertext to retrieve the original IP and port.
    - Provides a reversible mechanism for peers to discover connection information securely.

**Security & Practical Notes:**
- Uses **SHA-256 folding** and **time-based freshness** to limit token reuse.
- Pads keys and data to satisfy **3DES block size requirements**.
- Base85 encoding ensures compact, printable token strings.
- The system is suitable for **ad-hoc peer-to-peer lobby discovery** in games without relying on a central server.

