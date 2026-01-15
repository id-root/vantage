
# VANTAGE 

**Verifiable Adversary-Resistant Network Transport & Group Exchange**

VANTAGE is a high-assurance, metadata-resistant chat system designed for hostile network environments. It routes all traffic exclusively through Tor Onion Services and uses a custom Noise Protocol implementation to guarantee mutual authentication, forward secrecy, and traffic analysis resistance.

Unlike standard encrypted messengers, VANTAGE is **serverless in design** (no central authority) but operational via a **Hub-and-Spoke** model, allowing you to self-host a private, invisible chat relay for your team.

---

## 🛡️ Security Architecture

### 1. The Anonymity Layer (Tor)
VANTAGE does not use IP addresses. It binds strictly to **Tor Hidden Services (v3 Onion Addresses)**.
* **No Port Forwarding:** Works behind firewalls, NATs, and carrier-grade mobile networks.
* **Location Hiding:** The physical location of the Hub is hidden from Clients, and Clients are hidden from the Hub.
* **End-to-End Encryption:** Tor provides the first layer of encryption for the transport.

### 2. The Application Layer (Noise Protocol)
Inside the Tor tunnel, VANTAGE establishes a second, independent encrypted tunnel using the **Noise Protocol Framework**.
* **Handshake:** `Noise_XX_25519_ChaChaPoly_BLAKE2b`
    * **XX Pattern:** Mutual authentication. Both Client and Hub prove their identity before any data is exchanged.
    * **25519:** Curve25519 for Diffie-Hellman key exchange.
    * **ChaChaPoly:** ChaCha20-Poly1305 for authenticated encryption.
    * **BLAKE2b:** Hashing algorithm for keys.
* **Zeroization:** Private keys are marked with the `Zeroize` trait, ensuring they are wiped from memory immediately upon drop to prevent cold-boot attacks.

### 3. Traffic Analysis Resistance
Standard encryption hides *what* you say, but not *how much* you say. VANTAGE defeats packet size analysis.
* **Constant-Rate Padding:** Every single packet sent over the wire is padded to exactly **4096 bytes**.
* **Obfuscation:** An observer (ISP or compromised node) cannot distinguish between a short "Hi", a long paragraph, or a handshake packet. They all look identical.

---

## 🛠️ Prerequisites

Before installing, ensure you have the following:

1.  **Tor Background Service:** (Must be running on system port 9050)
    * Debian/Ubuntu: `sudo apt install tor`
    * Arch: `sudo pacman -S tor`

2.  **Rust Toolchain:**
    * Install via: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

---

## 📦 Installation

1.  **Clone & Build:**
    ```bash
    git clone [https://github.com/id-root/vantage.git](https://github.com/id-root/vantage.git)
    cd vantage
    cargo build --release
    ```

2.  **Locate Binary:**
    The executable is optimized and located at:
    `./target/release/vantage`

---

## ⚙️ Hub Configuration (Server)

To host a chat group, you must configure a Tor Hidden Service on the server machine.

1.  **Edit Tor Config (`/etc/tor/torrc`):**
    Add these two lines to the bottom of the file:
    ```text
    HiddenServiceDir /var/lib/tor/vantage_hub/
    HiddenServicePort 7878 127.0.0.1:7878
    ```

2.  **Start Tor:**
    ```bash
    sudo systemctl enable tor
    sudo systemctl start tor
    ```

3.  **Get Your Onion Address:**
    ```bash
    sudo cat /var/lib/tor/vantage_hub/hostname
    ```
    *Save/copy this address (e.g., `yw4...xyz.onion`). You will share this with your users.*

---

## 🚀 Usage Guide

### 1. Start the Hub (Server)
Run this on the machine hosting the Hidden Service.

```bash
./target/release/vantage server --port 7878

```

* **Identity:** A persistent identity file (`vantage.id`) is created automatically.
* **Fingerprint:** The server will display a Base64 fingerprint. **Share this with your users.**
> `🚀 Server Online. Fingerprint: vKfD+dDX5BSKtkhP31YiL09tM0lopzuHvwZggc094=`



### 2. Connect a User (Client)

Users connect using the Onion Address and the Hub's Fingerprint.

```bash
./target/release/vantage client \
  --address "your_onion_address.onion:7878" \
  --username "Alice" \
  --peer-fingerprint "SERVER_FINGERPRINT_HERE"

```

* **Verify:** If the server fingerprint does not match, the client will abort immediately to prevent Man-in-the-Middle (MITM) attacks.
* **Chat:** Once connected, type messages and press Enter. Messages are encrypted, sent to the Hub, and broadcast to all other connected users.

---

## ❓ Troubleshooting

**Error: SOCKS5 connection failed**

* Is Tor running? (`systemctl status tor`)
* Is Tor listening on port 9050? (`ss -nltp | grep 9050`)
* If you changed Tor's port, update the `--proxy` argument.

**Error: Decrypt error / Protocol Mismatch**

* Ensure both Server and Client are running the exact same version of VANTAGE.
* Ensure you strictly updated the `network.rs` code to include the Length-Prefix framing fix (v3.0).

**Fingerprint Mismatch**

* **STOP.** Do not connect. This means the Onion Address you are connecting to is NOT serving the key you expect. It could be a typo, or an adversary has hijacked the address.

---

## 🤝 Contributing

**Have an idea to make VANTAGE better?**

This project is open-source and thrives on community contributions. Whether you want to add file transfer support, a GUI, or improve the crypto implementation, we welcome your pull requests!

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes.
4. Open a Pull Request.

*Together, we can build a more private web.*
