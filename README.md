<p align="center">
  <a href="https://www.rust-lang.org/">
    <img src="https://img.shields.io/badge/Made%20with-Rust-black.svg" alt="Made with Rust">
  </a>
  <a href="https://github.com/id-root/vantage">
    <img src="https://img.shields.io/badge/version-3.0.0-black.svg" alt="Version 3.0.0">
  </a>
  <a href="https://github.com/id-root/vantage/actions">
    <img src="https://github.com/id-root/vantage/actions/workflows/rust.yml/badge.svg" alt="Build Status">
  </a>
  <a href="https://github.com/id-root/vantage">
    <img src="https://img.shields.io/badge/Security-Post--Quantum-blueviolet" alt="Security Status">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-black.svg" alt="License: MIT">
  </a>
</p>

# VANTAGE
<table>
  <tr>
    <td width="280" align="right">
      <img src="logo.png" width="280" alt="VANTAGE Logo">
    </td>
    <td>

### **Verifiable Adversary-Resistant Network Transport & Group Exchange**

VANTAGE is a metadata-resistant, post-quantum secure messaging system designed for hostile network environments. It routes all traffic exclusively through **Tor Onion Services** and secures it with a hybrid cryptographic stack combining **Noise Protocol** and **Kyber-1024**.

* **🛡️ Post-Quantum Security:** Native Kyber-1024 Key Encapsulation.
* **🧅 Tor Native:** Operates exclusively over Tor Hidden Services.
* **💬 Group Channels:** Support for partitioned topics (e.g., `#ops`, `#general`).
* **👻 Traffic Masking:** Constant-rate packet padding (4096 bytes).
* **🚨 Panic Switch:** Instantly wipe keys and data with a single keystroke.

    </td>
  </tr>
</table>

---

## 🛡️ Security Architecture

### 1. Hybrid Post-Quantum Encryption
VANTAGE uses a defense-in-depth approach. Even if the classic Elliptic Curve cryptography is broken by a quantum computer, the secondary Quantum-Resistant layer remains secure.
* **Layer 1 (Classic):** `Noise_XX_25519_ChaChaPoly_BLAKE2b` (Mutual Authentication).
* **Layer 2 (Quantum):** `Kyber-1024` Key Encapsulation Mechanism (NIST PQC Winner).
* **Rekeying:** The inner ChaCha20-Poly1305 cipher rotates keys based on the quantum shared secret.

### 2. The Anonymity Layer (Tor)
VANTAGE does not use IP addresses. It binds strictly to **Tor Hidden Services (v3 Onion Addresses)**.
* **Location Hiding:** The physical location of the Hub is hidden from Clients, and Clients are hidden from the Hub.
* **NAT Traversal:** Works behind strict firewalls and carrier-grade NAT without port forwarding.

### 3. Traffic Analysis Resistance
Standard encryption hides *what* you say, but not *how much* you say. VANTAGE defeats packet size analysis.
* **Constant-Rate Padding:** Every packet (Chat, System, or File Chunk) is padded to exactly **4096 bytes**.
* **Obfuscation:** An observer cannot distinguish between a text message, a file transfer segment, or a heartbeat.

### 4. Identity & Persistence
* **Persistent Identities:** Users generate a keypair stored in `vantage.id`. This allows you to maintain your "Fingerprint" across sessions.
* **Ephemeral Mode:** Use the `--temp` flag to generate a one-time identity that is destroyed upon exit.
* **Zeroization:** Sensitive keys are wiped from memory immediately upon drop using the `zeroize` crate.

---

## 🛠️ Prerequisites

1.  **Tor Background Service:** (Must be running on system port 9050)
    * Debian/Ubuntu/Kali: `sudo apt install tor`
    * Arch: `sudo pacman -S tor`
    * *Ensure `SocksPort 9050` is enabled in your `torrc`.*

2.  **Rust Toolchain:**
    * Install via: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

---

## 📦 Installation

1.  **Clone & Build:**
    ```bash
    git clone https://github.com/id-root/vantage.git
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
    ```text
    HiddenServiceDir /var/lib/tor/vantage_hub/
    HiddenServicePort 7878 127.0.0.1:7878
    ```

2.  **Restart Tor:**
    ```bash
    sudo systemctl enable tor
    sudo systemctl restart tor
    ```

3.  **Get Your Onion Address:**
    ```bash
    sudo cat /var/lib/tor/vantage_hub/hostname
    ```

---

## 🚀 Usage Guide

### 1. Start the Hub (Server)
Run this on the machine hosting the Hidden Service. It will generate a `server.id` file automatically.

```bash
./target/release/vantage server --port 7878 --identity server.id

```

> `🚀 Server Online. Fingerprint: vKfD+dDX5BSKtkhP31YiL09tM0lopzuHvwZggc094=`

### 2. Connect a User (Client)

Users connect using the Onion Address and the Hub's Fingerprint. You can specify a group channel (default is `#public`).

**Option A: Persistent Identity (Recommended)**

```bash
./target/release/vantage client \
  --username "Alice" \
  --address "your_onion_address.onion:7878" \
  --peer-fingerprint "SERVER_FINGERPRINT_HERE" \
  --group "hackers" \
  --identity alice.id

```

**Option B: Ephemeral Identity (Ghost Mode)**
Using `--temp` generates a random identity that is never saved to disk.

```bash
./target/release/vantage client \
  --username "Ghost" \
  --address "your_onion_address.onion:7878" \
  --peer-fingerprint "SERVER_FINGERPRINT_HERE" \
  --temp

```

### 3. TUI Controls & Commands

Once connected, you will see the VANTAGE Dashboard.

| Command | Description |
| --- | --- |
| `Esc` | Quit VANTAGE safely. |
| `/send <path>` | Offer a file to the group. `Limit: (10 MB)` |
| `/get <id>` | Accept and download a file. |
| `/nuke` or `Ctrl + x` | **PANIC:** Wipe identity file and downloads folder immediately. |
| `/quit` | Disconnect. |

---

## 📎 File Transfer Guide

VANTAGE uses an **Offer/Accept** model for security.

**1. Sender Offers a File**
Alice wants to send a photo. She types:

```text
/send /home/alice/secrets.pdf

```

* **Result:** The group sees: `📎 Alice offered 'secrets.pdf' (ID: 4921).`

**2. Receiver Accepts the File**
Bob wants the file. He types the ID shown in the offer:

```text
/get 4921

```

* **Result:** The system begins streaming the file securely using chunked, padded packets.

**3. Download Complete**
The file is saved automatically to the `downloads/` folder.

> `✅ File Saved: downloads/secrets.pdf`

*⚠️ Traffic Safety Limits (10 MB Cap)*

VANTAGE enforces a strict **10 MB limit** on file transfers to ensure the stability and anonymity of the Tor circuit.

---

## ❓ Troubleshooting

**Error: Connection failed / SOCKS5 error**

* Is Tor running? `systemctl status tor`
* Is Tor listening on port 9050? `ss -nltp | grep 9050`
* If your Tor proxy is on a different port, use the `--proxy` flag:
`./vantage client ... --proxy 127.0.0.1:9150`

**Error: "Fingerprint Mismatch"**

* **STOP.** The server you reached is NOT the one you expected. This indicates a potential Man-in-the-Middle attack or a typo in your command.

**Panic! I need to delete everything.**

* Press `Ctrl + x` inside the application. This executes the `nuke_everything` protocol, overwriting your identity file (`.id`) and `downloads/` folder with zeros before deleting them.

---

## 🤝 Contributing

This project is open-source. Whether you want to add voice support, improve the TUI, or audit the crypto implementation, we welcome your pull requests!

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes.
4. Open a Pull Request.

*Let's experience the cyberspace.*

```

```
