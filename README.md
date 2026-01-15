<p align="center">
  <a href="https://www.rust-lang.org/">
    <img src="https://img.shields.io/badge/Made%20with-Rust-black.svg" alt="Made with Rust">
  </a>
  <a href="https://github.com/id-root/vantage">
    <img src="https://img.shields.io/badge/version-3.1.0-black.svg" alt="Version 3.1.0">
  </a>
  <a href="https://github.com/id-root/vantage/actions">
    <img src="https://github.com/id-root/vantage/actions/workflows/rust.yml/badge.svg" alt="Build Status">
  </a>
  <a href="https://github.com/id-root/vantage">
    <img src="https://img.shields.io/badge/Security-Experimental-black" alt="Security Status">
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

VANTAGE is a metadata-resistant chat and file-sharing system designed for hostile network environments. It routes all traffic exclusively through **Tor Onion Services** and secures it with a **Noise Protocol** transport.

* **Secure TUI:** A full Terminal User Interface dashboard.
* **Stealth File Transfer:** Send files masquerading as chat traffic.
* **Offer/Accept Protocol:** Prevents unconsented drive-by downloads.

    </td>
  </tr>
</table>

---

## 🛡️ Security Architecture

### 1. The Anonymity Layer (Tor)
VANTAGE does not use IP addresses. It binds strictly to **Tor Hidden Services (v3 Onion Addresses)**.
* **Location Hiding:** The physical location of the Hub is hidden from Clients, and Clients are hidden from the Hub.
* **NAT Traversal:** Works behind strict firewalls and carrier-grade NAT without port forwarding.

### 2. The Application Layer (Noise Protocol)
Inside the Tor tunnel, VANTAGE establishes a second, independent encrypted tunnel using the **Noise Protocol Framework**.
* **Handshake:** `Noise_XX_25519_ChaChaPoly_BLAKE2b` (Mutual Authentication).
* **Zeroization:** Keys are wiped from memory immediately upon drop to prevent cold-boot attacks.

### 3. Traffic Analysis Resistance
Standard encryption hides *what* you say, but not *how much* you say. VANTAGE defeats packet size analysis.
* **Constant-Rate Padding:** Every packet (Chat, System, or File Chunk) is padded to exactly **4096 bytes**.
* **Obfuscation:** An observer cannot distinguish between a text message and a file transfer segment.

### 4. Secure File Transfer
* **Chunking:** Files are split into small encrypted chunks and interleaved with chat traffic.
* **Consent First:** Files are never automatically downloaded. The receiver must explicitly authorize the download via the `/get` command.
* **Sanitization:** Filenames are sanitized to prevent directory traversal attacks.

---

## 🛠️ Prerequisites

1.  **Tor Background Service:** (Must be running on system port 9050)
    * Debian/Ubuntu/Kali: `sudo apt install tor`
    * Arch: `sudo pacman -S tor`
    * *Ensure the service is active:* `sudo systemctl start tor`

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
    sudo systemctl start tor
    ```

3.  **Get Your Onion Address:**
    ```bash
    sudo cat /var/lib/tor/vantage_hub/hostname
    ```

---

## 🚀 Usage Guide

### 1. Start the Hub (Server)
Run this on the machine hosting the Hidden Service.

```bash
./target/release/vantage server --port 7878

```

> `🚀 Server Online. Fingerprint: vKfD+dDX5BSKtkhP31YiL09tM0lopzuHvwZggc094=`

### 2. Connect a User (Client)

Users connect using the Onion Address and the Hub's Fingerprint.

```bash
./target/release/vantage client \
  --address "your_onion_address.onion:7878" \
  --username "Alice" \
  --peer-fingerprint "SERVER_FINGERPRINT_HERE"

```

### 3. TUI Controls & Commands

Once connected, you will see the VANTAGE Dashboard.

| Command | Description |
| --- | --- |
| **Esc** | Quit VANTAGE safely. |
| `/send <path>` | Offer a file to the group. |
| `/get <id>` | Accept and download a file. |
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

* **Result:** The system begins streaming the file securely.

**3. Download Complete**
The file is saved automatically to the `downloads/` folder in your current directory.

> `✅ File Saved: downloads/secrets.bin`
 
*Why are files saved as .bin? Files are saved with generic IDs (e.g., file_8291.bin) as a security fail-safe to prevent Directory Traversal Attacks. VANTAGE ignores the remote filename during the write process to ensure a malicious peer cannot overwrite your system files (e.g., sending a file named ../../.bashrc). Users must manually rename files after verifying their safety.*

---

## ❓ Troubleshooting

**Error: Connection failed / SOCKS5 error**

* Is Tor running? `systemctl status tor`
* Is Tor listening on port 9050? `ss -nltp | grep 9050`

**Error: "Fingerprint Mismatch"**

* **STOP.** The server you reached is NOT the one you expected. This indicates a potential Man-in-the-Middle attack or a typo in your command.

**Where are my files?**

* Check the `downloads` folder created where you ran the binary.



---

## 🤝 Contributing

This project is open-source. Whether you want to add voice support, improve the TUI , or audit the crypto implementation, we welcome your pull requests!

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes.
4. Open a Pull Request.

*Let's experience the cyberspace.*

