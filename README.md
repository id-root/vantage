<p align="center">
  <img src="https://img.shields.io/badge/Made%20with-Rust-black.svg" alt="Made with Rust">
  <img src="https://img.shields.io/badge/version-4.0.0-black.svg" alt="Version 4.0.0">
  <img src="https://img.shields.io/badge/Security-Post--Quantum-blueviolet" alt="Security Status">
  <img src="https://img.shields.io/badge/License-MIT-black.svg" alt="License: MIT">
</p>

# ISOTOPE (formerly Vantage)
<table>
  <tr>
    <td width="280" align="right">
      <img src="logo.png" width="280" alt="VANTAGE Logo">
    </td>
    <td>

ISOTOPE is a metadata-resistant, post-quantum secure messaging system designed for **hostile network environments**. It routes all traffic exclusively through **Tor Onion Services** and secures it with a defense-in-depth hybrid cryptographic stack.

Unlike standard secure messengers, ISOTOPE is built for **operational security (OPSEC)**, offering plausible deniability, anti-forensics, and a TUI designed for rapid situational awareness.
   </td>
  </tr>
</table>
---

## 🛡️ Security Architecture

### 1. Hybrid Post-Quantum Encryption
ISOTOPE uses a defense-in-depth "hybrid" model to protect against Store-Now-Decrypt-Later (SNDL) attacks.
*   **Layer 1 (Classic):** `Noise_XX_25519_ChaChaPoly_BLAKE2b` (Authenticated Key Exchange).
*   **Layer 2 (Post-Quantum):** `Kyber-1024` Key Encapsulation Mechanism (NIST PQC Winner).
*   **Key Rotation:** Session keys rotate every 100 messages or 5 minutes (Double Ratchet inspired).

### 2. Operational Security (OPSEC) features
*   **A2: Dead Man's Switch:**
    *   Automatic data wiping after **5 minutes of inactivity**.
    *   Triggers **MAYDAY Protocol**: Broadcasts a silent distress signal to all peers before destruction.
*   **A3: Hidden Volumes (TrueCrypt-style):**
    *   **Outer Password:** Unlocks "decoy" data partition.
    *   **Inner Password:** Unlocks "real" high-security partition.
    *   Mathematically impossible to prove the inner volume exists.
*   **T1: Cover Traffic:**
    *   Sends constant-rate dummy packets every 2-8 seconds to mask message timing.
*   **T2: Multi-Hop Onion Routing:**
    *   Chains multiple SOCKS5 proxies for defense-in-depth anonymity.
*   **C3: Deniable Authentication:**
    *   Uses **Ring Signatures** to authenticate group membership without revealing identity.
*   **D1: Anomaly Detection:**
    *   Behavioral profiling (typing speed, session times) detects if an account is compromised.

### 3. Anti-Forensics
*   **Secure Memory:** All sensitive keys and buffers are zeroized (overwritten) on drop.
*   **Panic Switch:** `Ctrl+X` or `/nuke` instantly wipes keys, deletes the identity file, and shreds local data.

---

## 💻 TUI & User Interface (New in Phase 5)

ISOTOPE v4.0.0 features a professional-grade Terminal User Interface (TUI) with a modular tabbed layout.

### **Navigation Controls**
| Key | Action |
|:---:|:---|
| `Tab` | Cycle Panel Focus (**Input** -> **Chat** -> **Operatives**) |
| `Alt+Right` | Next Tab (`COMMS` -> `VAULT` -> `INTEL`) |
| `Alt+Left` | Previous Tab |
| `?` | Toggle Help Overlay |
| `Esc` | Cancel / Close Modals |

### **1. [COMMS] Tab**
The main workspace for secure communication.
*   **Chat Window:** Syntax-highlighted messages. Code blocks are automatically formatted.
*   **Input:** Type `/` to see available commands.
*   **Operative List:** Real-time visibility of online peers.

### **2. [INTEL] Dashboard (HUD)**
Real-time operational metrics for situational awareness.
*   **Network Graphs:** Live upload/download traffic visualization (Sparklines).
*   **Status Panel:**
    *   **CIPHER:** `KYBER-1024` (Green = Secure).
    *   **IDENTITY:** `Ghost @ Ops` (Shows current persona).
    *   **UPTIME:** Session duration.
    *   **RAM:** Secure memory usage.

---

## 🛠️ Installation

### Linux 
1.  **Tor Service** (Port 9050)
    *   Linux: `sudo apt install tor && sudo systemctl start tor`
    
2.  **Rust Toolchain**
    *   [Install Rust](https://rustup.rs/)

3. **Windows Prerequisites**
   * _If you are using it in windows you must install tor services on your system `Steps are given below`_
---


## 📦 Windows tor installation
**Install the tor service on Windows**
- Install tor expert bunder from here [Tor Expert Bundle](https://archive.torproject.org/tor-package-archive/torbrowser/15.0.4/tor-expert-bundle-windows-x86_64-15.0.4.tar.gz)
- Then extract the bundle using `tar -xzf tor-expert-bundle-windows-x86_64-15.0.4.tar.gz`
- Then move the extracted tor directory to `C:\tor`
- Then create a `torrc` file and add these lines into the file
  ```c
  SocksPort 9050
  ControlPort 9051
  CookieAuthentication 1
  DataDirectory C:\Tor\data
  ```
  _Make sure you don't forget to create the data directory_
- Then run this command on tor directory `tor.exe -f torrc` and wait till it reaches `Bootstrap (100) Done`
- Verify the tor connection `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org` (Optional)


> **Note:**
> If you don't want to build from source you can download the executables for Windows and linux here [release](https://github.com/id-root/isotope/tag/)

### Build from Source
```bash
git clone https://github.com/id-root/isotope.git
cd isotope
cargo build --release
```
Location: `./target/release/isotope`

---

## 🚀 Usage Guide

### 1. Start Hub (Server)
```bash
./isotope server --port 7878 --identity server.id
```
*   Share the **Onion Address** & **Fingerprint** with your team.

### 2. Connect Client
**Persistent Identity (Recommended):**
```bash
./isotope client \
  --username "Ghost" \
  --address "onion_address.onion:7878" \
  --peer-fingerprint "SERVER_FINGERPRINT" \
  --identity ghost.id
```

**Ephemeral Mode (No Trace):**
```bash
./isotope client \
  --username "Ghost" \
  --address "onion_address.onion:7878" \
  --peer-fingerprint "SERVER_FINGERPRINT" \
  --temp
```

### 3. Identity Setup (Blue/RedPill)
When creating an identity (`.id`), you must set **two** passwords:
1.  **REAL Password:** Logs into your standard operational profile.
2.  **DURESS Password:** Logs into a "Casual" decoy profile.
    *   *Safe to provide if forced. Checks out perfectly but reveals nothing.*

---

## ⚡ Command Reference

| Command | Description |
| :--- | :--- |
| `/msg <user> <txt>` | Direct Message (DM). |
| `/ttl <user> <sec> <txt>` | **Self-Destructing Message**. |
| `/send <file>` | Secure file transfer (encrypted/padded). |
| `/get <id>` | Download offered file. |
| `/browse` | Open interactive file picker for uploads. |
| `/vault_put <file>` | Move file to **Hidden Vault**. |
| `/vault_get <file>` | Extract file from **Hidden Vault**. |
| `/nuke` | **PANIC PROTOCOL:** Send distress signal + Wipe Data. |
| `Ctrl+c` | Safe Quit. |
| `Ctrl+x` | **PANIC PROTOCOL** (Instant). |

---

## 🧪 Verification
ISOTOPE runs comprehensive integration tests ensuring cryptographic integrity.
```bash
# Run Security Suite
cargo test
```

---
*Disclaimer: This software is provided "as is" for educational and research purposes. Use responsibly.*
