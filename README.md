# 🛡️ AlloChat Extension

> **A completely decentralized, secure, and metadata-resistant Web3 messenger embedded directly in your browser, powered by the Algorand Mainnet and IPFS.**

AlloChat is an ultra-lightweight, open-source browser extension for Chromium-based browsers that enables fully end-to-end encrypted (E2E) communication directly via secure, low-cost blockchain transactions. With no intermediate staging servers, sign-ups, or central databases, AlloChat guarantees the absolute highest level of user privacy and digital sovereignty.

---

## 🚀 Key Advantages & Features

AlloChat blends cutting-edge Web3 technologies with a pristine dark user interface, micro-animations, and a fluid decentralized user experience (UX).

### 🔒 1. Security-First Architecture (Zero Server Trail)
*   **100% Serverless Architecture:** All text messages and file pointers are transmitted directly through the decentralized Algorand ledger. Your conversations never interact with, nor are they logged by, third-party centralized servers.
*   **Military-Grade End-to-End Encryption:** Every message payload is automatically encrypted using highly secure **AES-256-GCM** keys derived through the Diffie-Hellman Key Exchange (X25519) algorithm. Decryption happens purely locally on the recipient's machine.
*   **Encrypted Contact Book:** Your contact list and companion notes are stored locally in an encrypted sandbox. An optional backup of your contacts can be exported, protected with your public key.
*   **Self-Encrypted Notes (Personal Safe):** A dedicated, automated mechanism allowing you to securely back up, encrypt, and store personal journals or credentials directly to your own wallet address via Algorand transaction notes.

### ⚡ 2. High-Performance UX (Async Pipeline)
*   **Asynchronous Background Sending (Service Worker):** AlloChat eliminates block confirmation delays. Messages appear immediately in your active UI thread, while the transaction is queued and dispatched in the background without locking your interface.
*   **Decentralized Media Uploads (Encrypted IPFS + Pinata Pinning):** For media files, photos, or documents exceeding the standard blockchain transaction note size limit (1KB), AlloChat automatically encrypts the files locally using an ephemeral AES-256 key, uploads them to IPFS, and signs the IPFS multi-hash pointer into the Algorand transaction note.
*   **Session Auto-Lock (RAM Wipe):** Set custom idle timeout thresholds. Once reached, any private keys or secure session tokens are completely wiped from active memory to protect against local physical compromises.

### 🌐 3. Powered by Algorand Mainnet
*   **Sub-3-Second Settlement:** Algorand settles blocks almost instantly, providing lightning-fast message arrival without the risk of chain re-organizations (no-fork promise).
*   **Extremely Low Cost:** Sending a message costs only a static transaction fee of **0.001 ALGO** (a fraction of a cent), keeping private, permanent, subscription-free communication affordable for everyone.

---

## 🔒 Cryptographic Design & Flow

AlloChat prioritizes cryptographic hygiene above all:
1.  **Local Account Initialization:** Key pairs are imported or generated locally using BIP-39 25-word mnemonics. Transactions are signed locally inline via `algosdk`—your cryptographic secret key never leaves your system.
2.  **Passcode Encryption:** The extension's local state and encrypted contact indexes are secured using an authentication passcode hashed with PBKDF2.

---

## ⚙️ Direct Installation & Developer Setup

This repository contains the complete package designed for Chromium browser installation:

### Step 1: Installing the Extension in Chrome / Chromium
1.  Download or clone this repository to your local machine.
2.  Open any Chromium-based browser (Google Chrome, Brave, Arc, Edge, Vivaldi, Opera).
3.  Navigate to the extensions manager page is: `chrome://extensions/`.
4.  Enable **Developer mode** using the toggle switch in the upper-right corner of the page.
5.  Click the **Load unpacked** button in the upper-left corner.
6.  Select the extension packaging directory `allochat-extension-mainnet` from your local copy of the repository.
7.  Pin the **AlloChat** launcher icon to your browser panel and start chatting securely!

### Step 2: Running the Local Simulation & Diagnostic Suite (Companion Vite App)
This workspace includes an interactive companion web dashboard that lets you test and view core cryptographic behaviors and simulate account events from a standard browser environment:
```bash
# Install development and module dependencies
npm install

# Start the interactive local development workspace (Port 3000)
npm run dev
```

---

## 🛠️ Technology Stack
*   **React + TypeScript + Vite + Tailwind CSS** (Interactive Companion & Diagnostic Panel)
*   **Algorand JS SDK (`algosdk`)** (On-chain state tracking, block parsing, and local tx signing)
*   **Web Crypto API** (Native, high-entropy cryptographic primitives and AES key operations)
*   **Pinata IPFS Gateway integration** (Privacy-preserved cloud hosting for files)

---

*AlloChat. Freedom of speech, speed of light, absolute privacy driven by Algorand’s neutral blockchain machinery.*
