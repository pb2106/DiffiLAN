# 🔐 Diffie-Hellman Key Exchange with LAN Device Scanner

This project demonstrates a **basic Diffie-Hellman key exchange** implementation over TCP sockets, combined with a **LAN device scanner** using ARP requests.
It shows how two peers can exchange keys securely and derive a **shared secret**, while also providing a quick utility to scan for devices in the same network.

---

##  Features

* 📡 **LAN Scanner** – Detect devices on the local network (IP & MAC addresses).
* 🔑 **Diffie-Hellman Key Exchange** – Securely exchange keys between two peers.
* 🔐 **Shared Secret Generation** – Both peers independently compute the same secret key.
* 🌍 **Client-Server Communication** – Supports running as a server and optionally connecting as a client.

---

## 📦 Requirements

* Python 3.8+
* `scapy` (for ARP-based LAN scanning)
* `tabulate` (for formatted table output)

---

## ⚙️ Installation

1. Clone or download this repository:

   ```bash
   git clone https://github.com/yourusername/diffie-hellman-lan.git
   cd diffie-hellman-lan
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## ▶️ Usage

1. Run the script:

   ```bash
   python dh_lan.py
   ```

2. The program will:

   * Scan your LAN and list available devices.
   * Ask you to enter a private key (integer).
   * Ask for your peer’s IP address (leave blank if you only want to run as a server).

3. Example workflow:

   * **Peer 1 (Server):**

     ```bash
     python dh_lan.py
     Enter a private key: 7
     Enter the peer's IP (leave blank if only running as server):
     ```
   * **Peer 2 (Client):**

     ```bash
     python dh_lan.py
     Enter a private key: 11
     Enter the peer's IP (leave blank if only running as server): 192.168.1.10
     ```

4. Both peers will compute the same **shared secret key**.

---

## ⚠️ Notes

* This is a **learning/demo project**; it does not implement cryptographic best practices.
* Do not use it for production security — use well-tested libraries instead.
* Running ARP scans may require **administrator/root privileges**.
* not maintained

---
