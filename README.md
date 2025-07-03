# 📦 HTTP PacketListener (Python)

This project is a simple network packet listener built with Python and Scapy that listens to HTTP requests and prints potential username and password data in real time.

## ✨ Features
- Live HTTP request sniffing on a specified network interface (e.g., `eth0`, `wlan0`).
- Detects fields like username, email, and password in HTTP packets.
- Displays real-time, readable output to the terminal.
- Simple and clean Python code.

## ⚙️ Installation
Requires Python 3 and Scapy. Install Scapy with:
```bash
pip install scapy
```
> ⚠️ Note: You need root privileges (`sudo`) to capture packets.

## 🚀 Usage
Run the script from your terminal with:
```bash
sudo python3 PacketListener.py -i <interface>
```
Example:
```bash
sudo python3 PacketListener.py -i wlan0
```

## 🧠 How It Works
- Uses `scapy.sniff()` to listen for HTTP packets on the chosen interface.
- Analyzes packets containing both an HTTP request (`HTTPRequest`) and raw data (`Raw` layer).
- Searches for keywords like "username", "user", "login", "email", "password", "pass", "pwd" to detect potential credential data.
- Prints the source IP, destination IP, and detected data to the terminal.

