# SSH Honeypot

**PucciSSH** is a custom SSH honeypot written in Python using `paramiko`. It emulates a basic shell environment and captures login attempts, commands, and client IPs. Designed to appear realistic, it supports basic Linux-like commands, logs user behavior, and serves as a lightweight deception system for threat intelligence collection.

---

## ✨ Features

- Fake SSH server using `paramiko`
- Simulated interactive shell with common commands:
  - `whoami`, `history`, `ls`, `pwd`, `cat`, `cd`, `clear`, `echo`, `exit`
- Logs:
  - Connection attempts with IP addresses
  - All entered commands
- Minimal, believable Linux-like shell responses
- Persistent rotating log files:
  - `audits.log`: connection logs
  - `cmd_audits.log`: command logs
- Handles shell control characters (like backspace and arrow keys)
- Uses RSA host key for SSH protocol handshake

---

## 🛠 Requirements

Ensure you have **Python 3.7+** installed.

### Python Libraries

Install the required packages with:

```bash
pip install -r requirements.txt
```

## 🚀 Usage
1. Generate a host RSA key if you don't already have one:
```bash
ssh-keygen -t rsa -b 2048 -f server.key
```
2. Run the honeypot:
```bash
python honeypot.py
```
3. The honeypot listens on 127.0.0.1:2223 (changeable in code).
4. Connect using any SSH client:
```bash
ssh -p 2223 user@127.0.0.1
```
## 📓 Example Logs
audits.log
```bash
[127.0.0.1] Connected to honeypot
```
cmd_audits.log
```bash
[127.0.0.1] whoami
[127.0.0.1] ls
[127.0.0.1] cat file1.txt
```
## 🔐 Disclaimer
This honeypot is intended for educational and research purposes only. Do not expose it to the public internet without proper safeguards.

## 📄 License
MIT License
