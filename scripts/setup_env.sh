#!/bin/bash
echo "[*] Setting up build environment for EAL..."
sudo apt update
sudo apt install -y build-essential cmake pkg-config libssl-dev linux-libc-dev clang
echo "[+] Environment ready."
