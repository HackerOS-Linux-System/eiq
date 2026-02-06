import argparse
import subprocess
import time
import os
import sys
import random
import string
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional

# --- Config ---
TOR_USER = "debian-tor"
INTERFACES = ["wlan0", "eth0", "enp"]  # wykrywa pierwsze pasujące
NEWNYM_INTERVAL = 600     # 10 min
MACRAND_INTERVAL = 3600   # 1h

# --- Helpers ---
def run(cmd: list, check=True, capture=False):
    if capture:
        return subprocess.run(cmd, check=check, capture_output=True, text=True)
    subprocess.run(cmd, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_interface():
    for iface in INTERFACES:
        try:
            out = run(["ip", "-br", "link"], capture=True)
            for line in out.stdout.splitlines():
                if iface in line and "UP" in line:
                    return line.split()[0]
        except:
            pass
    return None

# --- Core modules ---
def mac_randomize():
    iface = get_interface()
    if iface:
        run(["ip", "link", "set", iface, "down"])
        run(["macchanger", "-r", iface])
        run(["ip", "link", "set", iface, "up"])
        print(f"[+] MAC randomized on {iface}")

def randomize_hostname():
    name = "host-" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    run(["hostnamectl", "hostname", name])
    print(f"[+] Hostname -> {name}")

def disable_ipv6():
    run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
    run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"])

def tor_killswitch_up():
    """nftables: policy drop + only debian-tor + loopback + established"""
    nft_script = f"""
flush ruleset
table inet filter {{
    chain output {{
        type filter hook output priority 0; policy drop;
        oif lo accept
        skuid {TOR_USER} accept
        ct state established,related accept
    }}
}}
"""
    run(["nft", "-f", "-"], input=nft_script, check=True)
    print("[+] Tor-only killswitch ACTIVATED (nftables)")

def tor_killswitch_down():
    run(["nft", "flush ruleset"])
    print("[-] Killswitch DISABLED")

def tor_control():
    try:
        with stem.control.Controller.from_port(port=9051) as controller:
            controller.authenticate()
            return controller
    except:
        return None

def newnym():
    ctrl = tor_control()
    if ctrl:
        ctrl.signal(stem.Signal.NEWNYM)
        print("[+] NEWNYM sent")

# --- Crypto ---
def derive_key(password: str, salt: Optional[bytes] = None) -> bytes:
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(in_path: str, out_path: str, password: str):
    key, salt = derive_key(password)
    f = Fernet(key)
    with open(in_path, "rb") as f_in:
        data = f_in.read()
    token = f.encrypt(data)
    with open(out_path, "wb") as f_out:
        f_out.write(salt + token)
    print(f"[+] Encrypted → {out_path} (salt prepended)")

def decrypt_file(in_path: str, out_path: str, password: str):
    with open(in_path, "rb") as f:
        data = f.read()
    salt, token = data[:16], data[16:]
    key, _ = derive_key(password, salt)
    f = Fernet(key)
    try:
        plain = f.decrypt(token)
        with open(out_path, "wb") as f_out:
            f_out.write(plain)
        print(f"[+] Decrypted → {out_path}")
    except:
        print("[-] Wrong password / corrupted file")

# --- Main commands ---
def cmd_up(args):
    print("=== eiq UP ===")
    disable_ipv6()
    mac_randomize()
    randomize_hostname()
    tor_killswitch_up()
    run(["systemctl", "restart", "tor"])
    time.sleep(8)  # wait bootstrap
    print("[+] eiq protections ACTIVE. Use torsocks / SOCKS5 127.0.0.1:9050")

def cmd_down(args):
    print("=== eiq DOWN ===")
    tor_killswitch_down()
    run(["systemctl", "restart", "tor"])  # normal mode

def cmd_daemon(args):
    print("=== eiq DAEMON STARTED (Ctrl+C to stop) ===")
    last_newnym = last_mac = time.time()
    while True:
        try:
            ctrl = tor_control()
            if not ctrl or not ctrl.is_alive:
                print("Tor dead → restarting")
                run(["systemctl", "restart", "tor"])
                time.sleep(10)
            elif time.time() - last_newnym > NEWNYM_INTERVAL:
                newnym()
                last_newnym = time.time()
            if time.time() - last_mac > MACRAND_INTERVAL:
                mac_randomize()
                last_mac = time.time()
            time.sleep(30)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Daemon error: {e}")
            time.sleep(60)

def main():
    parser = argparse.ArgumentParser(description="eiq - Everywhere Is Quiet")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("up", help="Activate full protection")
    sub.add_parser("down", help="Disable protection")
    sub.add_parser("daemon", help="Run background monitor + NEWNYM")
    sub.add_parser("status", help="Show status")  # prosty

    enc = sub.add_parser("encrypt", help="Encrypt file")
    enc.add_argument("file", type=str)
    enc.add_argument("-o", "--out", type=str)
    enc.add_argument("-p", "--password", required=True)

    dec = sub.add_parser("decrypt", help="Decrypt file")
    dec.add_argument("file", type=str)
    dec.add_argument("-o", "--out", type=str, required=True)
    dec.add_argument("-p", "--password", required=True)

    args = parser.parse_args()

    if args.cmd == "up":
        cmd_up(args)
    elif args.cmd == "down":
        cmd_down(args)
    elif args.cmd == "daemon":
        cmd_daemon(args)
    elif args.cmd == "encrypt":
        out = args.out or args.file + ".eiq"
        encrypt_file(args.file, out, args.password)
    elif args.cmd == "decrypt":
        decrypt_file(args.file, args.out, args.password)
    else:
        parser.print_help()

if __name__ == "__main__":
    if os.getuid() != 0 and sys.argv[1] in ("up", "down", "daemon"):
        print("[-] Needs root for up/down/daemon")
        sys.exit(1)
    main()
