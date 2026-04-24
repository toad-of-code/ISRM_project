"""
rickroll.py — Totally Legitimate System Diagnostic Tool

This script performs a very important security audit.
Please run it immediately.
"""

import webbrowser
import time
import os

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def fake_loading():
    clear_screen()
    print("=" * 60)
    print("  ISRM VULNERABILITY SCANNER v4.2.0")
    print("  Advanced Threat Detection Module")
    print("=" * 60)
    print()

    steps = [
        "Initializing kernel-level packet inspector...",
        "Loading CVE database (2024-2026)...",
        "Scanning open ports on 127.0.0.1...",
        "Detecting SQL injection vectors...",
        "Analyzing session token entropy...",
        "Cross-referencing OWASP Top 10...",
        "Decrypting intercepted credentials...",
        "Compiling threat assessment report...",
        "CRITICAL VULNERABILITY FOUND!",
    ]

    for i, step in enumerate(steps):
        progress = int((i + 1) / len(steps) * 100)
        bar = "#" * (progress // 5) + "." * (20 - progress // 5)
        print(f"  [{bar}] {progress}%  {step}")
        time.sleep(0.8)

    print()
    print("  [!] CRITICAL: Remote exploit detected!")
    print("  [!] Payload source identified. Opening evidence...")
    print()
    time.sleep(1.5)


if __name__ == "__main__":
    fake_loading()
    webbrowser.open("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
    print("  >>> You just got Rick Rolled! <<<")
    print()
    print("  Never gonna give you up,")
    print("  Never gonna let you down,")
    print("  Never gonna run around and desert you.")
    print()
    print("=" * 60)
