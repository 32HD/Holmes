#!/usr/bin/env python3

"""Sanity-check that Tshark can read one of the bundled sample PCAPs."""

import os
import shutil
import subprocess
import sys


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PCAP = os.path.join(REPO_ROOT, "log", "timestep_pcap", "27s-44s.pcap")
PCAP_PATH = os.environ.get("HOLMES_SAMPLE_PCAP", DEFAULT_PCAP)


def check_environment() -> str | None:
    print("[*] Checking Holmes packet-analysis environment...")

    if not os.path.exists(PCAP_PATH):
        print(f"[!] Sample PCAP not found: {PCAP_PATH}")
        return None

    tshark_bin = shutil.which("tshark")
    if not tshark_bin:
        print("[!] Tshark was not found in PATH.")
        return None

    try:
        ver = subprocess.run([tshark_bin, "-v"], capture_output=True, text=True, check=True)
        first_line = ver.stdout.splitlines()[0] if ver.stdout else "unknown version"
        print(f"[+] Found {first_line}")
    except Exception as exc:
        print(f"[!] Failed to execute tshark: {exc}")
        return None

    print(f"[+] Using sample PCAP: {PCAP_PATH}")
    return tshark_bin


def run_probe(tshark_bin: str) -> int:
    cmd = [
        tshark_bin,
        "-r",
        PCAP_PATH,
        "-c",
        "5",
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "udp.length",
        "-e",
        "data.data",
    ]

    print(f"[*] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"[!] Tshark failed with exit code {exc.returncode}")
        print(exc.stderr.strip())
        return 1

    output = result.stdout.strip()
    if not output:
        print("[!] Tshark completed but returned no rows.")
        return 1

    print("[+] Real packet output:")
    print("src_ip\tudp.length\tpayload_hex_prefix")
    for line in output.splitlines():
        parts = line.split("\t")
        src_ip = parts[0] if len(parts) > 0 else "N/A"
        udp_len = parts[1] if len(parts) > 1 else "N/A"
        payload = (parts[2][:30] + "...") if len(parts) > 2 and parts[2] else "N/A"
        print(f"{src_ip}\t{udp_len}\t{payload}")

    return 0


if __name__ == "__main__":
    tshark_bin = check_environment()
    sys.exit(run_probe(tshark_bin) if tshark_bin else 1)
