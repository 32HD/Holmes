#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Holmes: an evidence-grounded LLM agent for auditable DDoS investigation.

The pipeline keeps a simple, auditable workflow:
monitor -> sFlow triage -> packet evidence extraction -> LLM verdict.

Run:
  python3 ddos_agent_v2.py

Environment:
  DISABLE_LLM=1 to skip the LLM and exercise the pipeline only
  HOLMES_DATA_ROOT=/path/to/log to override the bundled sample data
  HOLMES_REPORT_PATH=/path/to/security_audit_report.txt to override the output file
  VLLM_API_BASE=http://127.0.0.1:8002/v1 for a local OpenAI-compatible endpoint
  LLM_MODEL_NAME=deepseek-r1 (or another served model name)
"""

import os
import sys
import re
import json
import glob
import math
import shutil
import subprocess
import time
from datetime import datetime
from typing import Dict, Any, List, Tuple, TypedDict, Optional

import pandas as pd
import numpy as np
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, END

# ============================================================
# 0) Config
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DATA_ROOT = os.path.join(BASE_DIR, "log")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
DATA_ROOT = os.environ.get("HOLMES_DATA_ROOT", DEFAULT_DATA_ROOT)
PCAP_DIR_NAME = "timestep_pcap"
LOG_FILE = os.environ.get(
    "HOLMES_REPORT_PATH",
    os.path.join(OUTPUT_DIR, "security_audit_report.txt"),
)

MONITOR_THRESHOLD_BPS = int(os.environ.get("MONITOR_THRESHOLD_BPS", "10000000"))
MAX_DATA_DURATION = float(os.environ.get("MAX_DATA_DURATION", "950.0"))

COUNTER_HALF_WINDOW = float(os.environ.get("COUNTER_HALF_WINDOW", "0.5"))
SFLOW_HALF_WINDOW = float(os.environ.get("SFLOW_HALF_WINDOW", "0.5"))
INCIDENT_COOLDOWN_S = float(os.environ.get("INCIDENT_COOLDOWN_S", "10.0"))

DISABLE_LLM = os.environ.get("DISABLE_LLM", "0") == "1"

# tshark caps
TSHARK_MAX_SCAN_PKTS = int(os.environ.get("TSHARK_MAX_SCAN_PKTS", "50000"))
UDP_TOPK_SRC_IP = int(os.environ.get("UDP_TOPK_SRC_IP", "5"))
UDP_SAMPLES_PER_IP = int(os.environ.get("UDP_SAMPLES_PER_IP", "1"))

TCP_SAMPLE_HEXDUMPS = int(os.environ.get("TCP_SAMPLE_HEXDUMPS", "2"))  # optional
TCP_SAMPLE_PKTS_SCAN = int(os.environ.get("TCP_SAMPLE_PKTS_SCAN", "50000"))

# hexdump caps
DUMP_MAX_LINES = int(os.environ.get("DUMP_MAX_LINES", "200"))
DUMP_MAX_CHARS = int(os.environ.get("DUMP_MAX_CHARS", "2000"))
_HEX_START_RE = re.compile(r"^0000\s")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")



# ============================================================
# Helpers
# ============================================================
def debug(msg: str):
    print(f"[DEBUG] {msg}")
    sys.stdout.flush()

def init_log_file():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"=== Holmes Audit Log ===\nStarted: {datetime.now()}\n\n")

def write_audit_record(state: Dict[str, Any]):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = state.get("final_report", "Analysis Failed")

    raw1 = state.get("llm_raw_output_1", "")
    raw2 = state.get("llm_raw_output_2", "")
    raw3 = state.get("llm_raw_output_3", "")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n{'#'*100}\n[INCIDENT]: {ts}\n{'#'*100}\n")
        f.write(f"=== COUNTER ALERT ===\n{state.get('monitor_alert','').strip()}\n\n")
        f.write(f"=== TRIAGE (SFLOW) ===\n{json.dumps(state.get('triage',{}), ensure_ascii=False, indent=2)}\n\n")
        f.write(f"=== EVIDENCE (STRUCTURED) ===\n{state.get('evidence_text','').strip()[:30000]}\n\n")

        if raw1:
            f.write(f"=== LLM RAW OUTPUT #1 ===\n{raw1.strip()[:40000]}\n\n")
        if raw2:
            f.write(f"=== LLM RAW OUTPUT #2 ===\n{raw2.strip()[:40000]}\n\n")
        if raw3:
            f.write(f"=== LLM RAW OUTPUT #3 ===\n{raw3.strip()[:40000]}\n\n")

        f.write(f"=== FINAL VERDICT ===\n{report.strip()}\n")
        f.write(f"{'='*100}\n")

    debug(f"✅ Report saved to {LOG_FILE}")

def canon_ipv4(s: Any) -> str:
    if s is None:
        return ""
    s = str(s).replace("\u00a0", " ").strip()
    m = _IPV4_RE.search(s)
    return m.group(0) if m else ""

def extract_primary_anchors(ascii_excerpt: str, max_items: int = 12) -> List[str]:
    """
    Extract high-signal tokens from ASCII_EXCERPT to help LLM focus.
    This is NOT classification; it's just surfacing visible anchors.
    """
    s = (ascii_excerpt or "").strip()
    if not s or s == "(none)":
        return []

    tokens = set()

    # 1) Uppercase-ish tokens (NetBIOS, HTTP headers etc.)
    for m in re.findall(r"\b[A-Z0-9_]{4,}\b", s):
        tokens.add(m)

    # 2) Domain-like tokens (aids.gov, api.met.no, etc.)
    for m in re.findall(r"\b[a-zA-Z0-9\-]{2,}\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b", s):
        tokens.add(m)

    # 3) CamelCase / mixed tokens (LDAP/CLDAP fields often look like this)
    for m in re.findall(r"\b[A-Za-z][A-Za-z0-9]{7,}\b", s):
        tokens.add(m)

    # 4) Specific header words if present (still extraction only)
    for k in ["HTTP/1.1", "LOCATION:", "SERVER:", "ST:", "USN:", "UPnP", "HOST:"]:
        if k in s:
            tokens.add(k)

    out = list(tokens)
    out.sort(key=lambda x: (-len(x), x))
    return out[:max_items]

# ============================================================
# Counter & sFlow
# ============================================================
def get_snapshot(base_dir: str, t: float) -> List[Dict[str, Any]]:
    anoms = []
    for sw in ["spine", "tor1", "tor2"]:
        sw_dir = os.path.join(base_dir, sw)
        if not os.path.isdir(sw_dir):
            continue
        for p_file in glob.glob(os.path.join(sw_dir, "switch_port*.csv")):
            try:
                df = pd.read_csv(p_file)
                df.columns = [c.strip() for c in df.columns]
                if "t_s" not in df.columns:
                    continue
                row = df[(df["t_s"] > t - COUNTER_HALF_WINDOW) & (df["t_s"] <= t + COUNTER_HALF_WINDOW)]
                if row.empty:
                    continue

                tx_bps = float(row["tx_bps"].max()) if "tx_bps" in row.columns else 0.0
                drops = int(row["tx_qdrop_pkts"].max()) if "tx_qdrop_pkts" in row.columns else 0

                if drops > 0 or tx_bps > MONITOR_THRESHOLD_BPS:
                    anoms.append({"switch": sw, "bps": tx_bps, "drops": drops})
            except Exception:
                continue
    return anoms

def load_sflow_window(base_dir: str, t: float) -> pd.DataFrame:
    dfs = []
    for sw in ["spine", "tor1", "tor2"]:
        path = os.path.join(base_dir, sw, "sflow_samples.csv")
        if os.path.exists(path):
            try:
                df = pd.read_csv(path)
                df.columns = [c.strip() for c in df.columns]
                if "t" in df.columns:
                    w = df[(df["t"] > t - SFLOW_HALF_WINDOW) & (df["t"] <= t + SFLOW_HALF_WINDOW)]
                    if not w.empty:
                        dfs.append(w)
            except Exception:
                pass
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def _parse_tcp_flags_value(v: Any) -> int:
    if v is None:
        return 0
    if isinstance(v, (int, np.integer)):
        return int(v)
    s = str(v).strip()
    if s == "" or s.lower() == "nan":
        return 0
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        if re.fullmatch(r"[0-9a-fA-F]+", s) and re.search(r"[a-fA-F]", s):
            return int(s, 16)
        return int(float(s))
    except Exception:
        return 0

def summarize_sflow(df: pd.DataFrame) -> Dict[str, Any]:
    triage: Dict[str, Any] = {
        "victim_guess": "unknown",
        "dominant_l4": "MIXED",
        "dominance_score": 0.0,
        "proto_counts": {},
        "tcp_flags_stats": {},
        "rows": int(len(df)) if not df.empty else 0,
    }
    if df.empty:
        return triage

    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    p_counts = df["l4_proto_num"].value_counts().to_dict() if "l4_proto_num" in df.columns else {}
    mapped_p = {proto_map.get(int(k), str(k)): int(v) for k, v in p_counts.items()}
    triage["proto_counts"] = mapped_p

    total = sum(mapped_p.values()) if mapped_p else 0
    if total > 0:
        udp = mapped_p.get("UDP", 0)
        tcp = mapped_p.get("TCP", 0)
        if udp >= tcp:
            triage["dominant_l4"] = "UDP" if udp / total >= 0.55 else "MIXED"
            triage["dominance_score"] = round(udp / total, 3)
        else:
            triage["dominant_l4"] = "TCP" if tcp / total >= 0.55 else "MIXED"
            triage["dominance_score"] = round(tcp / total, 3)

    if "dst_ip" in df.columns and not df["dst_ip"].dropna().empty:
        triage["victim_guess"] = str(df["dst_ip"].value_counts().idxmax())

    tcp_flags_stats: Dict[str, Any] = {}
    flag_col_candidates = ["tcp_flags", "tcp_flags_hex", "l4_tcp_flags", "tcp.flag", "tcp.flags"]
    flag_col = None
    for c in flag_col_candidates:
        if c in df.columns:
            flag_col = c
            break

    if flag_col and "l4_proto_num" in df.columns:
        tcp_df = df[df["l4_proto_num"] == 6].copy()
        if not tcp_df.empty:
            flags_int = tcp_df[flag_col].apply(_parse_tcp_flags_value)
            n = int(len(flags_int))
            syn = int(((flags_int & 0x02) != 0).sum())
            ack = int(((flags_int & 0x10) != 0).sum())
            rst = int(((flags_int & 0x04) != 0).sum())
            fin = int(((flags_int & 0x01) != 0).sum())
            psh = int(((flags_int & 0x08) != 0).sum())
            tcp_flags_stats = {
                "source_column": flag_col,
                "total_tcp_samples": n,
                "syn_ratio": round(syn / n, 3) if n else 0.0,
                "ack_ratio": round(ack / n, 3) if n else 0.0,
                "rst_ratio": round(rst / n, 3) if n else 0.0,
                "fin_ratio": round(fin / n, 3) if n else 0.0,
                "psh_ratio": round(psh / n, 3) if n else 0.0,
            }
    triage["tcp_flags_stats"] = tcp_flags_stats
    return triage

# ============================================================
# Hexdump -> bytes; payload extraction + stats
# ============================================================
def _hexdump_to_bytes(lines: List[str]) -> bytes:
    bs: List[int] = []
    for ln in lines:
        m = re.match(r"^[0-9a-fA-F]{4}\s+(.*)$", ln)
        if not m:
            continue
        rest = m.group(1)
        for h in re.findall(r"\b[0-9a-fA-F]{2}\b", rest):
            bs.append(int(h, 16))
    return bytes(bs)

def _looks_like_ipv4(pkt: bytes, off: int) -> bool:
    if off < 0 or len(pkt) < off + 20:
        return False
    b = pkt[off]
    if (b >> 4) != 4:
        return False
    ihl = (b & 0x0F) * 4
    return ihl >= 20 and len(pkt) >= off + ihl

def _eth_ipv4_offset(pkt: bytes) -> Optional[int]:
    if len(pkt) < 20:
        return None

    for off in (0, 4, 14, 16, 18):
        if _looks_like_ipv4(pkt, off):
            return off

    for off in range(0, min(32, len(pkt) - 20)):
        if _looks_like_ipv4(pkt, off):
            return off

    return None

def _extract_l4_payload(pkt: bytes) -> Tuple[str, bytes]:
    ip_off = _eth_ipv4_offset(pkt)
    if ip_off is None or len(pkt) < ip_off + 20:
        return ("OTHER", b"")
    ver_ihl = pkt[ip_off]
    ver = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if ver != 4 or ihl < 20 or len(pkt) < ip_off + ihl:
        return ("OTHER", b"")
    proto = pkt[ip_off + 9]
    l4_off = ip_off + ihl

    if proto == 17:  # UDP
        if len(pkt) < l4_off + 8:
            return ("UDP", b"")
        return ("UDP", pkt[l4_off + 8:])

    if proto == 6:  # TCP
        if len(pkt) < l4_off + 20:
            return ("TCP", b"")
        data_off = (pkt[l4_off + 12] >> 4) * 4
        if data_off < 20 or len(pkt) < l4_off + data_off:
            return ("TCP", b"")
        return ("TCP", pkt[l4_off + data_off:])

    return ("OTHER", b"")

def _payload_stats(payload: bytes) -> Dict[str, Any]:
    n = len(payload)
    if n == 0:
        return {"payload_bytes": 0, "printable_ratio": 0.0, "alnum_ratio": 0.0, "entropy": 0.0, "top_ascii_snippets": []}

    printable = sum(1 for b in payload if 32 <= b <= 126)
    alnum = sum(1 for b in payload if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122))
    printable_ratio = printable / n
    alnum_ratio = alnum / n

    from collections import Counter
    cnt = Counter(payload)
    ent = 0.0
    for c in cnt.values():
        p = c / n
        ent -= p * math.log2(p)

    ascii_view = "".join(chr(b) if 32 <= b <= 126 else " " for b in payload)
    raw_snips = [m.group(0).strip() for m in re.finditer(r"[ -~]{4,}", ascii_view)]
    raw_snips = [s for s in raw_snips if s and not s.isspace()]
    raw_snips = [s for s in raw_snips if re.search(r"[A-Za-z0-9]", s)]

    def _snip_score(s: str) -> Tuple[int, int]:
        a = sum(ch.isalnum() for ch in s)
        return (a, len(s))

    snippets = sorted(raw_snips, key=_snip_score, reverse=True)[:6]
    return {
        "payload_bytes": n,
        "printable_ratio": round(printable_ratio, 3),
        "alnum_ratio": round(alnum_ratio, 3),
        "entropy": round(ent, 3),
        "top_ascii_snippets": snippets,
    }

def _ascii_excerpt(payload: bytes, max_len: int = 220) -> str:
    if not payload:
        return ""
    s = "".join(chr(b) if 32 <= b <= 126 else " " for b in payload)
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        return ""
    return s[:max_len] + ("..." if len(s) > max_len else "")

# ============================================================
# Tshark Toolkit
# ============================================================
class TsharkToolkit:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.tshark = shutil.which("tshark")

    def _run(self, cmd: List[str], timeout_s: int = 40) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)

    def top_src_ips_udp(self, victim_ip: str = "", limit: int = 5) -> List[Tuple[str, int]]:
        filt = "udp && ip"
        v = canon_ipv4(victim_ip)
        if v:
            filt = f"udp && ip && ip.dst == {v}"
        cmd = [
            self.tshark, "-r", self.pcap_path, "-n",
            "-Y", filt,
            "-c", str(TSHARK_MAX_SCAN_PKTS),
            "-T", "fields", "-e", "ip.src"
        ]
        try:
            res = self._run(cmd, timeout_s=45)
            if not res.stdout:
                return []
            ips = []
            for line in res.stdout.splitlines():
                ip = canon_ipv4(line)
                if ip:
                    ips.append(ip)
            from collections import Counter
            return Counter(ips).most_common(limit)
        except Exception as e:
            debug(f"top_src_ips_udp error: {e}")
            return []

    def udp_macro_stats(self, victim_ip: str = "") -> Dict[str, Any]:
        v = canon_ipv4(victim_ip)
        filt = "udp && ip"
        if v:
            filt = f"udp && ip && ip.dst == {v}"

        cmd = [
            self.tshark, "-r", self.pcap_path, "-n",
            "-Y", filt,
            "-c", str(TSHARK_MAX_SCAN_PKTS),
            "-T", "fields", "-E", "separator=|",
            "-e", "ip.src", "-e", "udp.length"
        ]
        out = {"rows": 0, "unique_src": 0, "top_src": "", "top_src_share": 0.0,
               "udp_len_p50": None, "udp_len_p90": None, "udp_len_mean": None}
        try:
            res = self._run(cmd, timeout_s=50)
            if not res.stdout:
                return out

            srcs: List[str] = []
            lens: List[int] = []
            for ln in res.stdout.splitlines():
                parts = ln.split("|")
                if len(parts) < 2:
                    continue
                ip = canon_ipv4(parts[0])
                if ip:
                    srcs.append(ip)
                try:
                    l = int(float(parts[1])) if parts[1].strip() else 0
                    if l > 0:
                        lens.append(l)
                except Exception:
                    pass

            out["rows"] = len(srcs)
            if srcs:
                from collections import Counter
                c = Counter(srcs)
                top_ip, top_cnt = c.most_common(1)[0]
                out["unique_src"] = len(c)
                out["top_src"] = top_ip
                out["top_src_share"] = round(top_cnt / len(srcs), 3) if len(srcs) else 0.0

            if lens:
                import numpy as _np
                arr = _np.array(lens, dtype=float)
                out["udp_len_mean"] = round(float(arr.mean()), 2)
                out["udp_len_p50"] = round(float(_np.percentile(arr, 50)), 2)
                out["udp_len_p90"] = round(float(_np.percentile(arr, 90)), 2)

            return out
        except Exception as e:
            debug(f"udp_macro_stats error: {e}")
            return out

    def top_udp_lengths(self, display_filter: str, limit: int = 3) -> List[Tuple[int, int]]:
        cmd = [
            self.tshark, "-r", self.pcap_path, "-n",
            "-Y", display_filter,
            "-c", str(TSHARK_MAX_SCAN_PKTS),
            "-T", "fields", "-e", "udp.length"
        ]
        try:
            res = self._run(cmd, timeout_s=45)
            if not res.stdout:
                return []
            vals = []
            for ln in res.stdout.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    vals.append(int(float(ln)))
                except Exception:
                    pass
            if not vals:
                return []
            from collections import Counter
            return Counter(vals).most_common(limit)
        except Exception:
            return []

    def tcp_flags_stats(self, victim_ip: str = "") -> Dict[str, Any]:
        v = canon_ipv4(victim_ip)
        filt = "tcp && ip"
        if v:
            filt = f"tcp && ip && ip.dst == {v}"

        cmd = [
            self.tshark, "-r", self.pcap_path, "-n",
            "-Y", filt,
            "-c", str(TCP_SAMPLE_PKTS_SCAN),
            "-T", "fields", "-e", "tcp.flags"
        ]
        out = {
            "rows": 0,
            "syn_only": 0,
            "ack_only": 0,
            "syn": 0,
            "ack": 0,
            "rst": 0,
            "fin": 0,
            "psh": 0,
            "syn_only_ratio": 0.0,
            "ack_only_ratio": 0.0,
            "syn_ratio": 0.0,
            "ack_ratio": 0.0,
        }
        try:
            res = self._run(cmd, timeout_s=45)
            if not res.stdout:
                return out
            flags = []
            for ln in res.stdout.splitlines():
                vraw = ln.strip()
                if not vraw:
                    continue
                flags.append(_parse_tcp_flags_value(vraw))

            n = len(flags)
            out["rows"] = n
            if n == 0:
                return out

            syn = sum(1 for x in flags if (x & 0x02) != 0)
            ack = sum(1 for x in flags if (x & 0x10) != 0)
            rst = sum(1 for x in flags if (x & 0x04) != 0)
            fin = sum(1 for x in flags if (x & 0x01) != 0)
            psh = sum(1 for x in flags if (x & 0x08) != 0)
            syn_only = sum(1 for x in flags if (x & 0x02) != 0 and (x & 0x10) == 0)
            ack_only = sum(1 for x in flags if (x & 0x10) != 0 and (x & 0x02) == 0)

            out.update({
                "syn": syn, "ack": ack, "rst": rst, "fin": fin, "psh": psh,
                "syn_only": syn_only, "ack_only": ack_only,
                "syn_only_ratio": round(syn_only / n, 3),
                "ack_only_ratio": round(ack_only / n, 3),
                "syn_ratio": round(syn / n, 3),
                "ack_ratio": round(ack / n, 3),
            })
            return out
        except Exception as e:
            debug(f"tcp_flags_stats error: {e}")
            return out

    def packet_hexdumps(self, display_filter: str, max_packets: int = 1) -> List[str]:
        cmd = [
            self.tshark, "-r", self.pcap_path, "-n",
            "-Y", display_filter,
            "-c", str(TSHARK_MAX_SCAN_PKTS),
            "-x", "-l",
        ]

        timeout_s = 70
        start = time.time()
        p = None
        dumps: List[str] = []
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

            cur_lines: List[str] = []
            in_pkt = False

            def flush_pkt():
                nonlocal cur_lines, in_pkt, dumps
                if cur_lines:
                    dump = "\n".join(cur_lines)
                    if DUMP_MAX_CHARS > 0 and len(dump) > DUMP_MAX_CHARS:
                        dump = dump[:DUMP_MAX_CHARS] + "\n... [TRUNCATED] ..."
                    dumps.append(dump)
                cur_lines = []
                in_pkt = False

            while True:
                if time.time() - start > timeout_s:
                    break
                if p.stdout is None:
                    break
                line = p.stdout.readline()
                if line == "":
                    break
                line = line.rstrip("\n")

                if _HEX_START_RE.match(line):
                    if in_pkt:
                        flush_pkt()
                        if len(dumps) >= max_packets:
                            break
                    in_pkt = True

                if in_pkt:
                    cur_lines.append(line)
                    if DUMP_MAX_LINES > 0 and len(cur_lines) >= DUMP_MAX_LINES:
                        flush_pkt()
                        if len(dumps) >= max_packets:
                            break

            if in_pkt and len(dumps) < max_packets:
                flush_pkt()

            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    p.kill()

            if p.stderr is not None:
                serr = (p.stderr.read() or "").strip()
                if serr and serr != 'Running as user "root" and group "root". This could be dangerous.':
                    dumps.insert(0, f"[TSHARK_STDERR] {serr}")

            return dumps[:max_packets]
        except Exception as e:
            return [f"[ERROR] Tshark hexdump exception: {e}"]
        finally:
            if p is not None and p.poll() is None:
                try:
                    p.kill()
                except Exception:
                    pass

# ============================================================
# Prompt (JSON-only)
# ============================================================
ALLOWED_ATTACK_TYPES = [
    "UDP Flood",
    "DNS Reflection",
    "SNMP Reflection",
    "LDAP/CLDAP Reflection",
    "NTP Reflection",
    "NetBIOS Reflection",
    "SSDP Reflection",
    "MSSQL Reflection",
    "Other Reflection",
    "SYN Flood",
    "ACK Flood",
    "HTTP/2 Rapid Reset",
    "Unknown",
]

PCAP_SYSTEM_PROMPT = r"""
You are a DDoS Incident Commander.

Your job: read ONE Evidence Pack (sFlow + tshark samples) and output ONE strict JSON verdict.

=====================================================================
CORE DESIGN (Route-1)
=====================================================================
1) Decide payload_style FIRST (structure), then attack_family, then attack_type.
2) “Unknown / Other Reflection” is a valid and preferred escape hatch when structure is unclear.
3) Protocol labels MUST come from payload_style (structure), NOT from fixed port assumptions.
4) Evidence language must cite WHAT YOU SEE (structure), not invented protocol lore.

=====================================================================
INPUT CONTEXT
=====================================================================
- Dataset may include Reflection/Amplification attacks (UDP) and Synthetic Floods (TCP/UDP).
- Evidence Pack is generated by tools. You MUST ground your analysis ONLY in the Evidence Pack shown in this message.
- CICDDoS2019 may randomize ports; DO NOT rely on port numbers for protocol identification.
- Evidence Pack usually contains PRIMARY samples:
  - UDP branch: [UDP_SAMPLE] rank=1 sample=1..N (+ ASCII_EXCERPT / HEX_DUMP)
  - TCP branch: [TCP_FLAGS_STATS] (+ a few [TCP_SAMPLE])
  - plus [PRIMARY_SCAN] / [PRIMARY_ANCHORS] sometimes.

=====================================================================
OUTPUT (STRICT JSON ONLY)
=====================================================================
- Output ONLY ONE JSON object. No extra text. No markdown. No code fences.
- JSON MUST start with '{' and end with '}'.
- Use ONLY the keys defined in the JSON SCHEMA below (no extra keys).
- Every string you claim as evidence must be grounded in the Evidence Pack.

=====================================================================
HARD GROUNDING & ANTI-HALLUCINATION
=====================================================================
A) SINGLE-SOURCE RULE:
   Use ONLY the current Evidence Pack. No external facts. No earlier incidents.

B) QUOTE RULE (KEY_EVIDENCE + TRACE):
   - Every item in key_evidence MUST contain >=1 exact substring copied from the Evidence Pack wrapped in backticks.
   - In analysis_trace.decision and each hypothesis evidence_for/evidence_against:
     include at least one backticked exact substring from the Evidence Pack somewhere across the hypotheses and decision.

C) NO REPUTATION / NO INVENTED CLAIMS:
   - Do NOT say “known malicious IP” or similar.
   - Do NOT invent counts/thresholds (“>10k”) unless that number appears.

D) PORTS ARE NOT IDENTITY:
   Ports may be randomized. Do NOT use ports as protocol identity evidence.

=====================================================================
STEP 1 — PAYLOAD_STYLE (STRUCTURE FIRST)
=====================================================================
Determine payload_style by inspecting PRIMARY payload content (prefer ASCII_EXCERPT; use HEX_DUMP if needed).
Choose ONE of these payload_style labels:

1) "random_noise"
   - Mostly gibberish / short fragments / no stable fields.
   - Often high entropy, low printable ratio, no recognizable record layout.

2) "http_like"
   - Visible HTTP-like start lines or headers (e.g., "HTTP/1.1", "GET ", "POST ", "LOCATION:", "USN:", "UPnP").

3) "asn1_oid_like"
   - Looks like ASN.1/BER encoded records or OID-heavy structures.
   - Often contains long dotted OIDs or directory-style attribute names.

4) "kv_semicolon_list"
   - Human-readable key/value list separated by semicolons.
   - Example shape: "Key;Value;Key;Value;..." (highly structured).

5) "text_banner_like"
   - Mostly printable text but not clearly HTTP; looks like a protocol banner / descriptive strings.

6) "mixed_or_unclear"
   - PRIMARY samples show conflicting structures OR too little to classify.

IMPORTANT:
- payload_style is about STRUCTURE, not about guessing the protocol name.
- If unsure, choose "mixed_or_unclear" (safe) rather than forcing a protocol.

=====================================================================
STEP 2 — ATTACK_FAMILY (FROM STRUCTURE + L4)
=====================================================================
Allowed attack_family values:
- "Reflection/Amplification"
- "Direct Flood"
- "Mixed"
- "Unknown"

Rules:
1) If dominant L4 is TCP:
   - attack_family is usually "Direct Flood" (unless evidence clearly shows Mixed).

2) If dominant L4 is UDP:
   - If payload_style is one of {"http_like","asn1_oid_like","kv_semicolon_list","text_banner_like"}:
       attack_family = "Reflection/Amplification" (looks like service response structure)
   - If payload_style == "random_noise":
       attack_family = "Direct Flood" (UDP flood / noise-style)
   - If payload_style == "mixed_or_unclear":
       attack_family = "Unknown" or "Mixed" (prefer Unknown unless strong reason)

3) Mixed:
   - Use "Mixed" ONLY if Evidence Pack strongly supports BOTH:
     - a TCP direct-flood signature (flags ratios) AND
     - a UDP reflection-style payload structure,
     in the SAME incident window.

=====================================================================
STEP 3 — ATTACK_TYPE (FROM STRUCTURE; ESCAPE HATCH OK)
=====================================================================
Allowed attack_type values:
- "DNS Reflection"
- "NetBIOS Reflection"
- "SNMP Reflection"
- "LDAP/CLDAP Reflection"
- "MSSQL Reflection"
- "SSDP Reflection"
- "NTP Reflection"
- "Other Reflection"
- "SYN Flood"
- "ACK Flood"
- "UDP Flood"
- "HTTP/2 Rapid Reset"
- "Unknown"

GATES (very important):
A) If dominant_l4_used is "TCP":
   - You MUST choose among: "SYN Flood", "ACK Flood", "HTTP/2 Rapid Reset", "Unknown".
   - You MUST NOT output any "* Reflection" label.

B) If dominant_l4_used is "UDP":
   - You MUST NOT output "SYN Flood" or "ACK Flood".
   - You MAY output a "* Reflection" label ONLY if payload_style is NOT "random_noise"
     AND you can quote at least one protocol-relevant substring from ASCII_EXCERPT or HEX_DUMP.

STRUCTURE→LABEL MAPPING (minimal, not a giant rule list):
1) If payload_style == "kv_semicolon_list":
   - Prefer "MSSQL Reflection" IF you can quote any of these semicolon-field anchors:
     `ServerName;` or `InstanceName;` or `IsClustered;` or `MSSQLSERVER`
   - Otherwise: "Other Reflection" is NOT allowed by schema -> use "Unknown" (or "UDP Flood" if noise-like)

2) If payload_style == "asn1_oid_like":
   - Prefer "LDAP/CLDAP Reflection" IF you can quote LDAP/dir-style anchors like:
     `1.2.840.113556` or `supportedLDAPVersion` or `isGlobalCatalogReady` or `domainFunctionality`
   - Prefer "SNMP Reflection" IF you can quote SNMP-style anchors like:
     `public` or `View-based Access Control Model for SNMP` or the BER-ish prefix fragment `30 82`
   - If ASN.1-like but cannot quote any supporting anchor: use "Unknown".

3) If payload_style == "http_like":
   - Prefer "SSDP Reflection" IF you can quote SSDP/UPnP style anchors like:
     `HTTP/1.1 200 OK` or `UPnP` or `USN:` or `LOCATION:`
   - If HTTP-like but not SSDP and you cannot justify another label: use "Unknown".

4) If payload_style == "text_banner_like":
   - Use "Unknown" unless a specific reflection anchor is clearly quotable.

5) If payload_style == "random_noise":
   - You MUST NOT output any specific "* Reflection" label.
   - Choose "UDP Flood" (if UDP dominant) or "Unknown" (if genuinely uncertain).

TCP FLAGS (for TCP dominant only):
- If [TCP_FLAGS_STATS] shows ack_ratio very high and syn_ratio very low -> "ACK Flood".
- If [TCP_FLAGS_STATS] shows syn_ratio very high and ack_ratio very low -> "SYN Flood".
- If neither is clear -> "Unknown".
- Only output "HTTP/2 Rapid Reset" if you can quote an HTTP/2/RST-oriented hint from payload/hex (rare); otherwise prefer "Unknown".

=====================================================================
EVIDENCE FORMATTING REQUIREMENTS
=====================================================================
- key_evidence: 2–6 strings, each MUST include >=1 backticked exact substring from Evidence Pack.
- hypotheses: include >=3 hypotheses:
  - one primary guess
  - one plausible alternative
  - one "Unknown" fallback
- Each hypothesis MUST have:
  - evidence_for: >=1 item
  - evidence_against: >=1 item
  - score: float in [0,1]
- analysis_trace.primary_samples_checked:
  - Use len([PRIMARY_SCAN]) if present;
  - else count of [UDP_SAMPLE] rank=1 samples if visible;
  - else 0.
  - Do NOT use "rows" as primary_samples_checked.

=====================================================================
REQUIRED JSON SCHEMA (NO EXTRA KEYS)
=====================================================================
{
  "verdict": "Malicious" | "Benign" | "Uncertain",
  "attack_family": "Reflection/Amplification" | "Direct Flood" | "Mixed" | "Unknown",
  "attack_type": "DNS Reflection" | "NetBIOS Reflection" | "SNMP Reflection" | "LDAP/CLDAP Reflection" |
                 "MSSQL Reflection" | "SSDP Reflection" | "NTP Reflection" | "Other Reflection" |
                 "SYN Flood" | "ACK Flood" | "UDP Flood" | "HTTP/2 Rapid Reset" | "Unknown",
  "analysis_trace": {
    "dominant_l4_used": "UDP" | "TCP" | "MIXED",
    "victim_guess_used": "x.x.x.x or unknown",
    "primary_samples_checked": 0,
    "payload_style": "random_noise" | "http_like" | "asn1_oid_like" | "kv_semicolon_list" | "text_banner_like" | "mixed_or_unclear",
    "hypotheses": [
      {
        "name": "DNS Reflection|NetBIOS Reflection|SNMP Reflection|LDAP/CLDAP Reflection|MSSQL Reflection|SSDP Reflection|NTP Reflection|Other Reflection|UDP Flood|SYN Flood|ACK Flood|HTTP/2 Rapid Reset|Unknown",
        "evidence_for": ["1-3 short strings; include >=1 backticked substring overall"],
        "evidence_against": ["1-3 short strings; include >=1 backticked substring overall"],
        "score": 0.0
      }
    ],
    "decision": "1-3 sentences; MUST include >=1 backticked exact substring from Evidence Pack."
  },
  "key_evidence": [
    "2-6 strings; EACH must include >=1 backticked exact substring from Evidence Pack."
  ],
  "reasoning": "1-3 sentences; MUST include >=1 backticked exact substring from Evidence Pack.",
  "recommended_actions": [
    "3-6 concrete actions consistent with attack_family."
  ],
  "confidence": 0.0
}

=====================================================================
YOUR TASK
=====================================================================
Read the Evidence Pack and output ONLY the JSON object that follows the schema and rules above.
""".strip()

def make_llm() -> ChatOpenAI:
    return ChatOpenAI(
        model=os.environ.get("LLM_MODEL_NAME", "deepseek-r1"),

        # vLLM/OpenAI-compatible servers often ignore the key but LangChain requires one.
        openai_api_key=os.environ.get("LLM_API_KEY", "EMPTY"),
        openai_api_base=os.environ.get("VLLM_API_BASE", "http://127.0.0.1:8002/v1"),
        temperature=float(os.environ.get("LLM_TEMPERATURE", "0.6")),
        max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "1024")),
    )

def _normalize_verdict_value(v: str) -> str:
    s = (v or "").strip().lower()
    s = re.sub(r"\s+", " ", s)

    # If model mistakenly puts an attack label into verdict, treat it as Malicious
    if any(k in s for k in ["reflection", "flood", "ddos", "attack"]):
        return "Malicious"

    if any(k in s for k in ["malicious", "attacking"]):
        return "Malicious"
    if any(k in s for k in ["benign", "normal", "legit", "legitimate"]):
        return "Benign"
    if any(k in s for k in ["uncertain", "unknown", "inconclusive", "unsure"]):
        return "Uncertain"
    return "Uncertain"

def _normalize_attack_type(v: str) -> str:
    s = (v or "").strip()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[<>]", "", s).strip()

    for a in ALLOWED_ATTACK_TYPES:
        if s.lower() == a.lower():
            return a

    low = s.lower()
    if "udp" in low and "flood" in low:
        return "UDP Flood"
    if "syn" in low:
        return "SYN Flood"
    if "ack" in low:
        return "ACK Flood"
    if "ssdp" in low or "upnp" in low:
        return "SSDP Reflection"
    if "netbios" in low or "msbrowse" in low or "workgroup" in low:
        return "NetBIOS Reflection"
    if "dns" in low:
        return "DNS Reflection"
    if "snmp" in low:
        return "SNMP Reflection"
    if "ldap" in low or "cldap" in low:
        return "LDAP/CLDAP Reflection"
    if "mssql" in low or "sql" in low:
        return "MSSQL Reflection"
    if "reflection" in low or "amplif" in low:
        return "Other Reflection"
    if "http/2" in low and "rapid" in low and "reset" in low:
        return "HTTP/2 Rapid Reset"
    return "Unknown"

def _safe_json_only(text: str) -> Dict[str, Any]:
    """
    Robust JSON extraction:
    - If output is pure JSON object: json.loads directly
    - Otherwise: extract the first JSON object using JSONDecoder.raw_decode starting from first '{'
    - Reject if no JSON object found
    """
    if not text or not text.strip():
        raise ValueError("empty output")

    s = text.strip()

    # Fast path: pure JSON
    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
            if not isinstance(obj, dict):
                raise ValueError("top-level JSON must be an object")
            return obj
        except Exception as e:
            raise ValueError(f"json.loads failed: {e}")

    dec = json.JSONDecoder()
    first = s.find("{")
    if first < 0:
        raise ValueError("no JSON object found (missing '{')")

    i = first
    while i < len(s):
        if s[i] == "{":
            try:
                obj, _end = dec.raw_decode(s[i:])
                if not isinstance(obj, dict):
                    raise ValueError("top-level JSON must be an object")
                return obj
            except Exception:
                pass
        i += 1

    raise ValueError("failed to parse any JSON object from output")


def _validate_json_result(obj: Dict[str, Any], evidence_text: str = "") -> Tuple[Dict[str, Any], List[str]]:
    """
    JSON-only validator (format + field types only).
    - Does NOT inspect evidence_text.
    - Does NOT do anchor consistency / process completeness checks.
    - Keeps normalization for verdict/attack_type.
    """
    errs: List[str] = []

    # -----------------------------
    # verdict (normalize allowed)
    # -----------------------------
    verdict_raw = str(obj.get("verdict", "")).strip()
    verdict = _normalize_verdict_value(verdict_raw)
    if verdict not in ("Malicious", "Benign", "Uncertain"):
        errs.append("verdict must be one of: Malicious|Benign|Uncertain")

    # -----------------------------
    # attack_type (normalize to allow-list)
    # -----------------------------
    attack_raw = str(obj.get("attack_type", "")).strip()
    attack_type = _normalize_attack_type(attack_raw)
    if attack_type not in ALLOWED_ATTACK_TYPES:
        errs.append(f"attack_type not allowed: {attack_type!r}")

    # -----------------------------
    # key_evidence: list[str] non-empty
    # -----------------------------
    key_evidence = obj.get("key_evidence", None)
    key_evidence_norm: List[str] = []
    if not isinstance(key_evidence, list) or len(key_evidence) == 0:
        errs.append("key_evidence must be a non-empty list of strings")
    else:
        for x in key_evidence[:12]:
            sx = str(x).strip()
            if sx:
                key_evidence_norm.append(sx)
        if len(key_evidence_norm) < 1:
            errs.append("key_evidence must contain at least 1 non-empty string")

    # -----------------------------
    # reasoning: non-empty string
    # -----------------------------
    reasoning = str(obj.get("reasoning", "")).strip()

    # Fallback: if reasoning missing, use analysis_trace.decision (common LLM behavior)
    if not reasoning:
        at = obj.get("analysis_trace", None)
        if isinstance(at, dict):
            decision = str(at.get("decision", "")).strip()
            if decision:
                reasoning = decision  # auto-fill
            else:
                errs.append("reasoning must be a non-empty string")
        else:
            errs.append("reasoning must be a non-empty string")

    # -----------------------------
    # confidence: number in [0,1]
    # -----------------------------
    conf_norm = None
    confidence = obj.get("confidence", None)
    if confidence is None:
        errs.append("confidence is required and must be between 0 and 1")
    else:
        try:
            conf_norm = float(confidence)
            if not (0.0 <= conf_norm <= 1.0):
                errs.append("confidence must be between 0 and 1")
        except Exception:
            errs.append("confidence must be a number between 0 and 1")

    # -----------------------------
    # Optional fields: only type-check if present (no content validation)
    # -----------------------------
    # attack_family
    attack_family = obj.get("attack_family", None)
    if attack_family is not None and not isinstance(attack_family, str):
        errs.append("attack_family must be a string if provided")

    # analysis_trace
    analysis_trace = obj.get("analysis_trace", None)
    if analysis_trace is not None and not isinstance(analysis_trace, dict):
        errs.append("analysis_trace must be an object if provided")

    # recommended_actions
    recommended_actions_norm: List[str] = []
    recommended_actions = obj.get("recommended_actions", None)
    if recommended_actions is not None:
        if not isinstance(recommended_actions, list):
            errs.append("recommended_actions must be a list of strings if provided")
        else:
            for x in recommended_actions[:12]:
                sx = str(x).strip()
                if sx:
                    recommended_actions_norm.append(sx)

    # hypotheses etc. are ignored (no process validation)

    # -----------------------------
    # normalized output
    # -----------------------------
    norm = {
        "verdict": verdict,
        "attack_type": attack_type,
        "key_evidence": key_evidence_norm[:12],
        "reasoning": reasoning,          # <= use filled reasoning
        "confidence": conf_norm,
    }
    # keep optional fields if present
    if isinstance(attack_family, str) and attack_family.strip():
        norm["attack_family"] = attack_family.strip()
    if isinstance(analysis_trace, dict):
        norm["analysis_trace"] = analysis_trace
    if recommended_actions_norm:
        norm["recommended_actions"] = recommended_actions_norm

    return norm, errs

def _format_final_from_json(norm: Dict[str, Any]) -> str:
    bullets = norm.get("key_evidence", []) or []
    bullets = bullets[:8]
    ke = "\n".join([f"- {b}" for b in bullets]) if bullets else "- (none)"
    return (
        f"Verdict: {norm.get('verdict','Uncertain')}\n"
        f"Attack Type: {norm.get('attack_type','Unknown')}\n"
        f"Key Evidence:\n{ke}\n"
        f"Reasoning: {norm.get('reasoning','')}"
    )

def llm_detect_json_with_retry(
    llm,
    system_prompt: str,
    user_prompt: str,
    max_rounds: int = 3
) -> Tuple[Optional[str], List[str], Optional[List[str]]]:
    """
    Force JSON-only output. Returns: (final_report_or_None, raw_outputs, errors_or_None)
    """
    raw_outputs: List[str] = []
    last_errs: List[str] = []

    for r in range(1, max_rounds + 1):
        if r == 1:
            sys_p = system_prompt
            hum_p = user_prompt
        else:
            sys_p = system_prompt + "\n\n" + (
                "CORRECTION REQUIRED:\n"
                "- Output ONLY ONE JSON object. No extra text. No markdown. No code fences.\n"
                "- Output must start with '{' and end with '}'.\n"
                "- verdict must be one of: Malicious|Benign|Uncertain\n"
                "- attack_type must be exactly one of the allowed types.\n"
                "- key_evidence MUST be a JSON array of STRINGS (each item is one string).\n"
                "  Bad: [ \"entropy\": 7.53 ] or [ \"top_src\": \"10.0.0.3\" ]\n"
                "  Good: [ \"\\\"entropy\\\": 7.53\", \"\\\"top_src\\\": \\\"10.0.0.3\\\"\" ]\n"
            )
            hum_p = (
                user_prompt
                + "\n\n[VALIDATION_ERRORS]\n- "
                + "\n- ".join(last_errs[:12])
                + "\n\nNow output ONLY the corrected JSON object."
            )

        res = llm.invoke([SystemMessage(content=sys_p), HumanMessage(content=hum_p)])
        raw = res.content or ""
        raw_outputs.append(raw)

        try:
            obj = _safe_json_only(raw)
        except Exception as e:
            last_errs = [f"json_only_parse_error: {e}"]
            continue

        evi = user_prompt
        norm, errs = _validate_json_result(obj, evidence_text=evi)
        if errs:
            last_errs = errs
            continue

        final = _format_final_from_json(norm)
        return final, raw_outputs, None

    return None, raw_outputs, last_errs

# ============================================================
# State
# ============================================================
class AgentState(TypedDict, total=False):
    base_dir: str
    cursor_time: float
    cooldown_until: float
    last_pcap: str

    evaluator_decision: str
    monitor_alert: str
    current_pcap: str

    triage: dict
    evidence_text: str
    final_report: str

    llm_raw_output_1: str
    llm_raw_output_2: str
    llm_raw_output_3: str

    seen_pcaps: list

# ============================================================
# Nodes
# ============================================================
def monitor_node(state: AgentState):
    t = float(state.get("cursor_time", 1.0))
    base_dir = state["base_dir"]
    cooldown_until = float(state.get("cooldown_until", -1.0))

    if t < cooldown_until:
        return {"cursor_time": t + 1.0, "evaluator_decision": "PENDING"}

    debug(f"🔎 Monitor T={t:.1f}s")
    found = get_snapshot(base_dir, t)

    if found:
        alert = f"Anomaly at T={t:.1f}s | Count={len(found)}"
        debug(f"🚨 {alert}")

        pcap_root = os.path.join(base_dir, PCAP_DIR_NAME)
        best = None
        for f in glob.glob(os.path.join(pcap_root, "*.pcap")):
            m = re.search(r"(\d+)s?-(\d+)s?\.pcap$", os.path.basename(f))
            if m:
                p_start, p_end = int(m.group(1)), int(m.group(2))
                if p_start <= t < p_end:
                    best = f
                    break

        if best:
            seen = state.get("seen_pcaps", []) or []
            if best in seen:
                debug(f"⏭️  Skip already-processed PCAP: {best}")
                if t + 1.0 > MAX_DATA_DURATION:
                    return {"evaluator_decision": "END"}
                return {"cursor_time": t + 1.0, "evaluator_decision": "PENDING"}

            seen.append(best)

            return {
                "cursor_time": t,
                "monitor_alert": alert,
                "current_pcap": best,
                "last_pcap": best,
                "seen_pcaps": seen,
                "evaluator_decision": "SFLOW"
            }
        else:
            debug(f"⚠️ Alert at {t}s but no matching PCAP found in {pcap_root}")

    if t + 1.0 > MAX_DATA_DURATION:
        return {"evaluator_decision": "END"}

    return {"cursor_time": t + 1.0, "evaluator_decision": "PENDING"}

def sflow_node(state: AgentState):
    base_dir = state["base_dir"]
    t = float(state.get("cursor_time", 1.0))
    df = load_sflow_window(base_dir, t)
    triage = summarize_sflow(df)
    debug(f"📊 sFlow triage: dominant={triage.get('dominant_l4')} score={triage.get('dominance_score')}, victim={triage.get('victim_guess')}")
    return {"triage": triage, "evaluator_decision": "EVIDENCE"}

def evidence_node(state: AgentState):
    pcap = state["current_pcap"]
    triage = state.get("triage", {}) or {}
    victim = canon_ipv4(triage.get("victim_guess", ""))

    tools = TsharkToolkit(pcap)
    debug(f"⚡ Evidence collection: pcap={pcap} victim={victim or 'unknown'}")

    dominant = (triage.get("dominant_l4") or "MIXED").upper()

    blocks: List[str] = []
    blocks.append(f"[PCAP_SELECTED]\n{pcap}\n")
    blocks.append(f"[SFLOW_TRIAGE]\n{json.dumps(triage, ensure_ascii=False)}\n")
    blocks.append("IMPORTANT: CICDDoS2019 may randomize ports; do NOT rely on port numbers for protocol identification.\n")

    do_udp = dominant in ("UDP", "MIXED")
    do_tcp = dominant in ("TCP", "MIXED")

    if do_udp:
        blocks.append("\n==================== UDP EVIDENCE ====================\n")
        macro = tools.udp_macro_stats(victim_ip=victim)
        blocks.append("[UDP_MACRO_STATS]\n" + json.dumps(macro, ensure_ascii=False) + "\n")

        top_src = tools.top_src_ips_udp(victim_ip=victim, limit=UDP_TOPK_SRC_IP)
        blocks.append("[UDP_TOP_SRC_IPS] (ingress to victim if known)\n" + json.dumps(top_src, ensure_ascii=False) + "\n")

        # Strategy: rank=1 src_ip, take top-3 udp.length classes, each dump 1 packet => total up to 3 packets.
        if not top_src:
            blocks.append("[UDP_SAMPLE] (none)\nNo UDP sources found under current filter.\n")
        else:
            ip, cnt = top_src[0]  # rank=1 only
            base_filt = f"udp && ip && ip.src == {ip}"
            if victim:
                base_filt += f" && ip.dst == {victim}"

            TOPK_LEN = 3
            top_lens = tools.top_udp_lengths(base_filt, limit=TOPK_LEN)
            blocks.append("[PRIMARY_UDP_LEN_CANDIDATES]\n" + json.dumps(top_lens, ensure_ascii=False) + "\n")

            # PRIMARY scan table (per-sample anchors)
            primary_scan: List[Dict[str, Any]] = []
            merged_anchor_set: set = set()

            if not top_lens:
                blocks.append("[PRIMARY_UDP_LEN_MODE]\n" + json.dumps({"udp.length": None, "count": None}, ensure_ascii=False) + "\n")
                blocks.append("[PRIMARY_REPRESENTATIVE_FILTER]\n" + base_filt + "\n")

                dumps = tools.packet_hexdumps(base_filt, max_packets=3)
                if not dumps:
                    dumps = ["(none)"]

                for j, dump in enumerate(dumps, 1):
                    lines = dump.splitlines()
                    pkt_bytes = _hexdump_to_bytes(lines)
                    _l4, payload = _extract_l4_payload(pkt_bytes)
                    pstats = _payload_stats(payload)
                    excerpt = _ascii_excerpt(payload)

                    blocks.append(
                        f"\n[UDP_SAMPLE] rank=1 src_ip={ip} src_count={cnt} sample={j} udp.length=(unknown)\n"
                        f"FILTER: {base_filt}\n"
                        f"PAYLOAD_STATS: {json.dumps(pstats, ensure_ascii=False)}\n"
                        f"ASCII_EXCERPT: {excerpt if excerpt else '(none)'}\n"
                        f"HEX_DUMP:\n{dump}\n"
                    )

                    anchors_j = extract_primary_anchors(excerpt if excerpt else "")
                    primary_scan.append({"sample": j, "udp_length": None, "anchors": anchors_j})
                    if anchors_j:
                        merged_anchor_set.update(anchors_j)

            else:
                for j, (ulen, ucnt) in enumerate(top_lens, 1):
                    ulen_i = int(ulen)
                    filt = base_filt + f" && udp.length == {ulen_i}"
                    blocks.append("[PRIMARY_UDP_LEN_MODE]\n" + json.dumps({"udp.length": ulen_i, "count": int(ucnt)}, ensure_ascii=False) + "\n")
                    blocks.append("[PRIMARY_REPRESENTATIVE_FILTER]\n" + filt + "\n")

                    dumps = tools.packet_hexdumps(filt, max_packets=1)
                    dump = dumps[0] if dumps else "(none)"

                    lines = dump.splitlines()
                    pkt_bytes = _hexdump_to_bytes(lines)
                    _l4, payload = _extract_l4_payload(pkt_bytes)
                    pstats = _payload_stats(payload)
                    excerpt = _ascii_excerpt(payload)

                    blocks.append(
                        f"\n[UDP_SAMPLE] rank=1 src_ip={ip} src_count={cnt} sample={j} udp.length={ulen_i}\n"
                        f"FILTER: {filt}\n"
                        f"PAYLOAD_STATS: {json.dumps(pstats, ensure_ascii=False)}\n"
                        f"ASCII_EXCERPT: {excerpt if excerpt else '(none)'}\n"
                        f"HEX_DUMP:\n{dump}\n"
                    )

                    anchors_j = extract_primary_anchors(excerpt if excerpt else "")
                    primary_scan.append({"sample": j, "udp_length": ulen_i, "anchors": anchors_j})
                    if anchors_j:
                        merged_anchor_set.update(anchors_j)

            # emit PRIMARY_SCAN + merged PRIMARY_ANCHORS
            if primary_scan:
                blocks.append("[PRIMARY_SCAN]\n" + json.dumps(primary_scan, ensure_ascii=False) + "\n")

            if merged_anchor_set:
                merged_list = sorted(list(merged_anchor_set), key=lambda x: (-len(x), x))[:20]
                blocks.append("[PRIMARY_ANCHORS]\n" + json.dumps(merged_list, ensure_ascii=False) + "\n")

    if do_tcp:
        blocks.append("\n==================== TCP EVIDENCE ====================\n")
        tstats = tools.tcp_flags_stats(victim_ip=victim)
        blocks.append("[TCP_FLAGS_STATS]\n" + json.dumps(tstats, ensure_ascii=False) + "\n")

        if TCP_SAMPLE_HEXDUMPS > 0 and dominant != "UDP":
            filt = "tcp && ip"
            if victim:
                filt += f" && ip.dst == {victim}"
            dumps = tools.packet_hexdumps(filt, max_packets=TCP_SAMPLE_HEXDUMPS)
            for k, dump in enumerate(dumps, 1):
                lines = dump.splitlines()
                pkt_bytes = _hexdump_to_bytes(lines)
                _l4, payload = _extract_l4_payload(pkt_bytes)
                pstats = _payload_stats(payload)
                excerpt = _ascii_excerpt(payload)

                blocks.append(
                    f"\n[TCP_SAMPLE] sample={k}\n"
                    f"FILTER: {filt}\n"
                    f"PAYLOAD_STATS: {json.dumps(pstats, ensure_ascii=False)}\n"
                    f"ASCII_EXCERPT: {excerpt if excerpt else '(none)'}\n"
                    f"HEX_DUMP:\n{dump}\n"
                )

    evidence_text = "\n".join(blocks)
    return {"evidence_text": evidence_text, "evaluator_decision": "DETECT"}

def detective_node(state: AgentState):
    debug("⚖️  LLM: Final Verdict...")

    t = float(state.get("cursor_time", 1.0))
    merged = dict(state)
    evidence_text = state.get("evidence_text", "")

    if DISABLE_LLM:
        final = (
            "Verdict: Uncertain\n"
            "Attack Type: Unknown\n"
            "Key Evidence:\n"
            "- `LLM disabled`\n"
            "Reasoning: LLM Disabled."
        )
        merged["final_report"] = final
        write_audit_record(merged)
        return {
            "cursor_time": t + INCIDENT_COOLDOWN_S,
            "cooldown_until": t + INCIDENT_COOLDOWN_S,
            "final_report": final,
            "evaluator_decision": "DONE"
        }

    llm = make_llm()

    user_prompt = (
        f"[Counter Alert]\n{state.get('monitor_alert','')}\n\n"
        f"[Evidence Pack]\n{evidence_text}\n"
    )

    # JSON-only path
    final, raws, errs = llm_detect_json_with_retry(
        llm=llm,
        system_prompt=PCAP_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        max_rounds=3
    )

    merged["llm_raw_output_1"] = raws[0] if len(raws) >= 1 else ""
    merged["llm_raw_output_2"] = raws[1] if len(raws) >= 2 else ""
    merged["llm_raw_output_3"] = raws[2] if len(raws) >= 3 else ""

    if final is None:
        err_txt = "\n".join(errs or [])
        if not merged.get("llm_raw_output_3"):
            merged["llm_raw_output_3"] = err_txt
        else:
            merged["llm_raw_output_3"] = (merged["llm_raw_output_3"] + "\n\n[VALIDATION_ERRORS]\n" + err_txt)[:40000]

        final = (
            "Verdict: Uncertain\n"
            "Attack Type: Unknown\n"
            "Key Evidence:\n"
            "- `Validation failed`\n"
            "Reasoning: LLM output failed JSON-only parse/field validation; see LLM RAW OUTPUT sections."
        )

    merged["final_report"] = final
    write_audit_record(merged)

    return {
        "cursor_time": t + INCIDENT_COOLDOWN_S,
        "cooldown_until": t + INCIDENT_COOLDOWN_S,
        "final_report": final,
        "evaluator_decision": "DONE"
    }

def router(state: AgentState):
    d = state.get("evaluator_decision", "PENDING")
    if d == "SFLOW":
        return "sflow"
    if d == "EVIDENCE":
        return "evidence"
    if d == "DETECT":
        return "detective"
    if d == "DONE":
        return "monitor"
    if d == "END":
        return "end"
    return "monitor"

# ============================================================
# Workflow
# ============================================================
workflow = StateGraph(AgentState)
workflow.add_node("monitor", monitor_node)
workflow.add_node("sflow", sflow_node)
workflow.add_node("evidence", evidence_node)
workflow.add_node("detective", detective_node)

workflow.set_entry_point("monitor")
workflow.add_conditional_edges("monitor", router, {"sflow": "sflow", "monitor": "monitor", "end": END})
workflow.add_conditional_edges("sflow", router, {"evidence": "evidence", "monitor": "monitor"})
workflow.add_conditional_edges("evidence", router, {"detective": "detective", "monitor": "monitor"})
workflow.add_conditional_edges("detective", router, {"monitor": "monitor"})

app = workflow.compile()

# ============================================================
# Main
# ============================================================
def main() -> int:
    init_log_file()
    print("=== Holmes (LLM-led, JSON-only) Running ===")

    if shutil.which("tshark") is None:
        print("ERROR: tshark not found.")
        return 1

    if not os.path.isdir(DATA_ROOT):
        print(f"ERROR: data root not found: {DATA_ROOT}")
        return 1

    state: AgentState = {
        "base_dir": DATA_ROOT,
        "cursor_time": 1.0,
        "evaluator_decision": "PENDING",
        "cooldown_until": -1.0,
        "last_pcap": "",
        "seen_pcaps": []
    }

    try:
        app.invoke(state, {"recursion_limit": 5000})
    except KeyboardInterrupt:
        print("Stopped by user.")
        return 130
    except Exception as e:
        print(f"Runtime Error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
