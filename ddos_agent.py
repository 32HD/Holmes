#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import glob
import pandas as pd
import numpy as np
from datetime import datetime
from typing import List, Dict, Any
from typing_extensions import TypedDict

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, END


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "ddos_report.txt")

# 阈值配置
MONITOR_THRESHOLD_BPS = 5_000_000   # 5 Mbps (捕获门槛)
TRIAGE_THRESHOLD_BPS = 50_000_000   # 50 Mbps (报警门槛)
MAX_EVENT_WINDOW = 10.0             # 事件最大聚合窗口
MAX_DATA_DURATION = 605.0           # 数据最大读取时间

def debug_print(msg):
    print(f"[DEBUG] {msg}")
    sys.stdout.flush()

def write_audit_record(state: dict, report: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    macro = state.get('macro_obs', 'No Macro Data')
    micro = state.get('micro_profile', 'No Micro Data')
    
    audit_block = f"""
{'#'*80}
[INCIDENT ID]: {timestamp}
{'#'*80}

=== [PART 1: MACRO OBSERVATIONS] (Scope & Severity) ===
{macro.strip()}

=== [PART 2: MICRO FORENSICS] (Deep Packet Inspection) ===
{micro.strip()}

=== [PART 3: AI INTELLIGENCE VERDICT] ===

{report.strip()}

{'='*80}
"""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(audit_block + "\n")
            f.flush()
            os.fsync(f.fileno())
        debug_print(f"✅ Report successfully written to {LOG_FILE}")
    except Exception as e:
        debug_print(f"❌ Failed to write file: {e}")

def init_log_file():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            f.write(f"=== Advanced Network Security Analysis Log (Started: {datetime.now()}) ===\n\n")

# ==========================================
# 1. 高级特征提取工具
# ==========================================

class TrafficAnalyzer:
    """专门用于提取详细网络特征的工具类"""
    
    PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF"}
    
    @staticmethod
    def get_proto_name(num: int) -> str:
        return TrafficAnalyzer.PROTOCOL_MAP.get(int(num), f"L4-{num}")

    @staticmethod
    def analyze_tcp_flags(df: pd.DataFrame) -> str:
        """
        深度解析 TCP 标志位分布。
        位掩码: FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32
        """
        if df.empty or 'tcp_flags' not in df.columns:
            return "N/A (Not TCP)"
        
        # 过滤出 TCP 流量
        tcp_df = df[df['l4_proto_num'] == 6]
        if tcp_df.empty:
            return "No TCP Traffic"
            
        total_tcp = len(tcp_df)
        flags = tcp_df['tcp_flags'].fillna(0).astype(int)
        
        # 使用位运算统计各标志位出现的次数
        stats = {
            "SYN": ((flags & 2) > 0).sum(),
            "ACK": ((flags & 16) > 0).sum(),
            "RST": ((flags & 4) > 0).sum(),
            "FIN": ((flags & 1) > 0).sum(),
            "PSH": ((flags & 8) > 0).sum()
        }
        
        # 计算百分比
        summary = []
        for name, count in stats.items():
            if count > 0:
                pct = (count / total_tcp) * 100
                summary.append(f"{name}:{pct:.0f}%")
        
        # 特殊组合判断 (Heuristics)
        heuristic = []
        if stats['SYN'] > 0 and stats['ACK'] == 0:
            heuristic.append("⚠️ PURE SYN (Poss. SynFlood/Scan)")
        if stats['RST'] > stats['SYN'] and stats['RST'] > stats['ACK']:
            heuristic.append("⚠️ HIGH RST (Connection Refusals)")
            
        base_str = ", ".join(summary) if summary else "None"
        note_str = f" [{', '.join(heuristic)}]" if heuristic else ""
        
        return f"{base_str}{note_str}"

    @staticmethod
    def analyze_packet_sizes(df: pd.DataFrame) -> str:
        if df.empty: return "N/A"
        sizes = df['ip_len']
        avg = sizes.mean()
        std = sizes.std()
        max_size = sizes.max()
        
        # 判断包大小的一致性
        consistency = "Variable"
        if std < 5.0: consistency = "Uniform (Mechanized)"
        elif std > 200.0: consistency = "High Variance (Normal Usage)"
        
        return f"Avg:{avg:.0f}B, Max:{max_size}B, StdDev:{std:.1f} ({consistency})"

    @staticmethod
    def calculate_entropy(series: pd.Series) -> str:
        if series.empty: return "N/A"
        counts = series.value_counts()
        probs = counts / counts.sum()
        entropy = -sum(probs * np.log2(probs))
        
        # 解释熵值
        tag = "Single Source"
        if entropy > 1.0: tag = "Small Botnet/Group"
        if entropy > 4.0: tag = "Distributed/High Noise"
        
        return f"{entropy:.2f} [{tag}]"

# ==========================================
# 2. 状态定义
# ==========================================

class NetState(TypedDict):
    base_dir: str           
    topo_mgr: Any           
    cursor_time: float      
    last_processed_time: float  
    current_stage: str          
    current_event_batch: List[Dict] 
    macro_obs: str              
    micro_profile: str          
    evaluator_decision: str     
    final_reports: List[str]

# ==========================================
# 3. 核心节点逻辑
# ==========================================

def get_snapshot_at_time(base_dir, t) -> List[Dict]:
    switches = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    anomalies = []
    
    for sw in switches:
        port_files = glob.glob(os.path.join(base_dir, sw, "switch_port*.csv"))
        for p_file in port_files:
            try:
                df = pd.read_csv(p_file)
                df.columns = [c.strip() for c in df.columns]
                row = df[(df['t_s'] > t - 0.5) & (df['t_s'] <= t + 0.5)]
                
                if not row.empty:
                    drops = row['tx_qdrop_pkts'].max()
                    bps = row['tx_bps'].max()
                    if drops > 0 or bps > MONITOR_THRESHOLD_BPS:
                        anomalies.append({
                            "switch": sw, "port": os.path.basename(p_file),
                            "t_s": t, "drops": drops, "bps": bps
                        })
            except: continue
    return anomalies

def monitor_node(state: NetState) -> Dict:
    current_t = state.get('cursor_time', 1.0)
    last_t = state.get('last_processed_time', 0.0)
    
    if current_t <= last_t:
        current_t = last_t + 1.0

    base_dir = state['base_dir']
    debug_print(f"🔎 Monitor Scanning from T={current_t:.1f}s...")
    
    MAX_SEARCH_STEPS = 5 
    found_start = False
    start_anomalies = []
    
    steps = 0
    while steps < MAX_SEARCH_STEPS:
        anomalies = get_snapshot_at_time(base_dir, current_t)
        if anomalies:
            found_start = True
            start_anomalies = anomalies
            break
        current_t += 1.0
        steps += 1
        
        if current_t > MAX_DATA_DURATION: 
            return {"evaluator_decision": "EOF"}

    if not found_start:
        return {
            "cursor_time": current_t, 
            "evaluator_decision": "PENDING",
            "current_stage": "MONITOR" 
        }

    # 聚合事件
    event_batch = []
    event_batch.extend(start_anomalies)
    event_start_time = current_t
    debug_print(f"⚠️  Anomaly Started at T={event_start_time:.1f}s. Aggregating...")
    
    probe_t = current_t + 1.0
    while probe_t < event_start_time + MAX_EVENT_WINDOW:
        next_anomalies = get_snapshot_at_time(base_dir, probe_t)
        if not next_anomalies: break
        event_batch.extend(next_anomalies)
        probe_t += 1.0
    
    duration = probe_t - event_start_time
    total_drops = sum(a['drops'] for a in event_batch)
    max_bps = max(a['bps'] for a in event_batch)
    affected_sw = list(set(a['switch'] for a in event_batch))
    
    obs = (
        f"Event Scope: {duration:.0f}s duration on {affected_sw}\n"
        f"Impact Metrics: Peak Bandwidth {max_bps/1e6:.2f} Mbps, Total Drops {int(total_drops)}"
    )
    
    debug_print(f"📦 Event Aggregated. Triage Handoff.")

    return {
        "cursor_time": probe_t,
        "last_processed_time": probe_t - 1.0,
        "macro_obs": obs,
        "current_event_batch": event_batch,
        "current_stage": "TRIAGE",
        "evaluator_decision": "PENDING"
    }

def investigator_node(state: NetState) -> Dict:
    event_batch = state['current_event_batch']
    base_dir = state['base_dir']
    
    if not event_batch:
        return {"micro_profile": "No Data", "current_stage": "ANALYSIS"}
        
    debug_print("🕵️  Investigator running Deep Packet Inspection (DPI) on Peak...")

    peak_anomaly = max(event_batch, key=lambda x: x['bps'])
    target_sw = peak_anomaly['switch']
    target_t = peak_anomaly['t_s']
    
    sflow_path = os.path.join(base_dir, target_sw, "sflow_samples.csv")
    profile_text = f"Forensics Target: {target_sw} @ T={target_t:.1f}s\n"
    
    if os.path.exists(sflow_path):
        try:
            df = pd.read_csv(sflow_path)
            df.columns = [c.strip() for c in df.columns]
            df = df[(df['src_ip'] != '-') & (df['dst_ip'] != '-')]
            df_win = df[(df['t'] >= target_t - 1.0) & (df['t'] <= target_t + 1.0)]
            
            if not df_win.empty:
                # === [特征工程核心部分] ===
                analyzer = TrafficAnalyzer()
                
                # 1. 协议分布 (L4)
                proto_counts = df_win['l4_proto_num'].value_counts(normalize=True)
                proto_str = ", ".join([f"{analyzer.get_proto_name(k)}:{v*100:.0f}%" for k,v in proto_counts.items()])
                
                # 2. TCP 标志位分析 (Key for SYN Flood vs Normal)
                tcp_analysis = analyzer.analyze_tcp_flags(df_win)
                
                # 3. 包大小统计 (Key for Amplification vs Control)
                pkt_size_analysis = analyzer.analyze_packet_sizes(df_win)
                
                # 4. 熵值与 Top Talker
                src_entropy = analyzer.calculate_entropy(df_win['src_ip'])
                top_src = df_win['src_ip'].value_counts().idxmax()
                top_dst = df_win['dst_ip'].value_counts().idxmax()
                
                profile_text += f"""
    [L4 Protocol Breakdown]
    {proto_str}
    
    [TCP Flags Heuristics]
    {tcp_analysis}
    
    [Packet Engineering]
    {pkt_size_analysis}
    
    [Identity & Pattern]
    Source Entropy: {src_entropy}
    Primary Actor: {top_src}
    Primary Victim: {top_dst}
                """
            else:
                profile_text += "No sFlow samples in window."
        except Exception as e:
            profile_text += f"DPI Error: {e}"
    else:
        profile_text += "sFlow log missing."

    return {
        "micro_profile": profile_text, 
        "current_stage": "ANALYSIS"
    }

def evaluator_node(state: NetState) -> Dict:
    stage = state.get("current_stage", "MONITOR")
    
    api_base = os.environ.get("VLLM_API_BASE", "http://127.0.0.1:8082/v1")
    model_name = os.environ.get("PANGU_MODEL_NAME", "pangu_embedded_7b")
    
    if stage == "MONITOR": return {}

    if stage == "TRIAGE":
        event_batch = state.get("current_event_batch", [])
        if not event_batch:
            return {"evaluator_decision": "IGNORE", "current_stage": "MONITOR"}

        max_bps = max(item['bps'] for item in event_batch)
        total_drops = sum(item['drops'] for item in event_batch)

        if total_drops > 0:
            debug_print(f"🚨 Triage: Drops detected ({total_drops}). Analyzing.")
            return {"evaluator_decision": "INVESTIGATE"}
        
        if max_bps > TRIAGE_THRESHOLD_BPS:
            debug_print(f"🚨 Triage: High Bandwidth ({max_bps/1e6:.1f}M). Analyzing.")
            return {"evaluator_decision": "INVESTIGATE"}
            
        debug_print(f"📉 Triage: IGNORED (BPS={max_bps/1e6:.1f}M, Drops={total_drops}).")
        return {"evaluator_decision": "IGNORE", "current_stage": "MONITOR"}

    elif stage == "ANALYSIS":
        debug_print("🧠 Evaluator utilizing LLM for classification...")
        
        llm = ChatOpenAI(
            model=model_name,
            openai_api_key="EMPTY",
            openai_api_base=api_base,
            temperature=0.1
        )
        
        # === [Prompt 泛化升级] ===
        system_prompt = """You are a Tier-3 Network Security Incident Responder.
Your task is to analyze the provided network traffic telemetry and classify the event.

**ANALYSIS GUIDELINES:**
1. **Holistic View**: Integrate Macro metrics (Bandwidth, Drops) with Micro forensics (TCP Flags, Protocols, Packet Sizes).
2. **Threat Classification**: Do not limit yourself to DDoS. Evaluate for:
   - **Flooding Attacks**: SYN Flood (High SYN, Low ACK), UDP Flood, ICMP Flood.
   - **Reconnaissance**: Port Scans (Low Bandwidth, High SYN, Low Entropy).
   - **Amplification**: Large Packet UDP responses (e.g., DNS/NTP).
   - **Legitimate Usage**: Data Transfers (High Bandwidth, High ACK/PUSH, Low Drops).
   - **Misconfiguration**: Loops or errors.
3. **Evidence-Based**: Your verdict must be supported by the data (e.g., "Identified SYN Flood due to 99% SYN flag ratio and zero ACKs").

**OUTPUT FORMAT:**
- **Verdict**: [Malicious / Suspicious / Benign]
- **Classification**: [Specific Attack Name or "Normal Traffic"]
- **Confidence**: [High/Medium/Low]
- **Key Evidence**: [Bullet points of the most damning data]
- **Reasoning**: [Concise technical explanation]"""

        user_prompt = f"""
        [Macro Scope]
        {state.get('macro_obs', 'N/A')}
        
        [Micro Forensics (DPI)]
        {state.get('micro_profile', 'N/A')}
        
        Analyze the nature of this traffic event.
        """
        
        report = ""
        try:
            response = llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            report = response.content
        except Exception as e:
            report = f"LLM Inference Error: {e}"
            
        write_audit_record(state, report)
        
        return {
            "evaluator_decision": "DONE",
            "final_reports": state["final_reports"] + [report],
            "current_stage": "MONITOR"
        }
    return {}

# ==========================================
# 4. 主程序
# ==========================================

def router(state: NetState):
    d = state["evaluator_decision"]
    if d == "PENDING": return "monitor"
    if d == "INVESTIGATE": return "investigator"
    if d == "IGNORE": return "monitor"
    if d == "DONE": return "monitor"
    if d == "EOF": return END
    return END

def build_agent():
    graph = StateGraph(NetState)
    graph.add_node("monitor", monitor_node)
    graph.add_node("investigator", investigator_node)
    graph.add_node("evaluator", evaluator_node)
    
    graph.set_entry_point("monitor")
    graph.add_edge("monitor", "evaluator")
    graph.add_conditional_edges("evaluator", router, 
                                {"investigator": "investigator", "monitor": "monitor", END: END})
    graph.add_edge("investigator", "evaluator")
    return graph.compile()

if __name__ == "__main__":
    if os.path.exists(os.path.join(os.getcwd(), "log")):
        DATA_ROOT = os.path.join(os.getcwd(), "log")
    else:
        DATA_ROOT = os.getcwd()
        
    print(f"=== NetSec Agent V2.0 (Advanced Features) ===")
    print(f"Data Source: {DATA_ROOT}")
    print(f"Max Duration: {MAX_DATA_DURATION}s")
    
    # 模拟 Topo
    class MockTopo: pass
    
    init_log_file()
    app = build_agent()
    
    initial_state = {
        "base_dir": DATA_ROOT,
        "topo_mgr": MockTopo(),
        "cursor_time": 1.0, 
        "last_processed_time": 0.0,
        "current_stage": "MONITOR",
        "evaluator_decision": "PENDING",
        "current_event_batch": [],
        "final_reports": []
    }
    
    try:
        app.invoke(initial_state, {"recursion_limit": 3000})
        print("\n✅ Analysis Complete.")
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")