# Holmes: An Evidence-Grounded LLM Agent for Auditable DDoS Investigation in Cloud Networks

[Paper on arXiv](https://arxiv.org/abs/2601.14601)

Holmes reframes DDoS detection as an auditable investigation workflow instead of a single black-box classifier. The agent continuously watches counter telemetry, uses sFlow to triage suspicious windows, extracts compact packet-level evidence from PCAPs, and asks an LLM to return a strict JSON verdict with grounded evidence anchors.

This repository packages the current research prototype behind the paper together with a lightweight, runnable sample of the cloud-network traces used during development.

## What Is In This Release

- `ddos_agent_v2.py`: the main Holmes pipeline built with LangGraph.
- `log/`: bundled counter snapshots, sFlow samples, topology metadata, and trimmed PCAP windows.
- `scripts/verify_tshark.py`: a quick environment check for Tshark-based packet inspection.

## Project Snapshot

The current workspace contained a much larger experimental directory with training artifacts, cached datasets, kernel metadata, full packet captures, and local runtime logs. For open-sourcing, the release was narrowed to the evidence-processing path that is directly relevant to Holmes:

- Kept the core investigation code in [`ddos_agent_v2.py`](ddos_agent_v2.py).
- Kept the network telemetry under [`log/`](log/) and converted the original `timestep_pcap/` windows into tiny sample captures so the public repo stays lightweight but still runnable.
- Excluded unrelated training/cache folders and multi-gigabyte raw captures from the public snapshot.

The bundled telemetry currently covers:

- 3 switches: `spine`, `tor1`, and `tor2`.
- 12 switch-port counter files, each spanning about 922 timestamps.
- 238,459 sFlow samples in total across the three switches.
- 11 representative packet windows under [`log/timestep_pcap/`](log/timestep_pcap/).

The local audit report generated from the same codebase contained 10 incidents spanning UDP flooding, SYN/ACK flooding, and multiple reflection families, which matches the multi-family investigation goal described in the paper.

## How Holmes Works

1. `monitor_node` scans switch-port counters for queue drops or bandwidth spikes.
2. `sflow_node` summarizes the suspicious window and estimates the likely victim plus dominant L4 protocol.
3. `evidence_node` uses Tshark to build an "Evidence Pack" from representative packets, payload statistics, and protocol anchors.
4. `detective_node` asks an LLM to output one strict JSON verdict and writes an auditable incident report.

The design intentionally separates sensing, triage, evidence collection, and reasoning so that failures are easier to inspect than in an end-to-end classifier.

## Requirements

- Python 3.10+
- Tshark / Wireshark CLI tools
- An OpenAI-compatible LLM endpoint if you want LLM-backed verdicts

Install Python dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Install Tshark on Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y tshark
```

## Quick Start

Sanity-check packet tooling:

```bash
python scripts/verify_tshark.py
```

Run the full pipeline without an LLM first:

```bash
DISABLE_LLM=1 python ddos_agent_v2.py
```

Run Holmes against a local OpenAI-compatible endpoint:

```bash
export VLLM_API_BASE=http://127.0.0.1:8002/v1
export LLM_MODEL_NAME=deepseek-r1
export LLM_API_KEY=EMPTY
python ddos_agent_v2.py
```

Outputs are written to `outputs/security_audit_report.txt` by default.

## Configuration

Key environment variables:

- `HOLMES_DATA_ROOT`: override the telemetry directory. Defaults to `./log`.
- `HOLMES_REPORT_PATH`: override the audit-report path.
- `DISABLE_LLM=1`: skip LLM calls and exercise only the sensing/evidence pipeline.
- `VLLM_API_BASE`: OpenAI-compatible base URL.
- `LLM_MODEL_NAME`: served model name.
- `LLM_API_KEY`: API key passed to the LangChain OpenAI client.
- `MONITOR_THRESHOLD_BPS`: counter threshold for incident triggering.
- `MAX_DATA_DURATION`: upper time bound for the scan loop.

## Notes On The Public Data

- The `log/timestep_pcap/` files in this repository are trimmed sample windows, not the original full captures from the lab environment.
- The workflow and evidence schema remain unchanged, so the repository still demonstrates how Holmes constructs auditable evidence packs.
- If you have the full packet windows, you can point `HOLMES_DATA_ROOT` to that dataset layout without changing the code.

## Citation

If you use Holmes in your work, please cite:

```bibtex
@article{chen2026holmes,
  title={Holmes: An Evidence-Grounded LLM Agent for Auditable DDoS Investigation in Cloud Networks},
  author={Chen, Haodong and Zhang, Ziheng and Jiang, Jinghui and Su, Qiang and Xiang, Qiao},
  journal={arXiv preprint arXiv:2601.14601},
  year={2026}
}
```

## License

This repository is released under the MIT License.
