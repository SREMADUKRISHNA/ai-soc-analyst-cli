# 🔐 VSMK-AI-SOC

**VSMK-AI-SOC** is a production-grade, AI-powered **SOC Analyst Command Line Interface (CLI) tool** that simulates real-world Security Operations Center workflows. The tool ingests security logs, detects and classifies alerts, performs **one-click automated Root Cause Analysis (RCA)**, and generates structured AI-driven incident reports — all directly from the terminal. This project is designed to reflect **industry SOC Tier-1 and Tier-2 practices**, not a basic student demo.

---

## 🚀 Key Features

- 📥 **Real-Time Log Ingestion**
  - Supports plain-text and JSON logs
  - Safe handling of malformed logs
  - Normalization for unified analysis

- 🚨 **Alert Detection & AI Classification**
  - Detects brute-force attacks, authentication failures, and suspicious IP activity
  - AI-based severity classification: Low / Medium / High / Critical
  - Automatic alert deduplication

- 🧠 **One-Click Automated Root Cause Analysis (Core Feature)**
  - Correlates events across multiple log sources
  - Identifies the true root cause of incidents
  - Explains what happened, why it happened, and how it propagated

- 📄 **AI-Generated Incident Reports**
  - Incident summary
  - Timeline of events
  - Root cause explanation
  - Impact assessment
  - Recommended remediation steps
  - Reports saved automatically to the output directory

- 🖥️ **Professional CLI Experience**
  - Clean command structure with `--help`
  - Modular, scalable architecture
  - Unique VSMK ASCII banner for branding

---

## 🏗️ Project Structure

ai-soc-analyst-cli/
├── src/
│ ├── ingestion/
│ ├── detection/
│ ├── ai_engine/
│ ├── rca/
│ ├── reporting/
│ ├── utils/
│ │ └── banner.py
│ └── main.py
├── logs/
├── output/
├── tests/
├── requirements.txt
├── README.md

---

## ⚙️ Installation & Setup

Clone the repository, create and activate a virtual environment, and install dependencies:

```bash
git clone https://github.com/SREMADUKRISHNA/ai-soc-analyst-cli.git
cd ai-soc-analyst-cli
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 src/main.py --help
python3 src/main.py scan --path logs
python3 src/main.py analyze
python3 src/main.py rca
python3 src/main.py report
python3 src/main.py scan --path logs && python3 src/main.py analyze && python3 src/main.py rca && python3 src/main.py report
