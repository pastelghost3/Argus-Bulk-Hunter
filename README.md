# Argus Bulk Hunter

An automated security hunting tool that leverages the **Argus Core** engine to scan GitHub repositories at scale. It combines dynamic API discovery with a multi-scanner pipeline (Gitleaks, Semgrep, Trivy, TruffleHog, and custom Threat Intelligence scanners) to identify secrets, vulnerabilities, and supply chain attacks without requiring external AI API keys.

## 🚀 Features

- **Dynamic Target Discovery:** Uses the GitHub Code Search API with pagination to find repos matching specific regex patterns (e.g., `.env`, `.claude/settings.json`).
- **Full Argus Pipeline:** Integrates with [pastelghost3/Argus-Security](https://github.com/pastelghost3/Argus-Security) to run:
  - 🔑 **Gitleaks (Aggressive):** Pattern-based secret detection with custom rules for generic passwords and base64 blobs.
  - 🕵️‍♂️ **TruffleHog:** Deep history scanning and high-entropy secret detection.
  - 🛡️ **Semgrep:** Static Application Security Testing (SAST).
  - 📦 **Trivy:** Vulnerability scanning for dependencies and OS packages.
  - 🏗️ **Checkov:** Infrastructure-as-Code (IaC) security.
 
    
- **Advanced Threat Intelligence:**
  - **Supply Chain Stealer Detection:** Identifies IOCs from recent GitHub CI/CD attacks (malicious branches like `wfx-docs`, suspicious commit messages, and workflow exfiltration scripts).
  - **GitHub Token Hunter:** Specifically scans for hardcoded Personal Access Tokens (`ghp_...`) in source code.
  - **AI Agent Leak Scanner:** Detects secrets accidentally saved in AI coding assistant configurations (e.g., `.claude/settings.local.json`, `.cursor/settings.json`).
- **Offline-First:** Designed to generate comprehensive reports (JSON, SQLite, Compliance Markdown) without requiring paid LLM API keys.
- **Smart Deduplication:** Ensures each repository is only cloned and scanned once per session.



## 📋 Prerequisites

- Python 3.10+
- Git
- **Argus Core:** This tool expects an `argus-core` submodule or folder in the root directory.
- **Tools:** Ensure `gitleaks`, `semgrep`, `trivy`, and `trufflehog` are installed in your environment or virtual environment.

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/Argus-Bulk-Hunter.git
   cd Argus-Bulk-Hunter
