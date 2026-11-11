Argus Bulk Hunter

An automated security hunting tool that leverages the **Argus Core** engine to scan GitHub repositories at scale. It combines dynamic API discovery with a multi-scanner pipeline (Gitleaks, Semgrep, Trivy, and custom Agent Config scanners) to identify secrets, vulnerabilities, and misconfigurations without requiring external AI API keys.

 Features

- **Dynamic Target Discovery:** Uses the GitHub Code Search API with pagination to find repos matching specific regex patterns (e.g., `.env`, `.claude/settings.json`).
- **Full Argus Pipeline:** Integrates with [pastelghost3/Argus-Security](https://github.com/pastelghost3/Argus-Security) to run:
  - 🔑 **Gitleaks:** Pattern-based secret detection.
  - 🛡️ **Semgrep:** Static Application Security Testing (SAST).
  - 📦 **Trivy:** Vulnerability scanning for dependencies and OS packages.
  - 🏗️ **Checkov:** Infrastructure-as-Code (IaC) security.
  - 🤖 **Agent Config Scanner:** Custom scanner for AI-assistant configuration leaks.
- **Offline-First:** Designed to generate comprehensive reports (JSON, SQLite, Compliance Markdown) without requiring paid LLM API keys.
- **Smart Deduplication:** Ensures each repository is only cloned and scanned once per session.

## 📋 Prerequisites

- Python 3.10+
- Git
- **Argus Core:** This tool expects an `argus-core` submodule or folder in the root directory.
- **Tools:** Ensure `gitleaks`, `semgrep`, and `trivy` are installed in your environment or virtual environment.

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/Argus-Bulk-Hunter.git
   cd Argus-Bulk-Hunter
