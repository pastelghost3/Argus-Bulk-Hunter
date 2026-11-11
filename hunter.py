import os
import sys
import subprocess
import requests
import time
import json
import re
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BASE_DIR = Path(__file__).parent.resolve()
ARGUS_PATH = BASE_DIR / "argus-core"
RESULTS_DIR = BASE_DIR / "findings"
TARGETS_FILE = BASE_DIR / "targets.txt"
LOG_FILE = BASE_DIR / "hunt_log.json"

# Advanced Search Patterns (Regex & File-based)
SEARCH_PROFILES = {
    "claude_leaks": {
        "query": "filename:settings.local.json path:.claude",
        "description": "Claude Code local settings with potential secrets"
    },
    "python_envs": {
        "query": "filename:.env language:python",
        "description": "Python environment files"
    },
    "js_configs": {
        "query": "filename:config.js OR filename:config.json language:javascript",
        "description": "JavaScript configuration files"
    },
    "hardcoded_keys": {
        "query": '"api_key" OR "secret_key" OR "password" extension:py OR extension:js',
        "description": "Hardcoded credentials in source code"
    }
}

def log_event(event_type, details):
    """Log events to a local JSON file for tracking."""
    log_entry = {"timestamp": datetime.now().isoformat(), "type": event_type, "details": details}
    logs = []
    if LOG_FILE.exists():
        try:
            logs = json.loads(LOG_FILE.read_text())
        except json.JSONDecodeError:
            logs = []
    logs.append(log_entry)
    LOG_FILE.write_text(json.dumps(logs, indent=2))

def search_github(query, per_page=30, max_pages=5):
    """Search GitHub Code API with pagination and rate-limit handling."""
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    all_items = []
    
    for page in range(1, max_pages + 1):
        url = f"https://api.github.com/search/code?q={query}&per_page={per_page}&page={page}"
        print(f"🔍 Searching page {page}/{max_pages}...")
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 403:
                print("⚠️ Rate limit reached. Waiting 60 seconds...")
                time.sleep(60)
                continue
            data = response.json()
            items = data.get('items', [])
            if not items:
                break 
            all_items.extend(items)
            time.sleep(2) # Respect secondary rate limits
        except Exception as e:
            print(f"❌ API Error on page {page}: {e}")
            break
            
    return all_items

def clone_and_scan(repo_url, repo_name):
    """Clone a repo and run the full Argus security pipeline."""
    target_dir = RESULTS_DIR / repo_name.replace("/", "_")
    analyzer = ARGUS_PATH / "scripts" / "hybrid_analyzer.py"
    
    if not target_dir.exists():
        print(f"📥 Cloning {repo_name}...")
        try:
            subprocess.run(["git", "clone", "--depth", "1", repo_url, str(target_dir)], 
                           capture_output=True, check=True)
        except subprocess.CalledProcessError:
            print(f"❌ Failed to clone {repo_name}")
            return

    print(f"🚀 Running Full Argus Scan on {repo_name}...")
    
    cmd = [
        sys.executable, str(analyzer), str(target_dir),
        "--no-enable-ai-enrichment",      
        "--no-enable-multi-agent",        
        "--enable-gitleaks",              
        "--enable-semgrep",               
        "--enable-trivy",                 
        "--enable-checkov",               
        "--enable-agent-config"
    ]
    
    try:
        result = subprocess.run(cmd, text=True, timeout=600) 
        argus_folder = target_dir / ".argus"
        if argus_folder.exists():
            print(f"   ✅ Scan data saved for {repo_name}")
            log_event("scan_complete", {"repo": repo_name, "path": str(target_dir)})
        else:
            print(f"   ⚠️ Scan finished but no data folder found for {repo_name}")
    except subprocess.TimeoutExpired:
        print(f"   ❌ Scan timed out for {repo_name}")
    except Exception as e:
        print(f"   ❌ Error during scan: {e}")

def process_static_targets():
    """Process repos listed in targets.txt."""
    if not TARGETS_FILE.exists():
        return
    with open(TARGETS_FILE, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    for target in targets:
        if target.startswith("http"):
            repo_name = target.split('/')[-1].replace('.git', '')
            clone_and_scan(target, repo_name)

def main():
    if not GITHUB_TOKEN:
        print("❌ Please set GITHUB_TOKEN environment variable.")
        return

    RESULTS_DIR.mkdir(exist_ok=True)
    print("🚀 Starting Argus Bulk Hunter v2.0...")
    
    # 1. Process static targets
    process_static_targets()
    
    # 2. Dynamic Hunt with Pagination
    processed_repos = set()
    
    for profile_name, profile in SEARCH_PROFILES.items():
        print(f"\n--- Profile: {profile['description']} ---")
        items = search_github(profile['query'], max_pages=3)
        for item in items:
            repo_name = item['repository']['full_name']
            if repo_name not in processed_repos:
                repo_url = item['repository']['html_url'] + ".git"
                clone_and_scan(repo_url, repo_name)
                processed_repos.add(repo_name)

if __name__ == "__main__":
    main()
