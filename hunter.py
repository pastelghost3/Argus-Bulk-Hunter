import os
import sys
import subprocess
import requests
from pathlib import Path

# Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ARGUS_PATH = Path("argus-core")
RESULTS_DIR = Path("findings")
TARGETS_FILE = "targets.txt"

def search_github(query, per_page=10):
    """Search GitHub Code API for specific files"""
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    url = f"https://api.github.com/search/code?q={query}&per_page={per_page}"
    print(f"🔍 Global Hunt: Searching for '{query}'...")
    try:
        response = requests.get(url, headers=headers)
        return response.json().get('items', [])
    except Exception as e:
        print(f"❌ API Error: {e}")
        return []

def clone_and_scan(repo_url, repo_name):
    """Clone a repo and run the Argus scanner"""
    target_dir = RESULTS_DIR / repo_name.replace("/", "_")
    
    if not target_dir.exists():
        print(f"📥 Cloning {repo_name}...")
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(target_dir)], 
                       capture_output=True, check=True)
    
    print(f"🚀 Scanning {repo_name} with Argus Core...")
    analyzer = ARGUS_PATH / "scripts" / "hybrid_analyzer.py"
    
    # Run your fork's scanner with secret-focused flags
    cmd = [
        sys.executable, str(analyzer), str(target_dir),
        "--enable-gitleaks", "--enable-agent-config", "--enable-heuristics",
        "--no-enable-semgrep", "--no-enable-trivy", "--no-enable-checkov"
    ]
    
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(f"✅ Scan complete for {repo_name}")
    except Exception as e:
        print(f"❌ Error scanning {repo_name}: {e}")

def process_targets():
    """Scan repos listed in targets.txt"""
    if not Path(TARGETS_FILE).exists():
        print(f"⚠️ {TARGETS_FILE} not found. Skipping targeted scan.")
        return

    with open(TARGETS_FILE, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    for target in targets:
        if target.startswith("http"):
            repo_name = target.split('/')[-1].replace('.git', '')
            clone_and_scan(target, repo_name)
        else:
            print(f"🚀 Scanning local path: {target}")

def main():
    if not GITHUB_TOKEN:
        print("❌ Please set the GITHUB_TOKEN environment variable.")
        return

    RESULTS_DIR.mkdir(exist_ok=True)
    
    # 1. Run Targeted Scans
    process_targets()
    
    # 2. Run Global Hunt for Claude Leaks
    items = search_github("filename:settings.local.json path:.claude")
    processed_repos = set()
    
    for item in items:
        repo_url = item['repository']['html_url'] + ".git"
        repo_name = item['repository']['full_name']
        
        if repo_name not in processed_repos:
            clone_and_scan(repo_url, repo_name)
            processed_repos.add(repo_name)

if __name__ == "__main__":
    main()
