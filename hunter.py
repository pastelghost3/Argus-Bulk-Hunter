import os
import sys
import subprocess
import requests
import time
import json
import shutil
from pathlib import Path

# Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BASE_DIR = Path(__file__).parent.resolve()
ARGUS_PATH = BASE_DIR / "argus-core"
RESULTS_DIR = BASE_DIR / "findings"
TARGETS_FILE = BASE_DIR / "targets.txt"
TRUFFLEHOG_PATH = "/usr/local/bin/trufflehog" # Adjust if installed elsewhere

def search_github(query, per_page=30, max_pages=3):
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    all_items = []
    for page in range(1, max_pages + 1):
        url = f"https://api.github.com/search/code?q={query}&per_page={per_page}&page={page}"
        print(f"🔍 Global Hunt: Searching page {page} for '{query}'...")
        try:
            response = requests.get(url, headers=headers)
            data = response.json()
            items = data.get('items', [])
            if not items: break 
            all_items.extend(items)
            time.sleep(2) 
        except Exception as e:
            print(f"❌ API Error on page {page}: {e}")
            break
    return all_items

def run_trufflehog_scan(target_dir):
    """Runs TruffleHog and returns a list of verified/high-confidence findings."""
    if not os.path.exists(TRUFFLEHOG_PATH):
        print("   ⚠️ TruffleHog not found at expected path. Skipping.")
        return []

    report_path = target_dir / "trufflehog_results.jsonl"
    cmd = [
        TRUFFLEHOG_PATH, "filesystem", str(target_dir),
        "--json", "--no-update", "--fail"
    ]
    
    findings = []
    try:
        with open(report_path, 'w') as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, timeout=300)
        
        # Parse JSONL
        if report_path.exists():
            with open(report_path, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            # Filter for high-value secrets (exclude common test mocks if desired)
                            if data.get('Raw'):
                                findings.append({
                                    "type": data.get('DetectorName', 'Unknown'),
                                    "secret": data.get('Raw', '')[:50] + "...",
                                    "file": data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'N/A'),
                                    "verified": data.get('Verified', False)
                                })
                        except json.JSONDecodeError:
                            continue
    except subprocess.TimeoutExpired:
        print("   ⚠️ TruffleHog scan timed out.")
    except Exception as e:
        print(f"   ⚠️ TruffleHog error: {e}")
        
    return findings

def clone_and_scan(repo_url, repo_name):
    target_dir = RESULTS_DIR / repo_name.replace("/", "_")
    analyzer = ARGUS_PATH / "scripts" / "hybrid_analyzer.py"
    
    # 1. Clone if needed
    if not target_dir.exists():
        print(f"📥 Cloning {repo_name}...")
        try:
            subprocess.run(["git", "clone", "--depth", "1", repo_url, str(target_dir)], 
                           capture_output=True, check=True, timeout=60)
        except subprocess.CalledProcessError:
            print(f"❌ Failed to clone {repo_name}")
            return

    print(f"🚀 Running Enhanced Secret Hunt on {repo_name}...")
    
    # 2. Run Aggressive Gitleaks with Custom Config
    gitleaks_report = target_dir / "aggressive-gitleaks.json"
    gitleaks_cmd = [
        "gitleaks", "detect", 
        "--source", str(target_dir),
        "--report-format", "json",
        "--report-path", str(gitleaks_report),
        "--config", "aggressive-gitleaks.toml", # Point to our new file
        "--no-banner"
    ]
    try:
        subprocess.run(gitleaks_cmd, check=True, capture_output=True)
        print(f"   🔍 Aggressive Gitleaks complete: {gitleaks_report}")
    except subprocess.CalledProcessError:
        print(f"   ⚠️ Gitleaks found issues or failed.")

    # 3. Run TruffleHog (Great for base64 and history)
    trufflehog_report = target_dir / "trufflehog.json"
    trufflehog_cmd = [
        "trufflehog", "filesystem", str(target_dir),
        "--json",
        "--fail",
        "--no-update"
    ]
    try:
        # Note: TruffleHog outputs to stdout, so we redirect to file
        with open(trufflehog_report, 'w') as f:
            subprocess.run(trufflehog_cmd, stdout=f, stderr=subprocess.DEVNULL)
        print(f"   🕵️ TruffleHog complete: {trufflehog_report}")
    except Exception as e:
        print(f"   ⚠️ TruffleHog error: {e}")

    # 4. Run Full Argus Pipeline
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
        
        # CLEANUP: Delete the .git folder to save space
        git_folder = target_dir / ".git"
        if git_folder.exists():
            import shutil
            shutil.rmtree(git_folder)
            print(f"   🧹 Cleaned .git folder for {repo_name}")

        argus_folder = target_dir / ".argus"
        if argus_folder.exists():
            print(f"   ✅ Argus Scan data saved for {repo_name}")
        else:
            print(f"   ⚠️ Argus finished but no data folder found for {repo_name}")
    except subprocess.TimeoutExpired:
        print(f"   ❌ Argus Scan timed out for {repo_name}")
    except Exception as e:
        print(f"   ❌ Argus Error: {e}")

def process_targets():
    if not TARGETS_FILE.exists(): return
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
    print("🚀 Starting Argus Bulk Hunter v2.0 (Pro Mode)...")
    process_targets()
    
    search_queries = [
        "filename:settings.local.json path:.claude",
        "filename:.env language:python",
        "filename:config.js language:javascript"
    ]
    
    processed_repos = set()
    for query in search_queries:
        items = search_github(query, max_pages=3)
        for item in items:
            repo_name = item['repository']['full_name']
            if repo_name not in processed_repos:
                repo_url = item['repository']['html_url'] + ".git"
                clone_and_scan(repo_url, repo_name)
                processed_repos.add(repo_name)

if __name__ == "__main__":
    main()
