import os
import logging
import sys
import subprocess
import requests
import time
import json
import shutil
from pathlib import Path
import argparse
from datetime import datetime, timedelta

# Add argus-core scripts to the Python path so we can import scanners
ARGUS_SCRIPTS = Path(__file__).parent / "argus-core" / "scripts"
sys.path.append(str(ARGUS_SCRIPTS))

logger = logging.getLogger(__name__)
# Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BASE_DIR = Path(__file__).parent.resolve()

# Ensure subprocesses (semgrep, gitleaks, trufflehog, analyzer) see venv/bin
# on PATH regardless of how hunter.py was launched (shell, cron, systemd).
import os
_VENV_BIN = BASE_DIR / "venv" / "bin"
if _VENV_BIN.exists():
    os.environ["PATH"] = str(_VENV_BIN) + os.pathsep + os.environ.get("PATH", "")
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


MANIFEST_PATH = BASE_DIR / ".scanned_repos.json"

def _load_manifest():
    if not MANIFEST_PATH.exists():
        return {}
    try:
        return json.loads(MANIFEST_PATH.read_text())
    except Exception:
        return {}

def _save_manifest(m):
    MANIFEST_PATH.write_text(json.dumps(m, indent=2, sort_keys=True))

def should_scan(repo_name, max_age_days=30, manifest=None):
    if manifest is None:
        manifest = _load_manifest()
    entry = manifest.get(repo_name)
    if not entry:
        return True, "never scanned"
    try:
        last = datetime.fromisoformat(entry["last_scan"])
        age = (datetime.now() - last).days
    except Exception:
        return True, "manifest unreadable"
    if age >= max_age_days:
        return True, "stale " + str(age) + "d"
    return False, "fresh " + str(age) + "d"

def mark_scanned(repo_name):
    m = _load_manifest()
    m[repo_name] = {"last_scan": datetime.now().isoformat()}
    _save_manifest(m)

def clone_and_scan(repo_url, repo_name, dry_run=False, max_age_days=30, manifest=None):
    target_dir = RESULTS_DIR / repo_name.replace("/", "_")
    analyzer = ARGUS_PATH / "scripts" / "hybrid_analyzer.py"

    ok, reason = should_scan(repo_name, max_age_days=max_age_days, manifest=manifest)
    if not ok:
        print("   skip " + repo_name + ": " + reason)
        return
    if dry_run:
        print("   [dry-run] would scan " + repo_name + " (" + reason + ")")
        return

    # 1. Clone if needed -- handle three states cleanly:
    #    (a) dir exists with content -> assume prior scan, skip clone
    #    (b) dir exists but empty     -> remove, re-clone
    #    (c) dir doesn't exist        -> clone
    if target_dir.exists():
        if any(target_dir.iterdir()):
            print(f"   (using existing clone of {repo_name})")
        else:
            print(f"   (removing empty {target_dir.name}, will re-clone)")
            shutil.rmtree(target_dir)

    if not target_dir.exists():
        max_retries = 3
        cloned = False
        for attempt in range(max_retries):
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
                    capture_output=True,
                    check=True,
                    timeout=120
                )
                cloned = True
                break
            except subprocess.TimeoutExpired:
                print(f"   Clone timed out (attempt {attempt + 1}/{max_retries}), retrying...")
                shutil.rmtree(target_dir, ignore_errors=True)
                if attempt == max_retries - 1:
                    print(f"   Failed to clone {repo_name} after {max_retries} attempts, marking skipped")
                    mark_scanned(repo_name)
                    return
            except subprocess.CalledProcessError as e:
                err = e.stderr.decode() if e.stderr else "unknown error"
                print(f"   Clone failed: {err[:200]}")
                print(f"   Marking {repo_name} in manifest to skip next run")
                shutil.rmtree(target_dir, ignore_errors=True)
                mark_scanned(repo_name)
                return
    
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
        res = subprocess.run(gitleaks_cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print("   gitleaks: clean")
        elif res.returncode == 1:
            print("   gitleaks: findings present")
        else:
            print("   gitleaks failed exit=" + str(res.returncode))
    except Exception as e:
        print("   gitleaks error: " + str(e))

    # 2.5  Verify High-Value Secrets (Runs immediately after Gitleaks)
    try:
        from scanners.verifier import SecretVerifier
        verifier = SecretVerifier()
        
        gitleaks_report = target_dir / "aggressive-gitleaks.json"
        if gitleaks_report.exists():
            with open(gitleaks_report, 'r') as f:
                findings = json.load(f)
            
            active_secrets = 0
            for finding in findings:
                secret = finding.get('Secret', '')
                context = finding.get('File', '')
                
                # Run verification
                verification = verifier.identify_and_verify(secret, context)
                
                # Update the finding with verification status
                finding['verification_status'] = verification.get('status', 'UNKNOWN')
                finding['verification_type'] = verification.get('type', 'UNKNOWN')
                
                if verification['status'] == 'ACTIVE':
                    active_secrets += 1
                    logger.warning(f"   🚨 VERIFIED ACTIVE SECRET: {verification.get('details', '')} in {context}")

            if active_secrets > 0:
                print(f"   🔥 Found {active_secrets} VERIFIED ACTIVE secrets!")
            else:
                print(f"   ℹ️  No verified active secrets found in this batch.")
                
            # Save the updated findings back to the report
            with open(gitleaks_report, 'w') as f:
                json.dump(findings, f, indent=2)
                
    except ImportError:
        print("   ⚠️ Verifier module not found. Skipping verification.")
    except Exception as e:
        print(f"   ⚠️ Verification error: {e}")

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
            shutil.rmtree(git_folder)
            print(f"   🧹 Cleaned .git folder for {repo_name}")
        argus_folder = target_dir / ".argus"
        if argus_folder.exists():
            print(f"   ✅ Argus Scan data saved for {repo_name}")
            
            # 4. Verify High-Value Secrets
            try:
                from scanners.verifier import SecretVerifier
                verifier = SecretVerifier()
                
                gitleaks_report = target_dir / "aggressive-gitleaks.json"
                if gitleaks_report.exists():
                    with open(gitleaks_report, 'r') as f:
                        findings = json.load(f)
                    
                    active_secrets = 0
                    for finding in findings:
                        secret = finding.get('Secret', '')
                        context = finding.get('File', '')
                        
                        # Run verification
                        verification = verifier.identify_and_verify(secret, context)
                        
                        # Update the finding with verification status
                        finding['verification_status'] = verification.get('status', 'UNKNOWN')
                        finding['verification_type'] = verification.get('type', 'UNKNOWN')
                        
                        if verification['status'] == 'ACTIVE':
                            active_secrets += 1
                            logger.warning(f"   🚨 VERIFIED ACTIVE SECRET: {verification.get('details', '')} in {context}")

                    if active_secrets > 0:
                        print(f"   🔥 Found {active_secrets} VERIFIED ACTIVE secrets!")
                    else:
                        print(f"   ℹ️  No verified active secrets found in this batch.")
                        
                    # Save the updated findings back to the report
                    with open(gitleaks_report, 'w') as f:
                        json.dump(findings, f, indent=2)
                        
            except ImportError:
                print("   ⚠️ Verifier module not found. Skipping verification.")
            except Exception as e:
                print(f"   ⚠️ Verification error: {e}")

        else:
            print(f"   ⚠️ Argus finished but no data folder found for {repo_name}")
        
        mark_scanned(repo_name)
    except subprocess.TimeoutExpired:
        print(f"   ❌ Argus Scan timed out for {repo_name}")
    except Exception as e:
        print(f"   ❌ Argus Error: {e}")

def process_targets(dry_run=False, max_new=10, max_age_days=30):
    if not TARGETS_FILE.exists():
        return 0
    with open(TARGETS_FILE, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    planned = 0
    for target in targets:
        if not target.startswith("http"):
            continue
        parts = target.rstrip("/").replace(".git", "").split("/")
        if len(parts) < 2:
            continue
        repo_name = parts[-2] + "/" + parts[-1]
        clone_and_scan(target, repo_name, dry_run=dry_run, max_age_days=max_age_days)
        planned += 1
        if planned >= max_new:
            print("   [cap] reached --max-new " + str(max_new) + " for targets.txt")
            break
    return planned


def interactive_launch():
    """Interactive menu — entry point when hunter.py is run without args."""
    if not sys.stdin.isatty():
        print("Non-interactive stdin. Use flags (--help for usage).", file=sys.stderr)
        sys.exit(2)

    print("""
╔══════════════════════════════════════════════════════════════════╗
║   Argus Bulk Hunter v2.0 — Secret Scanner                        ║
║   Interactive launcher (no args) / scriptable via flags (--help) ║
╚══════════════════════════════════════════════════════════════════╝
""")

    token_ok = bool(GITHUB_TOKEN)
    if not token_ok:
        print("GITHUB_TOKEN not set. Discovery modes require it; local-path scans work.")

    while True:
        print("""
  What do you want to do?

    [1] Scan a specific repo (GitHub URL or local path)
    [2] Discover & scan new repos (bounded rotation)
    [3] Re-scan already-cloned repos in findings/
    [4] Dry-run only (show plan, no clones/scans)
    [5] Show help / all flags
    [q] Quit
""")
        choice = input("  Choice [1-5, q]: ").strip().lower()
        if choice in ("q", "quit", "exit"):
            print("Bye.")
            return
        if choice == "5" or choice == "help":
            _print_help()
            continue
        if choice == "1":
            _launch_specific_repo()
            return
        if choice == "2":
            if not token_ok:
                print("Mode 2 needs GITHUB_TOKEN. Use mode 1 with a local path.")
                continue
            _launch_discovery()
            return
        if choice == "3":
            _launch_rescan()
            return
        if choice == "4":
            _launch_dryrun()
            return
        print(f"  Unknown choice: {choice!r}")


def _print_help():
    import argparse
    p = _build_parser()
    p.print_help()


def _build_parser():
    import argparse
    p = argparse.ArgumentParser(
        description="Argus Bulk Hunter — find secrets in repos.\n\n"
                    "Run with no args for an interactive launcher; use flags for scripting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python hunter.py                                    # interactive menu
  python hunter.py --dry-run --only-new --max-new=3   # show plan for 3 new repos
  python hunter.py --only-new --max-new=5             # discover+scan 5 new
  python hunter.py --no-discovery --max-age-days=7    # re-scan stale locally
""",
    )
    p.add_argument("--max-new", type=int, default=10,
                   help="Max new repos to scan per run (default: 10)")
    p.add_argument("--max-age-days", type=int, default=30,
                   help="Rescan repos older than N days (default: 30)")
    p.add_argument("--only-new", action="store_true",
                   help="Skip targets.txt, only do GitHub discovery")
    p.add_argument("--no-discovery", action="store_true",
                   help="Skip GitHub discovery, only scan targets.txt")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the plan, do not clone or scan")
    return p


def _ask_scanner_set():
    print("""
  Which scanners?

    [1] Fast (secrets only: gitleaks + argus agent-config)
    [2] Standard (secrets + semgrep + trivy + checkov)   <- default
    [3] Deep (standard + supply-chain + nuclei + threat-intel)
    [4] Everything (all 14 — slow, ~3-5min per repo)
""")
    pick = input("  Choice [1-4, default 2]: ").strip() or "2"
    presets = {
        "1": ["--enable-gitleaks", "--enable-agent-config"],
        "2": ["--enable-gitleaks", "--enable-semgrep", "--enable-trivy",
              "--enable-checkov", "--enable-agent-config"],
        "3": ["--enable-gitleaks", "--enable-semgrep", "--enable-trivy",
              "--enable-checkov", "--enable-agent-config",
              "--enable-supply-chain", "--enable-nuclei-templates",
              "--enable-threat-intel"],
        "4": [],
    }
    return presets.get(pick, presets["2"])


def _ask_yes_no(prompt, default=False):
    suffix = " [Y/n]" if default else " [y/N]"
    ans = input(prompt + suffix + ": ").strip().lower()
    if not ans:
        return default
    return ans in ("y", "yes")


def _launch_specific_repo():
    print("\n  -- Mode 1: Scan a specific repo --\n")
    target = input("  URL or local path: ").strip()
    if not target:
        print("  Cancelled.")
        return

    is_url = target.startswith(("http://", "https://", "git@"))
    if is_url:
        url = target.rstrip("/").replace(".git", "")
        if url.startswith("git@"):
            parts = url.split(":")[-1].split("/")
        else:
            parts = url.split("/")[-2:]
        if len(parts) < 2:
            print(f"  Can't parse org/repo from {target!r}")
            return
        repo_name = parts[-2] + "/" + parts[-1]
        print("  -> will clone and scan: " + repo_name)
    else:
        local = Path(target).resolve()
        if not local.exists():
            print(f"  Path does not exist: {local}")
            return
        repo_name = local.name
        print(f"  -> will scan local path: {local}")

    scanner_flags = _ask_scanner_set()
    dry = _ask_yes_no("  Dry-run only (no actual scan)?", default=False)

    if dry:
        if is_url:
            print(f"  [dry-run] would clone {target} -> findings/{repo_name.replace('/', '_')}")
        print(f"  [dry-run] scanner flags: {' '.join(scanner_flags) or '(all defaults)'}")
        return

    if is_url:
        clone_and_scan(target, repo_name)
    else:
        analyzer = ARGUS_PATH / "scripts" / "hybrid_analyzer.py"
        subprocess.run([sys.executable, str(analyzer), str(local),
                        "--no-enable-ai-enrichment", "--no-enable-multi-agent"]
                       + scanner_flags)


def _launch_discovery():
    print("\n  -- Mode 2: Discovery & rotation --\n")
    max_new = input("  Max new repos this run [default 5]: ").strip() or "5"
    max_age = input("  Rescan repos older than N days [default 30]: ").strip() or "30"
    dry = _ask_yes_no("  Dry-run only?", default=False)

    argv = ["--only-new", "--max-new=" + max_new, "--max-age-days=" + max_age]
    if dry:
        argv.append("--dry-run")
    print("\n  -> running: python hunter.py " + " ".join(argv) + "\n")
    old = sys.argv[:]
    try:
        sys.argv = ["hunter.py"] + argv
        main()
    finally:
        sys.argv = old


def _launch_rescan():
    print("\n  -- Mode 3: Re-scan already-cloned repos --\n")
    if not RESULTS_DIR.exists():
        print(f"  {RESULTS_DIR} does not exist. Try mode 1 or 2 first.")
        return
    repos = [d.name for d in RESULTS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    if not repos:
        print(f"  No repos in {RESULTS_DIR}. Try mode 1 or 2 first.")
        return
    print(f"  Found {len(repos)} cloned repos:")
    for r in repos[:20]:
        print("    - " + r)
    if len(repos) > 20:
        print(f"    ... and {len(repos) - 20} more")

    dry = _ask_yes_no("  Dry-run only?", default=False)
    max_age = input("  Rescan only repos older than N days [default 30]: ").strip() or "30"

    argv = ["--max-age-days=" + max_age, "--no-discovery"]
    if dry:
        argv.append("--dry-run")
    print("\n  -> running: python hunter.py " + " ".join(argv) + "\n")
    old = sys.argv[:]
    try:
        sys.argv = ["hunter.py"] + argv
        main()
    finally:
        sys.argv = old


def _launch_dryrun():
    print("\n  -- Mode 4: Dry-run (show plan) --\n")
    print("  Shows what the tool WOULD do, without cloning or scanning.\n")
    old = sys.argv[:]
    try:
        sys.argv = ["hunter.py", "--dry-run", "--only-new", "--max-new=10"]
        main()
    finally:
        sys.argv = old


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if not GITHUB_TOKEN:
        print("Please set GITHUB_TOKEN environment variable.")
        return

    RESULTS_DIR.mkdir(exist_ok=True)
    mode = " [DRY RUN]" if args.dry_run else ""
    print("Starting Argus Bulk Hunter v2.0 (Pro Mode)" + mode + "...")

    manifest = _load_manifest()
    print("[manifest] " + str(len(manifest)) + " repos tracked")

    total = 0
    if not args.only_new:
        total += process_targets(dry_run=args.dry_run, max_new=args.max_new,
                                 max_age_days=args.max_age_days)

    if not args.no_discovery:
        # Query pool — 12 targets, rotate 3 per run so each run sees
        # different repos without relying on GitHub API date filters
        # (pushed:/created: only work on /search/repositories, not /search/code).
        QUERY_POOL = [
            "filename:settings.local.json path:.claude",
            "filename:.env language:python",
            "filename:.env language:javascript",
            "filename:config.js language:javascript",
            "filename:config.json language:javascript",
            "filename:credentials language:python",
            "filename:secrets.yml",
            "filename:secrets.yaml",
            "filename:.aws/credentials",
            "path:.claude settings.json",
            "filename:.env.example",
            "filename:docker-compose.yml",
        ]
        state_path = BASE_DIR / ".search_state.json"
        try:
            state = json.loads(state_path.read_text()) if state_path.exists() else {}
        except Exception:
            state = {}
        offset = int(state.get("offset", 0)) % len(QUERY_POOL)
        chosen = [QUERY_POOL[(offset + i) % len(QUERY_POOL)] for i in range(3)]
        state["offset"] = (offset + 3) % len(QUERY_POOL)
        state_path.write_text(json.dumps(state, indent=2))
        search_queries = chosen
        print("[discovery] queries " + str(offset + 1) + "-" + str(offset + 3) + " of " + str(len(QUERY_POOL)))
        for q in chosen:
            print("  - " + q)

        processed = set()
        for query in search_queries:
            items = search_github(query, max_pages=3)
            for item in items:
                repo_name = item["repository"]["full_name"]
                if repo_name in processed:
                    continue
                processed.add(repo_name)
                ok, reason = should_scan(repo_name, max_age_days=args.max_age_days, manifest=manifest)
                if not ok:
                    continue
                if total >= args.max_new:
                    print("[cap] reached --max-new " + str(args.max_new) + ", stopping discovery")
                    break
                repo_url = item["repository"]["html_url"] + ".git"
                clone_and_scan(repo_url, repo_name, dry_run=args.dry_run,
                               max_age_days=args.max_age_days, manifest=manifest)
                total += 1

    print("[done] processed " + str(total) + " repos")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        interactive_launch()
    else:
        main()
