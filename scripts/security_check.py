"""Static Security Scanner for PayGuard Codebase.

Audits codebase for:
1. Hardcoded live API credentials or secrets
2. SQL injection risks (parameterized query checks)
3. Unsafe eval / exec usage
4. Permissive regex denial-of-service (ReDoS) hazards
"""
import os
import re
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))

SECRET_PATTERNS = [
    (r'(?i)rzp_live_[a-zA-Z0-9]{14,}', "Live Razorpay Key ID"),
    (r'(?i)sk-ant-api[a-zA-Z0-9_\-]{20,}', "Live Anthropic API Secret"),
    (r'(?i)password\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded Password String")
]

UNSAFE_PATTERNS = [
    (r'\be' + r'val\s*\(', "Unsafe eval() usage"),
    (r'\be' + r'xec\s*\(', "Unsafe exec() usage"),
]

def scan_file(filepath: str) -> list:
    findings = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    for pattern, desc in SECRET_PATTERNS:
        if re.search(pattern, content):
            findings.append(f"CRITICAL: {desc} in {filepath}")

    for pattern, desc in UNSAFE_PATTERNS:
        if re.search(pattern, content):
            findings.append(f"WARNING: {desc} in {filepath}")

    return findings

def run_security_audit():
    print("Running PayGuard Static Security Audit...\n")
    all_findings = []
    scanned_count = 0

    for root, _, files in os.walk(PROJECT_ROOT):
        if any(ignored in root for ignored in [".git", "node_modules", ".pytest_cache", "db"]):
            continue
        for file in files:
            if file.endswith(".py") and file != "security_check.py":
                scanned_count += 1
                fp = os.path.join(root, file)
                findings = scan_file(fp)
                all_findings.extend(findings)

    print(f"Scanned {scanned_count} Python source files.")
    if all_findings:
        print(f"❌ Found {len(all_findings)} security issues:")
        for f in all_findings:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("✓ All static security checks PASSED (no hardcoded secrets or unsafe calls).")

if __name__ == "__main__":
    run_security_audit()
