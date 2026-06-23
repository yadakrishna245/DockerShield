#!/usr/bin/env python3
"""DockerShield - Docker Image Security Scanner CLI Tool.

Scans Docker images for CVEs, secrets, malware, misconfigurations, and supply chain risks.
Includes digest verification, tag mutation detection, and network threat analysis.
Author: Krishna Chaithanya Yada
"""

import argparse
import json
import logging
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import docker
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except ImportError:
    print("Install dependencies: pip install docker rich")
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None

__version__ = "2.0.0"
console = Console()
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("dockershield")

TRUSTED_REGISTRIES = ["docker.io", "gcr.io", "ghcr.io", "quay.io", "registry.access.redhat.com"]
SENSITIVE_PORTS = [22, 23, 3389, 5900, 6379, 27017, 3306, 5432, 11211]
MAX_LAYERS = 30

KNOWN_VULNERABLE_PACKAGES = {
    "log4j-core": {"cve": "CVE-2021-44228", "severity": "critical", "fixed": "2.17.1"},
    "openssl": {"cve": "CVE-2022-3602", "severity": "high", "fixed": "3.0.7"},
    "libexpat": {"cve": "CVE-2022-25235", "severity": "critical", "fixed": "2.4.5"},
    "zlib": {"cve": "CVE-2022-37434", "severity": "high", "fixed": "1.2.12"},
    "curl": {"cve": "CVE-2023-38545", "severity": "high", "fixed": "8.4.0"},
    "glibc": {"cve": "CVE-2023-4911", "severity": "high", "fixed": "2.38"},
}

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}", "AWS Secret Access Key"),
    (r"ghp_[A-Za-z0-9_]{36}", "GitHub Personal Access Token"),
    (r"gho_[A-Za-z0-9_]{36}", "GitHub OAuth Token"),
    (r"ghs_[A-Za-z0-9_]{36}", "GitHub Server Token"),
    (r"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key"),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH Private Key"),
    (r"-----BEGIN EC PRIVATE KEY-----", "EC Private Key"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+", "Password in plaintext"),
    (r"(?i)(secret|token|api_key)\s*[=:]\s*\S+", "Secret/Token in plaintext"),
    (r"(?i)database_url\s*[=:]\s*\S+", "Database URL with credentials"),
]

MALWARE_BINARIES = ["xmrig", "minerd", "cpuminer", "ccminer", "cgminer", "bfgminer", "ethminer"]

MALWARE_PATTERNS = [
    (r"nc\s+.*-e\s+/bin/(ba)?sh", "Reverse shell via netcat"),
    (r"bash\s+-i\s+>&\s+/dev/tcp/", "Bash reverse shell"),
    (r"mkfifo\s+/tmp/", "Named pipe (potential reverse shell)"),
    (r"stratum\+tcp://", "Crypto mining pool connection"),
    (r"curl.*\|\s*(ba)?sh", "Remote code execution via curl pipe"),
    (r"wget.*\|\s*(ba)?sh", "Remote code execution via wget pipe"),
]

# Directories to exclude from secret file detection (SSL false positives)
CERT_SAFE_DIRS = ["/etc/ssl/certs/", "/usr/share/ca-certificates/", "/etc/pki/"]

# Known malicious mining pool domains
MALICIOUS_DOMAINS = [
    "pool.minexmr.com", "xmr.pool.minergate.com", "monerohash.com",
    "moneropool.com", "xmrpool.eu", "supportxmr.com", "pool.hashvault.pro",
    "mine.c3pool.com", "gulf.moneroocean.stream",
]

# Trust store path for digest verification
TRUST_STORE_DIR = Path.home() / ".dockershield"
TRUST_STORE_FILE = TRUST_STORE_DIR / "trusted_digests.json"


class Finding:
    """Represents a single security finding."""

    def __init__(self, category, severity, title, description, remediation=""):
        self.category = category
        self.severity = severity
        self.title = title
        self.description = description
        self.remediation = remediation
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return vars(self)


class DockerShield:
    """Main scanner class."""

    def __init__(self, image_name, severity_filter="low", block=False):
        self.image_name = image_name
        self.severity_filter = severity_filter
        self.block = block
        self.findings = []
        self.client = docker.from_env()
        self.image = None
        self.inspect_data = None
        self.scan_start_time = None

    def pull_and_inspect(self):
        """Pull image and get inspection data."""
        # Try local first
        try:
            self.image = self.client.images.get(self.image_name)
            console.print(f"[bold blue]Using local image:[/] {self.image_name}")
        except docker.errors.ImageNotFound:
            console.print(f"[bold blue]Pulling image:[/] {self.image_name}")
            try:
                self.image = self.client.images.pull(self.image_name)
            except Exception as e:
                console.print(f"[red]Cannot find or pull image: {self.image_name}[/]")
                console.print(f"[red]Error: {e}[/]")
                sys.exit(1)
        self.inspect_data = self.client.api.inspect_image(self.image_name)

    def scan_cve(self):
        """Check for known vulnerable packages in the image."""
        console.print("[bold]  [1/7] Scanning for CVEs...[/]")
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint", "", self.image_name,
                 "sh", "-c",
                 "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || apk list --installed 2>/dev/null"],
                capture_output=True, text=True, timeout=60
            )
            pkg_output = result.stdout.lower()
            for pkg, info in KNOWN_VULNERABLE_PACKAGES.items():
                if pkg in pkg_output:
                    self.findings.append(Finding(
                        "CVE", info["severity"],
                        f"{info['cve']} - {pkg}",
                        f"Vulnerable package '{pkg}' detected. Fixed in {info['fixed']}.",
                        f"Update {pkg} to version >= {info['fixed']}"
                    ))
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            logger.warning(f"CVE scan limited: {e}")

    def scan_secrets(self):
        """Scan image layers for secrets and credentials."""
        console.print("[bold]  [2/7] Scanning for secrets...[/]")
        config = self.inspect_data.get("Config", {})
        env_vars = config.get("Env", []) or []
        for env in env_vars:
            for pattern, desc in SECRET_PATTERNS:
                if re.search(pattern, env):
                    self.findings.append(Finding(
                        "Secrets", "critical", f"Secret in ENV: {desc}",
                        f"Found '{desc}' in environment variable: {env.split('=')[0]}",
                        "Use Docker secrets or external secret manager"
                    ))
                    break
        # Check filesystem for secret files (excluding standard cert locations)
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint", "", self.image_name,
                 "sh", "-c",
                 "find / -name '*.env' -o -name '*.pem' -o -name '*.key' "
                 "-o -name 'id_rsa' -o -name '.npmrc' -o -name '.pypirc' 2>/dev/null | head -20"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split("\n"):
                f_path = line.strip()
                if not f_path:
                    continue
                # Skip standard SSL certificate directories
                if any(f_path.startswith(safe) for safe in CERT_SAFE_DIRS):
                    continue
                self.findings.append(Finding(
                    "Secrets", "high", f"Sensitive file: {f_path}",
                    f"Potentially sensitive file found: {f_path}",
                    "Remove sensitive files or use multi-stage builds"
                ))
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        # Check layer history for leaked secrets
        for layer in self.image.history():
            created_by = layer.get("CreatedBy", "")
            for pattern, desc in SECRET_PATTERNS:
                if re.search(pattern, created_by):
                    self.findings.append(Finding(
                        "Secrets", "critical", f"Secret in layer: {desc}",
                        f"Found '{desc}' leaked in image build layer",
                        "Use --secret flag or multi-stage builds"
                    ))

    def scan_malware(self):
        """Check for malware signatures and suspicious binaries."""
        console.print("[bold]  [3/7] Scanning for malware...[/]")
        try:
            find_expr = " -o ".join([f"-name '{b}'" for b in MALWARE_BINARIES])
            cmd = f"find / -type f \\( {find_expr} \\) 2>/dev/null | head -10"
            result = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint", "", self.image_name, "sh", "-c", cmd],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    self.findings.append(Finding(
                        "Malware", "critical", f"Crypto miner: {line.strip()}",
                        f"Known cryptocurrency miner binary detected: {line.strip()}",
                        "Remove the binary and investigate its origin"
                    ))
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        # Check crontabs
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint", "", self.image_name,
                 "sh", "-c", "cat /etc/crontab /var/spool/cron/* /etc/cron.d/* 2>/dev/null"],
                capture_output=True, text=True, timeout=20
            )
            for pattern, desc in MALWARE_PATTERNS:
                if re.search(pattern, result.stdout):
                    self.findings.append(Finding(
                        "Malware", "critical", f"Suspicious cron: {desc}",
                        f"Suspicious pattern in crontab: {desc}",
                        "Review and remove unauthorized cron jobs"
                    ))
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        # Check layer history
        for layer in self.image.history():
            created_by = layer.get("CreatedBy", "")
            for pattern, desc in MALWARE_PATTERNS:
                if re.search(pattern, created_by):
                    self.findings.append(Finding(
                        "Malware", "high", f"Suspicious build cmd: {desc}",
                        f"Image layer contains: {desc}",
                        "Review Dockerfile and rebuild from trusted source"
                    ))

    def scan_misconfiguration(self):
        """Check for security misconfigurations."""
        console.print("[bold]  [4/7] Scanning for misconfigurations...[/]")
        config = self.inspect_data.get("Config", {})
        user = config.get("User", "")
        if not user or user == "root" or user == "0":
            self.findings.append(Finding(
                "Misconfiguration", "high", "Container runs as root",
                "No USER directive; container runs as root by default.",
                "Add USER directive: USER nonroot:nonroot"
            ))
        if not config.get("Healthcheck"):
            self.findings.append(Finding(
                "Misconfiguration", "medium", "No HEALTHCHECK defined",
                "Image has no HEALTHCHECK instruction.",
                "Add HEALTHCHECK instruction to Dockerfile"
            ))
        exposed_ports = config.get("ExposedPorts", {}) or {}
        for port_str in exposed_ports:
            match = re.search(r"\d+", port_str)
            if match:
                port_num = int(match.group())
                if port_num in SENSITIVE_PORTS:
                    self.findings.append(Finding(
                        "Misconfiguration", "medium",
                        f"Sensitive port exposed: {port_num}",
                        f"Port {port_num} is exposed and may pose security risks.",
                        f"Avoid exposing port {port_num} unless necessary"
                    ))
        layers = self.inspect_data.get("RootFS", {}).get("Layers", [])
        if len(layers) > MAX_LAYERS:
            self.findings.append(Finding(
                "Misconfiguration", "low", f"Excessive layers: {len(layers)}",
                f"Image has {len(layers)} layers (max recommended: {MAX_LAYERS}).",
                "Combine RUN commands and use multi-stage builds"
            ))
        size_mb = self.inspect_data.get("Size", 0) / (1024 * 1024)
        if size_mb > 1000:
            self.findings.append(Finding(
                "Misconfiguration", "low", f"Large image: {size_mb:.0f}MB",
                f"Image size is {size_mb:.0f}MB, increasing attack surface.",
                "Use slim/alpine base images and multi-stage builds"
            ))

    def scan_supply_chain(self):
        """Check supply chain security including tag mutation detection."""
        console.print("[bold]  [5/7] Scanning supply chain...[/]")
        repo_tags = self.inspect_data.get("RepoTags", []) or []
        repo_digests = self.inspect_data.get("RepoDigests", []) or []
        is_trusted = False
        for tag in repo_tags + repo_digests:
            for registry in TRUSTED_REGISTRIES:
                if registry in tag or "/" not in tag.split(":")[0]:
                    is_trusted = True
                    break
        if not is_trusted and repo_tags:
            self.findings.append(Finding(
                "Supply Chain", "medium", "Untrusted registry",
                "Image is from an unverified registry.",
                "Use images from: " + ", ".join(TRUSTED_REGISTRIES)
            ))
        if not repo_digests:
            self.findings.append(Finding(
                "Supply Chain", "medium", "No image digest/signature",
                "Image lacks a verified digest for tamper detection.",
                "Use signed images and Docker Content Trust"
            ))
        for tag in repo_tags:
            if tag.endswith(":latest"):
                self.findings.append(Finding(
                    "Supply Chain", "medium", "Using 'latest' tag",
                    "'latest' tag is mutable and can change unexpectedly.",
                    "Pin to specific version tags or SHA256 digests"
                ))
                break
        created = self.inspect_data.get("Created", "")
        if created:
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(created_dt.tzinfo) - created_dt).days
                if age_days > 90:
                    self.findings.append(Finding(
                        "Supply Chain", "low", f"Image is {age_days} days old",
                        f"Created {age_days} days ago; may lack recent patches.",
                        "Rebuild images regularly for security patches"
                    ))
            except (ValueError, TypeError):
                pass
        # Tag Mutation Detection - check if mutable tags were recently modified
        self._check_tag_mutation(repo_tags)

    def _check_tag_mutation(self, repo_tags):
        """Check Docker Hub for recently modified tags (tag mutation detection)."""
        if not requests:
            return
        mutable_tags = ["latest", "stable", "edge", "main", "master"]
        for full_tag in repo_tags:
            parts = full_tag.rsplit(":", 1)
            if len(parts) != 2:
                continue
            image_name, tag = parts
            if tag not in mutable_tags:
                continue
            # Normalize library images (e.g., "nginx" -> "library/nginx")
            if "/" not in image_name:
                image_name = f"library/{image_name}"
            url = f"https://hub.docker.com/v2/repositories/{image_name}/tags/{tag}"
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                last_updated = data.get("last_updated", "")
                if not last_updated:
                    continue
                updated_dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
                hours_ago = (datetime.now(timezone.utc) - updated_dt).total_seconds() / 3600
                if hours_ago < 24:
                    self.findings.append(Finding(
                        "Supply Chain", "high",
                        f"Recently modified image (:{tag})",
                        f"Image tag ':{tag}' was updated {hours_ago:.1f}h ago on Docker Hub. Possible tag poisoning.",
                        "Verify the update is legitimate or pin to a digest"
                    ))
            except Exception:
                pass

    def scan_digest_integrity(self):
        """Verify image digest against local trust store to detect tag poisoning."""
        console.print("[bold]  [6/7] Verifying digest integrity...[/]")
        try:
            # Get current image digest
            digests = self.inspect_data.get("RepoDigests", [])
            current_id = self.inspect_data.get("Id", "")
            digest_key = self.image_name
            current_digest = digests[0] if digests else current_id

            # Load trust store
            TRUST_STORE_DIR.mkdir(parents=True, exist_ok=True)
            trust_store = {}
            if TRUST_STORE_FILE.exists():
                trust_store = json.loads(TRUST_STORE_FILE.read_text(encoding="utf-8"))

            if digest_key in trust_store:
                if trust_store[digest_key] != current_digest:
                    self.findings.append(Finding(
                        "Digest Integrity", "critical",
                        "Image content changed since last scan!",
                        f"Previous: {trust_store[digest_key][:40]}... Current: {current_digest[:40]}...",
                        "Investigate if the image was legitimately updated or tag-poisoned"
                    ))
            # Save/update digest
            trust_store[digest_key] = current_digest
            TRUST_STORE_FILE.write_text(json.dumps(trust_store, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Digest integrity check limited: {e}")

    def scan_network_threats(self):
        """Detect network-related threats in the image."""
        console.print("[bold]  [7/7] Scanning for network threats...[/]")
        # Check for known malicious domains in image layers
        for layer in self.image.history():
            created_by = layer.get("CreatedBy", "")
            for domain in MALICIOUS_DOMAINS:
                if domain in created_by:
                    self.findings.append(Finding(
                        "Network Threat", "critical",
                        f"Mining pool domain: {domain}",
                        f"Known malicious domain found in build layer: {domain}",
                        "Remove the layer referencing this domain and rebuild"
                    ))
        # Check for curl/wget with suspicious URLs in layers
        for layer in self.image.history():
            created_by = layer.get("CreatedBy", "")
            if re.search(r"(curl|wget)\s+.*\.(sh|bin|exe|elf)", created_by):
                self.findings.append(Finding(
                    "Network Threat", "high",
                    "Suspicious download in build layer",
                    f"Layer downloads executable: {created_by[:100]}",
                    "Review the downloaded content and verify its source"
                ))
        # Check /etc/hosts and /etc/resolv.conf for suspicious entries
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "--entrypoint", "", self.image_name,
                 "sh", "-c", "cat /etc/hosts /etc/resolv.conf 2>/dev/null"],
                capture_output=True, text=True, timeout=15
            )
            for domain in MALICIOUS_DOMAINS:
                if domain in result.stdout:
                    self.findings.append(Finding(
                        "Network Threat", "critical",
                        f"Malicious DNS in config: {domain}",
                        f"Found '{domain}' in /etc/hosts or /etc/resolv.conf",
                        "Remove suspicious DNS entries from the image"
                    ))
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        # Brief container run with network=none to check outbound attempts
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "--network=none", "--entrypoint", "",
                 self.image_name, "sh", "-c",
                 "timeout 5 sh -c 'cat /etc/hosts' 2>&1 || true"],
                capture_output=True, text=True, timeout=15
            )
            for domain in MALICIOUS_DOMAINS:
                if domain in result.stdout:
                    self.findings.append(Finding(
                        "Network Threat", "critical",
                        f"Malicious host entry: {domain}",
                        f"Container has malicious domain in hosts file",
                        "Rebuild from a trusted base image"
                    ))
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass

    def _calculate_risk_score(self):
        """Calculate a 0-100 risk score based on findings."""
        score = 0
        for f in self.findings:
            if f.severity == "critical":
                score += 25
            elif f.severity == "high":
                score += 15
            elif f.severity == "medium":
                score += 8
            elif f.severity == "low":
                score += 3
        return min(score, 100)

    def _get_recommendation(self, score):
        """Return one-line recommendation based on risk score."""
        if score >= 75:
            return "DO NOT DEPLOY. Critical vulnerabilities require immediate remediation."
        elif score >= 50:
            return "High risk. Address critical/high findings before deployment."
        elif score >= 25:
            return "Moderate risk. Review and remediate medium+ findings."
        elif score > 0:
            return "Low risk. Minor improvements recommended."
        return "Image looks clean. No significant issues detected."

    def run_scan(self):
        """Execute all scans."""
        self.scan_start_time = time.time()
        self.pull_and_inspect()
        console.print(Panel(
            f"[bold green]DockerShield v{__version__}[/]\nScanning: {self.image_name}",
            box=box.DOUBLE
        ))
        self.scan_cve()
        self.scan_secrets()
        self.scan_malware()
        self.scan_misconfiguration()
        self.scan_supply_chain()
        self.scan_digest_integrity()
        self.scan_network_threats()
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_order.get(self.severity_filter, 3)
        self.findings = [f for f in self.findings if severity_order.get(f.severity, 3) <= threshold]
        return self.findings

    def get_exit_code(self):
        if any(f.severity == "critical" for f in self.findings):
            return 1
        if self.findings:
            return 2
        return 0

    def print_report(self):
        """Print colored terminal report with risk score and recommendations."""
        table = Table(title="Security Scan Results", box=box.ROUNDED, show_lines=True)
        table.add_column("Category", style="cyan", width=16)
        table.add_column("Severity", width=10)
        table.add_column("Finding", style="white")
        table.add_column("Remediation", style="dim")
        sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}
        for f in sorted(self.findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}[x.severity]):
            table.add_row(
                f.category,
                f"[{sev_style[f.severity]}]{f.severity.upper()}[/]",
                f.title,
                f.remediation
            )
        console.print(table)
        total = len(self.findings)
        crit = sum(1 for f in self.findings if f.severity == "critical")
        high = sum(1 for f in self.findings if f.severity == "high")
        med = sum(1 for f in self.findings if f.severity == "medium")
        low = sum(1 for f in self.findings if f.severity == "low")
        status = "[bold red]FAIL[/]" if crit else "[red]FAIL[/]" if high else "[yellow]WARN[/]" if med else "[bold green]PASS[/]"
        # Scan duration
        duration = time.time() - self.scan_start_time if self.scan_start_time else 0
        # Risk score
        risk_score = self._calculate_risk_score()
        recommendation = self._get_recommendation(risk_score)
        console.print(f"\n  Status: {status} | Total: {total} | Critical: {crit} High: {high} Medium: {med} Low: {low}")
        console.print(f"  Risk Score: [bold]{risk_score}/100[/] | Duration: {duration:.1f}s")
        console.print(f"  Recommendation: {recommendation}\n")
        # Block flag for CI/CD
        if self.block and (crit > 0 or high > 0):
            console.print("[bold red]  ██ DEPLOYMENT BLOCKED ██[/]")
            console.print("[red]  Critical/High findings detected. Pipeline should fail.[/]\n")

    def to_json(self):
        return json.dumps({
            "tool": "DockerShield", "version": __version__,
            "image": self.image_name, "scan_time": datetime.now().isoformat(),
            "summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "medium": sum(1 for f in self.findings if f.severity == "medium"),
                "low": sum(1 for f in self.findings if f.severity == "low"),
            },
            "findings": [f.to_dict() for f in self.findings],
        }, indent=2)

    def to_html(self):
        sev_color = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#0dcaf0"}
        rows = ""
        for f in self.findings:
            c = sev_color[f.severity]
            rows += f"<tr><td>{f.category}</td><td style='color:{c};font-weight:bold'>{f.severity.upper()}</td><td>{f.title}</td><td>{f.description}</td><td>{f.remediation}</td></tr>"
        crit = sum(1 for f in self.findings if f.severity == "critical")
        high = sum(1 for f in self.findings if f.severity == "high")
        med = sum(1 for f in self.findings if f.severity == "medium")
        low = sum(1 for f in self.findings if f.severity == "low")
        return (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            f"<title>DockerShield Report - {self.image_name}</title>"
            "<style>body{font-family:system-ui;margin:2rem;background:#1a1a2e;color:#eee}"
            "table{border-collapse:collapse;width:100%}th,td{border:1px solid #333;padding:8px;text-align:left}"
            "th{background:#16213e}tr:nth-child(even){background:#0f3460}h1{color:#4fc3f7}"
            ".badge{padding:4px 12px;border-radius:4px;font-weight:bold;margin-right:8px}</style>"
            f"</head><body><h1>&#128737; DockerShield Scan Report</h1>"
            f"<p>Image: <code>{self.image_name}</code> | Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
            f"<p><span class='badge' style='background:#dc3545'>Critical: {crit}</span>"
            f"<span class='badge' style='background:#fd7e14'>High: {high}</span>"
            f"<span class='badge' style='background:#ffc107;color:#000'>Medium: {med}</span>"
            f"<span class='badge' style='background:#0dcaf0;color:#000'>Low: {low}</span></p>"
            "<table><thead><tr><th>Category</th><th>Severity</th><th>Finding</th>"
            f"<th>Description</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table>"
            "</body></html>"
        )


def main():
    parser = argparse.ArgumentParser(
        prog="dockershield",
        description="DockerShield - Docker Image Security Scanner",
        epilog="Example: python dockershield.py nginx:latest --severity high --json"
    )
    parser.add_argument("image", help="Docker image to scan (e.g., nginx:latest)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--html", type=str, metavar="FILE", help="Generate HTML report")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"],
                        default="low", help="Minimum severity to report")
    parser.add_argument("--block", action="store_true",
                        help="Block deployment if critical/high findings exist (for CI/CD)")
    parser.add_argument("--version", action="version", version=f"DockerShield {__version__}")
    args = parser.parse_args()

    scanner = DockerShield(args.image, severity_filter=args.severity, block=args.block)
    scanner.run_scan()

    if args.json:
        print(scanner.to_json())
    elif args.html:
        Path(args.html).write_text(scanner.to_html(), encoding="utf-8")
        console.print(f"[green]HTML report saved to: {args.html}[/]")
        scanner.print_report()
    else:
        scanner.print_report()

    sys.exit(scanner.get_exit_code())


if __name__ == "__main__":
    main()
