# 🛡️ DockerShield

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?logo=docker)](https://docker.com)
[![Security](https://img.shields.io/badge/Security-Scanner-green?logo=shield)](https://github.com/yadakrishna245/DockerShield)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**Stop vulnerable containers before they start.** DockerShield is a comprehensive Docker image security scanner that detects CVEs, leaked secrets, malware, misconfigurations, and supply chain risks — all from a single CLI command.

---

## 🚀 v2.0 — Anti Tag-Poisoning Edition

### New in v2.0

| Feature | Description |
|---------|-------------|
| 🔒 **Digest Verification** | Detects tag poisoning by tracking SHA256 digests in a local trust store (`~/.dockershield/trusted_digests.json`). Alerts if image content changes between scans. |
| 🏷️ **Tag Mutation Detection** | Queries Docker Hub API to detect recently modified mutable tags (`:latest`, `:stable`). Flags images updated within 24 hours as potential attacks. |
| 🌐 **Network Threat Detection** | Scans for known mining pool domains, suspicious DNS entries, and curl/wget downloading executables in build layers. |
| 🩹 **SSL False Positive Fix** | Excludes `/etc/ssl/certs/` and `/usr/share/ca-certificates/` from secret file detection — no more false positives on standard certs. |
| 📊 **Risk Score (0-100)** | Aggregated risk score with one-line recommendation and scan duration. |
| 🚫 **`--block` Flag** | CI/CD gate: prints `DEPLOYMENT BLOCKED` in red and fails the pipeline if critical/high findings exist. |

---

## ✨ Features

| Check | What it detects |
|-------|----------------|
| 🔍 **CVE Scan** | Known vulnerable packages (log4j, openssl, curl, glibc, etc.) |
| 🔑 **Secret Detection** | AWS keys, GitHub tokens, private keys, passwords in ENV/layers |
| 🦠 **Malware Signatures** | Crypto miners (xmrig, minerd), reverse shells, suspicious crons |
| ⚙️ **Misconfiguration** | Running as root, sensitive ports, no healthcheck, bloated images |
| 🔗 **Supply Chain** | Untrusted registries, unsigned images, stale builds, `latest` tag, tag mutation |
| 🔒 **Digest Integrity** | Tag poisoning detection via SHA256 digest tracking across scans |
| 🌐 **Network Threats** | Mining pool domains, suspicious DNS, malicious downloads in layers |

---

## 🚀 Quick Start

### Install via pip

```bash
git clone https://github.com/yadakrishna245/DockerShield.git
cd DockerShield
pip install .
```

### Run directly

```bash
python dockershield.py nginx:latest
```

### 🐳 Docker Hub

```bash
# Pull from Docker Hub
docker pull krishna8688/dockershield:v2.0

# Run directly from Docker Hub (scan any image)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock krishna8688/dockershield:v2.0 nginx:latest

# With --block flag for CI/CD
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock krishna8688/dockershield:v2.0 myapp:latest --block
```

> **Docker Hub:** [hub.docker.com/r/krishna8688/dockershield](https://hub.docker.com/r/krishna8688/dockershield)

### With options

```bash
# JSON output
python dockershield.py myapp:v2.1 --json

# HTML report
python dockershield.py myapp:v2.1 --html report.html

# Filter by severity
python dockershield.py myapp:v2.1 --severity high

# CI/CD pipeline gate - blocks deployment on critical/high findings
python dockershield.py myapp:v2.1 --block
```

### Docker run

```bash
docker build -t dockershield .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock dockershield nginx:latest
```

### GitHub Action

```yaml
- uses: yadakrishna245/DockerShield@main
  with:
    image: "myapp:latest"
    severity: "medium"
    output-format: "json"
```

---

## 📋 Example Output

```
╔══════════════════════════════════════════╗
║ DockerShield v2.0.0                      ║
║ Scanning: nginx:latest                   ║
╚══════════════════════════════════════════╝
  [1/7] Scanning for CVEs...
  [2/7] Scanning for secrets...
  [3/7] Scanning for malware...
  [4/7] Scanning for misconfigurations...
  [5/7] Scanning supply chain...
  [6/7] Verifying digest integrity...
  [7/7] Scanning for network threats...

╭──────────────────────────────────────────────────────────────────╮
│ Category         │ Severity │ Finding              │ Remediation │
├──────────────────┼──────────┼──────────────────────┼─────────────┤
│ CVE              │ CRITICAL │ CVE-2022-25235       │ Update pkg  │
│ Misconfiguration │ HIGH     │ Runs as root         │ Add USER    │
│ Supply Chain     │ MEDIUM   │ Using 'latest' tag   │ Pin version │
╰──────────────────────────────────────────────────────────────────╯

  Status: FAIL | Total: 3 | Critical: 1 High: 1 Medium: 1 Low: 0
  Risk Score: 48/100 | Duration: 12.3s
  Recommendation: High risk. Address critical/high findings before deployment.
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  DockerShield CLI                 │
├─────────────────────────────────────────────────┤
│  Input: image name ──► Docker SDK (pull/inspect) │
│                                                   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐            │
│  │CVE Scan │ │ Secrets │ │ Malware │            │
│  └────┬────┘ └────┬────┘ └────┬────┘            │
│       │            │           │                  │
│  ┌────┴────┐ ┌────┴────┐                        │
│  │ Misconf │ │ Supply  │                        │
│  │  igure  │ │ Chain   │                        │
│  └────┬────┘ └────┬────┘                        │
│       │            │                              │
│       ▼            ▼                              │
│  ┌─────────────────────────┐                     │
│  │   Findings Aggregator   │                     │
│  └────────────┬────────────┘                     │
│               │                                   │
│     ┌─────────┼─────────┐                        │
│     ▼         ▼         ▼                        │
│  [Terminal] [JSON]   [HTML]                      │
└─────────────────────────────────────────────────┘
```

---

## 🔄 Comparison

| Feature | DockerShield | Trivy | Grype |
|---------|:---:|:---:|:---:|
| CVE Scanning | ✅ | ✅ | ✅ |
| Secret Detection | ✅ | ✅ | ❌ |
| Malware Detection | ✅ | ❌ | ❌ |
| Misconfiguration | ✅ | ✅ | ❌ |
| Supply Chain | ✅ | ⚠️ | ❌ |
| Single file tool | ✅ | ❌ | ❌ |
| GitHub Action | ✅ | ✅ | ✅ |
| HTML Reports | ✅ | ❌ | ❌ |
| Zero config | ✅ | ✅ | ✅ |
| Crypto miner detect | ✅ | ❌ | ❌ |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-check`
3. Commit changes: `git commit -m "Add amazing security check"`
4. Push: `git push origin feature/amazing-check`
5. Open a Pull Request

### Ideas for contributions:
- Add more CVE databases
- SBOM generation
- Policy-as-code (OPA integration)
- Slack/Teams notifications

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 👤 Author

**Krishna Chaithanya Yada**
- GitHub: [@yadakrishna245](https://github.com/yadakrishna245)

---

> 🛡️ *Secure your containers before they secure a foothold in your infrastructure.*
