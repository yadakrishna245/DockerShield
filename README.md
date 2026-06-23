# 🛡️ DockerShield

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?logo=docker)](https://docker.com)
[![Security](https://img.shields.io/badge/Security-Scanner-green?logo=shield)](https://github.com/yadakrishna245/DockerShield)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

**Stop vulnerable containers before they start.** DockerShield is a comprehensive Docker image security scanner that detects CVEs, leaked secrets, malware, misconfigurations, and supply chain risks — all from a single CLI command.

---

## ✨ Features

| Check | What it detects |
|-------|----------------|
| 🔍 **CVE Scan** | Known vulnerable packages (log4j, openssl, curl, glibc, etc.) |
| 🔑 **Secret Detection** | AWS keys, GitHub tokens, private keys, passwords in ENV/layers |
| 🦠 **Malware Signatures** | Crypto miners (xmrig, minerd), reverse shells, suspicious crons |
| ⚙️ **Misconfiguration** | Running as root, sensitive ports, no healthcheck, bloated images |
| 🔗 **Supply Chain** | Untrusted registries, unsigned images, stale builds, `latest` tag |

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

### With options

```bash
# JSON output
python dockershield.py myapp:v2.1 --json

# HTML report
python dockershield.py myapp:v2.1 --html report.html

# Filter by severity
python dockershield.py myapp:v2.1 --severity high
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
║ DockerShield v1.0.0                      ║
║ Scanning: nginx:latest                   ║
╚══════════════════════════════════════════╝
  [1/5] Scanning for CVEs...
  [2/5] Scanning for secrets...
  [3/5] Scanning for malware...
  [4/5] Scanning for misconfigurations...
  [5/5] Scanning supply chain...

╭──────────────────────────────────────────────────────────────────╮
│ Category         │ Severity │ Finding              │ Remediation │
├──────────────────┼──────────┼──────────────────────┼─────────────┤
│ CVE              │ CRITICAL │ CVE-2022-25235       │ Update pkg  │
│ Misconfiguration │ HIGH     │ Runs as root         │ Add USER    │
│ Supply Chain     │ MEDIUM   │ Using 'latest' tag   │ Pin version │
╰──────────────────────────────────────────────────────────────────╯

  Status: FAIL | Total: 3 | Critical: 1 High: 1 Medium: 1 Low: 0
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
