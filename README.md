# 🔬 ScanMalware GitHub Action

**Runs Chainguard's [Malcontent](https://github.com/chainguard-dev/malcontent) diff between the base commit and PR to detect and report potential malware.**

This composite GitHub Action compares two directories or Git commits, scans for malware risks, and fails the check if specified risk thresholds are exceeded.

---

## 🚀 Usage

```yaml
jobs:
  malware-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan PR with Malcontent
        id: scan
        uses: ./action
        with:
          min-risk: high  # Options: low, medium, high, critical

