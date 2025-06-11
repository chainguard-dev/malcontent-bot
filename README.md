# 🔬 ScanMalware GitHub Action

**Runs Chainguard's [Malcontent](https://github.com/chainguard-dev/malcontent) diff between the base commit and PR to detect and report potential malware.**

This composite GitHub Action compares two directories or Git commits, scans for malware risks, and fails the check if specified risk thresholds are exceeded.

---

## Basic Usage

```yaml
    uses: ./action
    with:
      min-risk: high  # Options: low, medium, high, critical
```

## Inputs / Outputs

### Inputs

| Name | Required | Description | Default |
|------|-------------|--------|
| `malcontent-image` | false | Fully qualified Malcontent image reference | `cgr.dev/chainguard/malcontent@sha256:fdfca44c401a5ca98af51292a821278644895bc1963f7a76a733d76647ff0ede` |
| `before-dir` | true | DIR1 baseline see https://github.com/chainguard-dev/malcontent?tab=readme-ov-file#diff  | N/A |
| `after-dir` | true | DIR2 see https://github.com/chainguard-dev/malcontent?tab=readme-ov-file#diff  | N/A |
| `min-risk` | false | Minimum risk level that causes a failure | low, medium, high, critical |

### Outputs

| Name | Description |
|------|-------------|
| `diff-markdown` | Path to the generated Malcontent Diff Report in Markdown |
