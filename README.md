# Malcontent Action

> [GitHub Action](https://github.com/features/actions) for [Malcontent](https://github.com/chainguard-dev/malcontent)

Run static malware diff scans between two directories using [Malcontent](https://github.com/chainguard-dev/malcontent) and fail the CI pipeline based on severity thresholds.

---

## Scenarios

- Fails the workflow (by default) if malware findings meet or exceed the configured `min-risk` level.
- Requires the caller to provide both `before-dir` and `after-dir`
  - Can be directories, docker images, or git checkouts see [Malcontent Diff](https://github.com/chainguard-dev/malcontent?tab=readme-ov-file#diff) for details
- Generates:
  - A human-readable Markdown Summary
  - A machine-readable [SARIF](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif#overview) report for ingestion into the [GitHub Code Scanning Engine](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning)

---

### Examples

#### Nonblocking, Produce GitHub Markdown Summary

```yaml
jobs:
  malware-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: chainguard-dev/malcontent-action@d3247e43f654c16ea49fcb5d11ff376f923e3035
        id: malcontent
        with:
          before-dir: ./before
          after-dir: ./after
          min-risk: high
          exit-code: 0
```
---

#### Enable with CodeQL Code Scanning 

```yaml
jobs:
  malware-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: chainguard-dev/malcontent-action@d3247e43f654c16ea49fcb5d11ff376f923e3035
        id: malcontent
        with:
          before-dir: ./before
          after-dir: ./after
          min-risk: high
          exit-code: 0
    
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@ce28f5bb42b7a9f2c824e633a3f6ee835bab6858 #v3.29.0 - 11 Jun 2025
        with:
          sarif_file: ${{ steps.malcontent.outputs.diff-sarif }}
          category: malcontent
```

---

### Usage

#### Inputs

| Name              | Required | Description                                                                                       | Default |
|-------------------|----------|---------------------------------------------------------------------------------------------------|---------|
| `malcontent-image`| false     | Fully qualified Malcontent image reference                                                       | `cgr.dev/chainguard/malcontent@sha256:fdfca44c401a5ca98af51292a821278644895bc1963f7a76a733d76647ff0ede` |
| `before-dir`      | true      | Baseline directory (`DIR1`). [See instructions](https://github.com/chainguard-dev/malcontent?tab=readme-ov-file#diff) | N/A     |
| `after-dir`       | true      | Target directory (`DIR2`). [See instructions](https://github.com/chainguard-dev/malcontent?tab=readme-ov-file#diff)   | N/A     |
| `min-risk`        | false     | Minimum severity that causes a CI failure. Options: `none`, `low`, `medium`, `high`, `critical`  | `high` |
| `exit-code`       | false     | Exit code to use when findings exceed the severity threshold                                     | `1`     |

---

#### Outputs

| Name             | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| `diff-markdown`  | Path to the generated Markdown report. **Fixed path:** `malcontent-diff.md` |
| `diff-sarif`     | Path to the generated SARIF report. **Fixed path:** `malcontent.sarif`       |

---

### Related

- [Malcontent GitHub repo](https://github.com/chainguard-dev/malcontent)
- [YARA rule definitions](https://github.com/chainguard-dev/malcontent/tree/main/rules)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning)
