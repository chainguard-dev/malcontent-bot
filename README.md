# Malcontent Action

> [GitHub Action](https://github.com/features/actions) for [Malcontent](https://github.com/chainguard-dev/malcontent)

## Usage

### Scan CI Pipeline

```yaml
    uses: ./action
    with:
      min-risk: high  # Options: low, medium, high, critical
```

### Inputs

| Name | Required | Description | Default |
|------|-------------|--------|
| `malcontent-image` | false | Fully qualified Malcontent image reference | `cgr.dev/chainguard/malcontent@sha256:fdfca44c401a5ca98af51292a821278644895bc1963f7a76a733d76647ff0ede` |
| `before-dir` | true | DIR1 baseline see https://github.com/chainguard-dev/malcontent?tab=readme-ov-file#diff  | N/A |
| `after-dir` | true | DIR2 see https://github.com/chainguard-dev/malcontent?tab=readme-ov-file#diff  | N/A |
| `min-risk` | false | Minimum risk level that causes a failure | low, medium, high, critical |
| `exit-code` | false | Exit code to use when findings exceed the minimum risk threshold | 1 |

### Outputs

| Name            | Description                                                                 |
| --------------- | --------------------------------------------------------------------------- |
| `diff-markdown` | Path to the generated Markdown report. **Fixed path:** `malcontent-diff.md` |
| `diff-sarif`    | Path to the generated SARIF report. **Fixed path:** `malcontent.sarif`      |

