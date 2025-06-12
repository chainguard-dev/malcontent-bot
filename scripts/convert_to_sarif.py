import json
import argparse

# Risk level to SARIF level
def map_risk_to_level(risk):
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note"
    }.get(risk.upper(), "note")

# Risk level to SARIF security-severity
def map_risk_to_severity(risk):
    return {
        "CRITICAL": "9.0",
        "HIGH": "7.0",
        "MEDIUM": "5.0",
        "LOW": "3.0"
    }.get(risk.upper(), "3.0")

def create_help_markdown(description, match_strings):
    if not match_strings:
        return f"**Detected Behavior:** {description}"
    matches_md = "\n".join(f"- `{s}`" for s in match_strings)
    return f"**Detected Behavior:** {description}\n\n**Matched Strings:**\n{matches_md}"

def create_sarif_result(file_path, behavior, rule_id_prefix):
    description = behavior.get("Description", "No description provided")
    match_strings = behavior.get("MatchStrings", [])
    risk_level = behavior.get("RiskLevel", "MEDIUM")

    return {
        "ruleId": f"{rule_id_prefix}_{description.replace(' ', '_')[:50]}",
        "level": map_risk_to_level(risk_level),
        "message": {
            "text": description
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path
                    }
                }
            }
        ],
        "properties": {
            "tags": match_strings,
            "security-severity": map_risk_to_severity(risk_level)
        }
    }

def convert_malcontent_to_sarif(input_file, output_file, tool_name="malcontent", tool_version="0.1.0"):
    with open(input_file, "r") as f:
        data = json.load(f)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/chainguard-dev/malcontent",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    results = []
    rule_ids = set()
    modified_files = data.get("Diff", {}).get("Modified", {})

    for label, file_data in modified_files.items():
        file_path = file_data.get("Path", label)
        behaviors = file_data.get("Behaviors", [])
        file_risk_level = file_data.get("RiskLevel")

        # Include file-level risk if present
        if file_risk_level:
            rule_id = f"malcontent_file_risk_{file_risk_level.lower()}"
            description = f"File-level {file_risk_level} risk"
            if rule_id not in rule_ids:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": description,
                    "shortDescription": { "text": description },
                    "fullDescription": { "text": f"Overall risk detected in file: {file_path}" },
                    "help": {
                        "text": description,
                    },
                    "helpUri": "https://github.com/chainguard-dev/malcontent",
                    "properties": {
                        "tags": [],
                        "security-severity": map_risk_to_severity(file_risk_level)
                    }
                })
                rule_ids.add(rule_id)

            results.append({
                "ruleId": rule_id,
                "level": map_risk_to_level(file_risk_level),
                "message": { "text": description },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            }
                        }
                    }
                ],
                "properties": {
                    "tags": [],
                    "security-severity": map_risk_to_severity(file_risk_level)
                }
            })

        # Include behavior-level findings
        for behavior in behaviors:
            description = behavior.get("Description", "unknown")
            risk_level = behavior.get("RiskLevel", "MEDIUM")
            match_strings = behavior.get("MatchStrings", [])
            rule_id = f"malcontent_{description.replace(' ', '_')[:50]}"

            if rule_id not in rule_ids:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": description,
                    "shortDescription": {
                        "text": description
                    },
                    "fullDescription": {
                        "text": f"Behavior detected: {description}"
                    },
                    "help": {
                        "text": description,
                    },
                    "helpUri": "https://github.com/chainguard-dev/malcontent",
                    "properties": {
                        "tags": match_strings,
                        "security-severity": map_risk_to_severity(risk_level)
                    }
                })
                rule_ids.add(rule_id)

            result = create_sarif_result(file_path, behavior, "malcontent")
            results.append(result)

    sarif["runs"][0]["results"] = results

    with open(output_file, "w") as f:
        json.dump(sarif, f, indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Malcontent JSON to SARIF")
    parser.add_argument("--input", required=True, help="Path to malcontent-diff.json")
    parser.add_argument("--output", required=True, help="Path to write sarif file")
    parser.add_argument("--tool-name", default="malcontent", help="Name of the scanning tool")
    parser.add_argument("--tool-version", default="0.1.0", help="Version of the scanning tool")

    args = parser.parse_args()
    convert_malcontent_to_sarif(args.input, args.output, args.tool_name, args.tool_version)
