import json
import argparse

def main(file_in, file_out):
    # Loading ZAP report
    with open(file_in, 'r') as file:
        zap_data = json.load(file)

    # Initializing SARIF structure
    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OWASP ZAP",
                    "version": zap_data.get("@version", ""),
                    "informationUri": "https://www.zaproxy.org/",
                    "rules": []
                }
            },
            "results": []
        }]
    }

    # Dictionary to register unique rules
    rule_ids = {}

    # Processing each alert
    for site in zap_data.get("site", []):
        for alert in site.get("alerts", []):
            rule_id = f"ZAP-{alert['pluginid']}"
            if rule_id not in rule_ids:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": alert["name"],
                    "shortDescription": {"text": alert.get("alert", "")},
                    "fullDescription": {"text": alert.get("desc", "")},
                    "help": {"text": alert.get("solution", ""), "markdown": alert.get("solution", "")},
                    "properties": {
                        "tags": [alert.get("riskdesc", "")]
                    }
                })
                rule_ids[rule_id] = True

            for instance in alert.get("instances", []):
                sarif["runs"][0]["results"].append({
                    "ruleId": rule_id,
                    "level": "error" if alert["riskcode"] == "3" else "warning" if alert["riskcode"] == "2" else "note",
                    "message": {"text": alert.get("desc", "")},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": instance.get("uri", "")},
                        },
                        "logicalLocations": [{
                            "name": alert.get("name", ""),
                            "kind": "function"
                        }]
                    }],
                    "properties": {
                        "confidence": alert.get("confidence", ""),
                        "evidence": instance.get("evidence", ""),
                        "parameter": instance.get("param", ""),
                        "method": instance.get("method", "")
                    }
                })

    # Saving SARIF file
    with open(file_out, 'w') as sarif_file:
        json.dump(sarif, sarif_file, indent=2)

    print(f"SARIF report generated at {file_out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert ZAP JSON report to SARIF format.")
    parser.add_argument("file_in", help="Input ZAP JSON file")
    parser.add_argument("file_out", help="Output SARIF JSON file")
    args = parser.parse_args()
    main(args.file_in, args.file_out)