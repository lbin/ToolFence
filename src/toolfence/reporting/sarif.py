from __future__ import annotations

import json
from pathlib import Path

from toolfence.models import Finding, ScanReport


SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def report_to_sarif(report: ScanReport) -> str:
    rules = {}
    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.message},
            "help": {"text": finding.remediation or ""},
            "properties": {
                "category": finding.category,
                "severity": finding.severity,
                "confidence": finding.confidence,
            },
        }

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool["name"],
                        "version": report.tool["version"],
                        "informationUri": "https://github.com/toolfence/toolfence",
                        "rules": list(rules.values()),
                    }
                },
                "results": [_finding_to_result(finding) for finding in report.findings],
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


def _finding_to_result(finding: Finding) -> dict:
    result = {
        "ruleId": finding.rule_id,
        "level": SARIF_LEVELS[finding.severity],
        "message": {"text": finding.message},
        "properties": {
            "severity": finding.severity,
            "category": finding.category,
            "targetType": finding.target_type,
            "targetId": finding.target_id,
        },
    }
    if finding.evidence:
        path = finding.evidence.path
        region = {}
        if finding.evidence.line:
            region["startLine"] = finding.evidence.line
        if finding.evidence.snippet:
            region["snippet"] = {"text": finding.evidence.snippet}
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": Path(path).as_posix()},
                    "region": region,
                }
            }
        ]
    return result

