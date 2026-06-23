from __future__ import annotations

import json

from toolfence.models import ScanReport


def report_to_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False) + "\n"

