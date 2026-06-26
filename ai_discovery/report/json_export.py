from __future__ import annotations

import json
from pathlib import Path

from ai_discovery.models import ScanReport


def write_json(report: ScanReport, output_path: str) -> None:
    data = report.model_dump(mode="json")
    Path(output_path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def to_json_str(report: ScanReport) -> str:
    data = report.model_dump(mode="json")
    return json.dumps(data, indent=2, default=str)
