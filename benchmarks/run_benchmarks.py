"""CLI runner for VaultLineage real SQLite + KMS Envelope + Live Bedrock Nova benchmarks."""
from __future__ import annotations

import json
from pathlib import Path

from vault_lineage.benchmarks import run_vault_lineage_benchmarks


def main() -> None:
    results = run_vault_lineage_benchmarks(
        num_events=1200,
        live_bedrock=True,
        use_disk_sqlite=True,
    )
    out_path = Path(__file__).resolve().parent / "latest_results.json"
    out_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))
    print(f"\nSaved verified benchmark telemetry -> {out_path}")


if __name__ == "__main__":
    main()
