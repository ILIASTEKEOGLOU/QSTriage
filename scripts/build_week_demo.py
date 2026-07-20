from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEMO_SOURCE = REPOSITORY_ROOT / "examples" / "build-week"


def _run(arguments: list[str]) -> None:
    command = [sys.executable, "-m", "qstriage.cli", *arguments]
    print("+ " + " ".join(str(part) for part in command), flush=True)
    subprocess.run(command, cwd=REPOSITORY_ROOT, check=True)


def run_demo(output_dir: Path) -> None:
    destination = output_dir.resolve(strict=False)
    if destination.exists():
        raise ValueError(f"Output directory already exists: {destination}")
    if destination in {REPOSITORY_ROOT.resolve(), DEMO_SOURCE.resolve()}:
        raise ValueError("Output directory cannot be the repository root or demo source.")
    destination.mkdir(parents=True)

    imported = destination / "imported.yaml"
    gaps = destination / "gaps.json"
    approved_patch = destination / "approved.patch.yaml"
    enriched = destination / "enriched.yaml"
    comparison = destination / "comparison.json"

    _run(["import", "cbom", str(DEMO_SOURCE / "sample_cbom.json"), "--output", str(imported)])
    _run(["closure", "inspect", str(imported)])
    _run(["closure", "inspect", str(imported), "--format", "json", "--output", str(gaps)])
    print(f"+ copy {DEMO_SOURCE / 'approved_enrichment.patch.yaml'} {approved_patch}", flush=True)
    shutil.copyfile(DEMO_SOURCE / "approved_enrichment.patch.yaml", approved_patch)
    _run(["closure", "validate", str(imported), str(approved_patch)])
    _run(["closure", "apply", str(imported), str(approved_patch), "--output", str(enriched)])
    _run(["review", "evidence", str(imported)])
    _run(["review", "evidence", str(enriched)])
    _run(["closure", "compare", str(imported), str(enriched)])
    _run(["closure", "compare", str(imported), str(enriched), "--format", "json", "--output", str(comparison)])

    print("\nEvidence score: 0.00 -> 1.00")
    print("Confidence cap: 0.50 -> 1.00")
    print("Closed evidence gaps: 7")
    print("Action: migration_planning -> migration_planning")
    print("Execution: gated -> gated")
    print("\nThe enriched inventory is decision-grade for the supplied evidence.")
    print("The migration action remains gated and requires human verification.")
    print("This is not production authorization.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic Build Week demo.")
    parser.add_argument("--output-dir", type=Path, default=Path("build-week-demo-output"))
    arguments = parser.parse_args()
    try:
        run_demo(arguments.output_dir)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"Build Week demo failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
