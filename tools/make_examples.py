"""Write example reports for every corpus device into examples/ (reports only, no dumps).

Usage: python -m tools.make_examples
Uses a fixed analysis time so the committed examples are reproducible.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from flashtrace.bench import keys_for_device as bench_keys
from flashtrace.bench import markdown_table, run_bench
from flashtrace.commands import write_reports
from flashtrace.diff import diff_dumps
from flashtrace.pipeline import analyze, load_baselines
from flashtrace.report.model import diff_dict, result_dict
from tools.corpus.generate import generate

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "examples"
FIXED_TIME = "2026-01-01T00:00:00+00:00"


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        corpus = Path(tmp) / "corpus"
        generate(corpus, use_esptool=False)
        if OUT.exists():
            shutil.rmtree(OUT)
        OUT.mkdir()
        for dev in sorted(p for p in corpus.iterdir() if p.is_dir()):
            gt = json.loads((dev / "ground_truth.json").read_text())
            base = load_baselines(dev / b for b in gt["baselines"])
            r = analyze(
                (dev / "dump.bin").read_bytes(),
                baselines=base,
                analysed_at=FIXED_TIME,
                keys=bench_keys(dev, gt),
                sb_public_key=(dev / gt["sb_pubkey"]).read_bytes() if gt.get("sb_pubkey") else None,
            )
            write_reports(result_dict(r), OUT / dev.name, ["json", "md", "html"], "report")
            (OUT / dev.name / "ground_truth.json").write_text(json.dumps(gt, indent=2) + "\n")
        d = diff_dumps(
            (corpus / "clean_control" / "dump.bin").read_bytes(),
            (corpus / "forced_rollback" / "dump.bin").read_bytes(),
        )
        write_reports(
            diff_dict(d), OUT / "diff_clean_vs_forced_rollback", ["json", "md", "html"], "diff"
        )
        bench = run_bench(corpus).as_dict()
        (OUT / "bench_results.json").write_text(json.dumps(bench, indent=2) + "\n")
        (OUT / "bench_results.md").write_text(markdown_table(bench))
    print(f"examples written to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
