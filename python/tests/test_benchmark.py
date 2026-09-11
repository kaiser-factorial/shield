"""
Detection benchmark — the honest catch rate of the pattern layer.
Mirrors test/benchmark.test.ts and reads the SAME corpus and floors, so the
two implementations cannot drift apart without one of them failing.

The floors are a FLOOR, not a target. Recall is deliberately well under 1.0:
the corpus includes translated, base64-encoded and purely paraphrased attacks
that no regex catches. That is the measurement working. To raise it, add a
detector (shield.detectors) — not a pattern that memorises the corpus.

    cd python && python3 -m unittest tests.test_benchmark -v
    SHIELD_CORPUS=/path/to.jsonl python3 -m unittest tests.test_benchmark
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

os.environ.setdefault("SHIELD_QUIET", "1")

from shield import detect_injection

_REPO = Path(__file__).resolve().parents[2]
_CORPUS = Path(os.environ.get("SHIELD_CORPUS") or _REPO / "bench" / "corpus.jsonl")
_BASELINE = json.loads((_REPO / "bench" / "baseline.json").read_text(encoding="utf-8"))

SAMPLES = [json.loads(line) for line in _CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]


def _score(rows):
    tp = fp = fn = tn = 0
    missed: dict[str, list[str]] = {}
    false_positives: list[dict] = []
    for s in rows:
        flagged = detect_injection(s["text"]).flagged
        if s["label"] == "attack":
            if flagged:
                tp += 1
            else:
                fn += 1
                missed.setdefault(s["family"], []).append(s["id"])
        elif flagged:
            fp += 1
            false_positives.append(s)
        else:
            tn += 1
    precision = 1.0 if tp + fp == 0 else tp / (tp + fp)
    recall = 1.0 if tp + fn == 0 else tp / (tp + fn)
    f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=precision, recall=recall, f1=f1,
                missed=missed, false_positives=false_positives)


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


class TestBenchmark(unittest.TestCase):
    def test_meets_committed_floor(self):
        m = _score(SAMPLES)
        print(f"\ndetection benchmark — {len(SAMPLES)} samples "
              f"({m['tp'] + m['fn']} attacks, {m['fp'] + m['tn']} benign)")
        print(f"  precision {_pct(m['precision'])}  (floor {_pct(_BASELINE['precision'])})   tp={m['tp']} fp={m['fp']}")
        print(f"  recall    {_pct(m['recall'])}  (floor {_pct(_BASELINE['recall'])})   fn={m['fn']} tn={m['tn']}")
        print(f"  f1        {_pct(m['f1'])}  (floor {_pct(_BASELINE['f1'])})")
        if m["missed"]:
            print("  missed attacks by family:")
            for family, ids in sorted(m["missed"].items()):
                print(f"    {family:<16} {len(ids)}  ({', '.join(ids)})")
        if m["false_positives"]:
            print("  false positives:")
            for s in m["false_positives"]:
                print(f"    {s['id']} [{s['family']}] {s['text'][:70]!r}")

        self.assertGreaterEqual(
            m["precision"], _BASELINE["precision"],
            f"precision {_pct(m['precision'])} fell below the floor — a change is flagging ordinary traffic")
        self.assertGreaterEqual(
            m["recall"], _BASELINE["recall"],
            f"recall {_pct(m['recall'])} fell below the floor — a change stopped catching attacks it used to catch")
        self.assertGreaterEqual(m["f1"], _BASELINE["f1"])

    def test_parity_with_typescript_corpus_shape(self):
        # Guards against "improving" the score by deleting the hard samples.
        attacks = [s for s in SAMPLES if s["label"] == "attack"]
        benign = [s for s in SAMPLES if s["label"] == "benign"]
        self.assertGreaterEqual(len(attacks), 50)
        self.assertGreaterEqual(len(benign), 40)
        self.assertGreaterEqual(len([s for s in SAMPLES if s["family"] == "hard"]), 15)
        self.assertGreaterEqual(len([s for s in attacks if s["family"] == "evasion"]), 5)
        self.assertEqual(len({s["id"] for s in SAMPLES}), len(SAMPLES))


if __name__ == "__main__":
    unittest.main()
