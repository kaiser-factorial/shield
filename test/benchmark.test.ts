/**
 * Detection benchmark — the honest catch rate of the pattern layer.
 *
 * Until this existed the weights were tuned by hand and "did that change help?"
 * had no answer. This scores `detectInjection` over bench/corpus.jsonl and
 * fails if precision or recall drops below the committed baseline, so a
 * pattern tweak that fixes one report and breaks five others cannot land
 * quietly.
 *
 * The baseline is a FLOOR, not a target. Recall is deliberately well under
 * 1.0: the corpus includes translated, base64-encoded and purely paraphrased
 * attacks that no regex catches. That is the measurement working. To raise
 * it, add a detector (see src/detectors.ts) — not a pattern that memorises
 * this file.
 *
 *   npm run bench                     # human-readable report
 *   SHIELD_CORPUS=/path/to.jsonl …    # measure against your own corpus
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { detectInjection } from "../src/shield.js";

interface Sample { id: string; label: "attack" | "benign"; family: string; text: string }

const repoUrl = (p: string) => fileURLToPath(new URL(`../../${p}`, import.meta.url));
const corpusPath = process.env["SHIELD_CORPUS"] ?? repoUrl("bench/corpus.jsonl");
const baseline = JSON.parse(readFileSync(repoUrl("bench/baseline.json"), "utf8")) as {
  precision: number; recall: number; f1: number; note?: string;
};

const samples: Sample[] = readFileSync(corpusPath, "utf8")
  .split("\n")
  .filter((l) => l.trim())
  .map((l) => JSON.parse(l) as Sample);

interface Metrics {
  tp: number; fp: number; fn: number; tn: number;
  precision: number; recall: number; f1: number;
  missedByFamily: Map<string, Sample[]>;
  falsePositives: Sample[];
}

function score(rows: Sample[]): Metrics {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  const missedByFamily = new Map<string, Sample[]>();
  const falsePositives: Sample[] = [];

  for (const s of rows) {
    const flagged = detectInjection(s.text).flagged;
    if (s.label === "attack") {
      if (flagged) tp++;
      else {
        fn++;
        const list = missedByFamily.get(s.family) ?? [];
        list.push(s);
        missedByFamily.set(s.family, list);
      }
    } else if (flagged) {
      fp++;
      falsePositives.push(s);
    } else tn++;
  }

  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { tp, fp, fn, tn, precision, recall, f1, missedByFamily, falsePositives };
}

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

test("benchmark: pattern layer meets the committed precision/recall floor", () => {
  const m = score(samples);

  const lines = [
    "",
    `detection benchmark — ${samples.length} samples (${m.tp + m.fn} attacks, ${m.fp + m.tn} benign)`,
    `  precision ${pct(m.precision)}  (floor ${pct(baseline.precision)})   tp=${m.tp} fp=${m.fp}`,
    `  recall    ${pct(m.recall)}  (floor ${pct(baseline.recall)})   fn=${m.fn} tn=${m.tn}`,
    `  f1        ${pct(m.f1)}  (floor ${pct(baseline.f1)})`,
  ];
  if (m.missedByFamily.size > 0) {
    lines.push("  missed attacks by family:");
    for (const [family, rows] of [...m.missedByFamily].sort()) {
      lines.push(`    ${family.padEnd(16)} ${rows.length}  (${rows.map((r) => r.id).join(", ")})`);
    }
  }
  if (m.falsePositives.length > 0) {
    lines.push("  false positives:");
    for (const s of m.falsePositives) lines.push(`    ${s.id} [${s.family}] ${JSON.stringify(s.text.slice(0, 70))}`);
  }
  console.log(lines.join("\n"));

  assert.ok(m.precision >= baseline.precision,
    `precision ${pct(m.precision)} fell below the ${pct(baseline.precision)} floor — a change is flagging ordinary traffic`);
  assert.ok(m.recall >= baseline.recall,
    `recall ${pct(m.recall)} fell below the ${pct(baseline.recall)} floor — a change stopped catching attacks it used to catch`);
  assert.ok(m.f1 >= baseline.f1, `f1 ${pct(m.f1)} fell below the ${pct(baseline.f1)} floor`);
});

test("benchmark: the corpus keeps its adversarial shape", () => {
  // A benchmark is only worth its floor if the corpus stays hard. These guard
  // against someone "improving" the score by deleting the samples that fail.
  const attacks = samples.filter((s) => s.label === "attack");
  const benign = samples.filter((s) => s.label === "benign");
  assert.ok(attacks.length >= 50, "keep at least 50 attack samples");
  assert.ok(benign.length >= 40, "keep at least 40 benign samples");
  assert.ok(samples.filter((s) => s.family === "hard").length >= 15,
    "keep at least 15 attack-shaped benign samples — they are what precision actually measures");
  assert.ok(attacks.filter((s) => s.family === "evasion").length >= 5,
    "keep the known-miss evasion samples — deleting them would inflate recall");
  assert.equal(new Set(samples.map((s) => s.id)).size, samples.length, "duplicate ids");
});
