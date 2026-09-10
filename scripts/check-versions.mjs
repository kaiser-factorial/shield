#!/usr/bin/env node
// The TS and Python halves must ship the same version. Each side's own test
// pins its constant to its manifest; this pins the two manifests to each other
// (they drifted to 1.4.2 / 1.4.1 once without anything noticing).
import { readFileSync } from "node:fs";
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const py = readFileSync(new URL("../python/pyproject.toml", import.meta.url), "utf8").match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const core = readFileSync(new URL("../python/shield/core.py", import.meta.url), "utf8").match(/^SHIELD_VERSION\s*=\s*"([^"]+)"/m)?.[1];
if (pkg !== py || pkg !== core) {
  console.error(`version drift: package.json=${pkg} pyproject=${py} core.py=${core}`);
  process.exit(1);
}
console.log(`versions in sync: ${pkg}`);
