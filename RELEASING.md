# Releasing prompt-shield

Both halves ship under the name **`prompt-shield`**: npm `prompt-shield`, PyPI
`prompt-shield`. The Python *import* stays `shield` — only the distribution
name changed, so no consumer's `from shield import ...` line moves.

Nothing has been published yet. Everything below has been rehearsed except the
two upload commands, which need your credentials.

## Before the first publish — decisions to confirm

1. **The licence.** `LICENSE` was added as MIT with `Copyright (c) 2026
   kaiser-factorial`, because publishing without a licence leaves users with no
   rights and every registry flags it. MIT is the conventional default for a
   library like this, but it was not your explicit choice — change the file, and
   the `license` fields in `package.json` and `python/pyproject.toml`, if you
   want something else. Once published under a licence, that version stays
   under it.
2. **Both names are unclaimed as of 2026-09-11** and unscoped npm names are
   first-come. If you want `prompt-shield`, claim it sooner rather than later;
   publishing `1.9.0` is what reserves it.
3. **npm two-factor.** If your account enforces 2FA for publishes, have the
   OTP ready — `npm publish` will prompt.

## Pre-flight (all of this must be green)

```bash
cd /path/to/shield

npm run lint                      # eslint, type-aware
npx tsc --noEmit                  # types
npm test                          # 146 tests + version-sync check
npm run bench                      # precision/recall vs the committed floor

cd python
ruff check shield                 # lint
mypy shield                       # types
python3 -m unittest discover -s tests    # 126 tests
cd ..
```

`npm test` already runs `check:versions`, which fails if `package.json`,
`python/pyproject.toml` and `python/shield/core.py` disagree. Bump all three
together, or it will stop you.

## Rehearse the package (do not skip — this is what caught the real bugs)

Testing from inside the repo proves nothing: relative paths resolve even when
the `exports` map is wrong, and Python finds the source tree on `sys.path` even
when a module is missing from the wheel. Both smoke tests deliberately run from
an install, outside the repo.

### npm

```bash
npm run build
npm pack                                  # → prompt-shield-<version>.tgz

mkdir -p /tmp/shield-consumer && cd /tmp/shield-consumer
npm init -y >/dev/null && npm pkg set type=module
npm install /path/to/shield/prompt-shield-<version>.tgz
node /path/to/shield/scripts/smoke-package.mjs      # expect 14/14 passed
cd - && rm -rf /tmp/shield-consumer
```

The smoke test exercises every advertised entry point: the root, `/anthropic`,
`/openai`, `/node`, `/shield`, and resolution of `/react` and `/browser`. It
also asserts that `/anthropic` does **not** re-export the OpenAI wrapper, since
a subpath that is secretly an alias for the root is not a narrowing.

Check the file list `npm pack` prints. It should carry `dist`, `src`, `bin`,
`README.md` and `LICENSE`, and nothing else — no tests, no `bench/`, no
`.github/`.

### PyPI

```bash
cd python
rm -rf dist build
python3 -m build                          # → dist/*.whl and dist/*.tar.gz

python3 -m venv /tmp/shield-venv
/tmp/shield-venv/bin/pip install dist/prompt_shield-<version>-py3-none-any.whl
cd /tmp && /tmp/shield-venv/bin/python /path/to/shield/scripts/smoke_package.py
                                          # expect 12/12 passed
cd - && rm -rf /tmp/shield-venv

python3 -m twine check dist/*             # metadata and README render
```

`python/README.md` is what PyPI shows, and it is a different document from the
root README, which is TypeScript-first. If you change one, decide whether the
other needs the same change.

## Publish

```bash
# npm — --access public is required for a first publish even unscoped
npm publish --access public

# PyPI — TestPyPI first if you want a dry run of the upload itself
cd python
python3 -m twine upload --repository testpypi dist/*     # optional
python3 -m twine upload dist/*
```

## After

```bash
git tag -a v<version> -m "v<version>" && git push origin v<version>

# Verify what the world actually gets, from a clean machine or container:
npm view prompt-shield version
pip download prompt-shield --no-deps -d /tmp/verify
```

Then update the consumers (bulwork, voicelogger-cli, group-chat) from their
`file:` / path installs to the published versions. `shield status` flags
anything still on an older build.

## Version policy

The two packages share one version number, enforced by `check:versions`. A
change to detection behaviour is a minor bump at least; the benchmark floor in
`bench/baseline.json` is the guard that says whether detection actually
changed. Raise the floor only when a change genuinely raises the measurement,
and never lower it to make a build pass.
