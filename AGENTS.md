# Agent notes — prompt-shield

## pnpm (converted from npm, 2026-09-18)

This git repo uses **pnpm**. Do not run `npm install` / `npm ci` here.

- Install: `pnpm install`
- Test / lint / bench: `pnpm test`, `pnpm lint`, `pnpm bench`
- Lockfile: `pnpm-lock.yaml`. `package-lock.json` is gitignored.
- `pnpm-workspace.yaml` is **not** a monorepo — it only holds `allowBuilds`.
- Published consumers still `npm install prompt-shield` from the registry. That is not this repo's installer.
- Sibling consumers (`../bulwork`, `../voicelogger-cli`) depend on `file:../shield` and are also pnpm now. `the-ledger` is pnpm; `ledger-cli` is Go.

If a module that resolved under npm is missing, declare it — do not enable `shamefully-hoist` unless there is no other option, and record that in `HANDOFF.md`.

Full project context: `HANDOFF.md`.
