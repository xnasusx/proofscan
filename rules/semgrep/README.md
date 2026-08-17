# Semgrep rules

Five custom rules, as standalone `.yml` files so they can be used without
proofscan — `semgrep scan --config rules/semgrep .` works on its own, and the
files drop into an existing Semgrep setup or CI pipeline unchanged.

Validated against **Semgrep 1.172.0**. On the FlaudeCode fixture the set produces
8 findings and 0 rule errors:

| Rule | Fires on fixture |
|---|---|
| `proofscan.hardcoded-fallback-secret` | `server.js:13`, `server.js:14` |
| `proofscan.cors-credentials-reflected-origin` | `server.js:18` |
| `proofscan.unauthenticated-secret-exposure` | `server.js:72` |
| `proofscan.missing-input-validation-schema` | `server.js:76`, `server.js:101` |
| `proofscan.missing-rate-limit-auth-route` | `server.js:76`, `server.js:101` |

## Why the same rules exist twice

Each rule here is also implemented as an AST rule in the built-in engine
(`src/analyzers/builtin/rules/`). That is intentional, not duplication left by
accident:

- **The built-in engine has no external dependency.** proofscan produces its full
  Phase 1 finding set whether or not Semgrep is installed. A tool whose core
  detections evaporate when a binary is missing is not dependable, and the
  coverage block in every report states which engines actually ran.
- **These files are portable.** They are useful to someone who runs Semgrep and
  has no interest in proofscan.
- **When both fire, that is corroboration.** The finding is reported once with
  `detected_by: ["builtin", "semgrep"]`.

## The built-in engine is authoritative on severity

When the two engines disagree, the built-in rating wins. It is not a matter of
preference — the built-in engine has strictly more context:

- it resolves the route middleware chain, so it knows whether an auth gate applies;
- it respects `app.use` ordering, because Express middleware is positional;
- it evaluates details Semgrep patterns cannot express, such as whether an
  exposed secret is truncated before being returned — the difference between
  `medium` and `high` on `unauthenticated-secret-exposure`.

Taking the harsher of the two ratings would discard that and report the more
alarming number rather than the better-informed one.

## Two rules are approximations

`missing-rate-limit-auth-route` and `missing-input-validation-schema` carry
`approximation: true` in their metadata and `confidence: LOW`.

Semgrep matches one file at a time. It cannot see that `app.use(limiter)` ran
earlier in the composed application, cannot resolve middleware imported from
another module, and cannot respect mount order across files. Used standalone,
these two over-report. The Semgrep versions are also scoped more narrowly than
their built-in counterparts — to credential routes only — so that standalone use
stays tolerable; the built-in engine covers the full POST/PUT/PATCH surface with
graded severity.

The other three rules are precise enough to use standalone. In particular,
`unauthenticated-secret-exposure` matches the two-argument route form
(`app.get(path, handler)`), which is what establishes that no middleware runs —
and because credential-issuing routes are POSTs, a login endpoint returning
`token` is not matched.

## Semgrep does not read every file proofscan reads

Semgrep applies a default ignore list that excludes test, fixture and vendor
directories. `--no-git-ignore` does not override it. Pointed at this repository,
Semgrep examines 26 files while the built-in engine parses 32 — and pointed
directly at `test/fixtures/repo/vulnerable/`, which is full of deliberate
defects, it returns nothing at all, because the path itself matches the default
ignore patterns.

That matters for a security tool: credentials committed into test fixtures are a
common real leak, and this is the blind spot that conceals them. proofscan
therefore compares each external scanner's file count against the built-in
engine's and emits a coverage-gap note when they differ, so a zero from Semgrep
is never mistaken for a clean result. If you run these rules standalone and want
test directories covered, override the defaults with an empty `.semgrepignore`.

## What is not here

`proofscan.schema-drift` has no Semgrep equivalent. It compares `CREATE TABLE`
definitions across the whole repository, and Semgrep's per-file model cannot
express a cross-file comparison. It is built-in only.
