# proofscan — tech stack for the curious

A technical walkthrough for someone who would actually read the source. For the
non-technical version see [OVERVIEW.md](OVERVIEW.md); for the data-flow picture
see [ARCHITECTURE.md](ARCHITECTURE.md).

## Shape at a glance

- **Language:** TypeScript, strict, compiled with plain `tsc` to `dist/` — no
  bundler, no transpiler tricks.
- **Runtime:** Node.js ESM, `"type": "module"`, NodeNext resolution (source
  imports carry `.js` extensions). Targets Node ≥20; runs on 24.
- **Form factor:** a CLI (`bin: proofscan → dist/cli.js`). Arg parsing is
  hand-rolled in [../src/cli.ts](../src/cli.ts) — no `commander`/`yargs`, on
  purpose (see deps).

## Dependencies — deliberately tiny

Three runtime deps: **`picocolors`** (ANSI), **`yaml`** (parse `targets.yaml`),
and — the one that surprises people — **`typescript` as a *runtime* dependency,
not just dev.** The static analyzer uses the **TypeScript Compiler API**
(`ts.createSourceFile` + AST walks) to parse the *target's* JS/TS and reason
about it structurally, so the compiler ships as a library. `@anthropic-ai/sdk`
sits in `optionalDependencies` and is `import()`-ed lazily; absent it, the tool
degrades to the deterministic path. For a security tool, keeping the dependency
graph this small is a supply-chain decision, not an aesthetic one.

## The layered architecture, mapped to code

Everything is orchestrated by [../src/core/scan.ts](../src/core/scan.ts), which
runs whichever layers you asked for:

- **Layer 1 — static** ([../src/analyzers/](../src/analyzers/)): built-in AST
  rules over the compiler API — it builds an Express route inventory, then flags
  authorization-ordering candidates, hardcoded fallback secrets, reflected-origin
  CORS, schema drift, missing validation/rate-limiting. It *also* shells out to
  Semgrep (custom `.yml` rules), Gitleaks, and Trivy and normalizes their output
  into one `Finding` shape, with **per-scanner coverage reporting** — a scanner
  that didn't run is reported as a gap, not a pass.

- **Layer 2 — reason + prove**: a `Reasoner` abstraction
  ([../src/analyzers/reasoning/](../src/analyzers/reasoning/)) with two backends —
  `heuristic` (deterministic AST ordering analysis) or `anthropic`
  (claude-opus-5). Whatever it nominates is only a *candidate*. Truth comes from
  [../src/verify/](../src/verify/): an ephemeral sandbox stands up the real app
  and runs an exploit.

- **Layer 3 — dynamic** ([../src/dynamic/](../src/dynamic/)): same exploit
  engine, but against a *running* instance over HTTP with no source access.
  Routes come from OpenAPI or a manifest.

- **Layer 4 — remediation** ([../src/remediate/](../src/remediate/)): emits a
  Markdown ticket + Jira-shaped JSON + draft PR, and `reverify` re-runs the
  exploit against a fix.

## The interesting bits

**The shared exploit engine ([../src/exploit/](../src/exploit/)) is the spine.**
`plan.ts` defines abstractions — `AuthPlan`, `ResourcePlan`, `ExploitPlan` — and
`infer.ts` *derives* that plan from the static inventory (or an
OpenAPI/manifest). That inference is what makes the tool target-agnostic: Layers
2 and 3 run the *same* `engine.ts` against a plan, so it isn't hardcoded to one
app. The verdict function is the whole thesis in code: `establishIdentities` →
two synthetic users → `testResource` reads the **victim's** state before and
after and diffs it. The attacker's HTTP status is deliberately ignored (the
flagship bug returns 404 while destroying data).

**The sandbox ([../src/verify/sandbox.ts](../src/verify/sandbox.ts))** is a
local-process provisioner (Docker is the documented intended default; it falls
back to processes where Docker isn't present). It copies the target, does
`npm install` with native-dep repair (e.g. rebuilding `better-sqlite3` against
the local Node ABI), *discovers secret-shaped `process.env.X` reads and injects
ephemeral values*, boots the server, waits for readiness, and tears down. There
is real Windows-spawn handling in [../src/core/exec.ts](../src/core/exec.ts) —
`.cmd` shims routed through `cmd.exe /c` because Node 24 rejects `.cmd` under
`shell:false`.

**The AI integration is deliberately constrained.** The `anthropic` backend uses
schema-constrained structured output and adaptive thinking, handles the
`refusal` stop reason, and — importantly — **exposes no tools to the model.**
It's a pure judgment call feeding the sandbox. The design rule is explicit in the
code: *the reasoner is a candidate generator, never an oracle.* A machine has to
actually run the exploit for anything to reach `verified-exploitable`.

**Persistence** is a `FileStore` ([../src/core/store.ts](../src/core/store.ts))
writing JSON under `.proofscan/` — runs, reports, and a **hash-chained
append-only audit log** so the dynamic layer's live requests against real targets
are tamper-evident.

## Testing

`vitest`, 102 unit tests, plus end-to-end acceptance harnesses
([../test/acceptance/](../test/acceptance/)) that clone the real vulnerable
fixture and run the full pipeline — including one against a *second,
differently-shaped* app to prove the agnosticism claim isn't just an assertion.

## Honest rough edges

Semgrep has no native Windows build (OCaml core), so on Windows it reports NOT
INSTALLED and the built-in AST rules carry that load. The local-process sandbox
is weaker isolation than the intended container path. And "verified" means *this
exploit worked in this provisioned setup* — sound, but not a claim about your
production config.
