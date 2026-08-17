# proofscan

A layered, target-agnostic application flaw scanner. Four layers ship today:

- **Layer 1 — deterministic static analysis** for authorisation, secret, CORS,
  rate-limit, input-validation and schema-drift defects, with per-scanner
  coverage reporting and a hash-chained audit log.
- **Layer 2 — AI-reasoning + sandboxed verification** for business-logic
  authorisation defects (a mutation that runs before the code checks who owns
  the resource). A candidate is not reported as real until a generated exploit
  has run against a sandboxed copy of the target and demonstrated impact.
- **Layer 3 — dynamic BOLA/IDOR fuzzer** for the same defect class from the
  outside: pointed at a *running* instance with no source access, it registers
  two synthetic identities and has one attack the other's resource, deciding by
  observable state change. This is the layer that sends live traffic to a real
  system, so it is gated on an authorisation record.
- **Layer 4 — remediation loop**: turns each verified finding into a ticket and
  a draft PR carrying the repro evidence, and — the part that matters —
  re-verifies a fix by re-running the exact exploit, flipping the finding to
  `fixed-verified` only when the attack no longer reproduces.

The name is the point. **A finding is `verified-exploitable` only when an
executed exploit changed another user's data** — Layer 2 in a sandbox, Layer 3
against the live target. Otherwise it stays `unverified-flagged`, and the tool
says which on every run. Nothing is promoted on a model's say-so.

**It is target-agnostic.** proofscan was first built against the
[FlaudeCode](https://github.com/DevAriwala2712/FlaudeCode) fixture, but nothing
about that app is hardcoded. Verification derives an *exploit plan* — the auth
flow, the resource shapes, the field names — from the target's own source
(Layer 2) or from a manifest/OpenAPI (Layer 3), so it works on any Express-style
app. This is proven by a second fixture that shares none of FlaudeCode's naming
(`/auth/signup` not `/api/register`, `username`/`passphrase` not
`email`/`password`, `/v1/bookmarks/:bookmarkId` not `/api/tasks/:id`): the tool
finds and verifies *its* IDOR with zero app-specific config — see
`npm run acceptance:agnostic`.

This is a command-line tool, so there is nothing deployed to link to.

![Terminal output of a proofscan run with Layer 2 enabled against the FlaudeCode
fixture. The scanner coverage block lists builtin, gitleaks and a heuristic
reasoner as having run. Finding 4 is a high-severity authorisation-ordering
defect in DELETE /api/tasks/:id at server.js:223, carrying a green "verified:"
line: identity B issued the delete against identity A's resource, received a 404,
yet a note belonging to A was destroyed — a cross-user mutation confirmed by
reading the victim's state back, not by the attacker's status code. Its status
reads verified-exploitable in green.](docs/img/proofscan-verify.svg)

The image is generated from the run's real emitted bytes by an ANSI-to-SVG
converter, so it cannot drift from what the tool actually prints.

## Running it

```bash
# Layer 1 only (static, fast, no network):
npm install && npm run build && node dist/cli.js scan --path ../some-repo

# Layers 1 + 2 (adds authorisation-ordering detection with sandboxed verification):
node dist/cli.js scan --path ../some-repo --layers static,ai-reasoning

# Layer 3 (dynamic fuzzer against a running instance; gated — see below):
node dist/cli.js scan --target my-app-staging --layers dynamic-fuzzer --authorized

# Layer 4 (remediation loop, after a scan with a store):
node dist/cli.js remediate --store ../some-repo          # ticket + draft PR per verified finding
node dist/cli.js reverify  --store ../some-repo --fix ../some-repo-fix-branch
```

The coverage block prints before the findings on purpose. See
[Why the coverage block exists](#why-the-coverage-block-exists).

## Why it exists

Static scanners are good at defects with a known shape and structurally blind to
defects that are only wrong in context. An endpoint that deletes a resource
before checking who owns it is syntactically unremarkable; no pattern matches it,
because the pattern *is* the ordering. That class — business-logic authorisation
flaws — is what the full design targets, and it is why verification matters:
a model can plausibly describe such a bug in code that does not have one, so a
finding is worth reporting only once an exploit has actually run.

Layer 1 is the cheap, high-confidence layer underneath that, and it is worth
building carefully because two failure modes are common in the tools that occupy
this space:

**Generic secret scanners miss hardcoded fallbacks.** They look for values shaped
like issued credentials — `AKIA…`, `sk_live_…`, high-entropy blobs. A fallback
like `process.env.JWT_SECRET || 'demo-jwt-secret-change-me'` has none of those
properties, and is the value the application signs tokens with whenever the
variable is unset. Measured on the FlaudeCode fixture:

| Scanner | Findings | Caught either fallback secret? |
|---|---|---|
| Gitleaks 8.30.1, full default ruleset | 0 | no |
| VibeCheck secret scanner, 21 patterns | 0 | no |
| `proofscan.hardcoded-fallback-secret` | 2 | yes, both |

**A scanner that did not run looks exactly like a clean result.** Trivy resolves
dependency versions from lockfiles. Point it at a project with `package.json` and
no lockfile and it returns no results — not an error, just nothing. Reported as
"0 dependency vulnerabilities", that is a lie by omission. The FlaudeCode fixture
is precisely this case.

## What it does

Four scanners, normalised into one findings list:

- **Built-in AST engine** — no external dependency, always runs. Six rules over
  JavaScript and TypeScript, built on the TypeScript compiler API. It models the
  Express route inventory: middleware chains, `app.use` mount paths, and
  registration order, since Express middleware is positional and middleware
  registered after a route does not protect it.
- **Semgrep** — the same five expressible rules as standalone `.yml` files, usable
  without proofscan. Runs when Semgrep is on `PATH`. When both engines fire on a
  line, the finding is reported once with `detected_by: ["builtin", "semgrep"]`.
- **Gitleaks** — issued-credential scanning. Detected secrets are **never written
  into the report**; only a four-character prefix, the length and Gitleaks' own
  fingerprint are kept.
- **Trivy** — dependency CVEs, with CVSS, CWE and fix availability surfaced as
  context. Severity remains the sort key; exploitability is never used to reorder.

The rules, their severity rationale, and their false-positive and
false-negative behaviour are documented per rule in [docs/RULES.md](docs/RULES.md).

### Layer 2: reasoning, then proof

Static rules are structurally blind to authorisation-ordering defects — an
endpoint that deletes a resource before checking who owns it is syntactically
unremarkable, because the *pattern is the ordering*. Layer 2 (`--layers
static,ai-reasoning`) is built for that class, in three steps:

1. **Mechanical inventory.** Before any model is consulted, an AST pass extracts
   every authenticated mutation handler and lists its operations — mutations,
   ownership checks, short-circuiting guards — in execution order. A handler is a
   *candidate* only when a request-driven mutation runs with no caller-scoped
   filter and no ownership check short-circuiting before it. On the FlaudeCode
   fixture this yields exactly one candidate: `DELETE /api/tasks/:id`.

2. **Scoped rubric, not open-ended review.** Each candidate gets one question:
   *does an ownership check execute and short-circuit before this mutation,
   scoped to the same resource identifier it touches?* A narrow rubric over code
   already located beats a "find the bugs" prompt that invites invention. Two
   backends answer it: `heuristic` (default — deterministic, no network,
   reproducible) and `anthropic` (`claude-opus-5`, schema-constrained, no tools
   exposed). Either way the verdict is a *candidate*.

3. **Mandatory verification.** A flagged candidate is not reported as real on the
   reasoner's word. proofscan stands up an **ephemeral sandboxed copy** of the
   target, registers two synthetic identities, has identity A create a resource,
   then has identity B attempt the flagged mutation against it — and decides the
   verdict by reading A's state back **as A**, before and after. Only a
   demonstrated cross-user state change promotes a finding to
   `verified-exploitable`; everything else stays `unverified-flagged`. The full
   request trail and before/after assertion are attached as evidence.

Why read-back rather than the attacker's response code: the flagship fixture bug
returns **404 to the attacker** while still destroying the victim's notes. A
verifier that trusted the status would call it not-exploitable and be exactly
wrong. Impact is a change in the victim's data, so that is what gets measured.

### Layer 3: the same bug, found from the outside

Layer 2 needs the source. Layer 3 (`--layers dynamic-fuzzer`) needs only a
**running instance** — it finds the same broken-object-level-authorisation class
against a staging deployment or any HTTP target you can reach, with no repo
access. It discovers routes from the target's OpenAPI document or a supplied
`dynamic.resources` manifest, registers two synthetic identities through the
target's own signup flow, and runs the same differential test: A creates, B
attacks, verdict by reading A's state back **as A**. Every dynamic finding is a
live demonstration, so it is `verified-exploitable` by construction. Full detail
in [docs/LAYER3.md](docs/LAYER3.md).

Two guarantees are enforced in the one module that touches the network, so they
hold for the whole layer: it **self-throttles** (minimum interval between
requests, exponential backoff honouring `Retry-After` on 429/503 — scanning
cannot become a DoS), and it **logs every request** — method, path, status,
timestamp — to the audit trail, so there is a complete record of what it did to
the running target.

Pointed at a live FlaudeCode instance with no source access, it independently
rediscovers the DELETE IDOR, catches the cross-user side effect despite the 404,
and does not false-positive the ownership-scoped PUT
([screenshot](docs/img/proofscan-dynamic.svg)).

### Why the coverage block exists

Every report states, per scanner, whether it `ran`, was `not_installed`, had
`no_input`, `failed`, or was `skipped` — with the reason. A findings list is only
meaningful next to what actually executed. `not_installed` and `no_input` are
distinct from a clean run, and both are distinct from each other: one means the
tool was absent, the other means the tool ran and had nothing it could analyse.

### The authorisation gate

Layer 3 creates test accounts against a **running, operator-supplied**
application and attempts cross-user access. That is the same activity as an
authorised penetration test, and the difference between authorised security
tooling and unauthorised access tooling is whether permission actually exists —
so it is enforced in code rather than documented as a warning.

A dynamic layer requires **both** a complete authorisation record for the target
in `targets.yaml` (`authorized_by`, `authorized_at`, `authorization_basis`, and a
`runtime_base_url`) **and** `--authorized` on the invocation. The record is the
durable evidence of who granted permission and on what basis; the flag is a
per-run confirmation of intent. Requiring both means an authorisation cannot be
conjured by a flag alone at the moment of the scan. A run without a record is
refused with an explanation.

Layer 2's verification does **not** go through this gate, and deliberately so:
it never touches the operator's running instance. It stands up its *own*
ephemeral copy of the source you already have on disk, exercises that, and tears
it down — closer to running the target's own test suite than to probing a live
system. Reading and running local source is not an intrusive act against a third
party. (Every request the sandbox makes is still written to the audit log, so
there is a full record of what Layer 2 did.)

### Audit log

Every run appends to a hash-chained, append-only log
(`<target>/.proofscan/audit.jsonl`): scan started, each finding recorded, scan
completed. Each entry's hash covers the previous entry's hash, so editing,
removing or reordering any entry breaks every hash after it.

```bash
node dist/cli.js audit verify --store ../some-repo
```

Both tamper modes are covered by tests and were confirmed by hand: an in-place
edit is reported as `entry_hash does not match its contents`, a deleted entry as
`an entry was removed, reordered, or inserted`.

## Verifying it yourself

```bash
npm test
```

102 tests. They cover each rule's positive cases, the mutation inventory's
ordering analysis, the exploit-plan **inference** against two differently-shaped
apps (proving the auth flow, resource shape and field names are derived, not
hardcoded), the dynamic layer's rate-limiter/backoff (with an injected clock)
and the shared differential-authorisation engine (including the 404-but-mutated
case, via a scripted client), the hash chain's tamper detection, the
authorisation gate's refusals, and the external adapters' parsers against **real
captured scanner output** rather than hand-written mocks — the Trivy fixture is
25 genuine CVEs from Trivy 0.73.0, and the Gitleaks parser is built against
verified 8.30.1 output.

The suite includes a **clean negative-control fixture**
(`test/fixtures/repo/clean/server.js`): the same application written correctly,
on which every rule must stay silent — and on which the Layer 2 inventory finds
no authorisation-ordering candidate. This is the half of a scanner's test suite
that usually gets skipped, and it is the half that determines whether the tool is
usable — a rule that fires on correct code produces false positives, which is how
scanners lose their audience.

Three acceptance checks run against the real fixture repository:

```bash
npm run acceptance          # Layer 1: each finding by rule, location, severity
npm run acceptance:phase2   # Layer 2: the ordering bug flips to verified-exploitable
npm run acceptance:phase3   # Layer 3: the same bug rediscovered live, no source access
npm run acceptance:agnostic # a second, differently-shaped app: found with zero config
npm run acceptance:phase4   # Layer 4: fix flips the finding to fixed-verified, gate holds
```

The Layer 1 check clones FlaudeCode and asserts each expected finding, and that
JWT-in-localStorage (outside the rule set) is absent. **Result: PASS**, 7
expectations, 14 findings. The Layer 2 check runs the full static + reasoning +
sandboxed-verification pipeline and asserts the notes-deletion ordering bug is
flagged, is `verified-exploitable`, carries a repro whose evidence records a
victim-side state change (not just a status code), and — the load-bearing
invariant — that **no finding is `verified-exploitable` without an accompanying
repro**. **Result: PASS**, 5 checks. The Layer 3 check boots the fixture as a
running instance, runs only the dynamic layer against its URL via a `runtime_url`
target (no source read), and asserts the DELETE IDOR is rediscovered live and
`verified-exploitable`, the side effect was caught despite the attacker's 404,
every request was logged to the audit trail, the gate refuses an unauthorised
run, and the ownership-scoped PUT is not false-positived. **Result: PASS**, 6
checks. The agnosticism check runs Layers 2 and 3 against the second (bookmarks)
fixture — which shares none of FlaudeCode's naming — and asserts both find and
verify *its* IDOR with no app-specific config, and neither false-positives the
ownership-scoped PATCH. **Result: PASS**, 5 checks. The Layer 4 check scans to a
verified finding, generates its ticket + draft PR (asserting both carry the
evidence and the reverify merge gate), re-verifies the *unfixed* source (still
reproduces — the control), applies the recommended ownership-check fix, and
re-verifies the fixed source (flips to `fixed-verified`, gate passes).
**Result: PASS**, 8 checks.

## Honest limits

**`verified-exploitable` means one specific thing.** A repro authenticated as a
second synthetic user, performed the flagged mutation against the first user's
resource, and the first user's stored data changed. It does not mean the finding
is exploitable in your production topology, against your real auth middleware, or
with your data. It means the ownership boundary failed in a faithful sandboxed
copy. Everything not carrying that status is `unverified-flagged` — triage input,
not confirmed impact.

**No finding carries a loss figure, and attaching one would be a category error.**
proofscan tells you an ownership boundary failed in a faithful copy of your
application. It does not tell you what that would cost, and it is not going to: a
published loss distribution describes what incidents cost across a population of
organisations, while a finding describes one weakness in one codebase. Multiplying
the two yields a number with a citation attached and no measurement behind it,
which is how risk-based prioritisation earns the reputation it has. Severity here
is a sort key for triage, never an input to a financial model. For what defensible
loss figures actually rest on — and how thin the evidence is even where it exists —
see [risk-benchmarks](https://github.com/RootCawsLLC/risk-benchmarks).

**What the output *is* evidence about.** In FAIR terms, a published loss study
fills exactly two nodes of the decomposition: Loss Event Frequency and Loss
Magnitude. Those are the only factors anyone measures across a population, which
is why a sourced benchmark can hand you a frequency and a per-event cost and
nothing else — the point
[fair-model-study](https://github.com/RootCawsLLC/fair-model-study) makes by loading a
real scenario onto the tree and lighting up two nodes of thirteen. The factors
underneath are the other half of the model, and Susceptibility and Resistance
Strength are exactly where an executed probe is the only real evidence there is: a
`verified-exploitable` finding says a specific control did not resist a specific
attack, and a probe that stops reproducing after a fix says it now does. No
dataset can hand you that. It has to be run.

**The verification sandbox is a local process, not a container.** The build spec
names Docker, and Docker is the right isolation boundary for running an arbitrary
untrusted target. proofscan ships a local-process sandbox instead because Docker
is not always present (it is not on the machine this was built on), and a
verification layer that only runs where Docker is installed cannot be
demonstrated at all. The local sandbox shares the host kernel and network
namespace and offers no real containment — treat it as a functional stand-in, run
Layer 2 only against targets you would run locally anyway, and prefer the Docker
provider once it lands. The authorisation gate and the "only authorised targets"
rule apply regardless of provider.

**Layer 2 verification is Node/Express-shaped.** The sandbox recognises a Node
target by its `package.json` and a conventional entry file, repairs native
dependencies for the current runtime, and drives a register → create → attack →
read-back exploit against a JSON/token API. A target it cannot confidently start,
or one whose auth/among/resource shape differs, yields no verification — the
finding stays a flagged candidate rather than being guessed at. Other stacks need
a Dockerfile or a supplied start command, which the Docker provider will take.

**The reasoner is a candidate generator, not an oracle.** The default `heuristic`
backend restates the mechanical ordering analysis and never claims more than
`medium` confidence. The `anthropic` backend can judge constructs the heuristic
cannot, but its verdict is still only a candidate — the sandbox is what turns
either one's guess into evidence. The model is given the handler source and the
operation list and nothing else: no tools, no filesystem, no network, no target
credentials.

**A safety classifier can decline to assess a handler.** The `anthropic` backend
asks a model to describe how to exploit a real authorisation bug, which sits near
the cyber-content boundary; a refusal is handled (server-side fallback, then a
preserved low-confidence candidate) rather than silently dropping the handler,
but it means the model backend is not guaranteed to assess every candidate. The
heuristic backend has no such limit.

**The built-in engine is JavaScript and TypeScript only.** Point it at a Python,
Go or Ruby service and the route, CORS, secret-fallback and validation rules
contribute nothing — the run reports that as a coverage note rather than
returning a clean result. Schema drift is text-based and covers `.sql` too.

**Express-style routing only.** Routes are recognised as
`<obj>.<method>('<path>', …)` with a string-literal path. Routes whose path is a
variable or a RegExp are missed. NestJS decorators, Fastify plugin registration,
Koa routers and framework-level guards are not modelled.

**Single-file analysis for middleware.** Authentication, rate limiting and
validation are recognised in the route's own chain or in an earlier `app.use` in
the same file. A gate applied in another module, at an API gateway, at a load
balancer or by a framework decorator is invisible, so those routes are reported
as unprotected. This is the largest source of false positives in a real
multi-file application, and the reason `missing-rate-limit-auth-route` states in
every finding that middleware from other modules is not visible to it.

**Handlers passed by reference are skipped.** `app.post('/x', createThing)` has no
inspectable body here, so body-dependent rules skip it rather than guess — a
deliberate false negative in preference to a fabricated finding.

**Semgrep and the built-in engine do not cover the same files.** Semgrep applies
its own default ignore list, which excludes test, fixture and vendor directories;
the built-in engine reads them. So Semgrep can report zero on code the built-in
rules flagged — measured on this repository, Semgrep examined 26 files where the
built-in engine parsed 32. proofscan emits a coverage-gap note whenever an
external scanner examined fewer files than the built-in engine, so the divergence
is visible instead of looking like a clean result. Secrets committed to test
fixtures are a common real leak, and this is exactly the blind spot that hides
them.

**Semgrep's TypeScript parser is not always ours.** Scanning this repository,
Semgrep reports a syntax error on one of proofscan's own source files that the
built-in engine parses without complaint. Parser failures are surfaced as
coverage notes rather than swallowed, but a file Semgrep cannot parse is a file
its rules did not examine.

**Scanning proofscan with proofscan reports 11 findings.** They come from
`test/fixtures/repo/vulnerable/`, which is deliberately vulnerable. That is
correct behaviour, not a defect in the tool or in its own source.

**No taint tracking or constant propagation.** `proofscan.hardcoded-fallback-secret`
matches the literal in place; a fallback assembled at a distance is missed. The
critical-versus-high split is decided by variable naming, not by tracing the value
to a signing call.

**KEV and EPSS are not fetched.** Trivy supplies neither. KEV status is applied
only from a local catalog passed with `--kev-catalog`, and when absent the finding
says KEV was not checked. EPSS is not implemented at all. No network calls are
made during a scan, so runs behave identically in CI and air-gapped.

**Reachability is not assessed.** A dependency finding means a vulnerable version
is present, not that your code calls the affected path.

**The audit chain detects tampering, not a full rewrite.** Anyone who can rewrite
the whole file can recompute a valid chain. Detecting that needs the head hash
anchored somewhere the attacker does not control — a signed commit, an append-only
bucket, a witness service. Not implemented; `audit verify` says so in its own
output rather than overstating what it proved.

**The store is JSON files, not Postgres.** The spec's Postgres schema — including
the `verification_runs` table Layer 2 populates — is modelled faithfully: field
names are snake_case throughout so the JSON shape and the eventual table shape
match 1:1. But persistence is `<target>/.proofscan/runs/*.json` for now.

**Layer 3 is Node/JSON-API shaped and doesn't crawl.** The dynamic fuzzer's
default auth flow is token-in-JSON-body; cookie sessions, multi-step login, MFA
and CSRF-token flows need pre-provisioned identities or are unsupported. It tests
only routes it discovers from OpenAPI or the manifest — it never crawls, and
reports what it tested rather than implying coverage it lacked. Side-effect
detection compares owner-readable state (collection presence, child-record
counts); a mutation with no owner-readable effect is caught only if the attack
itself returns 2xx.

**Layer 4 does not auto-apply patches, and its ticket sink is the filesystem.**
`remediate` writes a ticket + draft-PR body + Jira-shaped JSON to disk; a real
Jira/GitHub integration posts the same payload to an authenticated endpoint,
which needs a team's credentials and so isn't shipped. proofscan deliberately
does not auto-apply a source patch it cannot prove correct — it recommends the
fix and re-verifies whatever fix you write. The spec's scheduled re-scan / canary
is a scheduler around the existing commands (cron → `scan`/`reverify`), left as
an operational integration rather than shipped.

**`missing-input-validation-schema` is the noisiest rule.** In a codebase that
validates by hand throughout, it fires on every mutating route. Low-severity
instances are dropped by `--min-severity medium`.

## Documentation

| Document | Contents |
|---|---|
| [docs/OVERVIEW.md](docs/OVERVIEW.md) | Plain-language introduction: what proofscan is, what it does, and why "prove it" beats "flag it" — no security background needed |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The data flow end to end, as a diagram: target → static → reason + plan → exploit engine → verdict → remediation |
| [docs/TECH-STACK.md](docs/TECH-STACK.md) | The engineering: language, dependencies, how each layer maps to code, the exploit engine, the sandbox, and the AI integration |
| [docs/USE-CASES.md](docs/USE-CASES.md) | Playbooks: a one-off review of a vibe-coded app, running at enterprise scale, third-party/M&A due diligence, and confirming a reported vulnerability |
| [docs/RULES.md](docs/RULES.md) | Every rule: what it flags, severity rationale, known false positives and negatives |
| [docs/LAYER2.md](docs/LAYER2.md) | The reasoning + verification pipeline: inventory, rubric, sandbox, and how a finding earns `verified-exploitable` |
| [docs/LAYER3.md](docs/LAYER3.md) | The dynamic fuzzer: route discovery, synthetic identities, differential testing, rate limiting, and the authorisation gate |
| [docs/LAYER4.md](docs/LAYER4.md) | The remediation loop: ticket + draft-PR generation, and re-verifying a fix by re-running the exploit |
| [rules/semgrep/README.md](rules/semgrep/README.md) | The standalone Semgrep rules, validation results, and why the built-in engine is authoritative on severity |
| [targets.example.yaml](targets.example.yaml) | Target registry format, the authorisation fields, and the dynamic-layer config |

A [Layer 1-only run](docs/img/proofscan-scan.svg) shows the static output on its
own, for comparison with the Layer 2 run above.

## Test fixtures contain deliberately fake secrets

`test/fixtures/repo/vulnerable/` and `test/fixtures/repo/second-app/` contain
strings like `'demo-jwt-secret-change-me'` and `'placeholder-token-secret-change-me'`.
They are fabricated placeholders written for the test suite and authorise nothing
anywhere. A scanner needs positive cases to fire on; each fixture file says so in
a header comment.

## Attribution

- [FlaudeCode](https://github.com/DevAriwala2712/FlaudeCode) by Dev Ariwala is
  used as the validation fixture. It is not vendored — the acceptance check clones
  it. No code from it is included in this repository.
- [VibeCheck](https://github.com/Arun07AK/vibecheck) by Arun AK is prior art in
  this space and was used as a comparison baseline for the secret-scanner
  measurement above. No code from it is included here, and it is separately
  licensed.
- Scanners are invoked as external binaries and are not vendored or modified:
  [Semgrep](https://semgrep.dev), [Gitleaks](https://github.com/gitleaks/gitleaks),
  [Trivy](https://github.com/aquasecurity/trivy).
- CWE identifiers are from the [MITRE CWE](https://cwe.mitre.org) list. KEV refers
  to the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  catalog, read from a local file when supplied.

Mappings to CWE indicate the category a rule corresponds to. They are not a claim
of coverage of any framework, standard or certification.

## License

Copyright (c) 2026 RootCaws LLC.

[GNU AGPL v3 or later](LICENSE). If you modify this and run it as a network
service, the AGPL requires you to offer your users the modified source under the
same terms.

The AGPL covers this project's own code. The scanners proofscan invokes
(Semgrep, Gitleaks, Trivy) are separate projects under their own licences and are
neither vendored nor modified here.
