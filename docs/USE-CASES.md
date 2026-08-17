# proofscan — use cases & playbooks

proofscan is a command-line engine, not a platform. It scans, proves, tickets,
and re-verifies — and it exits with a status code. Everything below is a playbook
for putting that engine to work, from an afternoon review to an org-wide program.

One honesty note runs through all of it: proofscan ships the **scan / remediate /
reverify** commands and nothing else. It has **no built-in scheduler, daemon,
dashboard, or multi-repo orchestrator.** Where a scenario needs those, it says so
and shows the wrapper you build around the CLI — because pretending the tool does
more than it does is exactly the failure mode this tool exists to avoid.

> Commands below are written as `proofscan …`. From a source checkout that is
> `node dist/cli.js …` (see [Running it](../README.md#running-it)). Exit codes:
> `0` clean (or below `--fail-on`), `1` a finding met `--fail-on` (or a fix still
> reproduces), `2` refused or failed to run.

---

## Use case 1 — the one-off review

**Scenario.** A colleague vibe-coded an internal app — a task tracker, an admin
panel, something like the [FlaudeCode](https://github.com/DevAriwala2712/FlaudeCode)
fixture — and asks you to "check it for issues" before it goes anywhere. You have
an afternoon.

### The workflow

**1. Establish scope first.** Do you have the source, a running instance, or
both? Is it yours/your employer's to test? For a colleague's internal app the
answer is usually yes — but write it down. (For anything you don't own, see
[Use case 3](#use-case-3--third-party-and-ma-due-diligence).)

**2. Start cheap — static only.** No network, no sandbox, seconds to run:

```bash
proofscan scan --path ./their-app --min-severity medium --json report.json
```

**Read the coverage block before the findings.** It tells you which scanners
actually ran. If Semgrep or Trivy shows `NOT INSTALLED` / `NOTHING TO SCAN`, that
is a *gap*, not a clean bill — the built-in AST rules still ran, but you know what
you didn't get.

**3. Escalate to proof.** Now let it actually try to exploit the
authorization-ordering bugs it suspects, in a throwaway sandbox:

```bash
proofscan scan --path ./their-app --layers static,ai-reasoning --min-severity medium
```

The `heuristic` reasoner is the default: deterministic, free, and it already
catches the common BOLA/IDOR shapes. Reach for `--reasoner anthropic` only when
you want the model to nominate candidates on unusual handler shapes the pattern
matcher can't recognise (needs the optional SDK and `ANTHROPIC_API_KEY`).

**4. (Optional) Exercise a running copy.** If they also handed you a running
instance and you want the outside-in view, see the dynamic layer in
[Use case 4](#use-case-4--confirming-a-reported-vulnerability).

### How to handle the findings

Triage on the one distinction that matters:

- **`verified-exploitable`** — proofscan logged in as two users, attacked one as
  the other, and *watched the victim's data change*. This is not a maybe. Treat
  it as a confirmed defect and fix it now. The report carries the exact request
  trail and the before/after victim state as evidence.
- **`unverified-flagged`** — a static or model signal that was **not** proven by
  execution. Real input to triage, but each rule states its assumptions (e.g.
  "middleware in another module is not visible to this rule") — confirm those
  against the actual app before you rate it.

Then **hand the work back in a form they can act on:**

```bash
proofscan remediate            # writes tickets + fix recommendations + a draft PR
proofscan reverify --fix ./their-app-fixed   # re-runs the exploit against their fix
```

`reverify` only flips a finding to `fixed-verified` when the exact exploit no
longer reproduces, and exits `1` if it still does. That is the difference between
"they changed some code" and "the bug is actually gone."

**What to say in the write-up.** Lead with the verified findings (facts), then the
flagged ones (triage), and — this is the part that signals judgment — state what
was *not* checked: scanners that didn't run, layers you didn't exercise, and that
"verified" means "in this setup," not "in their production config."

---

## Use case 2 — enterprise scale, (near-)autonomous

**Scenario.** You want proofscan watching every internal tool your org builds —
the growing pile of AI-generated apps especially — new and existing, with as
little human babysitting as possible.

**What "autonomous" honestly means here.** Discovery → verification → ticketing
can run completely unattended. Fixing cannot, by design: proofscan never merges a
patch it can't prove correct, so a human writes the fix and `reverify` gates the
merge. The ceiling is *autonomous detection and proof with a human in the fix
loop* — and that ceiling is deliberate.

Because the tool is a CLI, "scaling" means wiring that CLI into orchestration you
already run. Two triggers cover "new" and "existing":

### The registry is the source of truth

`targets.yaml` lists the fleet — one entry per app, each with its source location
or `runtime_base_url`, and (for anything dynamic) an authorization record
(`authorized_by`, `authorized_at`, `authorization_basis`). This registry is what
you template, generate from a service catalog, and review. See
[targets.example.yaml](../targets.example.yaml).

### Trigger A — pre-merge, event-driven (catches *new* code at creation)

A CI job on every pull request. This is where AI-generated tools get gated the
moment they're proposed:

```yaml
# .github/workflows/proofscan.yml  (illustrative — you own this file)
name: proofscan
on: pull_request
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build          # or install the published CLI
      - run: node dist/cli.js scan --path . --layers static,ai-reasoning --fail-on high --json proofscan.json
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}   # only if using --reasoner anthropic
      - uses: actions/upload-artifact@v4
        with: { name: proofscan-report, path: proofscan.json }
```

`--fail-on high` turns the exit code into a merge gate: any high-or-critical
finding fails the check. Pair it with a required-status-check branch rule, and no
tool ships past a proven authorization defect. When the fix PR arrives, a
`reverify` step is the gate that lets it merge.

### Trigger B — scheduled fleet sweep (catches *existing* tools and drift)

Nothing in proofscan schedules itself — the tool's own Layer 4 "scheduled
re-scans" are explicitly **not built**. You supply the scheduler (cron, a
Kubernetes `CronJob`, an Actions `schedule:` trigger) and loop the registry:

```bash
# nightly.sh  (illustrative — you own this)
for target in $(yq '.targets[].name' fleet.yaml); do
  proofscan scan --target "$target" --targets fleet.yaml \
    --layers static,ai-reasoning --json "reports/$target.json" || true
done
# ship reports/ to your SIEM / ticketing; alert on any verified-exploitable
```

This re-checks code you already shipped and re-runs dependency scanning (Trivy)
as CVEs land against pinned versions.

### The pieces that make it hold at scale

- **Execution substrate.** Run in ephemeral containerised runners. For the
  sandboxed verification layer, prefer the Docker sandbox path over the
  local-process fallback when you're standing up many untrusted apps in parallel
  — it's the isolation boundary you want around a fleet of vibe-coded code.
- **Cost control.** Default to the free deterministic `heuristic` reasoner across
  the fleet; spend `--reasoner anthropic` selectively — high-value services, or a
  periodic deeper pass — not on every PR. The AI is a candidate generator; the
  sandbox is the oracle either way.
- **Secrets.** `ANTHROPIC_API_KEY` comes from your platform's secrets manager,
  injected as an env var into the runner. It is never written to a file and never
  appears in a report (proofscan redacts secret excerpts).
- **Results pipeline.** `--json` output → normalise → dedupe by fingerprint →
  route `verified-exploitable` straight to an incident/ticket queue and
  `unverified-flagged` to a triage backlog. Don't page a human on a maybe.
- **Governance & the audit trail.** Static and sandboxed runs touch no production
  system, so they need no per-target authorisation. **Dynamic runs do** — they're
  gated on the registry's authorisation record plus `--authorized`, and every
  live request is written to a hash-chained, append-only audit log. That log is
  your retained, tamper-evident record of what the program touched and when.

---

## Use case 3 — third-party and M&A due diligence

**Scenario.** You're evaluating software you *don't own* — a SaaS vendor you're
about to depend on, or an acquisition target's application — and you need an
evidence-backed read on its security before you sign.

### The workflow

- **If you're given source** (an escrow copy, a data-room checkout): run it like
  [Use case 1](#use-case-1--the-one-off-review). Full layer coverage.
- **If you only get a running demo instance:** point the dynamic layer at it — no
  source required. This is exactly where the authorisation gate earns its keep,
  because you are testing someone else's system:

```bash
# targets.yaml entry: source_type runtime_url, runtime_base_url, a dynamic
# resource manifest, AND a written authorisation record.
proofscan scan --target vendor-demo --targets targets.yaml \
  --layers dynamic-fuzzer --authorized
```

proofscan **refuses** to run the dynamic layer unless the target carries
`authorized_by` / `authorized_at` / `authorization_basis` and you pass
`--authorized`. In a due-diligence context that isn't friction — it's the record
that you had permission, captured alongside the hash-chained log of every request
you made.

### The output

An evidence-backed memo for the deal team. A `verified-exploitable` cross-user
access finding is a hard fact you can put in front of the counterparty: fix it
before close, price it into the deal, or walk. It is worth far more than a
scanner's list of "potential" issues that the vendor can wave away.

**Honest limit.** No source means narrower coverage — you get the dynamic layer's
view of the routes you can discover, not the static and sandbox layers. Say that
plainly in the memo; a partial scan presented as complete is worse than no scan.

---

## Use case 4 — confirming a reported vulnerability

**Scenario.** A report lands — a bug-bounty submission, a pentest finding, a
scanner alert: "IDOR on `DELETE /api/tasks/:id`." Before you rate its severity,
open an incident, or argue about it, you want to know: **does it actually
reproduce, and does it actually cause harm?**

### Reproduce it, don't debate it

Point the dynamic layer at a staging instance (authorised, as in Use case 3) and
let the differential test settle it:

```bash
proofscan scan --target app-staging --targets targets.yaml \
  --layers dynamic-fuzzer --authorized
```

Because the verdict is the *victim's* state and not the attacker's HTTP status,
you get a straight yes/no on real impact — not a maybe. The infamous case where
the attacker receives a `404` while the victim's data is quietly destroyed is
precisely the one a status-code check gets wrong and this does not. That answer
feeds a defensible severity — or materiality — call, with evidence attached.

### Then close the loop

When the fix lands, prove it's actually fixed rather than trusting the diff:

```bash
proofscan reverify --fix ./app-with-fix
```

Only `fixed-verified` — the exact exploit no longer reproducing — closes the
finding; if it still reproduces, the command exits `1`. The audit log gives you a
contemporaneous, tamper-evident timeline of the whole episode, which is useful
well beyond engineering (incident records, materiality memos).

**Honest limit.** proofscan adjudicates the authorization-ordering / BOLA class it
models. A report outside that class — an XSS, an injection, a logic flaw it has no
rule for — it will not confirm or deny; use it for what it proves, not as a
universal oracle.

---

## At a glance

| Scenario | Layers used | Ships today | You build around it |
|---|---|---|---|
| 1 · One-off review | static → ai-reasoning → remediate/reverify | the whole flow | nothing |
| 2 · Enterprise scale | static → ai-reasoning (+ dynamic) per app | the scans, `--fail-on` gate, reverify gate, JSON output, audit log | scheduler, CI wiring, registry generation, results pipeline, dashboards |
| 3 · Due diligence | dynamic-fuzzer (or full, if source) | dynamic layer, authorisation gate, audit log | the authorisation record and the memo |
| 4 · Confirm a report | dynamic-fuzzer → reverify | reproduce + fix-gate + audit log | staging target + authorisation record |

The line between columns three and four is the whole point: proofscan gives you a
proof engine and an honest status code. The program you build on top is yours —
but every "verified" it emits is one you can stand behind.
