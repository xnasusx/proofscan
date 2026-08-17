# Layer 4 — remediation loop

Finding a bug and proving it (Layers 1–3) is half the job. Layer 4 is the other
half: turn a verified finding into something a team acts on, and — the part that
matters — **prove the fix actually closed it** before anyone merges.

Two commands, both operating on the stored report from a prior scan.

## `proofscan remediate`

For every `verified-exploitable` finding in the latest stored report, writes a
remediation package to `<target>/.proofscan/remediation/` (or `--out <dir>`):

- **`<KEY>.md`** — a human-readable ticket: what was found, the **reproduction
  evidence** (the request trail and the victim-side before/after state), a
  concrete fix recommendation, and the command to verify the fix.
- **`<KEY>.jira.json`** — the same content shaped as a Jira issue
  (`POST /rest/api/3/issue` fields: summary, description, issue type, labels,
  priority). A Jira integration is this object posted to that endpoint.
- **`<KEY>.pr.md`** — a draft pull-request body carrying the evidence and an
  explicit **merge gate**: do not merge until `proofscan reverify` reports the
  finding `fixed-verified`.

The recommendation is specific to the defect class. For authorisation-ordering /
BOLA it is: load the target resource scoped to the caller as the first step,
short-circuit before any mutation if the caller isn't the owner, and apply that
scoping to every statement including cascade deletes of child records — with the
explicit warning that returning 404 while the child rows are already gone is the
defect, not the fix.

**proofscan does not auto-apply a source patch.** A patch it cannot prove correct
is worse than a precise recommendation plus a verification gate. Generating the
patch is a good fit for the `anthropic` reasoner backend; re-verification is what
proves any patch, however it was written.

Why filesystem output rather than a live Jira/GitHub call: the ticket and PR are
the demonstrable, shippable artifact. A real integration is the same payload sent
to an authenticated endpoint — which would need a team's credentials and can't be
exercised in a portfolio without them. The sink is the seam; the content is done.

## `proofscan reverify --fix <checkout>`

The loop-closer, and the spec's Phase 4 acceptance: *re-run the pipeline against
the fix; the original repro must now fail before merge.*

It reuses the **same agnostic engine** that produced the finding, pointed at the
fixed source: infer the exploit plan from the fix, stand it up in a sandbox, run
the differential test, and check each previously `verified-exploitable` finding's
route. Then:

- exploit no longer reproduces → **`fixed-verified`**;
- exploit still reproduces → stays **`verified-exploitable`** (the fix is
  incomplete), and the command **exits 1** — the merge gate;
- fix couldn't be exercised (sandbox failed, or the route vanished) →
  **`fixed-unverified`** — the code changed but the loop could not confirm it,
  which is stated rather than assumed.

Because it re-runs the real exploit rather than re-reading the code, it cannot be
fooled by a change that looks like a fix but isn't. The Phase 4 acceptance proves
both directions: re-verifying against the *unfixed* source still reports the
exploit reproducing (so the check isn't vacuously passing), and only after the
ownership-check fix is applied does the finding flip to `fixed-verified`.

## Acceptance

`npm run acceptance:phase4` runs the whole loop against FlaudeCode: scan →
verified finding → generate ticket + PR (asserting they carry the evidence and
the merge gate) → re-verify unfixed (still vulnerable, the control) → apply the
recommended ownership-check fix → re-verify fixed (flips to `fixed-verified`, gate
passes).

## Not built

The spec's Layer 4 also lists **scheduled re-scans** — periodic dependency-CVE
re-checks of shipped code and a scheduled Layer 3 canary against staging. Those
are a scheduler wrapping the existing commands (cron → `proofscan scan` /
`reverify`), not new analysis, and are left as an operational integration rather
than shipped here.
