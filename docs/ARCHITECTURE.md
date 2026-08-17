# proofscan — architecture and data flow

How a target moves through proofscan, from input to a proven (or unproven)
verdict. For the code behind each stage, see [TECH-STACK.md](TECH-STACK.md); for
the plain-language version, [OVERVIEW.md](OVERVIEW.md).

![proofscan data-flow diagram: a target (source repo or running app) enters Layer 1 static analysis, which produces a route inventory that feeds both a reasoner (heuristic or claude-opus-5) and plan inference (auth, resources, fields). Both feed a differential exploit engine that runs the real attack in a sandbox for Layer 2 or against a live target for Layer 3. The verdict is decided by reading the victim's data back rather than the attacker's 404, and splits into verified-exploitable (an exploit actually ran) or unverified-flagged (a signal, not proof). Only verified findings flow into Layer 4 remediation, which files a ticket and draft PR and re-runs the exploit on the fix as a merge gate.](img/proofscan-architecture.svg)

## How to read it

- **Straight down the middle is the "prove it" spine** (teal): everything
  converges on the *differential exploit engine*, which runs the real attack —
  in a throwaway **sandbox** for source-based runs (Layer 2) or against a **live
  instance** for source-less runs (Layer 3). Same engine, two entry points.

- **The verdict is the whole thesis.** It is decided by reading the *victim's*
  data back, not by the attacker's HTTP response — which is why the "404 but the
  data was still deleted" case does not fool it.

- **The split at the bottom is deliberate.** Only `verified-exploitable` (green —
  an exploit actually ran) flows into remediation. `unverified-flagged` is a
  terminal state: a real signal, but not proof, so it does not get the "proven"
  treatment. That asymmetry *is* the tool's honesty.

- **The dashed loop is the merge gate.** Layer 4 does not just file a ticket — it
  re-runs the exact exploit against the fix, so a fix only counts when the attack
  stops working.

## What the diagram compresses

Two cross-cutting concerns run alongside every stage above rather than at one
point in the flow:

- **Per-scanner coverage reporting.** Layer 1 records which scanners ran and
  which did not, so a tool that was never installed shows up as a gap instead of
  looking like a clean result.
- **A hash-chained, append-only audit log.** Every run — and every live request
  the dynamic layer makes against a real target — is written to a tamper-evident
  log under `.proofscan/`.

The diagram is authored by hand as a self-contained SVG (no external fonts,
scripts, or stylesheets) so it renders identically wherever this repo is read.
