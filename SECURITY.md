# Security

## Reporting a vulnerability in proofscan

Open a [private security advisory](https://github.com/RootCawsLLC/proofscan/security/advisories/new)
rather than a public issue. Please include the version, the command you ran, and
what happened.

## Using proofscan responsibly

proofscan is security tooling.

**Layer 1** reads source files on disk and is not intrusive.

**Layer 2** (`--layers static,ai-reasoning`) registers test accounts and attempts
cross-user access — but against an **ephemeral copy of the source it stands up
itself**, never the operator's running instance. It is closer to running the
target's own test suite than to probing a live system, so it is not gated. Note
that the local-process sandbox provides no real isolation (see the README's
honest limits): run Layer 2 only against source you would run locally anyway.

**Layer 3** (`--layers dynamic-fuzzer`) sends live traffic to a running,
operator-supplied application, registers throwaway accounts, and attempts
cross-user access — the same activity as an authorised penetration test. **Only
run it against systems you are authorised to test.** The tool enforces this
rather than asking politely: it requires both a complete authorisation record for
the target in `targets.yaml` (`authorized_by`, `authorized_at`,
`authorization_basis`, `runtime_base_url`) and `--authorized` on the invocation.
Neither alone is sufficient, and a run without a record is refused. Layer 3 also
self-throttles (minimum request interval, backoff on 429/503) so scanning cannot
become a denial of service against the target.

Every request Layer 2's sandbox and Layer 3's fuzzer make is written to the
hash-chained audit log — the ephemeral sandbox as `verification.executed`, the
live fuzzer as `dynamic.requests` with the full ordered request trail — so there
is a complete record of what proofscan did to any target.

Every run appends to a hash-chained audit log under `<target>/.proofscan/`, so
there is a record of what the tool did. Verify it with
`proofscan audit verify --store <target>`.

## How proofscan handles secrets it finds

Detected credentials are never written into a report. Reports get committed,
attached to tickets and pasted into chat; echoing a secret would turn the report
into a second copy of the leak.

- Gitleaks findings carry a four-character prefix, the value's length, and
  Gitleaks' own fingerprint. The matched line is not included.
- Hardcoded fallback secrets have the literal replaced with
  `'<redacted: N chars>'`.

If proofscan reports a secret, treat it as compromised and **rotate it first**.
Deleting the value does not end the exposure: if it was ever pushed, it remains
retrievable from the object history, and on GitHub a force-pushed commit stays
fetchable by SHA until GitHub Support garbage-collects it.

## Deliberately vulnerable test fixtures

`test/fixtures/repo/vulnerable/` contains fabricated placeholder secrets and
insecure patterns. They exist so the rules have positive cases to fire on, they
authorise nothing anywhere, and each file says so in a header comment. Do not
copy them into anything real.

## What proofscan does not claim

Phase 1 findings are all `unverified-flagged`. No severity has been confirmed by
execution, dependency findings do not establish that vulnerable code is
reachable, and CWE mappings indicate category only — they are not a claim of
coverage of any framework, standard or certification.
