# Layer 2 — AI reasoning + sandboxed verification

Layer 1 finds defects with a known shape. Layer 2 finds the one that has no
shape: a database mutation that runs before the code confirms the caller owns the
resource. That defect is invisible to a pattern scanner because *the pattern is
the ordering* — the same statements in a different order are correct.

Run it with `--layers static,ai-reasoning`. It has three stages, and the third is
the one the project is named for.

```
source ──▶ 1. mechanical inventory ──▶ candidates
                                          │
                       2. scoped rubric (heuristic | anthropic)
                                          │
                                       flagged (unverified)
                                          │
                       3. sandboxed exploit ── read victim state back
                                          │
                    verified-exploitable  or  unverified-flagged
```

## 1. Mechanical inventory (no model involved)

`src/analyzers/reasoning/inventory.ts` runs first, before anything is sent to a
model. For each authenticated route handler it extracts an ordered list of
operations — database mutations, caller-scoped ownership checks, and
short-circuiting 4xx guards — in source order, which for a synchronous Express
handler is execution order. It does a shallow taint pass to know which values
came from request input (`req.params`/`body`/`query`) and which from the
authenticated caller (`req.user`).

A handler becomes a **candidate** only when all of these hold:

- it is authenticated (an unauthenticated route has no caller to compare against;
  cross-user access is not the applicable question, and Layer 1 covers those);
- it performs a mutation driven by request input;
- that mutation is **not** already constrained to the caller in its own filter;
- **no** caller-scoped ownership check short-circuits before it;
- the mutation is not a create (an `INSERT` of a new row has no prior owner).

On the FlaudeCode fixture this produces exactly one candidate,
`DELETE /api/tasks/:id`, and correctly excludes `PUT /api/tasks/:id` (whose
update is scoped to `user_id`) and `POST /api/tasks` (a create). The point of
doing this mechanically is cost and honesty: the model is never asked to *find*
handlers, only to judge ordering in handlers already located, and every candidate
arrives with the ordered facts attached.

## 2. Scoped rubric

Each candidate gets exactly one question (`src/analyzers/reasoning/rubric.ts`):

> Does an authorisation/ownership check execute and short-circuit before this
> mutation runs, scoped to the same resource identifier the mutation touches? If
> not, flag it and explain what a caller would need to do to exploit it.

A narrow rubric over pre-located code beats an open "find the bugs" prompt, which
invites a model to invent plausible findings across the whole file. Two backends
answer it, selected with `--reasoner`:

| Backend | What it is | Confidence ceiling |
|---|---|---|
| `heuristic` (default) | Deterministic restatement of the ordering analysis. No model, no network, reproducible — the right choice for CI and for reproducing a run later. | `medium` (it can only see what the inventory extracted) |
| `anthropic` | `claude-opus-5`, schema-constrained answer, **no tools exposed**. Can judge unusual constructs the heuristic cannot. | `high` |

The `anthropic` backend's guardrails matter: the model is handed the handler
source and the operation list and nothing else — it cannot read files, run
commands, or reach the network; the answer is constrained to a JSON schema, not
parsed out of prose; the system prompt is byte-stable across candidates so it
caches; and no target credential ever enters a prompt. Because the prompt asks a
model to describe exploiting a real authorisation bug, a safety classifier can
decline (`stop_reason: "refusal"`). That is handled — server-side fallback first,
then the candidate is preserved as a low-confidence finding — never silently
dropped.

**Either backend's verdict is a candidate, not a conclusion.** A model can
describe this bug convincingly in code that does not have it. So nothing a
reasoner says is reported as real.

## 2a. The exploit plan is inferred, not hardcoded

Before verification runs, `src/exploit/infer.ts` derives an **exploit plan** from
the same route inventory: how the target authenticates (register/login paths,
the credential field names each handler reads, the token field it returns) and
what to attack (each id-parameterised resource, its create endpoint, the fields
that create expects, and any child collection). Nothing about a particular app
is baked in — FlaudeCode's `/api/register` + `{email, password}` + `token` and a
different app's `/auth/signup` + `{username, passphrase}` + `accessToken` are
both reconstructed from source. The operator's `dynamic` config overlays the
inferred plan (`mergeConfig`) for anything the inference misreads. This same plan
model feeds Layer 3, so both verifying layers share one engine
(`src/exploit/engine.ts`).

## 3. Sandboxed verification — where a candidate earns its status

`src/verify/` stands up an **ephemeral copy** of the target
(`src/verify/sandbox.ts`), runs the shared differential-authorisation engine
against it driven by the inferred plan (`src/verify/exploit.ts`), and tears it
down. The sandbox injects an ephemeral value for whatever secret-shaped
`process.env` variable the target reads (not a hardcoded `JWT_SECRET`), so an app
that signs tokens with `APP_TOKEN_SECRET` boots just as well.

The exploit:

1. establishes two synthetic identities through the target's own auth flow (per
   the inferred plan);
2. has identity A create a resource (and attach a child record, since the
   flagship bug is a cascading child delete);
3. reads A's state back **as A** — resource present, child-record count;
4. has identity B perform the flagged mutation against A's resource id;
5. reads A's state back **as A** again.

The verdict is decided by step 3 vs. step 5 — a change in the *victim's* stored
data. **Not** by identity B's HTTP status. This is the crux: the FlaudeCode bug
returns `404 Task not found` to the attacker while the cascading
`DELETE FROM notes` has already run. A verifier that trusted the status would
report not-exploitable and be exactly wrong. Only a demonstrated cross-user state
change promotes the finding to `verified-exploitable`; a sandbox that could not be
provisioned, an inconclusive run, or a genuine no-change all leave it
`unverified-flagged`. Nothing is ever silently promoted or silently dropped.

Every request the exploit makes is recorded — actor, method, path, status,
truncated response — as a `verification_run` on the report and in the audit log.
Detected tokens are redacted from that trail even though the sandbox mints them
itself with a throwaway key: the "credentials never appear in a report" rule
holds uniformly, including in the record the tool writes about itself.

### Why local-process, not Docker

The build spec names Docker, and Docker is the correct isolation boundary for
running an arbitrary untrusted target. The shipped sandbox is a local process
because Docker is not always available (it was not on the machine this was built
on), and a verification layer that only runs where Docker is installed cannot be
demonstrated at all. The local sandbox shares the host kernel and network
namespace and provides no real containment — it is a functional stand-in that
proves the pipeline, and the Docker provider is the intended default once
present. Isolation aside, the sandbox does take real precautions: a fresh
per-run signing key, an isolated empty database, native-dependency repair for the
current runtime, and full teardown of the temporary directory.

### What "verified-exploitable" does and does not mean

It means: in a faithful sandboxed copy, a second synthetic user performed the
flagged mutation against the first user's resource and the first user's stored
data changed. It does **not** mean the finding reproduces in your production
topology, against your real authentication middleware, or with your data. It is
strong evidence the ownership boundary is missing in the code as written — which
is exactly what a static or model signal alone cannot establish.

## Acceptance

`npm run acceptance:phase2` runs this whole pipeline against the FlaudeCode
fixture and asserts the ordering bug is flagged, is `verified-exploitable`,
carries a repro whose evidence records a victim-side state change, and that no
finding anywhere is `verified-exploitable` without an accompanying repro.
