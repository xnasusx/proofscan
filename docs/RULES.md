# Rule catalogue

Every rule, what it flags, how severity is decided, and where it breaks down. The
last column is the important one: a rule whose false-positive and false-negative
behaviour is undocumented cannot be triaged, only guessed at.

Layer 1 rule IDs are shared between the built-in AST engine and the Semgrep rule
files. When both fire on the same line the finding is reported once with
`detected_by: ["builtin", "semgrep"]`. See [the Semgrep rules note](../rules/semgrep/README.md)
for why the built-in engine is authoritative on severity. The Layer 2 rule
(`proofscan.authorization-ordering`, full detail in [LAYER2.md](LAYER2.md)) and
the Layer 3 rule (`proofscan.bola-idor-dynamic`, full detail in
[LAYER3.md](LAYER3.md)) are documented at the end.

---

## `proofscan.hardcoded-fallback-secret`

**Flags** `process.env.X || '<literal>'` and the `??` equivalent, where either the
environment variable name or the assigned variable name is secret-shaped
(`secret`, `token`, `password`, `api_key`, `private_key`, `credential`, `salt`,
`signing`, `key`, …).

**Severity** `critical` when the name indicates a token-signing or session key
(`jwt`, `session`, `signing`, `auth`, `cookie_secret`, `csrf`, `token_secret`);
`high` otherwise.

The split is deliberate. A known signing key is an authentication bypass: an
attacker mints a token for any user id and is that user, with no credential. A
known third-party API key is a scoped credential — serious, but the blast radius
is whatever that one service permits. Rating both the same loses the distinction
that decides which one gets fixed tonight.

**Why this rule exists.** Generic secret scanners look for values shaped like
issued credentials — `AKIA…`, `sk_live_…`, `ghp_…`, high-entropy blobs. A
fallback like `'demo-jwt-secret-change-me'` has none of those properties, so it
is invisible to them, and yet it is the value the application signs tokens with
whenever the variable is unset. This is measured, not asserted:

| Scanner | Findings on the FlaudeCode fixture | Caught `server.js:13` / `server.js:14`? |
|---|---|---|
| Gitleaks 8.30.1 (full default ruleset) | 0 | no / no |
| VibeCheck secret scanner (21 patterns) | 0 | no / no |
| `proofscan.hardcoded-fallback-secret` | 2 | yes / yes |

**Reports never contain the literal.** The value is replaced with
`'<redacted: N chars>'` before it reaches the finding. Reports get committed,
attached to tickets and pasted into chat; echoing the secret would make the
report a second copy of the leak.

**Limits.** Only `process.env` is recognised — not `os.environ`, `ENV[]`,
`System.getenv`, or a config library's `get('KEY', 'default')`. Fallbacks
assembled at a distance (`const d = 'abc'; … || d`) are missed, since the rule
does not do constant propagation. Placeholder literals (`''`, `changeme`,
`undefined`, `todo`) are excluded, so a deployment that genuinely relies on
`'changeme'` is not reported.

---

## `proofscan.cors-credentials-reflected-origin`

**Flags** a `cors(...)` call whose config sets `credentials: true` together with
an origin that reflects the caller: `origin: true`, `origin: req.headers.origin`,
or a callback that answers `cb(null, true)` with no allowlist check.

**Severity** `high` for a reflected origin. `low` for `origin: '*'` with
credentials, because browsers refuse to honour the wildcard when credentials are
requested — it is a configuration error to correct, not an exposure.

`origin: true` in the `cors` package does not mean "allow `*`". It echoes back
whatever `Origin` the request carried, which is strictly worse than the wildcard:
the wildcard is blocked by the browser, the echo is not.

**Limits.** Only recognises the `cors` package's call shape. Manually written
`Access-Control-Allow-*` headers are not covered, nor is CORS configured in a
reverse proxy, an API gateway, or framework middleware other than `cors`. The
callback heuristic looks for allowlist-ish operations (`includes`, `test`, `===`)
and will treat a genuinely unsafe callback as safe if it happens to contain one.

**Rating this in your own environment.** The finding assumes cookie-borne
sessions. If sessions are carried only in `localStorage` and attached by script,
a cross-origin read cannot reach them and the practical severity is lower. The
`exploitability_note` says so on every instance rather than leaving the reader to
work it out.

---

## `proofscan.unauthenticated-secret-exposure`

**Flags** a route with no authentication or authorisation middleware that returns
a response field whose name indicates credential material.

**Severity** `high` when the value appears to be returned in full; `medium` when
it is narrowed first by `.slice(...)`, `.substring(...)`, masking or redaction.

A truncated value is genuinely less severe and genuinely not harmless: a prefix
confirms the credential exists, narrows a brute-force search, identifies which
key is deployed, and the truncation length is a code detail that can change
without anyone revisiting the endpoint.

**The false positive this rule must not produce.** Login and registration
endpoints are unauthenticated and return a session token — that is their entire
job. A naive `/token|key|secret/i` match over unauthenticated responses fires on
essentially every application ever written. Token-family field names (`token`,
`accessToken`, `refreshToken`, `idToken`, `jwt`, `csrfToken`, …) are therefore
exempt **on credential-issuing paths only**. A login route returning `apiKey` or
`dbPassword` is still flagged.

`key` is matched as a substring, not a whole word, because real field names are
camelCase compounds — `fakeAiKeyPreview`, `apiKeyHint`, `signingKeyId`. A
word-boundary match misses all of them. Words that merely contain "key"
(`monkey`, `keyboard`, `keyword`, `keystone`, …) are excluded.

**Limits.** Express-style routing only. Authentication must be visible as route
middleware or as an `app.use` earlier in the same file — a gate applied in
another module, at a gateway, or by a framework decorator is not seen, and the
route will be reported as unauthenticated. Handlers passed by reference
(`app.get('/x', handler)`) have no inspectable body and are skipped entirely,
which is a false negative by design rather than a guess.

---

## `proofscan.missing-rate-limit-auth-route`

**Flags** a POST, PUT or PATCH route on a credential or account-recovery path
(`login`, `register`, `password`, `reset`, `forgot`, `token`, `otp`, `mfa`, …)
with no rate-limiting middleware applied to it.

**Severity** `medium`, uniformly. Rated medium rather than high because
exploitation still depends on a weak or reused credential; the tool cannot know
your password policy. What it can say is that the control which should bound the
attempt rate is absent.

Scoped to credential routes on purpose. Every endpoint benefits from a limiter,
and flagging all of them produces a wall of findings nobody reads. GET requests
on auth paths are excluded: those render a form, they do not accept a guess.

**Limits.** A limiter is recognised by name (`rateLimit`, `throttle`,
`slowDown`, `limiter`, `brute`, …) in the route's middleware chain or in an
earlier `app.use` in the same file. A limiter applied in another module, at a
load balancer, at Cloudflare, or by an API gateway is invisible, and the route
will be flagged anyway. When the file imports a rate-limiting package but the
route is unprotected, the finding says so — that pattern usually means the
limiter exists and was not wired to this route.

`app.use` ordering is respected: middleware registered *after* a route does not
apply to it in Express, and the rule does not pretend otherwise.

---

## `proofscan.missing-input-validation-schema`

**Flags** a POST, PUT or PATCH route with no declarative request schema — no Zod,
Joi, Yup, Ajv, superstruct, valibot, class-validator, express-validator or
celebrate reference in the route middleware or the handler.

**Severity** `medium` on credential routes, `low` elsewhere.

DELETE is excluded: it carries no body in normal use, so "no body schema" is not
a defect there.

**Graded, and honest about what it found.** On a credential route the unvalidated
fields are the identifier and the secret themselves — no format check, no length
bound. Elsewhere it is a robustness and consistency gap. Where the handler does
hand-rolled checks (explicit coercion, a 4xx early return), the finding says so
explicitly instead of implying the input is untouched; the absence of a *schema*
is the finding, not the absence of all checking. This is the rule most likely to
be noise in a codebase that validates by hand throughout, and `--min-severity
medium` drops the low-severity instances.

**Limits.** Detection is by library call shape and middleware naming, so a
hand-rolled validator module that happens not to match those names reads as
absent. Validation performed in a shared parent router is not attributed to the
child route.

---

## `proofscan.schema-drift`

**Flags** the same table name created in more than one place with differing
column constraints, types or defaults. Runs repo-wide over embedded SQL
(template literals, string literals) and `.sql` files. One finding per table.

**Severity** `medium`.

**Why it matters more than it looks.** With `CREATE TABLE IF NOT EXISTS`,
whichever statement runs first creates the table and every later definition is a
silent no-op — no error, no migration. Which constraints the database is actually
enforcing depends on start-up order, and the constraints a reviewer reads in one
file may not be the ones in force. On the FlaudeCode fixture, `server.js`
declares `email TEXT UNIQUE NOT NULL` while `initDb.js` declares `email TEXT
UNIQUE`; if `initDb.js` ran first, the `NOT NULL` a reviewer sees in `server.js`
does not exist.

**Reported against the weakest definition** — the one to bring up to parity, and
the one whose constraints the database may be missing — with every location
listed in the description.

**Limits.** Text extraction, not a SQL parser: dialect-specific syntax may parse
imperfectly, and `CREATE TABLE` inside a comment is still extracted (arguably
correct — a commented-out schema that disagrees with the live one is worth
seeing). Schemas defined through an ORM's model classes or a migration DSL are
not covered. Table names are compared unqualified, so `main.users` and `users`
collide deliberately.

---

## `proofscan.authorization-ordering` (Layer 2)

**Flags** an authenticated route handler that performs a request-driven database
mutation before confirming the caller owns the resource — the IDOR / broken
object-level authorisation class. Runs only under `--layers static,ai-reasoning`.
Full pipeline detail in [LAYER2.md](LAYER2.md).

**Severity** `high` by default; `medium` when the reasoner returns `low`
confidence (typically because the handler depends on code the inventory could not
follow).

**Status is the point.** Unlike every Layer 1 rule, this one can carry
`verified-exploitable` — but only after a generated exploit ran against a
sandboxed copy of the target and a cross-user state change was observed. Absent
that proof it stays `unverified-flagged`. The verdict is decided by reading the
victim's state back as the victim, never by the attacker's HTTP status: the
FlaudeCode flagship bug returns 404 to the attacker while still destroying the
victim's notes.

**How it is produced.** A mechanical AST pass inventories each authenticated
mutation handler's operations in execution order and marks a *candidate* only
when a request-driven mutation has no caller-scoped filter and no short-circuiting
ownership check before it. A reasoner (`heuristic` default, or `anthropic`) then
answers one scoped question about each candidate. Then verification runs.

**Limits.** Candidate detection is Express-shaped and single-file, inheriting the
route-inventory limits above. Creates are never flagged (no prior owner to
check). Ownership established through a helper function the inventory does not
follow is not seen — the handler is reported unresolvable rather than guessed at.
Verification needs a Node/Express-shaped target the sandbox can start; anything
else leaves the finding a flagged-but-unverified candidate. The `anthropic`
backend may decline a handler on a safety classifier, in which case it is
preserved as a low-confidence candidate, not dropped.

---

## `proofscan.bola-idor-dynamic` (Layer 3)

**Flags** a cross-user access defect proven against a *running* target: an
authenticated non-owner performed an operation on another user's resource and
either got a success status or produced an observable change in the owner's data.
Runs only under `--layers dynamic-fuzzer`, and only against an authorised target
(see [LAYER3.md](LAYER3.md)). No source is read.

**Severity** `critical` for a destructive cross-user side effect (delete or
overwrite) or an allowed cross-user mutation; `high` for a cross-user read.

**Status is always `verified-exploitable`.** A Layer 3 finding only exists
because the exploit was observed to work on a live target — the test is the
verification, so there is no unverified state for this rule.

**How it is produced.** Two synthetic identities are established against the
target's own auth flow; identity A creates a resource, identity B attacks it, and
the verdict is read back as A. As in Layer 2, the decision is a victim-side state
change, not the attacker's HTTP status — the fixture bug returns 404 to the
attacker while destroying the victim's child records.

**Limits.** Needs a create endpoint that returns an id and an id-parameterised
item path (from OpenAPI or the manifest); no crawling. Default auth flow is
token-in-JSON-body. Side-effect detection compares owner-readable collection
presence and child counts; a mutation with no owner-readable effect is caught
only when the attack itself returns 2xx. Rate-limited and fully request-logged.

---

## Dependency findings (`CVE-…`, via Trivy)

Rule ID is the CVE. Severity comes from Trivy's own rating.

**Exploitability is context, never a sort key.** Each finding records CVSS v3
score and vector where the advisory supplies one, whether a fixed version exists,
and KEV status **only when a catalog was supplied** via `--kev-catalog`. When no
catalog is given the note says KEV was not checked — absence of a KEV flag is
never presented as evidence that a flaw is unexploited. The catalog is read from
a local file; proofscan makes no network calls during a scan, so a run behaves the
same in CI and in an air-gapped environment.

**Reachability is not assessed.** Every dependency finding states this. Trivy
reports that a vulnerable version is installed, not that the affected code path
is called by your application.

**"Nothing to scan" is not "clean."** Trivy resolves versions from lockfiles. A
project with `package.json` and no lockfile produces no results at all, which is
indistinguishable from a clean scan unless the tool says otherwise. proofscan
reports that case as `no_input` with the reason, and repeats it as a coverage
note. This is not hypothetical: the FlaudeCode fixture has no lockfile, and a
scanner that reported "0 dependency vulnerabilities" there would be lying by
omission.

---

## Secret findings (`gitleaks.…`)

Rule ID is `gitleaks.<rule>`. Severity is **derived, not read** — Gitleaks v8
emits no severity field. Rule families indicating live cloud, payment, registry
or database credentials, and private keys, are rated `critical`; a generic
pattern match with entropy below 3.5 is rated `medium`; everything else `high`.

**The secret is never written into the finding.** Only a four-character prefix,
the length, and Gitleaks' own fingerprint are carried, and `code_excerpt` is
null because the matched line contains the value.

**Remediation wording is deliberate.** Every finding says to rotate first.
Deleting the value from the working tree does not end the exposure: if it was
ever pushed, it remains retrievable from the object history, and on GitHub a
force-pushed commit stays fetchable by SHA. Rotation is the control that actually
ends it.
