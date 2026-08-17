# Layer 3 — dynamic BOLA/IDOR fuzzer

Layer 2 needs the source: it inventories mutation handlers, reasons about them,
and verifies against a sandboxed copy. Layer 3 needs **only a running instance**.
It is the same defect class — broken object-level authorisation, where one user
can act on another's resource — approached from the outside, so it works against
a staging deployment or any target you can reach over HTTP without repo access.

Run it with `--layers dynamic-fuzzer` against a target that has a
`runtime_base_url` and a complete authorisation record. Unlike Layer 2 (which
exercises an ephemeral copy of local source), Layer 3 sends live traffic to a
**real, operator-supplied** system, so it is gated — see *Authorisation* below.

## What it does

1. **Route discovery.** From the target's OpenAPI/Swagger document if it serves
   one (tried at the usual paths), and/or from a `dynamic.resources` manifest in
   `targets.yaml`. The unit of testing is a *resource collection* — a create
   endpoint plus the id-parameterised operations a non-owner should be denied —
   because cross-user testing needs the create/attack pairing, not a flat URL
   list. Crawling/enumeration is a deliberate non-goal (a later phase).

2. **Two synthetic identities.** Registered through the target's own signup flow
   (`.invalid`-domain throwaway accounts, RFC 2606), or supplied pre-provisioned
   for targets without open registration. The auth flow (paths, field names,
   where the token lives in the response) is configurable and defaults to the
   common `{email, password} -> {token}` shape.

3. **Differential authorisation testing.** For each id-parameterised resource:
   identity A creates an object (and a child record where the resource has one),
   then identity B attempts each method against A's object. The verdict is
   decided by reading **A's state back as A**, before and after B's request —
   never by B's response code.

That last point is the whole design, and it is why Layer 3 exists as a live
tester rather than a status-code checker. The flagship bug returns `404` to the
attacker while the cascading delete has already destroyed the victim's child
records. A fuzzer that trusted the `404` would report no problem. So every attack
is bracketed by an owner-side read of both the object and its children, and a
finding is raised when B's request either succeeds (2xx) **or** produces an
observable change in A's data despite an error status.

## Findings are verified by construction

A Layer 3 finding only exists because the cross-user effect was *observed* on a
live target. There is no separate "candidate then verify" step as in Layer 2 —
the test **is** the verification. So every dynamic finding carries
`status: verified-exploitable`. A destructive cross-user side effect (delete or
overwrite) is rated `critical`; a cross-user read is `high`.

## Not a DoS, and fully logged

Two requirements from the build spec are enforced in the one place that touches
the network (`src/dynamic/client.ts`), so they hold for the whole layer:

- **Self-throttling.** Every request passes a minimum-interval gate
  (configurable via `dynamic.rate_limit_rps`), and a `429`/`503` triggers
  exponential backoff that honours a `Retry-After` header. Scanning cannot become
  a flood.
- **Complete request log.** Every request — method, path, status, timestamp — is
  recorded and written to the hash-chained audit log as a `dynamic.requests`
  entry, so there is a full account of what the tool did to the running target,
  including requests that failed.

## Authorisation

This is the layer the authorisation gate was built for. A `dynamic-fuzzer` run
requires **both**:

- a complete record in `targets.yaml` — `authorized_by`, `authorized_at`,
  `authorization_basis`, and `runtime_base_url`; and
- `--authorized` on the invocation.

Neither alone is sufficient, so an authorisation cannot be conjured by a flag at
the moment of the scan. A run without a record is refused with an explanation.
The difference between authorised security tooling and unauthorised access
tooling is whether permission actually exists, so it is enforced in code.

## Configuration

```yaml
targets:
  - name: my-app-staging
    source_type: runtime_url            # no source on disk; reach it over HTTP
    runtime_base_url: https://staging.my-app.example
    authorized_by: rootcaws.ops
    authorized_at: "2026-08-09"
    authorization_basis: >-
      Application I own and operate; staging, no production data.
    dynamic:
      rate_limit_rps: 5                 # optional; default ~6-7 req/s
      auth:                             # optional; these are the defaults
        register_path: /api/register
        login_path: /api/login
        username_field: email
        password_field: password
        token_field: token
        # or, for targets without open registration:
        # identities:
        #   - { username: tester-a@example.com, password: "..." }
        #   - { username: tester-b@example.com, password: "..." }
      resources:                        # or rely on OpenAPI auto-discovery
        - name: tasks
          collection: /api/tasks        # POST here to create; response has {id}
          item: /api/tasks/:id          # id-parameterised operations
          methods: [GET, PUT, DELETE]
          child: /api/tasks/:id/notes   # optional; catches cascade side-effects
```

`source_type: runtime_url` is for a target you can only reach as a running
instance. Static and Layer 2 runs are refused on such a target (there is no
source to read); a `local_path` target can run all three layers.

## Acceptance

`npm run acceptance:phase3` boots the FlaudeCode fixture as a running instance
(reusing the sandbox provisioner), then runs **only** the dynamic layer against
its base URL via a `runtime_url` target — no source read — and asserts the
DELETE IDOR is rediscovered live and `verified-exploitable`, the side effect was
caught despite the attacker's `404`, every request was logged to the audit
trail, the gate refuses an unauthorised run, and GET / the ownership-scoped PUT
are not false-positived.

## Limits

- **Route shape.** Testing needs a create endpoint that returns the new id and an
  id-parameterised item path. Resources without a discoverable create are skipped
  (there is nothing to attack), and reported as skipped rather than silently
  dropped.
- **Auth shape.** The default flow is token-in-JSON-body. Cookie-session auth,
  multi-step login, MFA, or CSRF-token flows need pre-provisioned identities or
  are not yet supported.
- **No crawling.** Routes come from OpenAPI or the manifest. An endpoint absent
  from both is not tested — the tool reports what it tested, never implying
  coverage it did not have.
- **Observable-state model.** Side-effect detection compares collection presence
  and child-record counts read back as the owner. A mutation with no
  owner-readable effect (a field flipped on an object the owner can't re-read, a
  write to a store with no read-back endpoint) is not caught by the state diff,
  though a 2xx on the attack still is.
