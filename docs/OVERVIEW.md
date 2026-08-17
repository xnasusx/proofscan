# proofscan — a scanner that *proves* the bug instead of guessing

A plain-language introduction. No prior security background assumed. For the
implementation, see [TECH-STACK.md](TECH-STACK.md) and
[ARCHITECTURE.md](ARCHITECTURE.md); for the deep dives, the
[documentation table](../README.md#documentation) in the README.

**The one-sentence version:** most security scanners hand you a pile of "maybe"
findings that a human has to sort through; proofscan actually tries to exploit
the bug and only flags it if the attack really worked — so you get evidence, not
a guess.

## What it is

A command-line tool that inspects a web application for security flaws. The name
is the point: it doesn't just *scan*, it looks for *proof*. A finding is only
marked "verified" once proofscan has run a real attack and watched it change data
it shouldn't have been able to touch.

## What it does

It looks for a whole class of flaws, but its signature move is catching **broken
access control** — where an app checks *that* you're logged in but not *whether
the specific thing you're touching is actually yours*. (The formal name is BOLA /
IDOR, if you want to look it up.)

Here's the example it was built around. Imagine a to-do app. You ask it to delete
*your* task #5, and behind the scenes it deletes the notes attached to task #5
— **before** it checks whether task #5 belongs to you. So a logged-in stranger
can send "delete task #5" and wipe *your* notes.

Now the part that matters: when the attacker does this, the app replies **"404
Not Found"** — as if nothing happened. A normal scanner sees that error and
concludes the app is safe. **proofscan doesn't trust the reply.** It logs in as
two different users, has one attack the other, and then reads the *victim's* data
afterward. The notes are gone. The "404" was hiding real damage. That's the
difference between guessing and proving.

It also runs the fast, boring-but-important checks: passwords or API keys
hard-coded as fallbacks, overly permissive cross-site settings, missing input
validation, and so on.

## How it's used

You point it at a project and it works in layers, cheapest first:

1. **Static checks** — reads the code for the obvious problems. Fast, free,
   always runs.
2. **Reason + prove** — it identifies likely access-control bugs, then spins up a
   throwaway copy of the app and *actually attacks it* to confirm.
3. **Live fuzzing** — optionally, it can attack a *running* copy of the app with
   no access to the source, the way a real attacker would.
4. **Fix loop** — it writes up a ticket with the evidence, and after someone
   fixes it, re-runs the exact same attack to confirm the fix actually worked
   before it's allowed to ship.

It runs deterministically for free; there's an optional AI mode for the trickier
cases. See [Running it](../README.md#running-it) for the exact commands.

## Why it matters (especially for GRC)

- **Evidence beats opinion.** GRC lives on the question "can you *show* this
  control works?" A list of 200 "possible" findings doesn't answer that. "Here is
  the attack we ran, and here is the other user's data it destroyed" does.
- **"Didn't run" is not "clean."** proofscan reports what it *couldn't* check,
  instead of letting a silent gap look like a pass — the coverage-vs-clean
  distinction GRC people already care about.
- **It closes the loop.** Find → prove → ticket → re-verify the fix. That's a
  control lifecycle, not a one-time report.
- **It's a model for using AI responsibly.** The AI only *suggests where to look*
  — it never gets to *decide* a bug is real. A machine has to run the actual
  exploit for anything to count. That's a concrete answer to "how do we use AI in
  assurance without just trusting it?"

## Honest limits

It goes *deep* on one high-impact flaw class rather than shallow on everything —
it is not a "finds every bug" tool. The live-fuzzing layer only runs against
systems you are authorized to test, and it logs everything it does. And
"verified" means *this exploit worked in this setup* — it is still your judgment
call what that means for production. The full list is in
[Honest limits](../README.md#honest-limits).
