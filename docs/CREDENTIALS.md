# Credentials — two keys, two owners

> The strain governs what an agent may **do**. This governs what an agent may
> **hold**. They are different questions, they have different owners, and
> answering only the first leaves the more consequential one open.

---

## The problem nobody had five years ago

Give a program a credential and the risk is that the program misuses it. That
risk is old, and the industry has good answers: scope it, rotate it, audit it.

Give an **AI agent** a credential and something new happens. The moment the
agent *reads* the value, that value is in the model's context window. It is
transmitted to a model provider. It lands in a session transcript. It may be
retained, and it may be reproduced later into a file, a log, or a pull request.

None of that requires malice. It is the ordinary, correct operation of the
system. But the outcome is indistinguishable from disclosure, and no amount of
scoping or rotation prevents it, because the leak happens at the moment of
*reading* — the one operation every traditional secret manager treats as safe.

Traditional secret managers are built on the assumption that retrieval is the
safe half and storage is the risky half. For agents, that is inverted.

## What the strain used to say

Nothing useful. `credential-access` is one of the five capability classes, and
an organisation that forbids it stops agents touching secrets at all.

That is a safe default and a useless one. Real work needs real credentials. An
agent that cannot deploy, cannot call an API, and cannot read a database is an
agent nobody adopts — and a control nobody adopts protects nothing. "Forbid it"
is the answer that ends the pilot.

## The two keys

A credential is used only when two independent parties agree, and they are
deliberately not the same party:

```
   the machine  ──  RAPP Keyring  ──▸   which PROCESS may hold this secret
                                        owned by the user, on the device

   the estate   ──  the strain    ──▸   which AGENT may cause it to be used
                                        owned by the administrator, in sealed policy
```

**Neither is sufficient alone, and that is the point.**

Keyring cannot see inside the brainstem. Every agent in that process is the same
caller — one process, one identity — so Keyring alone cannot tell the deploy
agent from the note-taking agent. The strain can, because it already identifies
agents by the sha256 of their bytes.

The strain cannot hold a secret safely. A policy manifest is a file that gets
copied, mailed, committed and screenshotted. The day it contains a value is the
day the control becomes the leak.

So: **the strain holds grants, Keyring holds values.**

```
strain.json   "this approved agent may use azure/*"      names, never values
keyring        the bytes of azure/storage-key            values, never in policy
```

## Use without sight

The credential organ has **no action that returns a secret.** Not a restricted
one, not a flag-gated one — none. Its tool surface is `available`, `check`,
`use`, `explain`, and conformance check **L7** fails the build if anything
resembling `get`, `read`, `reveal` or `fetch` ever appears there.

What `use` does is ask the broker to run a command with the credential injected
into *that command's* environment, with the broker masking the value in
everything the command prints. Watch what comes back to the agent:

```console
$ # the agent asks to deploy, and the command deliberately echoes the secret
{
  "status": "ok",
  "credentials_injected": ["azure/storage-key"],
  "exit_code": 0,
  "stdout": "deploying with «redacted:azure/storage-key»\n"
}
```

The command ran with the real value. The agent received a masked one. The bytes
never entered the model's context, so they never left the machine.

A human who genuinely needs a plaintext value uses `rapp-keyring get --i-know`
at a terminal, as a person, and it is recorded as a *sighted read* in Keyring's
own log — a distinct event from ordinary use, precisely so it can be asked about.

## Administering it

```bash
# 1. approve the agent — a credential cannot be granted to an agent the
#    strain does not admit, so this comes first
strainctl approve agents/deploy_agent.py --by secops@contoso.example

# 2. grant it a credential by name or glob
strainctl cred grant deploy_agent.py 'azure/*'

# 3. deny a pattern for everyone; deny outranks every grant, including one
#    an administrator adds later by mistake
strainctl cred deny 'prod/*'

# 4. the value goes in the broker, never in the manifest
printf '%s' "$VALUE" | rapp-keyring set azure/storage-key --stdin

# 5. answer the question an administrator actually asks
strainctl cred check deploy_agent.py prod/db
#   DENY   deploy_agent.py → prod/db
#          denied by the strain rule 'prod/*'
```

## The identity check does double duty

An agent cannot acquire a credential grant by being edited after it was
approved. The grant is recorded against a sha256, so changing the file changes
its identity, and its grants stop applying until it is approved again:

```console
$ strainctl cred check deploy_agent.py azure/storage-key
  DENY   deploy_agent.py → azure/storage-key
         deploy_agent.py has changed since it was approved
         (recorded 11744ea8681a, on disk 68ebcbbf4570) — its grants
         do not apply until it is re-approved
```

This is the strain's existing check 3 doing a second job, and it is why grants
are bound to hashes rather than filenames.

## What is enforced, and what is only recorded

**Enforced.** The set of secrets reachable from this machine under this strain
is bounded by the manifest, and the bound is sealed. An LLM cannot widen it by
asking nicely. A grant naming an agent that is not approved does not apply. A
manifest whose seal does not verify grants *nothing* — it fails closed. A
refused credential means the command never runs at all, which conformance check
**L9** proves by looking for the side effect on disk.

**Recorded, not enforced.** *Which* approved agent claimed to be the requester,
within a single brainstem process. All agents share one process; separating them
would need OS support this deliberately does not require. The claim is written
to the audit record, and the union of grants bounds the blast radius.

That limit is stated here rather than implied, for the same reason the threat
model states T6 plainly: a control trusted past its boundary is worse than no
control at all.

## The record

Every decision — used, refused, and why — appends to the strain audit record,
which is hash-chained. Modifying, deleting or forging an entry breaks the chain
at a point `strainctl audit verify` will name:

```console
$ strainctl audit tail -n 2
  2026-07-25T16:14:05  credential.refused   rogue.py         'rogue.py' is not in the strain allowlist
  2026-07-25T16:14:05  credential.refused   deploy_agent.py  denied by the strain rule 'prod/*'

$ strainctl audit verify
  OK — chain intact (2 record(s))

$ strainctl audit export --format cef | head -1
CEF:0|RAPP|rapp-light|1.0|credential.refused|credential.refused|7|agent=rogue.py ...
```

The record carries names, decisions and reasons — never a value and never a line
of agent source — so it can be shipped to a SIEM without becoming the leak it
exists to detect. Conformance check **L11** proves that.

Destruction remains possible: this is a file in the user's own home directory,
and no user-space tool can prevent its own deletion. **Tampering** is what is
detectable. For environments where that gap matters, forward the record — it is
append-only JSONL and designed to be tailed.

## Installing the broker

```bash
curl -fsSL https://kody-w.github.io/rapp-keyring/install.sh | bash
```

If the broker is absent, the organ says so plainly and grants nothing. It never
falls back to reading an environment variable, and it never asks the user to
paste a secret into the conversation — the system prompt it injects tells the
model not to, every turn, because a model with no instructions on this subject
reliably invents the worst one.

---

*RAPP Keyring: <https://github.com/kody-w/rapp-keyring>*
