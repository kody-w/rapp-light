# RAPP Light — a **strain** of the RAPP brainstem

> A locked-down, auditable RAPP deployment for enterprise networks — built for
> users who have no elevated permissions, and administered the way data loss
> prevention already is.
>
> **It is not a fork.** The brainstem is byte-identical to the one everyone else
> runs. What changes is the policy around it.

---

## The problem

An AI assistant that can load capabilities is, from a security team's point of
view, a program that runs arbitrary code that arrived from somewhere. That is
usually where the conversation ends.

The standard answer is to ship a "hardened edition" — a fork with the dangerous
parts removed. Every hardened fork dies the same way: it drifts, it stops
receiving upstream security fixes, and eighteen months later the locked-down
build is the *least* secure thing in the estate.

## The answer

**A strain constrains the kernel from outside it, so there is only ever one
kernel.**

```
   ┌──────────────────────────────────────────────┐
   │   the same brainstem everyone else runs      │   ← unmodified, byte-identical
   │   (a loader + an LLM loop + a splitter)      │
   └───────────────────┬──────────────────────────┘
                       │ loads agents/*_agent.py on every turn
   ┌───────────────────▼──────────────────────────┐
   │  aa_strain_policy_agent.py   ← the organ     │
   │  seal → ring → identity → capability → egress│
   └───────────────────┬──────────────────────────┘
                       │ reads
   ┌───────────────────▼──────────────────────────┐
   │  strain.json   ← sealed policy, admin-owned  │
   └──────────────────────────────────────────────┘
```

A grail security fix reaches the locked-down deployment **the same day** it
reaches everyone else, because it is the same grail.

---

## The five checks

| # | Check | What it stops |
|---|---|---|
| 1 | **Seal** | policy edited to widen what is admitted — fails *closed*, to admitting nothing |
| 2 | **Ring** | capabilities more experimental than the organisation accepts |
| 3 | **Identity** | an approved agent that was edited afterwards |
| 4 | **Capability** | code that reaches further than it declares |
| 5 | **Egress** | outbound connections to unapproved hosts |

### Check 4 is the one that is different

Most allowlists trust a manifest field. That is an allowlist of *promises*.

RAPP Light reads the agent's syntax tree and compares what the code can actually
reach against what it declared. Undeclared network access, process execution,
credential reads or dynamic code are **refused** — at approval time, and again
at load time, even if an administrator forced the approval through.

```
$ strainctl approve agents/helper_agent.py

  REFUSED: helper_agent.py reaches capabilities it does not declare:
    process-exec: subprocess.run
    network: requests.post

  Approving this would put an undeclared capability into your estate
  under an approval that does not mention it.
```

An agent cannot quietly acquire a capability between review and execution
without changing its bytes — and changing its bytes fails check 3.

---

## Maturity rings — the band that expands

Enterprise adoption is not binary, so the strain is not either. Every capability
carries a ring, and the organisation sets the band it admits:

```
   frontier  ▸  private-preview  ▸  public-preview  ▸  ga
   ◀── more experimental                 more assured ──▶
```

An organisation starts at `ga` and widens deliberately. Anything above the
standing band needs an **individual approval carrying a recorded reason**, so
one team can pilot one frontier capability without moving the whole population
onto the frontier ring:

```bash
strainctl approve agents/log_detective_agent.py \
  --exception "pilot with the SRE team, review 2026-10-01" --by secops@corp
```

Every exception appears in `strainctl report`, with who approved it and when.

---

## Elevation is a credential, not a build

A locked-down strain and a full brainstem are **the same brainstem**. An
administrator holding the strain credential gets the full surface in the same
session:

```
you    ▸ what's being held back?
RAPP   ▸ 3 capabilities are withheld by policy. log-detective is at
         public-preview and your band is ga; two others are not approved.
         Your administrator can approve them.

admin  ▸ (RAPP_STRAIN_ADMIN_KEY set) approve log-detective for the SRE pilot
RAPP   ▸ Approved at public-preview with a recorded exception. Live on your
         next message.
```

Holding the credential lets you change the policy the checks read. **It does not
let you bypass the checks** — an administrator cannot approve an agent whose
code reaches further than it declares. That is asserted by
`test_elevation_cannot_bypass_capability_checking`.

---

## No elevated permissions required

| | |
|---|---|
| Install location | the user's home directory |
| Administrator rights | **not required** |
| System service registered | none |
| Ports | loopback only, unprivileged |
| Registry / system files touched | none |
| Network at install time | one HTTPS fetch, or none for an offline bundle |

```bash
curl -sfL https://kody-w.github.io/rapp-light/install.sh | sh
```

---

## For your security reviewer

Everything a review needs is in this repo, written to be argued with rather than
to reassure:

- **[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)** — assets, trust boundaries,
  ten threats with dispositions, and **an explicit list of what this does not
  stop**. T6 states plainly that a local administrator can disable the control,
  because every endpoint DLP product has that same boundary and pretending
  otherwise is how a control gets trusted where it should not be.
- **[`docs/COMPLIANCE.md`](docs/COMPLIANCE.md)** — data flows, what leaves the
  machine, retention, and the audit record.
- **[`docs/RAI.md`](docs/RAI.md)** — responsible-AI posture: what the system
  decides, what a human decides, and how a user is told a capability is withheld
  rather than left to guess.
- **[`docs/RINGS.md`](docs/RINGS.md)** — the maturity model and what each ring
  commits to.

Every mitigation claimed in the threat model has a test named for it:

```bash
python3 -m unittest discover -s tests -v     # 27 tests, no network, no deps
```

---

## Quick start (administrator)

```bash
# 1. seal key comes from your configuration management, not a shell profile
export RAPP_STRAIN_SEAL_KEY="$(cat /etc/rapp/seal.key)"

# 2. create the policy — starts denying everything
strainctl init "Contoso Ltd" --band ga --forbid process-exec --forbid network

# 3. see what would be admitted, and why not
strainctl scan ./agents

# 4. approve exact byte sequences
strainctl approve ./agents/json_doctor_agent.py --by secops@contoso.example

# 5. set the in-session elevation credential
strainctl admin --set-key -

# 6. prove the policy is intact, and produce the record
strainctl verify
strainctl report > posture-$(date +%F).json
```

## Quick start (user)

There isn't one. That is the point — the user runs RAPP and it is already
compliant. If they ask for something withheld, the assistant tells them why and
who can approve it.

---

## What a strain is, generally

RAPP Light is the first strain, not the only possible one. The pattern is:

> **Take the kernel unmodified. Add a sealed policy and an organ that enforces
> it. Never fork.**

The same shape produces a regulated-industry strain, an air-gapped strain, or a
per-team strain, without any of them becoming a different product to maintain.

This is not a convention someone remembered to follow. It is
[constitutional law](https://github.com/kody-w/RAPP/blob/main/CONSTITUTION.md):
Article I confines the brainstem to a loader, an LLM loop and a response
splitter; Article XXVI rejects any change that loads responsibility into the
kernel which an agent could serve. **RAPP Light adds zero lines to the
brainstem**, and `test_the_strain_ships_no_brainstem` fails the build if a
kernel ever appears in this repo.

---

## Licence

MIT. See [`LICENSE`](LICENSE).

RAPP is a project of Wildhaven Homes LLC. See
[TRADEMARKS](https://kody-w.github.io/rapp-train/TRADEMARKS.md).
