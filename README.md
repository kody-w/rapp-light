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
   │  seal → ring → identity → capability →       │
   │  imports → egress                            │
   └───────────────────┬──────────────────────────┘
                       │ reads
   ┌───────────────────▼──────────────────────────┐
   │  strain.json   ← sealed policy, admin-owned  │
   └──────────────────────────────────────────────┘
```

A grail security fix reaches the locked-down deployment **the same day** it
reaches everyone else, because it is the same grail.

---

## The seven checks

| # | Check | What it stops |
|---|---|---|
| 1 | **Seal** | policy edited to widen what is admitted — fails *closed*, to admitting nothing |
| 2 | **Ring** | capabilities more experimental than the organisation accepts |
| 3 | **Identity** | an approved agent that was edited afterwards |
| 4 | **Capability** | code that reaches further than it declares |
| 5 | **Egress** | outbound connections to unapproved hosts |
| 6 | **Credential** | an agent using a secret the estate never granted it |
| 7 | **Imports** | an agent whose imports would make the host fetch a package from an index at load time |

### Check 7 exists because the hole is live, not hypothetical

The brainstem auto-installs missing dependencies. On 2026-07-25, `basic_agent`
— imported by **105** registry agents — was **unclaimed on PyPI**, and `agents`
(50 importers) was already owned by a stranger. An approved agent's import can
therefore fetch and execute someone else's package as the user who owns the
machine. The strain refuses agents whose module-level imports the host cannot
already satisfy. See `docs/THREAT-MODEL.md` T11.

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

## Credentials — two keys, two owners

The strain governs what an agent may *do*. Credentials are what it may *hold*,
and that is a different question with a different owner.

It matters more for agents than for ordinary programs. The moment an agent
**reads** a secret, that value is in the model's context — transmitted to a
provider, written to a transcript, and possibly reproduced later into a file or
a pull request. No amount of scoping or rotation prevents it, because the leak
happens at the one operation every traditional secret manager treats as safe.

So a credential is used only when two independent parties agree:

```
   the machine  ──  RAPP Keyring  ──▸  which PROCESS may hold this secret
                                       owned by the user, on the device

   the estate   ──  the strain    ──▸  which AGENT may cause it to be used
                                       owned by the administrator, in sealed policy
```

Keyring cannot see inside the brainstem — every agent there is one caller. The
strain can, because it identifies agents by the sha256 of their bytes. And the
strain must never hold a value, because a policy manifest is a file that gets
copied and committed. **The strain holds grants; Keyring holds values.**

The credential organ has **no action that returns a secret** — not a restricted
one, not a flag-gated one. It runs your command with the value injected and
masked in the output:

```console
$ # the command deliberately echoes the secret; this is what the agent receives
{
  "credentials_injected": ["azure/storage-key"],
  "stdout": "deploying with «redacted:azure/storage-key»\n"
}
```

```bash
strainctl approve agents/deploy_agent.py --by secops@contoso.example
strainctl cred grant deploy_agent.py 'azure/*'
strainctl cred deny 'prod/*'              # outranks every grant, everywhere
strainctl cred check deploy_agent.py prod/db
```

An agent edited after approval loses its grants — the identity check doing
double duty. Full model: **[`docs/CREDENTIALS.md`](docs/CREDENTIALS.md)**.

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
  twelve threats with dispositions, and **an explicit list of what this does not
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
- **[`docs/CREDENTIALS.md`](docs/CREDENTIALS.md)** — the two-key credential
  model, and why an agent may use a secret but never see one.
- **[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)** — getting policy onto a fleet,
  why the seal key must never land on the endpoint, and the SIEM record.
- **[`SECURITY.md`](SECURITY.md)** — what is in scope, what is a documented
  non-goal, and how to report the difference.

Every mitigation claimed in the threat model has a test named for it:

```bash
python3 conformance.py                       # checks, proved against the code
python3 -m unittest discover -s tests -v     # no network, no deps
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

---

## License

MIT — see [LICENSE](LICENSE).

---

<sub>RAPP Light is a trademark of Wildhaven Homes LLC. Code is MIT licensed; the license does not grant rights to the name. [Trademark notice](TRADEMARK.md)</sub>
