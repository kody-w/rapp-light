# Deployment — getting a strain onto a fleet

The one-liner install works for one machine. This is the part that decides
whether an organisation adopts: how policy reaches five hundred of them, how it
stays current, and what happens at three in the morning when something is wrong.

---

## The shape of it

```
   configuration management            each machine
   (Intune / Jamf / Ansible / GPO)
                                        ~/.brainstem/
        strain.json  ────────────────▸    strain.json      ← policy, sealed
        seal key     ────────────────▸    (env, not on disk)
                                          agents/*.py      ← organs + agents
                                          strain-audit.jsonl ─▸ SIEM
```

Three things are distributed. Two of them are files; one of them must never be.

| Artifact | How it travels | Notes |
|---|---|---|
| `strain.json` | config management, as a managed file | sealed; safe to store in the tool |
| the seal key | a secret store your CM already has | **never** a file on the endpoint, never a shell profile |
| the organs | the installer, or an offline bundle | byte-identical everywhere |

## Why the seal key must not land on the endpoint

The seal is an HMAC when `RAPP_STRAIN_SEAL_KEY` is set, and a plain checksum
when it is not. A checksum seal detects accidental edits. It does not stop a
determined user, because anyone can recompute a checksum over a policy they
just widened.

So the key is what makes the seal mean anything — and a key sitting in
`/etc/rapp/seal.key` on the same machine as the policy it protects is not a
control, it is a formality. Inject it into the process that runs `strainctl`,
in your CM run, and let it leave with that process.

```bash
# Ansible, as an example — the key comes from the vault and is never written
- name: apply strain policy
  environment:
    RAPP_STRAIN_SEAL_KEY: "{{ vault_rapp_seal_key }}"
  ansible.builtin.command: strainctl verify
```

Endpoints do **not** need the key. Verification of a seal needs it; *creating* a
narrower policy locally is exactly what you are preventing. A machine with no
key can read its policy and enforce it, and can change nothing.

## Rollout, deliberately slow

A capability band that moves for everyone at once is the change that gets the
whole control switched off after one bad week.

**Weeks 1–2 — observe.** Install with `enforce: false`. Nothing is withheld;
everything that *would* be withheld is recorded. At the end you have a real
inventory of what your people actually run, rather than a guess.

```bash
strainctl init "Contoso Ltd" --band ga
python3 -c "import json;p='$HOME/.brainstem/strain.json';m=json.load(open(p));m['enforce']=False;json.dump(m,open(p,'w'),indent=2)"
strainctl seal
```

**Weeks 3–4 — approve what survives.** Read the record. Approve the agents your
teams depend on, by bytes. Anything reaching a capability it does not declare
gets fixed by its author, not force-approved.

```bash
strainctl scan ~/.brainstem/agents
strainctl approve ~/.brainstem/agents/json_doctor_agent.py --by secops@contoso.example
```

**Week 5 — enforce.** Flip `enforce` on for one pilot group. The band stays at
`ga`; individual exceptions carry a reason and a date.

**Ongoing — widen by exception, not by band.** One team piloting one
`public-preview` capability is an approval with an exception. It is not a reason
to move the population's band.

```bash
strainctl approve agents/log_detective_agent.py \
  --exception "SRE pilot, review 2026-10-01" --by secops@contoso.example
```

## Credentials

Grants are part of the sealed manifest and travel with it. Values are not, and
never travel — they are placed on each machine's own broker, by whatever
mechanism already puts secrets on your endpoints.

```bash
strainctl cred grant deploy_agent.py 'azure/*'
strainctl cred deny 'prod/*'          # outranks every grant, everywhere
```

See [CREDENTIALS.md](CREDENTIALS.md) for the two-key model.

## Shipping the record to a SIEM

The audit record is append-only JSONL, hash-chained, and contains names,
decisions and reasons — never a credential value and never a line of agent
source. It is designed to be tailed.

```bash
# JSON lines, for anything modern
strainctl audit export --format jsonl >> /var/log/rapp/strain.jsonl

# CEF, for what most SIEMs still ingest without a custom parser
strainctl audit export --format cef | logger -t rapp-light
```

Verify before you trust a period of it:

```bash
strainctl audit verify     # exits 2 if the chain is broken, and names the record
```

Chain verification detects modification, deletion and forged appends. It does
not prevent deletion of the whole file — no user-space tool writing to the
user's own home directory can. Forwarding is the mitigation; a record already in
your SIEM cannot be edited by deleting a local file.

## Air-gapped and offline installs

The installer makes **no network calls** when the files are already beside it,
which is the path to use when you want an authenticated install rather than
merely an intact one:

```bash
git clone https://github.com/kody-w/rapp-light && cd rapp-light
git verify-tag v1.0.0          # verify provenance yourself
./install.sh                   # installs from the local bundle, no network
```

Over the network the installer verifies **integrity** — every fetched file must
parse and carry an expected marker, so a truncated download fails loudly instead
of installing something half-formed. That is not authenticity. If you need
authenticity, use the bundle above.

## Upgrades

The strain rides the same grail brainstem as everyone else, which is the whole
argument for it being a strain and not a fork: a grail security fix reaches the
locked-down deployment the same day it reaches everyone else.

Re-running the installer replaces the organs and leaves `strain.json` alone.
After any upgrade:

```bash
strainctl verify          # the seal still matches
python3 conformance.py    # the build still does what it claims
```

## Removing it

```bash
rm -rf ~/.brainstem/agents/aa_strain_policy_agent.py \
       ~/.brainstem/agents/strain_admin_agent.py \
       ~/.brainstem/agents/strain_credential_agent.py
```

Stated plainly because it is true, and because a user with a shell will find it
in a minute anyway. The strain is not a sandbox — `docs/THREAT-MODEL.md` T6 says
so. It makes the compliant path the default path and leaves an attestable record
of what ran. An organisation that needs a control a user cannot remove needs
endpoint management, and RAPP Light is meant to sit *inside* that, not replace it.
