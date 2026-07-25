# Security policy

## Reporting a vulnerability

Open a private advisory:
<https://github.com/kody-w/rapp-light/security/advisories/new>

Include the version, the platform, and a reproduction. If your finding is that
something in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) is *worse than
described*, that is a valid and welcome report — the threat model is written to
be argued with.

## What is in scope

- A way to load an agent the strain should have withheld.
- A way to make an agent's code reach a capability it did not declare, without
  changing its bytes.
- A way to obtain a credential value through the credential organ.
- A way to edit the audit record without `strainctl audit verify` detecting it.
- A way to widen policy without the seal key.

## What is out of scope, and why

These are stated as non-goals in the threat model, not as oversights:

- **A local user editing their own files.** The strain is not a sandbox. Neither
  is data loss prevention. A user who owns the machine can disable it, and T6
  says so.
- **A granted secret being misused by the command it was granted to.** `use`
  hands the value to that command. That is the entire operation.
- **Deletion of the audit record.** Tampering is detectable; destruction is not
  preventable by a user-space tool writing to the user's own home directory.
  Forward the record if that gap matters to you.

A report that one of these is possible will be closed as working-as-documented.
A report that one of these is *worse than the threat model claims* will not.

## Verifying a build yourself

```bash
python3 conformance.py                        # 14 checks, proved against the code
python3 -m unittest discover -s tests -v      # the full suite
```

Every claim in the README has a conformance check or a named test. If a claim
has neither, treat the claim as unproven and say so in an issue.
