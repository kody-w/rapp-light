# Maturity rings

Enterprise adoption of a capability is not a yes/no decision, so RAPP Light
does not model it as one. Every capability declares a ring, and an organisation
declares the band it admits.

```
   frontier  ▸  private-preview  ▸  public-preview  ▸  ga
   ◀── more experimental                      more assured ──▶
```

## What each ring commits to

| Ring | Means | Support | Interface stability | Typical use |
|---|---|---|---|---|
| `frontier` | exists, works for its author | none | may change without notice | RAPP-internal, one team, eyes-on |
| `private-preview` | works for named organisations | best effort, named contact | may change with notice | a design partnership |
| `public-preview` | works for anyone who tries it | community | breaking changes flagged | a pilot with a rollback plan |
| `ga` | works, and stays working | supported | stable within the major version | default for a population |

A ring is a statement about **assurance and change**, not about quality. A
`frontier` capability may be excellent; the point is that nobody has promised it
will still behave the same next month.

## How an organisation uses them

Start at `ga`. Everything above it is withheld and every withholding is
reported, so the band is a deliberate decision rather than a default nobody
revisited.

```bash
strainctl init "Contoso Ltd" --band ga
```

**Widen the standing band** when the organisation as a whole is ready:

```bash
strainctl band public-preview
```

**Or admit one capability above the band** without moving everyone, which is the
usual case:

```bash
strainctl approve ./agents/log_detective_agent.py \
  --exception "SRE pilot; review 2026-10-01" --by secops@contoso.example
```

Every exception is recorded with an approver, a date and a reason, and surfaces
in `strainctl report` — so "why is this frontier thing running in production"
always has an answer.

## The band expands; it does not leak

Raising the band changes what **may be approved**. It does not admit anything on
its own while `require_allowlist` is true, which is the default. Asserted by
`test_raising_the_band_does_not_bypass_the_allowlist`.

## Declaring a ring

Two fields in an agent's existing `__manifest__`:

```python
__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "@rapp/json-doctor",
    "version": "1.0.0",
    "ring": "ga",
    "capabilities": [],          # verified against the code, not trusted
}
```

An agent that declares no ring is treated as `frontier` — the most restricted
reading, so forgetting to declare cannot accidentally widen anything. Asserted
by `test_an_agent_with_no_ring_is_treated_as_frontier`.

## Relationship to the release train

RAPP's release train (canary → nightly → alpha → beta → grail) is about **how a
change reaches production**. Rings are about **how much an organisation is
willing to depend on a capability**. They are different axes and deliberately
not merged: a capability can be fully released and still be `frontier`, and a
`ga` capability still enters at canary like everything else.
