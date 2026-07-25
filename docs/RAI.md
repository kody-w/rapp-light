# Responsible AI posture — RAPP Light

## 1. What the system decides, and what a human decides

| Decision | Made by |
|---|---|
| Which capabilities exist in the deployment | **a human administrator**, per exact byte sequence |
| Which maturity ring the organisation admits | **a human administrator** |
| Whether an agent's declared capabilities match its code | the system, mechanically, from the syntax tree |
| Whether a given capability runs on a given turn | the model, from the user's request, within the above |
| Whether to widen the band or grant an exception | **a human administrator**, with a recorded reason |

No policy change is ever made automatically. The system's only autonomous
action is **withholding** — the restrictive direction. It never admits anything
on its own.

## 2. Failure direction

Every ambiguity resolves toward less capability:

- No policy file → nothing runs (not "no policy, so everything runs").
- Policy fails its seal → nothing runs.
- Undeclared ring → treated as the most experimental ring.
- Undeclared capability → refused, even with an administrator's approval.
- Policy tampered to widen → narrows to zero.

This is asserted, not asserted-about: see `tests/test_strain.py`.

## 3. Transparency to the user

A user on a restricted deployment must never experience a capability silently
not happening. The policy organ injects the posture into the system prompt every
turn, and instructs the assistant to:

- say plainly that a capability is withheld,
- give the actual reason (ring above the band, not approved, forbidden class),
- name that an administrator can approve it,
- **not** attempt a workaround.

An assistant that quietly routes around a compliance control is a worse outcome
than one that cannot do the task, and this is the instruction that prevents it.

## 4. Contestability

A user can always ask what is withheld and why (`action: "withheld"`), without
any credential. The reason strings are written to be actionable by the person
reading them — naming the original approver and date when an approved agent was
edited, rather than an opaque "not permitted".

## 5. Accountability

Every withholding, re-admission, approval, revocation, band change and
capability restriction is written to an append-only audit record with a
timestamp. Approvals carry an approver identity and, above the band, a written
reason. The record is designed for collection off-machine.

## 6. Scope boundaries

This control governs **which capabilities are loaded**. It does not:

- evaluate model outputs for harm, bias or accuracy,
- constrain what an approved agent does once loaded,
- provide content filtering or safety classification.

Those are properties of the model deployment and of the individual agents, and
must be reviewed there. What the strain contributes to the safety story is
**blast-radius reduction**: a capability that is withheld cannot be invoked by
any prompt, including an injected one, because it is not loaded at all.

## 7. Human oversight in practice

The intended operating model is that an organisation starts at `ga` with an
empty allowlist — a deployment that can converse and do nothing else — and adds
capabilities one reviewed hash at a time. The default is not "audit what
happened"; it is "nothing happens until someone approved it".
