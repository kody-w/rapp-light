# Threat model — RAPP Light (a RAPP strain)

This document exists to be argued with. It states what the control does, what
it does not do, and where the boundaries are, in the terms a security reviewer
uses. Where the honest answer is "this does not stop that", it says so — a
control that overclaims is the one that fails review, and worse, the one an
organisation relies on when it should not.

---

## 1. What the system is

A **RAPP strain** is the unmodified RAPP brainstem plus:

- `strain.json` — a sealed policy manifest
- `aa_strain_policy_agent.py` — an organ that enforces the policy on every turn
- `strain_admin_agent.py` — an in-session elevation surface
- `strainctl` — an offline administration tool

There is **no fork of the brainstem**. The kernel binary/source in a locked-down
deployment is byte-identical to the one everybody else runs. This is a
deliberate security property, not a convenience: a hardened fork receives
upstream security fixes late or never, and the gap between "the fix shipped" and
"the hardened edition rebuilt" is where real incidents live.

### 1.1 Trust boundaries

| # | Boundary | Crosses it |
|---|---|---|
| B1 | User ↔ brainstem process | chat messages, tool calls |
| B2 | Brainstem ↔ agent code | `load_agents()` imports and executes `agents/*_agent.py` |
| B3 | Brainstem ↔ model endpoint | prompts and completions, over TLS |
| B4 | Administrator ↔ policy | `strain.json`, seal key, admin credential |
| B5 | Deployment ↔ enterprise | the append-only audit log |

**B2 is the boundary this product exists to control.** An agent is Python that
the brainstem imports and runs in its own process. There is no sandbox between
them, and the strain does not add one — see §4.

---

## 2. Assets

| Asset | Why an attacker wants it |
|---|---|
| Corporate data reachable from the workstation | exfiltration |
| Credentials in the process environment | lateral movement |
| The model endpoint / API key | cost abuse, data egress |
| The policy manifest | the control itself; disabling it enables everything else |
| The audit log | destroying evidence |

---

## 3. Threats and dispositions

### T1 — An unreviewed agent is dropped into `agents/` and runs
**Mitigated.** Every `*_agent.py` must have a sha256 in the allowlist. Anything
else is moved out of the load path before it can run and is recorded in the
audit log. Default policy is deny: an empty allowlist means nothing runs.

### T2 — An approved agent is modified after approval
**Mitigated.** Approval is of a sha256, not of a filename. One changed byte is a
different identity and lands in `withheld/` with a message naming the original
approver and date.

### T3 — An agent acquires a capability its reviewer did not see
**Mitigated.** The `__manifest__` capability declaration is verified against the
file's abstract syntax tree. Undeclared network, process execution, credential
reads, filesystem writes or dynamic code cause a refusal — at approval time in
`strainctl`, and again at load time. An agent cannot gain reach without changing
bytes, and changing bytes triggers T2.

**Residual risk:** static analysis is decidable only for what it can see. An
approved agent that reaches capability through a path the analyser does not
model — a C extension, a dependency imported at runtime by name, a string
passed to a permitted helper — is not caught. This is why an allowlist is a
review process with a technical backstop, and not a substitute for review.

### T4 — The policy manifest is edited to widen what is admitted
**Mitigated, and it fails in the safe direction.** The manifest carries a seal
over its own policy content. On mismatch the runtime does not use the file; it
falls back to the most restrictive setting (band `ga`, allowlist required, empty
allowlist), which admits **nothing**. Tampering to widen the policy therefore
*narrows* it to zero. Verified by test `test_tamper_fails_closed`.

**Residual risk:** with `RAPP_STRAIN_SEAL_KEY` unset the seal is a plain
checksum, which anyone who can edit the file can recompute. The runtime reports
this as assurance `unsealed`/`sealed-checksum` rather than pretending
otherwise. Enterprises deploying this should distribute the seal key by the
same channel they use for any other machine configuration.

### T5 — A user elevates themselves to administrator
**Partially mitigated.** Elevation requires `RAPP_STRAIN_ADMIN_KEY` matching a
salted hash in the sealed manifest. Without the secret, the admin agent refuses
every state-changing action and only reports posture.

**Residual risk:** a user who obtains the credential is an administrator. That
is what a credential means. The mitigation is credential hygiene, not code.

### T6 — A user with local administrative rights disables the control
**NOT MITIGATED, BY CONSTRUCTION.** A user who owns the machine can edit the
organ, delete it, point `AGENTS_PATH` elsewhere, or run a different brainstem.

This is the same boundary every endpoint DLP product has, and it should be
stated the same way: **the control makes the compliant path the default path
and produces an attestable record; it is not a defence against a determined
local administrator.** Organisations that need that property need OS-level
controls (application allowlisting, MDM-managed file permissions, a managed
runtime), and the strain composes with those rather than replacing them.

The honest security value is real and worth naming: it eliminates *accidental*
non-compliance, which is the overwhelming majority of real incidents, and it
makes *deliberate* non-compliance leave a trace.

### T7 — Prompt injection causes the model to call a capability it should not
**Out of scope for the strain; narrowed by it.** The strain does not police the
model's reasoning. What it does is reduce the tool surface the model can reach
at all: a capability that is withheld cannot be called by any prompt, because
it is not loaded. Narrowing the band and forbidding capability classes is
therefore a direct mitigation for injection blast radius, even though it is not
an injection defence.

### T8 — Data egress to an unapproved host
**Partially mitigated.** `allowed_hosts` narrows the brainstem's existing
`BRAINSTEM_ALLOWED_HOSTS` control, and `forbidden_capabilities: ["network"]`
withholds any agent whose code can open a socket at all.

**Residual risk:** the model endpoint itself is by definition an approved
egress. Anything the model is told, leaves. This is a property of using a
hosted model, not of this control, and should be addressed in the model-hosting
decision.

### T9 — The audit log is deleted or forged
**Not mitigated locally.** It is a local append-only file written by the same
user. It is designed for **shipping** — the enterprise should collect it to a
SIEM, where deletion locally no longer erases it. The log deliberately contains
filenames, hashes and reasons but **never file contents**, so collecting it
does not exfiltrate proprietary capability source.

### T10 — Supply chain: a malicious agent is approved because it looked fine
**Not mitigated by this control.** The strain enforces *that* a human approved
specific bytes; it cannot make the review good. Its contribution is to make the
subject of review unambiguous (a hash, with a declared capability list verified
against the code) instead of a moving target.

### T11 — An approved agent makes the host fetch a package from an index
**Mitigated, and this is the estate's most concrete live exposure.**

The brainstem auto-installs missing dependencies: a module-level import it
cannot satisfy causes it to shell `pip install <name>` at load time and then
execute what comes back, in-process, as the user who owns the machine.

Measured on 2026-07-25 across the public registry:

| module | PyPI status | agents importing it |
|---|---|---|
| `basic_agent` | **404 — unclaimed; anyone could register it** | 105 |
| `agents` | 200 — **already owned by a third party** | 50 |
| `utils` | 200 — already owned by a third party | 17 |

So this is not a hypothetical typosquat. The names an honest agent imports are
already registrable or already registered by strangers.

The strain refuses any agent whose **module-level** imports are neither
standard library, nor bundled with the host, nor listed in the organisation's
`allowed_imports`. The check runs before the allowlist decision, so an
administrator learns a file is dangerous even under default-deny where
everything is unapproved anyway.

Imports **inside functions** are deliberately not flagged: they raise inside
the agent's own code and never reach the installer, so flagging them would be
noise — and a control that cries wolf gets switched off.

Deployments should additionally set `no-index` in the host venv's `pip.conf`
and `PIP_NO_INDEX=1` in the launcher, which makes the failure closed at the
installer itself rather than only at the policy layer.

**Residual risk:** an approved agent may still import a module the host *does*
have, and a compromised version of a legitimately-installed dependency is
outside this control. This narrows the fetch-at-load-time path; it is not a
substitute for controlling the host image.

---

## 4. Explicitly out of scope

- **Sandboxing.** Agents run in the brainstem's process with its privileges. The
  strain controls *which* agents load, not what a loaded agent may do at
  runtime. Do not deploy an approved agent you would not run as that user.
- **Model behaviour and content safety.** See `RAI.md`.
- **Defence against local administrators.** See T6.
- **Network-layer enforcement.** `allowed_hosts` is an in-process convention,
  not a firewall.

---

## 5. Deployment assumptions

1. Installed per-user, in the user's home directory, with no elevated
   permissions required and no system service registered (see `install.sh`).
2. Listens on loopback only, on an unprivileged port.
3. `RAPP_STRAIN_SEAL_KEY` is delivered by enterprise configuration management
   and is not present in the user's shell profile.
4. The audit log is collected off-machine.

Assumptions 3 and 4 are what move the deployment from "self-attested" to
"attestable". A deployment without them still works and still reports its own
posture honestly — it simply carries less assurance, and says so.

---

## 5a. Two behaviours a reviewer will notice

**Withheld files produce loader errors on the sweep that withholds them.**
`load_agents()` snapshots the file list and then loads each path; the policy
organ sorts first and moves withheld files during its own `__init__`, so the
loader reaches paths that no longer exist and prints
`Failed to load ...: [Errno 2] No such file or directory`. This is expected and
happens **once per withholding event** — on subsequent sweeps the file is
already outside the glob. The authoritative record of *why* something was
withheld is `strain-audit.jsonl` and `action=withheld`, not the loader log.

**The shared base class is never adjudicated.** `basic_agent.py` matches
`*_agent.py` but is not a capability and declares no `__manifest__`.
Withholding it would remove the class every agent imports. It is exempt, and
`test_the_shared_base_class_is_never_withheld` asserts it — this was a real
defect, found the first time the strain was run inside a live brainstem, that
every isolated test had missed.

## 6. Verification

The claims above are covered by the test suite (`tests/test_strain.py`), which
a reviewer can run in one command with no network access and no dependencies:

```bash
python3 -m unittest discover -s tests -v
```

Each test is named for the threat it covers.

The suite also reproduces `load_agents()`'s snapshot-then-load algorithm
exactly, with no brainstem and no dependencies, so the interaction that only
appears at runtime is covered anywhere the tests run.

**Live verification** (2026-07-25, brainstem on an isolated port, sandboxed
`HOME`): with one of four agents approved, the live loader reported exactly
`['StrainPolicy', 'JsonDoctor', 'StrainAdmin']`; the unapproved agents and an
agent importing an unregistrable package were in `withheld/`; `basic_agent.py`
remained on the load path; and the brainstem logged **zero** auto-install
attempts.
