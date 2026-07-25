# Compliance notes — RAPP Light

Written for a reviewer who needs to answer "what does this touch, and what
leaves the machine".

## 1. Data flows

| Flow | Contents | Destination | Controlled by |
|---|---|---|---|
| F1 user ↔ brainstem | chat text, tool arguments and results | loopback only | never leaves the machine |
| F2 brainstem → model | system prompt, conversation, tool schemas | the configured model endpoint, TLS | the model-hosting decision, not this control |
| F3 agent → anywhere | whatever an approved agent does | wherever that agent connects | `forbidden_capabilities: ["network"]`, `allowed_hosts`, and the approval itself |
| F4 strain → enterprise | the audit log | wherever the enterprise collects it | the enterprise |

**F2 is the flow that matters most and this control does not narrow it.**
Anything the model is told, leaves the machine. That is a property of using a
hosted model; address it in the hosting decision (a tenant-bound endpoint, a
private deployment), not here. Stated in the threat model as T8.

## 2. What the strain itself writes

| File | Contents | Sensitive? |
|---|---|---|
| `strain.json` | policy, allowlist of hashes, salted admin hash | contains no secrets; safe to store in configuration management |
| `strain-audit.jsonl` | timestamps, filenames, sha256s, ring, reason | **no file contents** — safe to ship to a SIEM |
| `withheld/` | agent files moved off the load path | as sensitive as the agents themselves |

The audit log deliberately excludes source. Asserted by
`test_T9_the_log_never_contains_file_contents`.

## 3. Credentials

| Credential | Where it lives | Where it does **not** live |
|---|---|---|
| `RAPP_STRAIN_SEAL_KEY` | enterprise configuration management | not in `strain.json`, not in the repo, not in a user profile |
| `RAPP_STRAIN_ADMIN_KEY` | the administrator's session | only a salted sha256 is stored in `strain.json` |
| model endpoint credential | the brainstem's own configuration | unchanged by this control |

Losing the admin credential means setting a new one, not recovering the old one.

## 4. Retention

Nothing in the strain expires anything. The audit log grows only on transitions
— a steady state adds no lines, so rotation is an ordinary log-rotation concern
rather than a volume problem. Asserted by
`test_T9_a_steady_state_does_not_grow_the_log`.

## 5. Installation footprint

- Per-user, under the user's home directory.
- No administrator rights, no system service, no registry keys, no PATH changes
  outside `~/.local/bin`.
- Loopback-only listener on an unprivileged port.
- Uninstall is deleting a directory.

## 6. Offline / air-gapped deployment

The strain has no runtime network dependency of its own. `strainctl`, the organ
and the tests all run with no network access. An air-gapped deployment sets
`forbidden_capabilities: ["network"]`, which withholds any agent whose code can
open a socket at all — enforced by static analysis, not by trust.

## 7. Change management

`strainctl report` emits a JSON posture record — band, approvals by ring, every
exception with its approver and date, and whether the policy seal is intact.
Collected periodically, this is a complete change history of what the
deployment was permitted to do, without needing access to the deployment.

## 8. What this does not provide

Read `THREAT-MODEL.md` §4 and T6 before relying on this for anything. In short:
it is not a sandbox, it does not constrain what an approved agent does at
runtime, and it does not defend against a user with local administrative rights.
It makes the compliant path the default and leaves an attestable record.
