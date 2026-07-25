"""Strain Credential — governed credential use, without the agent ever seeing a secret.

THE GAP THIS CLOSES
───────────────────
The strain governs what an agent may *do*. It says nothing about what an agent
may *hold*. Those are different questions with different owners, and answering
only the first leaves the most consequential one open.

Until now the strain's answer to credentials was to forbid the capability
outright: `credential-access` is a declared class, and an organisation that
forbids it stops agents touching secrets at all. That is a safe default and a
useless one. Real work needs real credentials. An agent that cannot deploy,
cannot call an API, and cannot read a database is an agent nobody adopts, and a
control nobody adopts protects nothing.

THE TWO-KEY MODEL
─────────────────
A credential is used only when two independent parties both agree, and they are
not the same party:

    the machine  ── RAPP Keyring ──▸  which PROCESS may hold this secret
                                      (owned by the user, on the device)

    the estate   ── the strain  ──▸   which AGENT may cause it to be used
                                      (owned by the administrator, in policy)

Neither is sufficient. Keyring cannot see inside the brainstem — every agent in
the process looks like one caller named `brainstem`, so Keyring alone cannot
distinguish the deploy agent from the note-taking agent. The strain can, because
it already identifies agents by the sha256 of their bytes. And the strain cannot
hold a secret safely, because a policy manifest is a file that gets copied,
mailed and committed. So the strain holds *grants*; Keyring holds *values*.

    strain.json  →  "this approved agent may use azure/*"     (names, never values)
    keyring      →  the bytes of azure/storage-key             (values, never names in policy)

THE SECRET IS NEVER RETURNED
────────────────────────────
This organ has no action that yields a credential. The only thing it can do is
ask Keyring to run a command with the credential injected into that command's
environment, with Keyring masking the value in everything the command prints.
The brainstem never receives the bytes, which means they never enter the model's
context, which means they never leave the machine.

That is the whole point, and it is why the organ's tool surface deliberately
lacks a `get`. There is no flag to add one. An administrator who genuinely needs
a plaintext value uses `rapp-keyring get --i-know` at a terminal, as a human,
and it is recorded as a sighted read in Keyring's own log.

WHAT IS ENFORCED AND WHAT IS RECORDED
─────────────────────────────────────
Enforced: the set of secrets reachable from this machine under this strain is
bounded by the manifest, and the bound is sealed. An LLM cannot widen it by
asking nicely, and a grant naming an agent that is not in the allowlist is
refused because the sha256 will not match.

Recorded, not enforced: *which* approved agent claimed to be the requester
inside a single brainstem process. All agents share one process; separating them
would need OS support this deliberately does not require. The claim is written
to the audit record and the union of grants bounds the blast radius. This is the
same boundary the threat model states for T6, and it is stated here rather than
implied, because a control trusted past its boundary is worse than no control.
"""

import ast
import fnmatch
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import time

try:
    from agents.basic_agent import BasicAgent
except ImportError:  # standalone — no brainstem required
    class BasicAgent:
        def __init__(self, name=None, metadata=None):
            if name:
                self.name = name
            if metadata:
                self.metadata = metadata

        def perform(self, **kwargs):
            return "Not implemented."

        def system_context(self):
            return ""

        def to_tool(self):
            return {"type": "function", "function": {
                "name": self.name,
                "description": self.metadata.get("description", ""),
                "parameters": self.metadata.get("parameters", {})}}


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "@rapp/strain-credential",
    "tier": "core",
    "trust": "verified",
    "ring": "ga",
    "version": "1.0.0",
    # Declared honestly and verified against this file's own syntax tree, like
    # every other agent the strain admits:
    #   credential-access — os.getenv for RAPP_STRAIN_* and broker discovery
    #   process-exec      — subprocess.run, to hand work to the broker
    #   filesystem-write  — appending to the audit record
    #
    # That last one was not in the first draft of this file. The strain's own
    # check 4 refused the organ until it was added, which is the control working
    # on its author. It is left documented rather than quietly corrected.
    "capabilities": ["credential-access", "process-exec", "filesystem-write"],
    "tags": ["strain", "credential", "keyring", "compliance", "enterprise",
             "singleton"],
    "example_call": {
        "args": {"action": "available"},
        "note": "Which credentials this strain may use — names only, never values.",
    },
}

BROKER = "rapp-keyring"
DEFAULT_BROKER_TIMEOUT = 900


# ── locating the strain (same rules as the policy organ) ─────────────────────

# Byte-for-byte the same resolution the policy organ uses. These two organs
# MUST agree on where the strain lives: if they disagree, one of them enforces a
# policy the other cannot see, which is worse than having no second organ at all.
# An earlier draft of this file resolved the agents directory from the
# environment instead, which agreed with the policy organ only by coincidence in
# the default layout.

def _agents_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _strain_path():
    env = os.getenv("RAPP_STRAIN_MANIFEST")
    if env:
        return os.path.abspath(env)
    here = _agents_dir()
    for cand in (os.path.join(os.path.dirname(here), "strain.json"),
                 os.path.join(here, "strain.json")):
        if os.path.isfile(cand):
            return cand
    return os.path.join(os.path.dirname(here), "strain.json")


def _seal_of(manifest):
    """Identical construction to the policy organ's seal, so one key covers the
    whole manifest and the credential section cannot be edited independently."""
    body = {k: v for k, v in manifest.items() if k not in ("seal", "sealed_at")}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    key = (os.getenv("RAPP_STRAIN_SEAL_KEY") or "").encode()
    if key:
        return "hmac-sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest():
    """An absent manifest is the most restrictive policy, not the absence of one.
    Failing open here would make deleting a file a privilege escalation."""
    path = _strain_path()
    if not os.path.isfile(path):
        return {"credentials": {"grants": {}}, "allowlist": {},
                "_assurance": "unsealed-absent",
                "_note": f"no strain manifest at {path}; no credential is grantable"}
    try:
        with open(path) as fh:
            man = json.load(fh)
    except (OSError, ValueError) as exc:
        return {"credentials": {"grants": {}}, "allowlist": {},
                "_assurance": "unreadable",
                "_note": f"strain manifest unreadable ({type(exc).__name__}); "
                         "no credential is grantable"}
    man.setdefault("credentials", {})
    man["credentials"].setdefault("grants", {})
    if man.get("seal"):
        man["_assurance"] = ("sealed" if hmac.compare_digest(
            str(man["seal"]), _seal_of(man)) else "ALTERED")
    else:
        man["_assurance"] = "unsealed"
    return man


# ── the broker ───────────────────────────────────────────────────────────────

def broker_path():
    """Find rapp-keyring. Absence is reported, never worked around."""
    return (os.getenv("RAPP_KEYRING_BIN") or shutil.which(BROKER)
            or os.path.expanduser(f"~/.local/bin/{BROKER}"))


def broker_available():
    path = broker_path()
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


def _broker(args, timeout=30):
    """Run the broker. Returns (rc, stdout, stderr) — never raises for a
    non-zero exit, because a policy denial is an ordinary outcome here."""
    path = broker_path()
    if not broker_available():
        return 127, "", (
            f"{BROKER} is not installed. The strain can grant a credential but "
            f"cannot broker one without it.\n"
            f"  curl -fsSL https://kody-w.github.io/rapp-keyring/install.sh | bash")
    try:
        proc = subprocess.run([path] + list(args), capture_output=True,
                              text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"{BROKER} timed out after {timeout}s"
    except OSError as exc:
        return 126, "", f"could not execute {BROKER}: {exc}"


def broker_names():
    """Secret names known to the broker. Names only — `list` never emits values."""
    rc, out, _err = _broker(["list", "--json"])
    if rc != 0:
        return []
    try:
        return sorted(json.loads(out).keys())
    except ValueError:
        return []


# ── grants ───────────────────────────────────────────────────────────────────

def _grant_patterns(man, agent_key):
    creds = man.get("credentials") or {}
    grants = creds.get("grants") or {}
    patterns = list(creds.get("default") or [])
    if agent_key and agent_key in grants:
        entry = grants[agent_key]
        patterns.extend(entry if isinstance(entry, list)
                        else (entry.get("allow") or []))
    return patterns


def _denied_patterns(man):
    creds = man.get("credentials") or {}
    return list(creds.get("deny") or [])


def resolve_agent_key(man, agent):
    """Map a claimed agent to an allowlist key, verifying its bytes.

    A grant that names an agent which is not approved, or whose file has changed
    since approval, resolves to nothing. That is the strain's existing identity
    check doing double duty: an agent cannot acquire a credential grant by being
    edited after it was approved.
    """
    if not agent:
        return None, "no agent named"
    allowlist = man.get("allowlist") or {}

    for key, entry in allowlist.items():
        if entry.get("file") == agent or key == agent:
            path = os.path.join(_agents_dir(), entry.get("file", ""))
            recorded = entry.get("sha256") or key
            if os.path.isfile(path):
                actual = _sha256_file(path)
                if recorded and actual != recorded:
                    return None, (
                        f"{entry.get('file')} has changed since it was approved "
                        f"(recorded {recorded[:12]}, on disk {actual[:12]}) — "
                        "its grants do not apply until it is re-approved")
            return key, "approved"
    return None, f"{agent!r} is not in the strain allowlist"


def adjudicate(man, agent, requested):
    """Decide whether `agent` may cause `requested` secret names to be used.

    Returns (allowed: list, refused: list of (name, reason)).
    """
    allowed, refused = [], []

    if man.get("_assurance") == "ALTERED":
        return [], [(n, "the strain manifest seal does not verify — refusing "
                        "every credential until it is re-sealed") for n in requested]

    key, why = resolve_agent_key(man, agent)
    if key is None:
        return [], [(n, why) for n in requested]

    patterns = _grant_patterns(man, key)
    denies = _denied_patterns(man)

    for name in requested:
        blocked = next((p for p in denies if fnmatch.fnmatch(name, p)), None)
        if blocked:
            refused.append((name, f"denied by the strain rule {blocked!r}"))
            continue
        match = next((p for p in patterns if fnmatch.fnmatch(name, p)), None)
        if match:
            allowed.append(name)
        else:
            refused.append((name, (
                f"the strain grants this agent no credential matching {name!r}"
                if patterns else
                "the strain grants this agent no credentials at all")))
    return allowed, refused


# ── audit ────────────────────────────────────────────────────────────────────

def audit_path(man):
    return (man.get("audit_log")
            or os.path.join(os.path.dirname(_agents_dir()), "strain-audit.jsonl"))


def record(man, event, **fields):
    """Append to the strain audit record.

    Names, decisions and reasons only — never a value, so the log can be shipped
    to a SIEM without becoming the leak it exists to detect.
    """
    entry = {"at": int(time.time()), "event": event}
    entry.update(fields)
    dest = audit_path(man)

    # One implementation of the chain, borrowed from the policy organ rather
    # than reimplemented here. Two implementations of one rule is one
    # implementation and one bug waiting to be found in production.
    policy_organ = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "aa_strain_policy_agent.py")
    if os.path.isfile(policy_organ):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("_sp", policy_organ)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.chain_append(dest, entry)
            return
        except Exception:  # noqa: BLE001 — never let auditing break the caller
            pass
    try:
        with open(dest, "a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        pass


# ── the organ ────────────────────────────────────────────────────────────────

class StrainCredentialAgent(BasicAgent):
    def __init__(self):
        self.name = "StrainCredential"
        self.metadata = {
            "name": self.name,
            "description": (
                "Use a credential without ever seeing it. Reports which "
                "credentials this deployment may use and runs a command with one "
                "injected by the broker. There is no action that returns a "
                "secret value — by design."),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["available", "check", "use", "explain"],
                        "description":
                            "available: credential names this strain may use. "
                            "check: would a given agent be granted a given "
                            "credential, and why. "
                            "use: run a command with credentials injected. "
                            "explain: how governed credential use works.",
                    },
                    "agent": {"type": "string",
                              "description": "The approved agent filename acting."},
                    "credential": {"type": "string",
                                   "description": "Credential name or glob."},
                    "command": {"type": "array", "items": {"type": "string"},
                                "description": "For use: argv of the command to run."},
                },
                "required": ["action"],
            },
        }
        super().__init__(name=self.name, metadata=self.metadata)

    # perform() must never raise: an exception here would take down the
    # brainstem this organ exists to make safe.
    def perform(self, **kwargs):
        try:
            return self._perform(**kwargs)
        except Exception as exc:  # noqa: BLE001 — deliberately total
            return json.dumps({"status": "error",
                               "detail": f"{type(exc).__name__}: {exc}"}, indent=2)

    def _perform(self, **kwargs):
        action = (kwargs.get("action") or "available").strip()
        man = load_manifest()

        if action == "explain":
            return self._explain(man)
        if action == "available":
            return self._available(man)
        if action == "check":
            return self._check(man, kwargs)
        if action == "use":
            return self._use(man, kwargs)
        return json.dumps({"status": "error",
                           "detail": f"unknown action {action!r}"}, indent=2)

    def _available(self, man):
        known = broker_names()
        creds = man.get("credentials") or {}
        grants = creds.get("grants") or {}
        reachable = set()
        for entry in list(grants.values()) + [creds.get("default") or []]:
            patterns = entry if isinstance(entry, list) else (entry.get("allow") or [])
            for pattern in patterns:
                reachable.update(n for n in known if fnmatch.fnmatch(n, pattern))
        for pattern in _denied_patterns(man):
            reachable.difference_update(
                {n for n in reachable if fnmatch.fnmatch(n, pattern)})
        return json.dumps({
            "status": "ok",
            "broker": BROKER,
            "broker_installed": broker_available(),
            "seal": man.get("_assurance"),
            "stored_on_this_machine": len(known),
            "reachable_under_this_strain": sorted(reachable),
            "agents_with_grants": sorted(grants.keys()),
            "note": "Names only. No action of this organ returns a value.",
        }, indent=2)

    def _check(self, man, kwargs):
        agent = kwargs.get("agent")
        credential = kwargs.get("credential")
        if not credential:
            return json.dumps({"status": "error",
                               "detail": "check needs a credential"}, indent=2)
        requested = ([credential] if not any(c in credential for c in "*?[")
                     else [n for n in broker_names()
                           if fnmatch.fnmatch(n, credential)] or [credential])
        allowed, refused = adjudicate(man, agent, requested)
        return json.dumps({
            "status": "ok",
            "agent": agent,
            "granted": allowed,
            "refused": [{"credential": n, "reason": r} for n, r in refused],
        }, indent=2)

    def _use(self, man, kwargs):
        agent = kwargs.get("agent")
        credential = kwargs.get("credential")
        command = kwargs.get("command") or []
        if not credential or not command:
            return json.dumps({
                "status": "error",
                "detail": "use needs both a credential and a command"}, indent=2)

        requested = ([credential] if not any(c in credential for c in "*?[")
                     else [n for n in broker_names()
                           if fnmatch.fnmatch(n, credential)] or [credential])
        allowed, refused = adjudicate(man, agent, requested)

        if not allowed:
            record(man, "credential.refused", agent=agent, credential=credential,
                   reason=refused[0][1] if refused else "no grant")
            return json.dumps({
                "status": "refused",
                "agent": agent,
                "refused": [{"credential": n, "reason": r} for n, r in refused],
                "remedy": "An administrator can grant this with: "
                          f"strainctl cred grant {agent or '<agent>'} '{credential}'",
            }, indent=2)

        args = ["run"]
        for name in allowed:
            args += ["--grant", name]
        args += ["--"] + [str(c) for c in command]
        rc, out, err = _broker(args, timeout=DEFAULT_BROKER_TIMEOUT)

        record(man, "credential.used", agent=agent, credentials=sorted(allowed),
               command=str(command[0]), exit_code=rc,
               refused=[n for n, _ in refused])

        return json.dumps({
            "status": "ok" if rc == 0 else "command-failed",
            "agent": agent,
            "credentials_injected": sorted(allowed),
            "refused": [{"credential": n, "reason": r} for n, r in refused],
            "exit_code": rc,
            # Output arrives already masked by the broker: any occurrence of a
            # secret has been replaced before it reached this process, so it
            # cannot enter the model's context from here.
            "stdout": out[-4000:],
            "stderr": err[-2000:],
            "note": "The value was injected into the command's environment and "
                    "masked in its output. It was never returned to this agent.",
        }, indent=2)

    def _explain(self, man):
        return json.dumps({
            "status": "ok",
            "model": "two keys, two owners",
            "machine": "RAPP Keyring decides which PROCESS may hold a secret. "
                       "Owned by the user, on the device.",
            "estate": "The strain decides which AGENT may cause one to be used. "
                      "Owned by the administrator, in sealed policy.",
            "why_both": "Keyring cannot see inside the brainstem — every agent "
                        "looks like one caller. The strain can, because it "
                        "identifies agents by the sha256 of their bytes. And a "
                        "policy manifest is a file that gets copied and "
                        "committed, so it must never hold a value.",
            "no_sighted_read": "This organ has no action that returns a secret. "
                               "A human who needs a plaintext value uses "
                               "`rapp-keyring get --i-know` at a terminal, and "
                               "it is recorded as a sighted read.",
            "enforced": "The set of secrets reachable under this strain is "
                        "bounded and sealed. A grant naming an agent that is not "
                        "approved, or whose bytes changed since approval, does "
                        "not apply.",
            "recorded_not_enforced": "Which approved agent claimed to be acting, "
                                     "within one brainstem process. Separating "
                                     "agents by process would need OS support "
                                     "this deliberately does not require.",
        }, indent=2)

    def system_context(self):
        """Injected every turn. Without it the model invents a credential story —
        usually that it should read the secret and paste it somewhere."""
        man = load_manifest()
        if not broker_available():
            return ("CREDENTIALS: no credential broker is installed, so no agent "
                    "on this machine can use a credential. Do not ask the user to "
                    "paste a secret into the conversation; tell them to install "
                    "rapp-keyring instead.\n")
        creds = man.get("credentials") or {}
        if not (creds.get("grants") or creds.get("default")):
            return ("CREDENTIALS: this strain grants no agent any credential. If a "
                    "task needs one, say so plainly and name the administrator "
                    "action required. Never ask the user to paste a secret into "
                    "the conversation.\n")
        return (
            "CREDENTIALS: credentials are available to approved agents through a "
            "broker, and you cannot see their values — this is deliberate. To use "
            "one, call StrainCredential with action='use', naming the agent, the "
            "credential and the command. The value is injected into that command "
            "and masked in its output. There is no way to read a secret, so do "
            "not try, and never ask the user to paste one into the conversation.\n")


# Instantiated by load_agents() on every turn.
if __name__ != "__main__":
    try:
        AGENT = StrainCredentialAgent()
    except Exception:  # noqa: BLE001 — an organ must never break the loader
        AGENT = None
