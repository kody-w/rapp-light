"""Strain Admin — elevation, in the same conversation, with the right credential.

A locked-down strain and a full brainstem are the same brainstem. The
difference is what the policy admits, and an administrator who holds the
strain's admin credential can change that from inside the chat rather than by
being handed a different build.

    posture      what this deployment admits (anyone)
    pending      what is withheld and would be approved by a click (anyone)
    approve      approve an exact byte sequence            (administrator)
    revoke       withdraw an approval                       (administrator)
    band         move the standing maturity ring            (administrator)
    forbid       forbid or restore a capability class       (administrator)

WHY ELEVATION IS A CREDENTIAL AND NOT A BUILD

If the locked-down deployment were a different program, an organisation would
be running two products: one that gets the security fix on Tuesday and one that
gets it whenever the hardened edition is rebuilt. Making elevation a credential
means there is exactly one brainstem, one release, and one thing to review —
and the compliance boundary is policy, which is inspectable, instead of
compilation, which is not.

WHAT HOLDING THE CREDENTIAL DOES NOT DO

It does not bypass the checks; it lets you change the policy the checks read.
An approval made here is written into the manifest, re-sealed, and enforced on
the next message exactly like one made with strainctl on the administrator's
own machine. There is no path through this agent that runs an agent the policy
would refuse — which is the property a reviewer will look for first.
"""

import hashlib
import hmac
import json
import os
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

        def to_tool(self):
            return {"type": "function", "function": {
                "name": self.name,
                "description": self.metadata.get("description", ""),
                "parameters": self.metadata.get("parameters", {})}}


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "@rapp/strain-admin",
    "tier": "core",
    "trust": "verified",
    "ring": "ga",
    "version": "1.0.0",
    "capabilities": ["credential-access", "filesystem-write"],
    "tags": ["strain", "admin", "compliance", "enterprise", "singleton"],
    "example_call": {
        "args": {"action": "posture"},
        "note": "What this deployment admits, and what is waiting on approval.",
    },
}

RINGS = ["ga", "public-preview", "private-preview", "frontier"]
CAPABILITIES = ["network", "process-exec", "credential-access",
                "filesystem-write", "dynamic-code"]


def _policy_organ():
    """Share one implementation of the rules with the enforcing organ. Two
    copies of a policy engine is one policy engine and one divergence."""
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, "aa_strain_policy_agent.py")
    if not os.path.isfile(p):
        return None
    spec = importlib.util.spec_from_file_location("_strain_policy_lib", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ORGAN = _policy_organ()


def _admin_hash(secret, salt):
    return hashlib.sha256((salt + ":" + secret).encode()).hexdigest()


class StrainAdminAgent(BasicAgent):
    def __init__(self):
        self.name = "StrainAdmin"
        self.metadata = {
            "name": self.name,
            "description": (
                "Administer this deployment's compliance policy. Anyone may see "
                "the posture and what is pending approval. With the "
                "organisation's admin credential, approve or revoke a specific "
                "capability, move the maturity band, or forbid a capability "
                "class — the same powers as the offline strainctl tool."),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string",
                               "enum": ["posture", "pending", "approve",
                                        "revoke", "band", "forbid", "whoami"],
                               "description": "What to do."},
                    "agent": {"type": "string",
                              "description": "For approve/revoke: the agent filename."},
                    "ring": {"type": "string", "enum": RINGS,
                             "description": "For band, or the ring to approve at."},
                    "capability": {"type": "string", "enum": CAPABILITIES,
                                   "description": "For forbid."},
                    "reason": {"type": "string",
                               "description": "Required to approve above the "
                                              "standing band, or to restore a "
                                              "forbidden capability class."},
                },
                "required": ["action"],
            },
        }
        super().__init__(name=self.name, metadata=self.metadata)

    # ---- elevation ----

    def _elevated(self, policy):
        """The credential is compared against a salted hash held in the sealed
        manifest, so the manifest never carries the secret itself."""
        secret = os.getenv("RAPP_STRAIN_ADMIN_KEY")
        adm = policy.get("admin") or {}
        want, salt = adm.get("key_sha256"), adm.get("key_salt") or ""
        if not want:
            return False, ("no administrator credential is configured for this "
                           "strain — run 'strainctl admin --set-key' on the "
                           "administrator's machine")
        if not secret:
            return False, ("RAPP_STRAIN_ADMIN_KEY is not set in this session")
        if not hmac.compare_digest(_admin_hash(secret, salt), want):
            return False, "the administrator credential does not match"
        return True, "elevated"

    def _load(self):
        if ORGAN is None:
            raise RuntimeError("aa_strain_policy_agent.py is not beside this "
                               "agent; the admin surface cannot run without the "
                               "policy engine it administers")
        path = ORGAN._strain_path()
        if not os.path.isfile(path):
            raise RuntimeError(f"no strain manifest at {path}")
        with open(path) as _fh:
            return path, json.load(_fh)

    def _save(self, path, man, event, detail):
        man["sealed_at"] = int(time.time())
        man["seal"] = ORGAN.seal_of(man)
        with open(path, "w") as fh:
            json.dump(man, fh, indent=2, sort_keys=True)
            fh.write("\n")
        try:
            log = man.get("audit_log") or os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "strain-audit.jsonl")
            with open(log, "a") as fh:
                fh.write(json.dumps({"at": int(time.time()), "event": event,
                                     **detail, "via": "strain-admin"}) + "\n")
        except OSError:
            pass

    def _find(self, filename):
        here = os.path.dirname(os.path.abspath(__file__))
        for cand in (os.path.join(here, filename),
                     os.path.join(os.path.dirname(here), "withheld", filename)):
            if os.path.isfile(cand):
                return cand
        return None

    # ---- the wire ----

    def perform(self, **kwargs):
        action = kwargs.get("action") or "posture"
        try:
            path, man = self._load()
            elevated, why = self._elevated(man)

            if action == "whoami":
                return json.dumps({
                    "status": "ok", "elevated": elevated, "detail": why,
                    "organisation": man.get("organisation"),
                    "band": man.get("band"),
                    "note": "elevation is a credential, not a different build — "
                            "the same brainstem serves both",
                }, indent=2)

            if action in ("posture", "pending"):
                here = os.path.dirname(os.path.abspath(__file__))
                hold = os.path.join(os.path.dirname(here), "withheld")
                pend = []
                if os.path.isdir(hold):
                    for fn in sorted(os.listdir(hold)):
                        if not fn.endswith("_agent.py"):
                            continue
                        _, rec = ORGAN.adjudicate(os.path.join(hold, fn), man)
                        obs, _e = ORGAN.observed_capabilities(
                            os.path.join(hold, fn))
                        pend.append({"agent": fn, "ring": rec.get("ring"),
                                     "reaches": sorted(obs),
                                     "withheld_because": rec.get("reason")})
                if action == "pending":
                    return json.dumps({
                        "status": "ok", "elevated": elevated,
                        "pending_count": len(pend), "pending": pend,
                        "next_step": ("approve one with action=approve, agent=<file>"
                                      if elevated else
                                      f"an administrator must approve these ({why})"),
                    }, indent=2)
                return json.dumps({
                    "status": "ok", "organisation": man.get("organisation"),
                    "band": man.get("band"),
                    "requires_allowlist": man.get("require_allowlist", True),
                    "forbidden_capabilities": man.get("forbidden_capabilities") or [],
                    "approved_count": len(man.get("allowlist") or {}),
                    "pending_count": len(pend),
                    "elevated": elevated, "elevation_detail": why,
                }, indent=2)

            # everything below changes policy
            if not elevated:
                return json.dumps({
                    "status": "refused", "action": action, "elevated": False,
                    "reason": why,
                    "note": "Anyone can read the posture; changing it needs the "
                            "organisation's administrator credential. Ask your "
                            "administrator, or run strainctl on a machine that "
                            "holds the key.",
                }, indent=2)

            if action == "approve":
                fn = kwargs.get("agent")
                target = self._find(fn) if fn else None
                if not target:
                    return json.dumps({"status": "error",
                                       "message": f"no such agent: {fn}"}, indent=2)
                decl = ORGAN.declared_capabilities(target)
                if decl is None:
                    return json.dumps({
                        "status": "refused",
                        "reason": "this file has no readable __manifest__, so it "
                                  "cannot be adjudicated and must not be approved",
                    }, indent=2)
                observed, evidence = ORGAN.observed_capabilities(target)
                declared = set(decl.get("capabilities") or [])
                undeclared = observed - declared
                if undeclared:
                    return json.dumps({
                        "status": "refused", "agent": fn,
                        "reason": "the code reaches capabilities the agent does "
                                  "not declare",
                        "undeclared": sorted(undeclared),
                        "evidence": [e for e in evidence
                                     if e["capability"] in undeclared],
                        "note": "approving this would admit an undeclared "
                                "capability under an approval that does not "
                                "mention it — fix the agent's __manifest__",
                    }, indent=2)
                ring = kwargs.get("ring") or decl.get("ring") or "frontier"
                band = man.get("band", "ga")
                exception = None
                if RINGS.index(ring) > RINGS.index(band):
                    if not kwargs.get("reason"):
                        return json.dumps({
                            "status": "refused", "agent": fn,
                            "reason": f"ring {ring!r} is above the standing band "
                                      f"{band!r}; approving it needs an explicit "
                                      f"reason recorded against the exception",
                            "retry_with": {"action": "approve", "agent": fn,
                                           "reason": "<why this exception>"},
                        }, indent=2)
                    exception = kwargs["reason"]
                sha = ORGAN._sha256_file(target)
                man.setdefault("allowlist", {})[sha] = {
                    "file": os.path.basename(target), "name": decl.get("name"),
                    "ring": ring, "capabilities": sorted(declared),
                    "approved_by": "strain-admin (in-session)",
                    "approved_at": time.strftime("%Y-%m-%d"),
                    **({"exception": exception} if exception else {}),
                }
                self._save(path, man, "agent.approved",
                           {"file": os.path.basename(target), "sha256": sha,
                            "ring": ring, "exception": exception})
                return json.dumps({
                    "status": "ok", "approved": os.path.basename(target),
                    "sha256": sha[:16], "ring": ring, "exception": exception,
                    "capabilities": sorted(declared),
                    "live": "on your next message — the policy organ re-admits it "
                            "on the next sweep",
                }, indent=2)

            if action == "revoke":
                fn = kwargs.get("agent")
                al = man.get("allowlist") or {}
                hits = [k for k, v in al.items() if v.get("file") == fn]
                if not hits:
                    return json.dumps({"status": "error",
                                       "message": f"nothing approved named {fn!r}"},
                                      indent=2)
                for k in hits:
                    al.pop(k)
                self._save(path, man, "agent.revoked", {"file": fn})
                return json.dumps({"status": "ok", "revoked": fn,
                                   "approvals_removed": len(hits),
                                   "live": "withheld from your next message onward"},
                                  indent=2)

            if action == "band":
                ring = kwargs.get("ring")
                if ring not in RINGS:
                    return json.dumps({"status": "error",
                                       "message": f"ring must be one of {RINGS}"},
                                      indent=2)
                old = man.get("band")
                man["band"] = ring
                self._save(path, man, "band.changed", {"from": old, "to": ring})
                return json.dumps({
                    "status": "ok", "band": {"from": old, "to": ring},
                    "widened": RINGS.index(ring) > RINGS.index(old or "ga"),
                    "note": "individual approvals are still required" if
                            man.get("require_allowlist", True) else
                            "this strain does not require an allowlist, so the "
                            "band alone now decides",
                }, indent=2)

            if action == "forbid":
                cap = kwargs.get("capability")
                if cap not in CAPABILITIES:
                    return json.dumps({"status": "error",
                                       "message": f"capability must be one of "
                                                  f"{CAPABILITIES}"}, indent=2)
                s = set(man.get("forbidden_capabilities") or [])
                if cap in s:
                    if not kwargs.get("reason"):
                        return json.dumps({
                            "status": "refused",
                            "reason": f"{cap!r} is currently forbidden; restoring "
                                      f"it widens what this organisation permits "
                                      f"and needs a recorded reason",
                        }, indent=2)
                    s.discard(cap)
                    ev, detail = "capability.restored", {"capability": cap,
                                                         "reason": kwargs["reason"]}
                else:
                    s.add(cap)
                    ev, detail = "capability.forbidden", {"capability": cap}
                man["forbidden_capabilities"] = sorted(s)
                self._save(path, man, ev, detail)
                return json.dumps({
                    "status": "ok", "forbidden_capabilities": sorted(s),
                    "note": "any agent whose code reaches a forbidden class is "
                            "withheld on the next message, approved or not",
                }, indent=2)

            return json.dumps({"status": "error",
                               "message": f"unknown action {action!r}"}, indent=2)
        except Exception as e:  # noqa: BLE001
            return json.dumps({"status": "error",
                               "message": f"{type(e).__name__}: {e}"}, indent=2)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "--tool":
        print(json.dumps(StrainAdminAgent().to_tool(), indent=2))
    else:
        raw = a[0] if a else (sys.stdin.read().strip() or '{"action":"posture"}')
        print(StrainAdminAgent().perform(**json.loads(raw)))
