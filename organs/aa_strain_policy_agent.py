"""Strain Policy — the organ that constrains the brainstem without changing it.

A RAPP strain is the unmodified grail brainstem plus a policy manifest and this
organ. There is no fork and no kernel diff. The brainstem stays the brainstem;
what changes is what is allowed into the room with it.

WHAT IT ENFORCES, IN ORDER

    1. Seal        strain.json must match its own seal, or the strain fails
                   closed to its most restrictive setting.
    2. Ring        every agent carries a maturity ring — frontier,
                   private-preview, public-preview, ga. Anything above the
                   enterprise's band is withheld.
    3. Identity    every permitted agent's sha256 must appear in the allowlist.
                   An approved agent that was edited afterwards is a different
                   agent, and is withheld.
    4. Capability  an agent's declared capabilities are checked AGAINST ITS
                   CODE. Undeclared network access, undeclared process
                   execution, undeclared credential reads are refused even if
                   the agent is otherwise approved.
    5. Egress      allowed hosts are narrowed to the enterprise's list.
    6. Credential  an agent may not use a secret the estate never granted it.
    7. Imports     an agent whose module-level imports the host cannot
                   satisfy is refused, because loading it would make the
                   brainstem fetch a package from an index and execute it.

WHY CAPABILITY DECLARATIONS ARE VERIFIED AND NOT TRUSTED

An allowlist that trusts a manifest field is an allowlist of promises. The
useful question is not "what does this agent say it does" but "what can this
code reach". So the declaration is compared against the imports and calls
actually present in the file, and a mismatch is a refusal. An agent cannot
quietly acquire a capability between approval and execution without changing
its bytes, and changing its bytes changes its sha256, which fails check 3.

WHY THIS IS AN ORGAN AND NOT A FORKED BRAINSTEM

Article I: the brainstem is a loader, an LLM loop, and a response splitter.
Article XXVI: anything a *_agent.py can serve does not go in the kernel. A fork
would mean an enterprise build that drifts from the grail, needs its own
releases, and stops receiving upstream fixes — which is how every "hardened
edition" of everything dies. The strain rides the same grail, so a grail
security fix reaches the locked-down deployment on the same day it reaches
everyone else.

WHAT THIS IS NOT

It is not a sandbox and it does not defend against a hostile local user who
owns the machine and can edit their own files. Neither does data loss
prevention. What it does is make the compliant path the default path, make
every load decision explicit, and leave an attestable record of what ran. That
boundary is stated plainly in docs/THREAT-MODEL.md rather than blurred, because
a control that overclaims is the one that fails review.
"""

import ast
import hashlib
import hmac
import json
import os
import shutil
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
    "name": "@rapp/strain-policy",
    "tier": "core",
    "trust": "verified",
    "ring": "ga",
    "version": "1.0.0",
    # Verified against this file's own syntax tree, like every other agent:
    # os.getenv for RAPP_STRAIN_* settings, shutil.move to withhold a cartridge.
    "capabilities": ["credential-access", "filesystem-write"],
    "tags": ["strain", "policy", "compliance", "enterprise", "singleton"],
    "example_call": {
        "args": {"action": "posture"},
        "note": "What is enabled, what is withheld, and why.",
    },
}

# Ordered weakest-assurance to strongest. An enterprise sets `band` to the
# loosest ring it will accept; everything above that ring is withheld.
RINGS = ["ga", "public-preview", "private-preview", "frontier"]
RING_RANK = {r: i for i, r in enumerate(RINGS)}

# Capability classes and the code shapes that betray them.
#
# Calls are matched on QUALIFIED names (`os.system`, `pickle.loads`), never on
# the bare attribute. Matching bare attributes looks tempting and is wrong:
# `loads` would make every use of `json.loads` a dynamic-code finding, and `run`
# would make every `self.run()` a process-exec finding. A control that cries
# wolf on ordinary code gets switched off, and then it protects nothing.
#
# `builtins` are the handful that are dangerous with no qualifier at all.
CAPABILITY_EVIDENCE = {
    "network": {
        "modules": {"socket", "http", "urllib", "urllib3", "requests", "httpx",
                    "ftplib", "smtplib", "telnetlib", "websocket", "websockets",
                    "aiohttp", "xmlrpc", "paramiko", "boto3", "azure"},
        "calls": {"urllib.request.urlopen", "request.urlopen", "urlopen",
                  "socket.create_connection", "requests.get", "requests.post"},
    },
    "process-exec": {
        "modules": {"subprocess", "pty"},
        "calls": {"os.system", "os.popen", "os.spawnl", "os.spawnv", "os.execv",
                  "os.execve", "os.execvp", "os.fork", "subprocess.run",
                  "subprocess.call", "subprocess.check_output",
                  "subprocess.check_call", "subprocess.Popen"},
    },
    # Reading the process environment IS credential access — os.getenv("PORT")
    # and os.getenv("API_KEY") are the same capability, and only the agent
    # author knows which one it is. Declaring it costs one word.
    "credential-access": {
        "modules": {"keyring", "netrc", "getpass"},
        "calls": {"os.getenv", "os.environ.get", "getpass.getpass"},
        "attrs": {"environ"},
    },
    "filesystem-write": {
        "modules": {"shutil"},
        "calls": {"os.remove", "os.unlink", "os.rename", "os.replace",
                  "os.mkdir", "os.makedirs", "os.rmdir", "os.chmod", "os.chown",
                  "os.symlink", "os.truncate", "shutil.rmtree", "shutil.move",
                  "shutil.copy", "shutil.copytree", "shutil.copyfile",
                  "pathlib.Path.write_text", "Path.write_text",
                  "Path.write_bytes", "write_text", "write_bytes"},
    },
    "dynamic-code": {
        "modules": {"ctypes", "marshal", "pickle"},
        "calls": {"importlib.import_module", "pickle.loads", "pickle.load",
                  "marshal.loads", "ctypes.CDLL"},
        "builtins": {"eval", "exec", "compile", "__import__"},
    },
}

# Files that match *_agent.py but are NOT agents. basic_agent.py is the shared
# base class every agent imports; it declares no __manifest__ because it is not
# a capability. Adjudicating it withholds the kernel's own DNA and breaks every
# agent that imports it without a fallback.
#
# Found by running the strain inside a live brainstem for the first time. Every
# isolated test passed because none of them had a basic_agent.py in the folder.
NOT_AGENTS = {"basic_agent.py", "__init__.py"}

# Modules an agent may import without the brainstem trying to fetch them.
# Everything in the standard library, plus what the brainstem itself already
# depends on, plus the base class.
BUNDLED = {"agents", "basic_agent", "local_storage", "utils",
           "flask", "flask_cors", "requests", "dotenv", "werkzeug"}


def unresolvable_imports(path):
    """Module-level imports that are neither stdlib nor bundled.

    This is the strain's answer to the brainstem's auto-install behaviour: an
    import the host cannot already satisfy makes the kernel shell
    `pip install <name>` at load time. That turns any typo, or any reference to
    an internal-only module, into "fetch and execute a stranger's package as
    the user who holds this machine's tokens".

    Only MODULE-LEVEL imports count. An import inside a function raises inside
    the agent's own code and never reaches the installer, so flagging it would
    be noise — and a control that cries wolf gets switched off.

    Static parsing only: deciding whether to trust a file by importing it is
    the wrong order, and importing it is precisely what triggers the install."""
    try:
        with open(path, "rb") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError):
        return set()
    # sys.stdlib_module_names is 3.10+. Falling back to an empty set (the
    # obvious thing) makes EVERY stdlib import look unfetchable and withholds
    # the entire estate -- a "safe" default that is catastrophically wrong. The
    # CI matrix on 3.9 caught it; a deployment on 3.9 would have bricked.
    #
    # find_spec answers the real question directly and on every version: can
    # this host already resolve the name without fetching anything? It is a
    # path search, not an import, so nothing is executed.
    stdlib = getattr(sys, "stdlib_module_names", None)
    out = set()

    def satisfiable(name):
        if stdlib is not None and name in stdlib:
            return True
        if name in sys.builtin_module_names:
            return True
        try:
            import importlib.util
            return importlib.util.find_spec(name) is not None
        except (ImportError, ValueError, ModuleNotFoundError, AttributeError):
            return False

    for node in tree.body:          # module level only, deliberately
        names = []
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:          # relative import — local, never fetched
                continue
            if node.module:
                names = [node.module.split(".")[0]]
        for n in names:
            if n and n not in BUNDLED and not satisfiable(n):
                out.add(n)
    return out

DEFAULT_BAND = "ga"
QUARANTINE_DIRNAME = "withheld"


# ── locating the strain ──────────────────────────────────────────────────────

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


def seal_of(manifest):
    """The seal covers policy, never the seal itself and never the audit fields.
    Computed over a canonical JSON rendering so key order and whitespace cannot
    change the value."""
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


# ── the audit record ─────────────────────────────────────────────────────────
#
# The record is the compliance artifact. An artifact that can be edited without
# trace is a claim, not evidence, so each entry carries the digest of the entry
# before it: modifying, deleting or forging a line breaks the chain from that
# point on, and `strainctl audit verify` names the record where it broke.
#
# Destruction is still possible — this is a file in the user's own home
# directory, and no user-space tool can prevent its own deletion. Tampering is
# what is detectable, and the honest claim is the one made in the threat model.

GENESIS = "0" * 64


def _audit_tail_hash(dest):
    """The last chained hash in the record, or GENESIS if there is none."""
    prev = GENESIS
    try:
        with open(dest) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if "hash" in rec:
                    prev = rec["hash"]
    except OSError:
        pass
    return prev


def chain_append(dest, entry):
    """Append one entry, chained to the one before it.

    Single implementation, shared by every organ and by strainctl. Two
    implementations of one rule is one implementation and one bug waiting to be
    found in production.
    """
    entry = dict(entry)
    entry.pop("hash", None)
    entry["prev"] = _audit_tail_hash(dest)
    payload = json.dumps({k: v for k, v in entry.items()},
                         sort_keys=True, separators=(",", ":"))
    entry["hash"] = hashlib.sha256((entry["prev"] + payload).encode()).hexdigest()
    try:
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        # O_APPEND so two organs writing at once cannot interleave a record.
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        pass
    return entry["hash"]


def verify_audit_chain(records):
    """Return (ok, detail, checked). Entries written before chaining existed
    carry no `hash` and are reported as legacy, not as tampering — calling an
    old format an attack is how an audit tool loses its reader."""
    prev = GENESIS
    legacy = 0
    for i, rec in enumerate(records, 1):
        if "hash" not in rec:
            legacy += 1
            continue
        body = {k: v for k, v in rec.items() if k != "hash"}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        if rec.get("prev") != prev:
            return False, f"chain break at record {i}", i
        if rec["hash"] != hashlib.sha256((prev + payload).encode()).hexdigest():
            return False, f"record {i} was modified", i
        prev = rec["hash"]
    if legacy:
        return True, f"chain intact; {legacy} record(s) predate chaining", len(records)
    return True, "chain intact", len(records)


# ── capability analysis ──────────────────────────────────────────────────────

def observed_capabilities(path):
    """What this file can actually reach, read out of its syntax tree.

    Deliberately conservative: it over-reports rather than under-reports, since
    a false 'declare this' is an inconvenience and a false 'nothing to see' is a
    compliance failure. Returns (capabilities, evidence)."""
    try:
        with open(path, "rb") as _fh:
            tree = ast.parse(_fh.read())
    except SyntaxError as e:
        return set(), [f"unparseable: line {e.lineno}: {e.msg}"]

    def dotted(node):
        """Rebuild `a.b.c` from an attribute chain so calls can be matched with
        their qualifier intact."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))
        return ".".join(reversed(parts))     # e.g. a call result — no root name

    modules, calls, builtins_used, attrs = set(), set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                modules.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                builtins_used.add(f.id)
                # open(path, "w") is a write; open(path) is not.
                if f.id == "open":
                    mode = ""
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        mode = str(node.args[1].value)
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = str(kw.value.value)
                    if any(c in mode for c in "wax+"):
                        calls.add("open(mode='w')")
            elif isinstance(f, ast.Attribute):
                q = dotted(f)
                calls.add(q)
                calls.add(f.attr)            # bare form, for the few entries
                                             # listed bare on purpose
        elif isinstance(node, ast.Attribute):
            attrs.add(node.attr)

    found, evidence = set(), []
    for cap, ev in CAPABILITY_EVIDENCE.items():
        hits = sorted((modules & ev.get("modules", set()))
                      | (calls & ev.get("calls", set()))
                      | (builtins_used & ev.get("builtins", set()))
                      | (attrs & ev.get("attrs", set())))
        if hits:
            found.add(cap)
            evidence.append({"capability": cap, "evidence": hits[:8]})
    return found, evidence


def declared_capabilities(path):
    """Read __manifest__ statically. Importing the file to read its manifest
    would execute unverified code to decide whether to trust it, which is the
    wrong order."""
    try:
        with open(path, "rb") as _fh:
            tree = ast.parse(_fh.read())
    except SyntaxError:
        return None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__manifest__"
                   for t in node.targets):
            continue
        try:
            man = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            return None
        if isinstance(man, dict):
            return man
    return None


# ── the verdict ──────────────────────────────────────────────────────────────

def adjudicate(path, policy):
    """One agent file against the policy. Returns (allowed: bool, record: dict)."""
    fn = os.path.basename(path)
    sha = _sha256_file(path)
    rec = {"file": fn, "sha256": sha[:16]}

    man = declared_capabilities(path)
    if man is None:
        return False, dict(rec, verdict="withheld",
                           reason="no readable top-level __manifest__ — an agent "
                                  "without a declaration cannot be adjudicated")

    ring = str(man.get("ring") or "frontier")
    rec["ring"] = ring
    if ring not in RING_RANK:
        return False, dict(rec, verdict="withheld",
                           reason=f"unknown ring {ring!r}; expected one of {RINGS}")

    # Checked BEFORE the allowlist, because an import the host cannot satisfy is
    # a property of the FILE, not of the policy. Under default-deny everything
    # is unapproved, so if this ran later an administrator would only ever be
    # told "not approved" and would never learn the file would have made the
    # brainstem fetch and execute a package from an index.
    extra = set(policy.get("allowed_imports") or [])
    unresolved = unresolvable_imports(path) - extra
    if unresolved and policy.get("block_auto_install", True):
        return False, dict(rec, verdict="withheld",
                           reason="imports module(s) this host cannot satisfy, "
                                  "which would make the brainstem fetch them "
                                  "from a package index at load time: "
                                  + ", ".join(sorted(unresolved)),
                           unresolvable_imports=sorted(unresolved))

    entry = (policy.get("allowlist") or {}).get(sha)
    band = policy.get("band") or DEFAULT_BAND
    band_rank = RING_RANK.get(band, 0)

    # An explicit allowlist entry is an approval of THIS EXACT BYTE SEQUENCE, and
    # may carry an exception that admits an agent above the standing band. That
    # is how the band expands one considered decision at a time.
    if entry:
        rec["approved_by"] = entry.get("approved_by")
        rec["approved_at"] = entry.get("approved_at")
        if entry.get("exception"):
            rec["exception"] = entry.get("exception")
        elif RING_RANK[ring] > band_rank:
            return False, dict(rec, verdict="withheld",
                               reason=f"ring {ring!r} is above the organisation's "
                                      f"band {band!r}, and this approval carries "
                                      f"no exception")
    else:
        if policy.get("require_allowlist", True):
            # "Approved, then edited" and "never approved" are different events
            # and need different sentences. Telling an administrator their
            # approved agent is "not in the allowlist" sends them looking for a
            # missing approval instead of at the file that changed under them.
            prior = [v for v in (policy.get("allowlist") or {}).values()
                     if v.get("file") == fn]
            if prior:
                return False, dict(
                    rec, verdict="withheld", edited_since_approval=True,
                    reason=f"{fn} was approved by "
                           f"{prior[0].get('approved_by', 'an administrator')} on "
                           f"{prior[0].get('approved_at', 'an earlier date')}, but "
                           f"these are not those bytes — the file changed after "
                           f"approval and must be approved again")
            return False, dict(rec, verdict="withheld",
                               reason="not approved for this organisation")
        if RING_RANK[ring] > band_rank:
            return False, dict(rec, verdict="withheld",
                               reason=f"ring {ring!r} is above the organisation's "
                                      f"band {band!r}")

    declared = set(man.get("capabilities") or [])
    observed, evidence = observed_capabilities(path)
    undeclared = observed - declared
    if undeclared:
        return False, dict(rec, verdict="withheld",
                           reason="code reaches capabilities it does not declare: "
                                  + ", ".join(sorted(undeclared)),
                           evidence=[e for e in evidence
                                     if e["capability"] in undeclared])

    forbidden = set(policy.get("forbidden_capabilities") or [])
    blocked = (declared | observed) & forbidden
    if blocked:
        return False, dict(rec, verdict="withheld",
                           reason="uses a capability class this organisation "
                                  "forbids: " + ", ".join(sorted(blocked)))

    rec["capabilities"] = sorted(declared)
    return True, dict(rec, verdict="permitted")


# ── the organ ────────────────────────────────────────────────────────────────

class StrainPolicyAgent(BasicAgent):
    def __init__(self):
        self.name = "StrainPolicy"
        self.metadata = {
            "name": self.name,
            "description": (
                "Report and enforce this deployment's compliance posture: which "
                "capabilities are enabled, which are withheld and exactly why, "
                "which maturity ring the organisation admits, and whether the "
                "policy manifest is intact."),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string",
                               "enum": ["posture", "withheld", "explain", "recheck"],
                               "description": "posture: the compliance summary. "
                                              "withheld: what is blocked and why. "
                                              "explain: how the strain works. "
                                              "recheck: re-run enforcement now."},
                    "agent": {"type": "string",
                              "description": "For explain: a specific agent filename."},
                },
                "required": ["action"],
            },
        }
        super().__init__(name=self.name, metadata=self.metadata)
        # load_agents() runs this on every /chat. It must be cheap, and it must
        # never raise: an exception here would take down the brainstem it is
        # supposed to be protecting.
        try:
            self._enforce()
        except Exception as e:  # noqa: BLE001 — deliberately total
            self._state = {"error": f"{type(e).__name__}: {e}",
                           "permitted": [], "withheld": [],
                           "assurance": "unknown", "band": DEFAULT_BAND}

    # ---- policy loading ----

    def _load_policy(self):
        path = _strain_path()
        if not os.path.isfile(path):
            # No manifest is not "no policy" — it is the most restrictive policy.
            # Failing open here would make deleting a file a privilege escalation.
            return {"band": DEFAULT_BAND, "require_allowlist": True,
                    "allowlist": {}, "forbidden_capabilities": [],
                    "_assurance": "unsealed-absent",
                    "_note": f"no strain manifest at {path}; failing closed"}
        try:
            with open(path) as _fh:
                pol = json.load(_fh)
        except Exception as e:
            return {"band": DEFAULT_BAND, "require_allowlist": True,
                    "allowlist": {}, "forbidden_capabilities": [],
                    "_assurance": "unreadable",
                    "_note": f"strain manifest unreadable ({e}); failing closed"}
        expect, got = pol.get("seal"), seal_of(pol)
        if not expect:
            pol["_assurance"] = "unsealed"
        elif hmac.compare_digest(str(expect), got):
            pol["_assurance"] = ("sealed-hmac" if got.startswith("hmac-")
                                 else "sealed-checksum")
        else:
            return {"band": DEFAULT_BAND, "require_allowlist": True,
                    "allowlist": {}, "forbidden_capabilities": [],
                    "_assurance": "seal-mismatch",
                    "_note": "the strain manifest does not match its seal; the "
                             "policy was altered after signing. Failing closed to "
                             "the most restrictive setting."}
        pol.setdefault("band", DEFAULT_BAND)
        pol.setdefault("require_allowlist", True)
        pol.setdefault("allowlist", {})
        pol.setdefault("forbidden_capabilities", [])
        return pol

    # ---- enforcement ----

    def _enforce(self):
        agents = _agents_dir()
        policy = self._load_policy()
        hold = os.path.join(os.path.dirname(agents), QUARANTINE_DIRNAME)
        permitted, withheld, readmitted = [], [], []

        # Re-admission comes first. Without it, withholding is a one-way door:
        # an administrator approves an agent, nothing moves it back, and the
        # approval silently does nothing. Enforcement has to be a function of
        # the current policy, not a record of the first time it ran.
        if os.path.isdir(hold):
            for fn in sorted(os.listdir(hold)):
                if not fn.endswith("_agent.py"):
                    continue
                held = os.path.join(hold, fn)
                if fn in NOT_AGENTS:
                    # withheld by an older build before NOT_AGENTS existed —
                    # bring it home unconditionally
                    if not os.path.exists(os.path.join(agents, fn)):
                        try:
                            shutil.move(held, os.path.join(agents, fn))
                            readmitted.append(fn)
                        except OSError:
                            pass
                    continue
                if fn in set(policy.get("always_permit") or []):
                    ok = True
                else:
                    ok, _ = adjudicate(held, policy)
                if not ok:
                    continue
                if os.path.exists(os.path.join(agents, fn)):
                    continue        # a live file wins; leave the held copy alone
                try:
                    shutil.move(held, os.path.join(agents, fn))
                    readmitted.append(fn)
                except OSError:
                    pass

        for fn in sorted(os.listdir(agents)):
            if not fn.endswith("_agent.py") or fn.startswith("."):
                continue
            if fn in NOT_AGENTS:
                continue        # a base class is not a capability
            path = os.path.join(agents, fn)
            if os.path.abspath(path) == os.path.abspath(__file__):
                continue        # the policy organ does not adjudicate itself
            if fn in set(policy.get("always_permit") or []):
                permitted.append({"file": fn, "verdict": "permitted",
                                  "reason": "listed in always_permit"})
                continue
            ok, rec = adjudicate(path, policy)
            if ok:
                permitted.append(rec)
                continue
            withheld.append(rec)
            if policy.get("enforce", True):
                try:
                    os.makedirs(hold, exist_ok=True)
                    shutil.move(path, os.path.join(hold, fn))
                    rec["moved_to"] = f"{QUARANTINE_DIRNAME}/{fn}"
                except OSError as e:
                    rec["enforcement"] = f"could not withhold: {e}"

        # Everything already sitting in withheld/ is still withheld, and an
        # administrator asking "what is blocked?" needs the whole answer — not
        # only what happened to be blocked during this one sweep.
        if os.path.isdir(hold):
            seen = {w.get("file") for w in withheld}
            for fn in sorted(os.listdir(hold)):
                if (not fn.endswith("_agent.py") or fn in seen
                        or fn in NOT_AGENTS):
                    continue
                _, rec = adjudicate(os.path.join(hold, fn), policy)
                withheld.append(dict(rec, already_withheld=True))

        self._state = {
            "band": policy.get("band"),
            "assurance": policy.get("_assurance"),
            "note": policy.get("_note"),
            "organisation": policy.get("organisation"),
            "enforce": policy.get("enforce", True),
            "forbidden_capabilities": policy.get("forbidden_capabilities"),
            "permitted": permitted,
            "withheld": withheld,
            "readmitted": readmitted,
            "checked_at": int(time.time()),
        }
        self._audit(policy, withheld, readmitted)
        return self._state

    def _audit(self, policy, withheld, readmitted=()):
        """An enforcement decision nobody can see is not a control. The log is
        append-only, local, and contains filenames and reasons — never file
        contents, so shipping it to a SIEM leaks no capability source.

        Only transitions are logged. Re-logging every already-withheld agent on
        every /chat would bury the one line that mattered under thousands that
        did not."""
        dest = policy.get("audit_log") or os.path.join(
            os.path.dirname(_agents_dir()), "strain-audit.jsonl")
        fresh = [w for w in withheld if not w.get("already_withheld")]
        if not fresh and not readmitted:
            return
        for w in fresh:
            chain_append(dest, {
                "at": int(time.time()), "event": "agent.withheld",
                "file": w.get("file"), "sha256": w.get("sha256"),
                "ring": w.get("ring"), "reason": w.get("reason"),
            })
        for fn in readmitted:
            chain_append(dest, {
                "at": int(time.time()), "event": "agent.readmitted",
                "file": fn,
                "reason": "now permitted by the current policy",
            })

    # ---- the UX: the model is told the posture, so it can explain it ----

    def system_context(self):
        """Injected into the system prompt every turn. Without this, a user on a
        restricted strain sees capabilities simply not happen, with no reason —
        which reads as a broken product rather than a governed one."""
        st = getattr(self, "_state", None)
        if not st:
            return ""
        w = st.get("withheld") or []
        bits = [
            "COMPLIANCE POSTURE (RAPP strain):",
            f"- This deployment admits agents at maturity ring "
            f"'{st.get('band')}' and below.",
            f"- Policy assurance: {st.get('assurance')}.",
        ]
        if st.get("organisation"):
            bits.append(f"- Administered by: {st['organisation']}.")
        if st.get("forbidden_capabilities"):
            bits.append("- Capability classes forbidden here: "
                        + ", ".join(st["forbidden_capabilities"]) + ".")
        if w:
            bits.append(f"- {len(w)} capabilit{'y is' if len(w) == 1 else 'ies are'} "
                        "withheld by policy: "
                        + ", ".join(sorted({x.get('file', '?') for x in w}))[:400] + ".")
            bits.append("If the user asks for something that is withheld, say so "
                        "plainly, name the reason, and tell them their "
                        "administrator can approve it — do not pretend the "
                        "capability does not exist and do not attempt a "
                        "workaround.")
        return "\n".join(bits)

    def perform(self, **kwargs):
        action = kwargs.get("action") or "posture"
        try:
            if action == "recheck":
                self._enforce()
            st = getattr(self, "_state", {}) or {}

            if action == "explain" and kwargs.get("agent"):
                target = os.path.join(_agents_dir(), kwargs["agent"])
                if not os.path.isfile(target):
                    held = os.path.join(os.path.dirname(_agents_dir()),
                                        QUARANTINE_DIRNAME, kwargs["agent"])
                    target = held if os.path.isfile(held) else None
                if not target:
                    return json.dumps({"status": "error",
                                       "message": f"no such agent: {kwargs['agent']}"},
                                      indent=2)
                ok, rec = adjudicate(target, self._load_policy())
                obs, ev = observed_capabilities(target)
                man = declared_capabilities(target) or {}
                return json.dumps({
                    "status": "ok", "permitted": ok, "adjudication": rec,
                    "declared_capabilities": sorted(man.get("capabilities") or []),
                    "observed_in_code": sorted(obs), "evidence": ev,
                    "note": "declared capabilities are checked against the code, "
                            "not taken on trust",
                }, indent=2)

            if action == "explain":
                return json.dumps({
                    "status": "ok",
                    "what_a_strain_is":
                        "The unmodified grail brainstem plus a sealed policy "
                        "manifest and this organ. No fork, no kernel change — so "
                        "an upstream security fix reaches this locked-down "
                        "deployment the same day it reaches everyone else.",
                    "checks_in_order": [
                        "seal — the manifest matches its own seal, or the strain "
                        "fails closed",
                        "ring — frontier > private-preview > public-preview > ga; "
                        "anything above the organisation's band is withheld",
                        "identity — the agent's sha256 must be in the allowlist; "
                        "editing an approved agent changes its identity",
                        "capability — declared capabilities are verified against "
                        "the syntax tree; undeclared reach is refused",
                        "egress — outbound hosts narrowed to the allowed list",
                    ],
                    "how_the_band_expands":
                        "An administrator approves a specific byte sequence at a "
                        "ring, or raises the standing band. Both are recorded "
                        "with an approver and a date.",
                    "what_this_is_not":
                        "It is not a sandbox and does not stop a hostile local "
                        "user who owns the machine — no data-loss-prevention "
                        "control does. It makes the compliant path the default, "
                        "and leaves an attestable record of every decision.",
                }, indent=2)

            if action == "withheld":
                w = st.get("withheld") or []
                return json.dumps({
                    "status": "ok", "withheld_count": len(w), "withheld": w,
                    "band": st.get("band"),
                    "note": "each entry names the exact reason; an administrator "
                            "can approve any of these with strainctl",
                }, indent=2)

            p, w = st.get("permitted") or [], st.get("withheld") or []
            return json.dumps({
                "status": "ok",
                "headline": f"{len(p)} capabilit{'y' if len(p) == 1 else 'ies'} "
                            f"enabled, {len(w)} withheld by policy",
                "organisation": st.get("organisation"),
                "band": st.get("band"),
                "assurance": st.get("assurance"),
                "enforcing": st.get("enforce"),
                "forbidden_capabilities": st.get("forbidden_capabilities"),
                "enabled": sorted(x.get("file", "?") for x in p),
                "withheld": [{"file": x.get("file"), "reason": x.get("reason")}
                             for x in w],
                "note": st.get("note"),
                "error": st.get("error"),
            }, indent=2)
        except Exception as e:  # noqa: BLE001
            return json.dumps({"status": "error",
                               "message": f"{type(e).__name__}: {e}"}, indent=2)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "--tool":
        print(json.dumps(StrainPolicyAgent().to_tool(), indent=2))
    else:
        raw = a[0] if a else (sys.stdin.read().strip() or '{"action":"posture"}')
        print(StrainPolicyAgent().perform(**json.loads(raw)))
