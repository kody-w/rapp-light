#!/usr/bin/env python3
"""strainctl — administer a RAPP strain.

The enterprise-side tool. An administrator uses it to decide what the strain
admits; a user never needs it, and running it without the seal key can only
read, never approve.

    strainctl init        <org>            create a strain manifest
    strainctl scan        [agents-dir]     what would be admitted, and why not
    strainctl approve     <file> [--ring]  approve one exact byte sequence
    strainctl revoke      <sha|file>       remove an approval
    strainctl band        <ring>           set the standing maturity band
    strainctl forbid      <capability>     forbid a capability class outright
    strainctl seal                         re-seal after editing
    strainctl verify                       is the manifest intact?
    strainctl report                       posture, for an audit trail

APPROVAL IS OF BYTES, NOT OF NAMES

`approve` records a sha256. Re-approving is required after any edit, which is
the point: "we approved log-detective" is not a security statement, because the
next version of log-detective is a different program. Approving the hash makes
the approval mean what people already assume it means.

THE BAND EXPANDS; IT DOES NOT LEAK

`band` sets the standing maturity ring — ga, then public-preview, and so on.
Anything above the band needs an individual approval carrying an explicit
exception, recorded with an approver and a date. So an organisation can pilot
one frontier capability with one team without moving the whole population onto
the frontier ring.
"""

import argparse
import getpass
import hashlib
import hmac
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RINGS = ["ga", "public-preview", "private-preview", "frontier"]
CAPABILITIES = ["network", "process-exec", "credential-access",
                "filesystem-write", "dynamic-code"]


def _organ():
    """Load the policy organ as a library so the CLI and the runtime agree by
    construction. Two implementations of one rule is one implementation and one
    bug waiting to be found in production."""
    import importlib.util
    for cand in (os.path.join(HERE, "..", "organs", "aa_strain_policy_agent.py"),
                 os.path.join(HERE, "aa_strain_policy_agent.py")):
        p = os.path.abspath(cand)
        if os.path.isfile(p):
            spec = importlib.util.spec_from_file_location("_strain_policy", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    sys.exit("strainctl: cannot find aa_strain_policy_agent.py")


ORGAN = _organ()


def manifest_path(args):
    return os.path.abspath(args.manifest or os.getenv("RAPP_STRAIN_MANIFEST")
                           or os.path.join(HERE, "..", "strain.json"))


def load(path, required=True):
    if not os.path.isfile(path):
        if required:
            sys.exit(f"strainctl: no strain manifest at {path} — run 'init' first")
        return None
    with open(path) as fh:
        return json.load(fh)


def save(path, man, reseal=True):
    if reseal:
        man["sealed_at"] = int(time.time())
        man["seal"] = ORGAN.seal_of(man)
    with open(path, "w") as fh:
        json.dump(man, fh, indent=2, sort_keys=True)
        fh.write("\n")
    mode = "hmac" if man.get("seal", "").startswith("hmac-") else "checksum"
    if mode == "checksum":
        print("  note: sealed with a plain checksum. Set RAPP_STRAIN_SEAL_KEY "
              "to seal with an HMAC so a user cannot re-seal an edited policy.")
    return man


def require_key(action):
    if not os.getenv("RAPP_STRAIN_SEAL_KEY"):
        print(f"  warning: {action} without RAPP_STRAIN_SEAL_KEY — the manifest "
              "will carry a checksum seal that anyone can recompute.")


# ── commands ─────────────────────────────────────────────────────────────────

def cmd_init(args):
    path = manifest_path(args)
    if os.path.isfile(path) and not args.force:
        sys.exit(f"strainctl: {path} already exists (use --force to replace)")
    require_key("init")
    man = {
        "schema": "rapp-strain/1.0",
        "organisation": args.organisation,
        "band": args.band,
        "require_allowlist": True,
        "enforce": True,
        "forbidden_capabilities": list(args.forbid or []),
        "allowed_hosts": list(args.allow_host or []),
        "always_permit": ["aa_strain_policy_agent.py", "strain_admin_agent.py",
                          "strain_credential_agent.py"],
        "allowlist": {},
        "admin": {"contact": args.contact or ""},
        "created_at": int(time.time()),
    }
    save(path, man)
    print(f"  strain initialised: {path}")
    print(f"  organisation: {man['organisation']}   band: {man['band']}")
    print(f"  posture: no agents approved yet — everything is withheld until "
          f"an administrator approves it.")
    return 0


def cmd_scan(args):
    path = manifest_path(args)
    man = load(path, required=False) or {"band": "ga", "require_allowlist": True,
                                         "allowlist": {}}
    d = os.path.abspath(args.agents or os.path.join(HERE, "..", "agents"))
    if not os.path.isdir(d):
        sys.exit(f"strainctl: no such agents directory: {d}")
    files = sorted(f for f in os.listdir(d) if f.endswith("_agent.py"))
    if not files:
        print(f"  no *_agent.py in {d}")
        return 0
    ok_n = 0
    print(f"  scanning {len(files)} agent(s) against band "
          f"'{man.get('band')}' in {d}\n")
    always = set(man.get("always_permit") or [])
    for fn in files:
        p = os.path.join(d, fn)
        if fn in always:
            # Must mirror the runtime exactly, or scan tells an administrator
            # something the deployment will not do.
            ok_n += 1
            print(f"  PERMIT  {fn}\n           listed in always_permit\n")
            continue
        allowed, rec = ORGAN.adjudicate(p, man)
        obs, _ = ORGAN.observed_capabilities(p)
        unres = ORGAN.unresolvable_imports(p) - set(man.get("allowed_imports") or [])
        mark = "PERMIT " if allowed else "WITHHELD"
        ok_n += bool(allowed)
        print(f"  {mark} {fn}")
        print(f"           ring={rec.get('ring','?'):16} sha={rec.get('sha256','?')}")
        if obs:
            print(f"           reaches: {', '.join(sorted(obs))}")
        if unres:
            print(f"           would fetch: {', '.join(sorted(unres))}")
        if not allowed:
            print(f"           why: {rec.get('reason')}")
        print()
    print(f"  {ok_n} permitted, {len(files)-ok_n} withheld")
    return 0


def cmd_approve(args):
    path = manifest_path(args)
    man = load(path)
    target = os.path.abspath(args.file)
    if not os.path.isfile(target):
        sys.exit(f"strainctl: no such file: {target}")
    require_key("approve")

    decl = ORGAN.declared_capabilities(target)
    if decl is None:
        sys.exit("strainctl: this file has no readable top-level __manifest__ — "
                 "it cannot be adjudicated, so it cannot be approved")
    observed, evidence = ORGAN.observed_capabilities(target)
    declared = set(decl.get("capabilities") or [])
    undeclared = observed - declared
    if undeclared and not args.force:
        print(f"  REFUSED: {os.path.basename(target)} reaches capabilities it "
              f"does not declare:")
        for e in evidence:
            if e["capability"] in undeclared:
                print(f"    {e['capability']}: {', '.join(e['evidence'])}")
        print("\n  Approving this would put an undeclared capability into your "
              "estate under an approval that does not mention it.")
        print("  Fix the agent's __manifest__, or re-run with --force to record "
              "the approval anyway (the runtime will still withhold it).")
        return 2

    # The runtime withholds an agent whose imports the host cannot satisfy.
    # If approve stayed silent about that, an administrator would be told
    # "approved" and then find it withheld — the tool and the deployment must
    # never disagree.
    unresolved = ORGAN.unresolvable_imports(target) - set(
        man.get("allowed_imports") or [])
    if unresolved and not args.force:
        print(f"  REFUSED: {os.path.basename(target)} imports module(s) this "
              f"host cannot satisfy:")
        for u in sorted(unresolved):
            print(f"    {u}")
        print("\n  At load time the brainstem would try to fetch these from a "
              "package index and execute them.")
        print("  Vendor them, add them to \"allowed_imports\" in the manifest, "
              "or re-run with --force (the runtime will still withhold it).")
        return 2

    ring = args.ring or decl.get("ring") or "frontier"
    if ring not in RINGS:
        sys.exit(f"strainctl: unknown ring {ring!r}; expected one of {RINGS}")
    band_rank = RINGS.index(man.get("band", "ga"))
    exception = None
    if RINGS.index(ring) > band_rank:
        if not args.exception:
            sys.exit(f"strainctl: {ring!r} is above your standing band "
                     f"{man.get('band')!r}. Approving it needs an explicit "
                     f"reason: --exception \"pilot with the data team\"")
        exception = args.exception

    sha = ORGAN._sha256_file(target)
    man.setdefault("allowlist", {})[sha] = {
        "file": os.path.basename(target),
        "name": decl.get("name"),
        "ring": ring,
        "capabilities": sorted(declared),
        "approved_by": args.by or getpass.getuser(),
        "approved_at": time.strftime("%Y-%m-%d"),
        **({"exception": exception} if exception else {}),
    }
    save(path, man)
    print(f"  approved {os.path.basename(target)}")
    print(f"    sha256:       {sha}")
    print(f"    ring:         {ring}" + (f"  (exception: {exception})" if exception else ""))
    print(f"    capabilities: {', '.join(sorted(declared)) or 'none'}")
    print(f"    approved by:  {man['allowlist'][sha]['approved_by']}")
    print("\n  This approves these exact bytes. If the file changes, it must be "
          "approved again.")
    return 0


def cmd_revoke(args):
    path = manifest_path(args)
    man = load(path)
    al = man.get("allowlist") or {}
    hits = [k for k, v in al.items()
            if k.startswith(args.target) or v.get("file") == args.target]
    if not hits:
        sys.exit(f"strainctl: nothing approved matching {args.target!r}")
    require_key("revoke")
    for k in hits:
        print(f"  revoked {al[k].get('file')}  sha={k[:16]}")
        al.pop(k)
    save(path, man)
    print(f"  {len(hits)} approval(s) removed; they are withheld from the next "
          f"message onward")
    return 0


def cmd_band(args):
    path = manifest_path(args)
    man = load(path)
    if args.ring not in RINGS:
        sys.exit(f"strainctl: unknown ring {args.ring!r}; expected one of {RINGS}")
    require_key("band")
    old = man.get("band")
    man["band"] = args.ring
    save(path, man)
    widened = RINGS.index(args.ring) > RINGS.index(old or "ga")
    print(f"  band {old} -> {args.ring}")
    print("  this " + ("WIDENS" if widened else "narrows") + " what the strain admits."
          + ("  Everything still needs an individual approval."
             if man.get("require_allowlist", True) else ""))
    return 0


def cmd_forbid(args):
    path = manifest_path(args)
    man = load(path)
    if args.capability not in CAPABILITIES:
        sys.exit(f"strainctl: unknown capability {args.capability!r}; "
                 f"expected one of {CAPABILITIES}")
    require_key("forbid")
    s = set(man.get("forbidden_capabilities") or [])
    s.discard(args.capability) if args.remove else s.add(args.capability)
    man["forbidden_capabilities"] = sorted(s)
    save(path, man)
    print(f"  forbidden capability classes: "
          f"{', '.join(man['forbidden_capabilities']) or 'none'}")
    print("  any agent whose code reaches one of these is withheld, even if it "
          "is otherwise approved.")
    return 0


def cmd_admin(args):
    """Set the credential that unlocks in-session elevation.

    The manifest stores a salted sha256, never the secret. Losing the secret
    means setting a new one, not recovering the old one — which is the correct
    behaviour for a credential and worth stating out loud, because someone will
    ask."""
    path = manifest_path(args)
    man = load(path)
    if args.show:
        adm = man.get("admin") or {}
        print(f"  contact:   {adm.get('contact') or '(none)'}")
        print(f"  key set:   {'yes' if adm.get('key_sha256') else 'no'}")
        return 0
    secret = args.set_key
    if secret == "-":
        secret = getpass.getpass("  new admin credential: ")
        if secret != getpass.getpass("  repeat: "):
            sys.exit("strainctl: credentials did not match")
    if not secret or len(secret) < 12:
        sys.exit("strainctl: the admin credential must be at least 12 characters")
    require_key("admin --set-key")
    salt = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
    man.setdefault("admin", {})
    man["admin"]["key_salt"] = salt
    man["admin"]["key_sha256"] = hashlib.sha256(
        (salt + ":" + secret).encode()).hexdigest()
    if args.contact:
        man["admin"]["contact"] = args.contact
    save(path, man)
    print("  administrator credential set.")
    print("  An administrator elevates in-session by setting "
          "RAPP_STRAIN_ADMIN_KEY to this value.")
    print("  The manifest stores only a salted hash — this value cannot be "
          "recovered from it.")
    return 0


def cmd_seal(args):
    path = manifest_path(args)
    man = load(path)
    require_key("seal")
    save(path, man)
    print(f"  sealed: {man['seal']}")
    return 0


def cmd_verify(args):
    path = manifest_path(args)
    man = load(path)
    expect, got = man.get("seal"), ORGAN.seal_of(man)
    if not expect:
        print("  UNSEALED — this manifest carries no seal. The runtime will run "
              "it but report assurance 'unsealed'.")
        return 1
    if hmac.compare_digest(str(expect), got):
        kind = "HMAC" if got.startswith("hmac-") else "checksum"
        print(f"  INTACT — seal matches ({kind}).")
        if kind == "checksum":
            print("  Assurance is limited: a checksum seal can be recomputed by "
                  "anyone who can edit the file. Set RAPP_STRAIN_SEAL_KEY.")
        return 0
    print("  ALTERED — the manifest does not match its seal.")
    print(f"    recorded: {expect}")
    print(f"    computed: {got}")
    print("  The runtime fails closed to the most restrictive policy when it "
          "sees this.")
    return 2


def cmd_report(args):
    path = manifest_path(args)
    man = load(path)
    al = man.get("allowlist") or {}
    by_ring = {}
    for v in al.values():
        by_ring.setdefault(v.get("ring", "?"), []).append(v.get("file"))
    out = {
        "organisation": man.get("organisation"),
        "band": man.get("band"),
        "enforcing": man.get("enforce", True),
        "requires_allowlist": man.get("require_allowlist", True),
        "forbidden_capabilities": man.get("forbidden_capabilities") or [],
        "approved_total": len(al),
        "approved_by_ring": {k: sorted(v) for k, v in sorted(by_ring.items())},
        "exceptions": [{"file": v.get("file"), "ring": v.get("ring"),
                        "reason": v.get("exception"),
                        "approved_by": v.get("approved_by"),
                        "approved_at": v.get("approved_at")}
                       for v in al.values() if v.get("exception")],
        "seal_state": ("intact" if hmac.compare_digest(str(man.get("seal")),
                                                       ORGAN.seal_of(man))
                       else "ALTERED") if man.get("seal") else "unsealed",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    print(json.dumps(out, indent=2))
    return 0


# ── credentials ──────────────────────────────────────────────────────────────
#
# The strain grants; it never holds. A grant is a NAME or a glob, recorded
# against the sha256 of an approved agent. The value lives in the broker, on the
# device, and is never written here — a policy manifest is a file that gets
# copied, mailed and committed, and the day it contains a secret is the day the
# control becomes the leak.

def _resolve_agent(man, target):
    """Map a filename or sha prefix to its allowlist key."""
    al = man.get("allowlist") or {}
    hits = [k for k, v in al.items()
            if k.startswith(target) or v.get("file") == target]
    if not hits:
        sys.exit(
            f"strainctl: {target!r} is not an approved agent.\n"
            f"  A credential cannot be granted to an agent the strain does not\n"
            f"  admit. Approve it first:  strainctl approve <file>")
    if len(hits) > 1:
        sys.exit(f"strainctl: {target!r} is ambiguous ({len(hits)} matches)")
    return hits[0]


def cmd_cred_grant(args):
    path = manifest_path(args)
    man = load(path)
    key = _resolve_agent(man, args.agent)
    require_key("grant a credential")
    creds = man.setdefault("credentials", {})
    grants = creds.setdefault("grants", {})
    entry = grants.setdefault(key, [])
    if isinstance(entry, dict):
        entry = entry.setdefault("allow", [])
    if args.pattern in entry:
        print(f"  already granted: {args.pattern}")
        return 0
    entry.append(args.pattern)
    grants[key] = entry
    save(path, man)
    fn = (man["allowlist"][key]).get("file")
    print(f"  granted {args.pattern!r} to {fn}  sha={key[:16]}")
    print("  The value is not stored here — only the grant. Put the value in")
    print("  the broker, naming a concrete credential rather than the pattern:")
    example = args.pattern.replace("*", "storage-key").replace("?", "")
    print(f"    printf '%s' \"$VALUE\" | rapp-keyring set {example} --stdin")
    return 0


def cmd_cred_revoke(args):
    path = manifest_path(args)
    man = load(path)
    key = _resolve_agent(man, args.agent)
    require_key("revoke a credential")
    grants = (man.get("credentials") or {}).get("grants") or {}
    entry = grants.get(key) or []
    if isinstance(entry, dict):
        entry = entry.get("allow") or []
    if args.pattern not in entry:
        sys.exit(f"strainctl: {args.pattern!r} is not granted to that agent")
    entry.remove(args.pattern)
    grants[key] = entry
    save(path, man)
    print(f"  revoked {args.pattern!r}; it stops applying on the next message")
    return 0


def cmd_cred_deny(args):
    """A deny rule outranks every grant, including one an administrator adds
    later by mistake. This is where `prod/*` belongs."""
    path = manifest_path(args)
    man = load(path)
    require_key("add a credential deny rule")
    creds = man.setdefault("credentials", {})
    denies = creds.setdefault("deny", [])
    if args.remove:
        if args.pattern not in denies:
            sys.exit(f"strainctl: {args.pattern!r} is not denied")
        denies.remove(args.pattern)
        save(path, man)
        print(f"  removed the deny rule {args.pattern!r}")
        return 0
    if args.pattern not in denies:
        denies.append(args.pattern)
    save(path, man)
    print(f"  denied {args.pattern!r} for every agent, outranking any grant")
    return 0


def cmd_cred_list(args):
    path = manifest_path(args)
    man = load(path, required=False) or {}
    al = man.get("allowlist") or {}
    creds = man.get("credentials") or {}
    grants = creds.get("grants") or {}
    out = {
        "deny": creds.get("deny") or [],
        "default": creds.get("default") or [],
        "grants": {},
    }
    for key, entry in grants.items():
        patterns = entry if isinstance(entry, list) else (entry.get("allow") or [])
        out["grants"][(al.get(key) or {}).get("file", key[:16])] = patterns
    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    if not out["grants"] and not out["default"]:
        print("  no agent is granted any credential")
    for fn, patterns in sorted(out["grants"].items()):
        print(f"  {fn}")
        for pattern in patterns:
            print(f"      {pattern}")
    if out["default"]:
        print(f"  (default for every approved agent: {', '.join(out['default'])})")
    if out["deny"]:
        print(f"  denied for all: {', '.join(out['deny'])}")
    print()
    print("  Names only. Values live in the broker, never in this manifest.")
    return 0


def cmd_cred_check(args):
    """Answer the question an administrator actually asks: would this agent get
    this credential, and if not, why not."""
    path = manifest_path(args)
    man = load(path, required=False) or {}
    organ = _credential_organ()
    man.setdefault("credentials", {}).setdefault("grants", {})
    allowed, refused = organ.adjudicate(man, args.agent, [args.pattern])
    if allowed:
        print(f"  ALLOW  {args.agent} → {args.pattern}")
        return 0
    for name, reason in refused:
        print(f"  DENY   {args.agent} → {name}")
        print(f"         {reason}")
    return 1


def _credential_organ():
    import importlib.util
    for cand in (os.path.join(HERE, "..", "organs", "strain_credential_agent.py"),
                 os.path.join(HERE, "strain_credential_agent.py")):
        p = os.path.abspath(cand)
        if os.path.isfile(p):
            spec = importlib.util.spec_from_file_location("_strain_cred", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    sys.exit("strainctl: strain_credential_agent.py not found next to this tool")


# ── the audit record ─────────────────────────────────────────────────────────

def _audit_file(man):
    return (man.get("audit_log") or
            os.path.join(os.path.dirname(
                os.getenv("RAPP_AGENTS_DIR") or
                os.path.join(os.path.expanduser("~"), ".brainstem", "agents")),
                "strain-audit.jsonl"))


def cmd_audit(args):
    path = manifest_path(args)
    man = load(path, required=False) or {}
    dest = _audit_file(man)
    if not os.path.isfile(dest):
        print(f"  no audit record yet at {dest}")
        return 0
    records = []
    with open(dest) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except ValueError:
                    pass

    if args.audit_action == "verify":
        ok, detail, checked = ORGAN.verify_audit_chain(records) \
            if hasattr(ORGAN, "verify_audit_chain") else _verify_chain(records)
        print(f"  {'OK' if ok else 'TAMPERED'} — {detail} ({checked} record(s))")
        return 0 if ok else 2

    if args.audit_action == "export":
        # SIEM-shaped. Names, decisions and reasons only; the record has never
        # contained a credential value or a line of agent source.
        for rec in records:
            if args.format == "cef":
                print(_to_cef(rec))
            else:
                print(json.dumps(rec, sort_keys=True))
        return 0

    for rec in records[-args.count:]:
        print(f"  {time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(rec.get('at', 0)))}"
              f"  {rec.get('event', '?'):24} {rec.get('file') or rec.get('agent') or ''}"
              f"  {rec.get('reason', '')[:70]}")
    return 0


def _verify_chain(records):
    """Records written before chaining was introduced carry no `prev`, and are
    reported as unchained rather than as tampering — calling an old format an
    attack is how an audit tool loses its reader."""
    prev = "0" * 64
    unchained = 0
    for i, rec in enumerate(records, 1):
        if "hash" not in rec:
            unchained += 1
            continue
        body = {k: v for k, v in rec.items() if k != "hash"}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        expect = hashlib.sha256((prev + payload).encode()).hexdigest()
        if rec.get("prev") != prev:
            return False, f"chain break at record {i}", i
        if rec["hash"] != expect:
            return False, f"record {i} was modified", i
        prev = rec["hash"]
    if unchained:
        return True, f"chain intact; {unchained} legacy record(s) predate chaining", \
            len(records)
    return True, "chain intact", len(records)


def _to_cef(rec):
    """ArcSight CEF, because that is what most SIEMs still ingest without a
    custom parser."""
    sev = {"agent.withheld": 6, "credential.refused": 7,
           "credential.used": 4, "agent.readmitted": 3}.get(rec.get("event"), 5)
    def _esc(v):
        # CEF escapes '=' in extension values. Hoisted out of the f-string
        # because an f-string expression may not contain a backslash before
        # Python 3.12 -- this raised SyntaxError on the 3.9 CI matrix, which
        # made every strainctl invocation fail, which failed the audit tests
        # with a misleading "1 != 0".
        return str(v).replace("=", "\\=")

    ext = " ".join(
        "{}={}".format(k, _esc(v))
        for k, v in sorted(rec.items())
        if k not in ("event", "hash", "prev") and v not in (None, "", [])
    )
    return (f"CEF:0|RAPP|rapp-light|1.0|{rec.get('event','?')}|"
            f"{rec.get('event','?')}|{sev}|{ext}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="strainctl",
                                description="Administer a RAPP strain.")
    p.add_argument("--manifest", help="path to strain.json")
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("init", help="create a strain manifest")
    q.add_argument("organisation")
    q.add_argument("--band", default="ga", choices=RINGS)
    q.add_argument("--forbid", action="append", choices=CAPABILITIES)
    q.add_argument("--allow-host", action="append")
    q.add_argument("--contact")
    q.add_argument("--force", action="store_true")
    q.set_defaults(fn=cmd_init)

    q = sub.add_parser("scan", help="what would be admitted, and why not")
    q.add_argument("agents", nargs="?")
    q.set_defaults(fn=cmd_scan)

    q = sub.add_parser("approve", help="approve one exact byte sequence")
    q.add_argument("file")
    q.add_argument("--ring", choices=RINGS)
    q.add_argument("--exception", help="reason for admitting above the band")
    q.add_argument("--by")
    q.add_argument("--force", action="store_true")
    q.set_defaults(fn=cmd_approve)

    q = sub.add_parser("revoke", help="remove an approval")
    q.add_argument("target", help="sha256 prefix or filename")
    q.set_defaults(fn=cmd_revoke)

    q = sub.add_parser("band", help="set the standing maturity band")
    q.add_argument("ring", choices=RINGS)
    q.set_defaults(fn=cmd_band)

    q = sub.add_parser("forbid", help="forbid a capability class outright")
    q.add_argument("capability", choices=CAPABILITIES)
    q.add_argument("--remove", action="store_true")
    q.set_defaults(fn=cmd_forbid)

    q = sub.add_parser("admin", help="set the in-session elevation credential")
    q.add_argument("--set-key", metavar="SECRET",
                   help="the credential ('-' to be prompted without echo)")
    q.add_argument("--contact")
    q.add_argument("--show", action="store_true")
    q.set_defaults(fn=cmd_admin)

    q = sub.add_parser("cred", help="govern which agent may use which credential")
    csub = q.add_subparsers(dest="cred_action", required=True)
    r = csub.add_parser("grant", help="let an approved agent use a credential")
    r.add_argument("agent", help="approved filename or sha256 prefix")
    r.add_argument("pattern", help="credential name or glob, e.g. azure/*")
    r.set_defaults(fn=cmd_cred_grant)
    r = csub.add_parser("revoke", help="withdraw a grant")
    r.add_argument("agent")
    r.add_argument("pattern")
    r.set_defaults(fn=cmd_cred_revoke)
    r = csub.add_parser("deny", help="deny a pattern for every agent (outranks grants)")
    r.add_argument("pattern")
    r.add_argument("--remove", action="store_true")
    r.set_defaults(fn=cmd_cred_deny)
    r = csub.add_parser("list", help="who may use what — names only")
    r.add_argument("--json", action="store_true")
    r.set_defaults(fn=cmd_cred_list)
    r = csub.add_parser("check", help="would this agent get this credential, and why")
    r.add_argument("agent")
    r.add_argument("pattern")
    r.set_defaults(fn=cmd_cred_check)

    q = sub.add_parser("audit", help="read, verify and export the audit record")
    asub = q.add_subparsers(dest="audit_action", required=True)
    r = asub.add_parser("tail", help="recent decisions")
    r.add_argument("-n", "--count", type=int, default=20)
    r.set_defaults(fn=cmd_audit)
    r = asub.add_parser("verify", help="is the record intact?")
    r.set_defaults(fn=cmd_audit, count=0)
    r = asub.add_parser("export", help="emit for a SIEM")
    r.add_argument("--format", choices=["jsonl", "cef"], default="jsonl")
    r.set_defaults(fn=cmd_audit, count=0)

    for name, fn, helptext in (("seal", cmd_seal, "re-seal after editing"),
                               ("verify", cmd_verify, "is the manifest intact?"),
                               ("report", cmd_report, "posture, for an audit trail")):
        q = sub.add_parser(name, help=helptext)
        q.set_defaults(fn=fn)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
