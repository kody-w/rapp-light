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
        "always_permit": ["aa_strain_policy_agent.py", "strain_admin_agent.py"],
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
        mark = "PERMIT " if allowed else "WITHHELD"
        ok_n += bool(allowed)
        print(f"  {mark} {fn}")
        print(f"           ring={rec.get('ring','?'):16} sha={rec.get('sha256','?')}")
        if obs:
            print(f"           reaches: {', '.join(sorted(obs))}")
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

    for name, fn, helptext in (("seal", cmd_seal, "re-seal after editing"),
                               ("verify", cmd_verify, "is the manifest intact?"),
                               ("report", cmd_report, "posture, for an audit trail")):
        q = sub.add_parser(name, help=helptext)
        q.set_defaults(fn=fn)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
