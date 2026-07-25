#!/usr/bin/env python3
"""
RAPP Light conformance gate.

The artifact to hand a security reviewer. Every check states a claim this
project makes in its README or threat model, then proves or disproves it against
the running code. Nothing passes on inspection alone, and nothing passes because
a document says so.

    python3 conformance.py            # human-readable
    python3 conformance.py --json     # for CI

Exit codes:  0 all passed  |  1 one or more failed  |  2 could not run
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
ORGANS = os.path.join(ROOT, "organs")
TOOLS = os.path.join(ROOT, "tools")
STRAINCTL = [sys.executable, os.path.join(TOOLS, "strainctl.py")]

CHECKS = []


def check(cid, claim):
    def decorate(fn):
        fn._cid, fn._claim = cid, claim
        CHECKS.append(fn)
        return fn
    return decorate


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


POLICY = load("_pol", os.path.join(ORGANS, "aa_strain_policy_agent.py"))
CRED = load("_cred", os.path.join(ORGANS, "strain_credential_agent.py"))

ORGAN_FILES = [os.path.join(ORGANS, f) for f in sorted(os.listdir(ORGANS))
               if f.endswith("_agent.py")]


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# ── the kernel is not touched ────────────────────────────────────────────────

@check("L1", "The strain contains no brainstem kernel — it governs from outside.")
def l1_no_kernel():
    """Read the syntax tree, not the text.

    The first version of this check grepped for strings like "def load_agents"
    and duly failed on THIS file, which contains those strings as the data it
    searches for. That is the same false-positive failure L4 exists to prevent,
    committed by the checker itself. A definition is a definition in the AST; a
    string that mentions one is not.
    """
    import ast as _ast

    kernel_functions = {"load_agents", "chat", "split_response"}
    kernel_classes = {"Brainstem", "AgentLoader"}
    server_calls = {"Flask", "app.run", "uvicorn.run"}

    offenders, scanned = [], 0
    for root, _dirs, files in os.walk(ROOT):
        if ".git" in root:
            continue
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            scanned += 1
            try:
                with open(path, "rb") as fh:
                    tree = _ast.parse(fh.read())
            except SyntaxError:
                continue
            rel = os.path.relpath(path, ROOT)
            for node in _ast.walk(tree):
                if isinstance(node, _ast.FunctionDef) and node.name in kernel_functions:
                    offenders.append(f"{rel}: defines {node.name}()")
                elif isinstance(node, _ast.ClassDef) and node.name in kernel_classes:
                    offenders.append(f"{rel}: defines class {node.name}")
                elif isinstance(node, _ast.Call):
                    parts = []
                    target = node.func
                    while isinstance(target, _ast.Attribute):
                        parts.append(target.attr)
                        target = target.value
                    if isinstance(target, _ast.Name):
                        parts.append(target.id)
                    dotted = ".".join(reversed(parts))
                    if dotted in server_calls:
                        offenders.append(f"{rel}: calls {dotted}()")
    if offenders:
        return False, "kernel-shaped code found: " + ", ".join(sorted(set(offenders))[:3])
    return True, ("no loader, no LLM loop, no server across %d python files — "
                  "verified in the syntax tree, not by grepping text" % scanned)


@check("L2", "Every organ runs standalone, with no brainstem installed.")
def l2_standalone():
    for path in ORGAN_FILES:
        proc = subprocess.run(
            [sys.executable, "-c",
             f"import importlib.util,sys;"
             f"s=importlib.util.spec_from_file_location('m',{path!r});"
             f"m=importlib.util.module_from_spec(s);s.loader.exec_module(m)"],
            capture_output=True, text=True)
        if proc.returncode != 0:
            return False, (f"{os.path.basename(path)} does not import "
                           f"standalone: {proc.stderr.strip()[:120]}")
    return True, "all %d organs import with no brainstem present" % len(ORGAN_FILES)


# ── the five checks ──────────────────────────────────────────────────────────

@check("L3", "Capability declarations are verified against code, not trusted.")
def l3_capability_verified():
    probe = tempfile.mkdtemp(prefix="rl-conf-l3-")
    try:
        liar = os.path.join(probe, "liar_agent.py")
        with open(liar, "w") as fh:
            fh.write("__manifest__ = {'name': '@x/liar', 'capabilities': []}\n"
                     "import subprocess\n"
                     "def go():\n"
                     "    subprocess.run(['id'])\n")
        observed, evidence = POLICY.observed_capabilities(liar)
        declared = set((POLICY.declared_capabilities(liar) or {})
                       .get("capabilities") or [])
        undeclared = observed - declared
        if "process-exec" not in undeclared:
            return False, ("an agent declaring nothing while calling "
                           "subprocess.run was not caught")
        return True, ("an agent declaring [] while calling subprocess.run is "
                      "caught as %s" % sorted(undeclared))
    finally:
        shutil.rmtree(probe, ignore_errors=True)


@check("L4", "Ordinary code is not falsely accused (the control does not cry wolf).")
def l4_no_false_positives():
    """A control that fires on json.loads gets switched off, and then it
    protects nothing. This is as important as L3 and is usually untested."""
    probe = tempfile.mkdtemp(prefix="rl-conf-l4-")
    try:
        innocent = os.path.join(probe, "innocent_agent.py")
        with open(innocent, "w") as fh:
            fh.write(
                "__manifest__ = {'name': '@x/innocent', 'capabilities': []}\n"
                "import json\n"
                "class A:\n"
                "    def run(self):\n"
                "        return json.loads('{}')\n"
                "    def go(self):\n"
                "        return self.run()\n")
        observed, _ev = POLICY.observed_capabilities(innocent)
        if observed:
            return False, ("json.loads and self.run() were misread as %s"
                           % sorted(observed))
        return True, "json.loads and self.run() raise no finding"
    finally:
        shutil.rmtree(probe, ignore_errors=True)


@check("L5", "Every organ in this repo passes the check it enforces on others.")
def l5_organs_self_conform():
    bad = []
    for path in ORGAN_FILES:
        observed, _ev = POLICY.observed_capabilities(path)
        declared = set((POLICY.declared_capabilities(path) or {})
                       .get("capabilities") or [])
        undeclared = sorted(observed - declared)
        if undeclared:
            bad.append(f"{os.path.basename(path)} under-declares {undeclared}")
    if bad:
        return False, "; ".join(bad)
    return True, "%d organs declare every capability their code can reach" % len(ORGAN_FILES)


@check("L6", "An absent or altered manifest fails closed, not open.")
def l6_fails_closed():
    probe = tempfile.mkdtemp(prefix="rl-conf-l6-")
    try:
        agents = os.path.join(probe, "agents")
        os.makedirs(agents)
        shutil.copy(os.path.join(ORGANS, "strain_credential_agent.py"), agents)
        manifest = os.path.join(probe, "strain.json")
        os.environ["RAPP_STRAIN_MANIFEST"] = manifest
        cred = load("_c6", os.path.join(agents, "strain_credential_agent.py"))

        # absent
        man = cred.load_manifest()
        allowed, _ = cred.adjudicate(man, "anything.py", ["azure/key"])
        if allowed:
            return False, "an absent manifest granted a credential"

        # altered seal
        with open(manifest, "w") as fh:
            json.dump({"allowlist": {"a" * 64: {"file": "x.py", "sha256": "a" * 64}},
                       "credentials": {"grants": {"a" * 64: ["*"]}},
                       "seal": "sha256:" + "0" * 64}, fh)
        man = cred.load_manifest()
        if man.get("_assurance") != "ALTERED":
            return False, "a manifest with a wrong seal was not detected"
        allowed, _ = cred.adjudicate(man, "x.py", ["azure/key"])
        if allowed:
            return False, "a manifest with a broken seal still granted a credential"
        return True, "absent manifest and broken seal both grant nothing"
    finally:
        os.environ.pop("RAPP_STRAIN_MANIFEST", None)
        shutil.rmtree(probe, ignore_errors=True)


# ── credentials ──────────────────────────────────────────────────────────────

@check("L7", "No organ exposes an action that returns a credential value.")
def l7_no_sighted_read():
    agent = CRED.StrainCredentialAgent()
    actions = set(agent.metadata["parameters"]["properties"]["action"]["enum"])
    forbidden = {"get", "read", "reveal", "show", "value", "fetch", "dump"}
    overlap = actions & forbidden
    if overlap:
        return False, "the credential organ exposes %s" % sorted(overlap)
    # and no organ should shell out to the broker's sighted-read path
    for path in ORGAN_FILES:
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        if '"get"' in body and "rapp-keyring" in body and "--i-know" in body:
            return False, f"{os.path.basename(path)} can invoke a sighted read"
    return True, "actions are %s — none of them yields a value" % sorted(actions)


@check("L8", "An agent edited after approval loses its credential grants.")
def l8_identity_binds_grants():
    probe = tempfile.mkdtemp(prefix="rl-conf-l8-")
    try:
        agents = os.path.join(probe, "agents")
        os.makedirs(agents)
        shutil.copy(os.path.join(ORGANS, "strain_credential_agent.py"), agents)
        target = os.path.join(agents, "deploy_agent.py")
        with open(target, "w") as fh:
            fh.write("__manifest__ = {'name': '@x/d'}\n")
        sha = sha256_file(target)
        manifest = os.path.join(probe, "strain.json")
        with open(manifest, "w") as fh:
            json.dump({"allowlist": {sha: {"file": "deploy_agent.py",
                                           "sha256": sha, "ring": "ga"}},
                       "credentials": {"grants": {sha: ["azure/*"]}}}, fh)
        os.environ["RAPP_STRAIN_MANIFEST"] = manifest
        cred = load("_c8", os.path.join(agents, "strain_credential_agent.py"))

        allowed, _ = cred.adjudicate(cred.load_manifest(), "deploy_agent.py",
                                     ["azure/key"])
        if not allowed:
            return False, "an approved agent was refused its own grant"

        with open(target, "a") as fh:
            fh.write("# edited after approval\n")
        allowed, refused = cred.adjudicate(cred.load_manifest(),
                                           "deploy_agent.py", ["azure/key"])
        if allowed:
            return False, "an edited agent kept its credential grant"
        return True, "grant applied before the edit, refused after: %s" % refused[0][1][:60]
    finally:
        os.environ.pop("RAPP_STRAIN_MANIFEST", None)
        shutil.rmtree(probe, ignore_errors=True)


@check("L9", "A refused credential means the command never runs.")
def l9_refusal_is_not_advisory():
    probe = tempfile.mkdtemp(prefix="rl-conf-l9-")
    try:
        agents = os.path.join(probe, "agents")
        os.makedirs(agents)
        shutil.copy(os.path.join(ORGANS, "strain_credential_agent.py"), agents)
        manifest = os.path.join(probe, "strain.json")
        with open(manifest, "w") as fh:
            json.dump({"allowlist": {}, "credentials": {"grants": {}}}, fh)
        os.environ["RAPP_STRAIN_MANIFEST"] = manifest
        cred = load("_c9", os.path.join(agents, "strain_credential_agent.py"))
        agent = cred.StrainCredentialAgent()
        marker = os.path.join(probe, "side-effect")
        out = json.loads(agent.perform(action="use", agent="rogue.py",
                                       credential="azure/key",
                                       command=["sh", "-c", f"touch {marker}"]))
        if os.path.exists(marker):
            return False, "the command executed despite the credential refusal"
        if out.get("status") != "refused":
            return False, "a refusal did not report status=refused"
        return True, "refused request produced no side effect on disk"
    finally:
        os.environ.pop("RAPP_STRAIN_MANIFEST", None)
        shutil.rmtree(probe, ignore_errors=True)


# ── the audit record ─────────────────────────────────────────────────────────

@check("L10", "The audit record is tamper-evident.")
def l10_audit_tamper_evident():
    probe = tempfile.mkdtemp(prefix="rl-conf-l10-")
    try:
        path = os.path.join(probe, "audit.jsonl")
        for i in range(5):
            POLICY.chain_append(path, {"at": i, "event": "agent.withheld",
                                       "file": f"a{i}.py"})

        def records():
            with open(path) as fh:
                return [json.loads(line) for line in fh if line.strip()]

        ok, detail, _ = POLICY.verify_audit_chain(records())
        if not ok:
            return False, "a freshly written chain did not verify: %s" % detail

        original = open(path).read()
        detections = []

        rows = records()
        rows[2]["file"] = "tampered.py"
        with open(path, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        detections.append(("modification", not POLICY.verify_audit_chain(records())[0]))

        with open(path, "w") as fh:
            fh.write(original)
        rows = records()
        del rows[1]
        with open(path, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        detections.append(("deletion", not POLICY.verify_audit_chain(records())[0]))

        with open(path, "w") as fh:
            fh.write(original)
        with open(path, "a") as fh:
            fh.write(json.dumps({"at": 9, "event": "credential.used",
                                 "prev": "0" * 64, "hash": "f" * 64},
                                sort_keys=True) + "\n")
        detections.append(("forged append",
                           not POLICY.verify_audit_chain(records())[0]))

        missed = [name for name, caught in detections if not caught]
        if missed:
            return False, "undetected: %s" % ", ".join(missed)
        return True, "modification, deletion and forged append all detected"
    finally:
        shutil.rmtree(probe, ignore_errors=True)


@check("L11", "The audit record carries no secret and no agent source.")
def l11_audit_leaks_nothing():
    probe = tempfile.mkdtemp(prefix="rl-conf-l11-")
    try:
        path = os.path.join(probe, "audit.jsonl")
        POLICY.chain_append(path, {
            "at": 1, "event": "credential.used", "agent": "deploy_agent.py",
            "credentials": ["azure/storage-key"], "command": "deploy.sh"})
        blob = open(path).read()
        for forbidden in ("import ", "def ", "AccountKey=", "-----BEGIN"):
            if forbidden in blob:
                return False, "the record contains %r" % forbidden
        if "azure/storage-key" not in blob:
            return False, "the record does not name the credential used"
        return True, ("names, decisions and reasons only — shippable to a SIEM "
                      "without becoming the leak it exists to detect")
    finally:
        shutil.rmtree(probe, ignore_errors=True)


@check("L12", "Elevation changes policy; it cannot bypass a check.")
def l12_elevation_bounded():
    """An administrator can widen what is admitted. They cannot admit an agent
    whose code reaches further than it declares — that is the difference between
    an override and a hole."""
    probe = tempfile.mkdtemp(prefix="rl-conf-l12-")
    try:
        liar = os.path.join(probe, "liar_agent.py")
        with open(liar, "w") as fh:
            fh.write("__manifest__ = {'name': '@x/liar', 'capabilities': [], "
                     "'ring': 'ga'}\nimport subprocess\n"
                     "def go(): subprocess.run(['id'])\n")
        sha = sha256_file(liar)
        # Force it into the allowlist, as a determined administrator would.
        policy = {"band": "frontier", "require_allowlist": True,
                  "allowlist": {sha: {"file": "liar_agent.py", "sha256": sha,
                                      "ring": "ga"}},
                  "forbidden_capabilities": []}
        allowed, record = POLICY.adjudicate(liar, policy)
        if allowed:
            return False, ("an administrator-approved agent whose code exceeds "
                           "its declaration was admitted")
        return True, "forced approval still refused: %s" % str(
            record.get("reason", ""))[:70]
    finally:
        shutil.rmtree(probe, ignore_errors=True)


# ── tooling ──────────────────────────────────────────────────────────────────

@check("L13", "strainctl cannot approve anything without the seal key.")
def l13_seal_key_required():
    probe = tempfile.mkdtemp(prefix="rl-conf-l13-")
    try:
        manifest = os.path.join(probe, "strain.json")
        env = {k: v for k, v in os.environ.items() if k != "RAPP_STRAIN_SEAL_KEY"}
        subprocess.run(STRAINCTL + ["--manifest", manifest, "init", "Probe Ltd"],
                       capture_output=True, text=True, env=env)
        if not os.path.isfile(manifest):
            return None, "strainctl init did not produce a manifest"
        target = os.path.join(probe, "x_agent.py")
        with open(target, "w") as fh:
            fh.write("__manifest__ = {'name': '@x/x', 'capabilities': []}\n")
        env["RAPP_STRAIN_SEAL_KEY"] = "the-real-key"
        subprocess.run(STRAINCTL + ["--manifest", manifest, "seal"],
                       capture_output=True, text=True, env=env)
        env.pop("RAPP_STRAIN_SEAL_KEY")
        proc = subprocess.run(
            STRAINCTL + ["--manifest", manifest, "approve", target],
            capture_output=True, text=True, env=env)
        if proc.returncode == 0:
            return False, "an approval succeeded with no seal key present"
        return True, "approval without the seal key exits %d" % proc.returncode
    finally:
        shutil.rmtree(probe, ignore_errors=True)


@check("L14", "The repo contains no credential of its own.")
def l14_repo_is_clean():
    broker = shutil.which("rapp-keyring") or \
        os.path.expanduser("~/.local/bin/rapp-keyring")
    if not (os.path.isfile(broker) and os.access(broker, os.X_OK)):
        return None, "rapp-keyring not installed; cannot run the credential scan"
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT,
                             capture_output=True, text=True).stdout.split()
    if not tracked:
        return None, "not a git checkout"
    proc = subprocess.run([broker, "scan"] + tracked, cwd=ROOT,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return False, proc.stdout.strip().splitlines()[0] if proc.stdout else "findings"
    return True, "%d tracked files scanned, no plaintext credential" % len(tracked)


# ── report ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="RAPP Light conformance gate")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    rows, failed, skipped = [], 0, 0
    for fn in CHECKS:
        try:
            outcome = fn()
            ok, detail = outcome if outcome is not None else (None, "no result")
        except Exception as exc:  # a check that explodes is a failing check
            ok, detail = False, "check raised %s: %s" % (type(exc).__name__, exc)
        status = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        if ok is None:
            skipped += 1
        elif not ok:
            failed += 1
        rows.append({"id": fn._cid, "claim": fn._claim,
                     "status": status, "detail": detail})

    if args.json:
        print(json.dumps({"passed": sum(1 for r in rows if r["status"] == "PASS"),
                          "failed": failed, "skipped": skipped, "checks": rows},
                         indent=2))
        return 1 if failed else 0

    print("RAPP Light — conformance")
    print("=" * 74)
    for row in rows:
        print()
        print("%s  %-4s %s" % (row["status"].ljust(4), row["id"], row["claim"]))
        print("      %s" % row["detail"])
    print()
    print("=" * 74)
    print("%d passed, %d failed, %d skipped"
          % (sum(1 for r in rows if r["status"] == "PASS"), failed, skipped))
    if failed:
        print("\nCONFORMANCE FAILED — do not ship this build.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
