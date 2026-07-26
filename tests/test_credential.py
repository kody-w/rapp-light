"""Tests for governed credential use and the tamper-evident audit record.

Every mitigation the credential organ claims has a test named for it here. The
broker is not required: tests that need a real RAPP Keyring skip cleanly, so
this suite is meaningful on a bare CI runner and complete on a developer machine.

    python3 -m unittest discover -s tests -v
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ORGANS = os.path.join(ROOT, "organs")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


POLICY = _load("_pol", os.path.join(ORGANS, "aa_strain_policy_agent.py"))


def broker_available():
    path = shutil.which("rapp-keyring") or os.path.expanduser("~/.local/bin/rapp-keyring")
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


class StrainFixture(unittest.TestCase):
    """A throwaway strain: an agents dir, an approved agent, a manifest."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="rl-cred-")
        self.agents = os.path.join(self.home, "agents")
        os.makedirs(self.agents, exist_ok=True)
        # The organ resolves the strain relative to its own location, so it has
        # to be loaded from inside the fixture's agents directory.
        shutil.copy(os.path.join(ORGANS, "strain_credential_agent.py"), self.agents)
        shutil.copy(os.path.join(ORGANS, "aa_strain_policy_agent.py"), self.agents)
        self.manifest = os.path.join(self.home, "strain.json")

        self.agent_file = os.path.join(self.agents, "deploy_agent.py")
        with open(self.agent_file, "w") as fh:
            fh.write("__manifest__ = {'name': '@x/deploy', 'capabilities': []}\n")
        self.sha = self._sha(self.agent_file)

        self._saved = os.environ.get("RAPP_STRAIN_MANIFEST")
        os.environ["RAPP_STRAIN_MANIFEST"] = self.manifest
        self.write_manifest()
        self.cred = _load("_cred", os.path.join(self.agents,
                                                "strain_credential_agent.py"))

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("RAPP_STRAIN_MANIFEST", None)
        else:
            os.environ["RAPP_STRAIN_MANIFEST"] = self._saved
        shutil.rmtree(self.home, ignore_errors=True)

    @staticmethod
    def _sha(path):
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()

    def write_manifest(self, grants=None, deny=None, seal=None):
        man = {
            "organisation": "Test Ltd",
            "band": "ga",
            "allowlist": {self.sha: {"file": "deploy_agent.py",
                                     "sha256": self.sha, "ring": "ga"}},
            "credentials": {"grants": grants if grants is not None
                            else {self.sha: ["azure/*"]},
                            "deny": deny or []},
        }
        if seal is not None:
            man["seal"] = seal
        with open(self.manifest, "w") as fh:
            json.dump(man, fh, indent=2, sort_keys=True)
        return man


# ── grants ───────────────────────────────────────────────────────────────────

class TestGrants(StrainFixture):
    def test_granted_pattern_is_allowed(self):
        man = self.cred.load_manifest()
        allowed, refused = self.cred.adjudicate(man, "deploy_agent.py",
                                                ["azure/storage-key"])
        self.assertEqual(allowed, ["azure/storage-key"])
        self.assertEqual(refused, [])

    def test_ungranted_pattern_is_refused(self):
        man = self.cred.load_manifest()
        allowed, refused = self.cred.adjudicate(man, "deploy_agent.py",
                                                ["github/pat"])
        self.assertEqual(allowed, [])
        self.assertEqual(len(refused), 1)

    def test_deny_outranks_grant(self):
        """An administrator who grants azure/* later must not silently
        re-enable a pattern security explicitly denied."""
        self.write_manifest(grants={self.sha: ["azure/*", "prod/*"]},
                            deny=["prod/*"])
        man = self.cred.load_manifest()
        allowed, refused = self.cred.adjudicate(man, "deploy_agent.py",
                                                ["prod/db"])
        self.assertEqual(allowed, [])
        self.assertIn("denied by the strain rule", refused[0][1])

    def test_agent_not_in_allowlist_gets_nothing(self):
        man = self.cred.load_manifest()
        allowed, refused = self.cred.adjudicate(man, "rogue_agent.py",
                                                ["azure/storage-key"])
        self.assertEqual(allowed, [])
        self.assertIn("not in the strain allowlist", refused[0][1])

    def test_edited_agent_loses_its_grants(self):
        """The identity check doing double duty: an agent cannot acquire a
        credential grant by being edited after it was approved."""
        with open(self.agent_file, "a") as fh:
            fh.write("# edited after approval\n")
        man = self.cred.load_manifest()
        allowed, refused = self.cred.adjudicate(man, "deploy_agent.py",
                                                ["azure/storage-key"])
        self.assertEqual(allowed, [])
        self.assertIn("changed since it was approved", refused[0][1])

    def test_altered_seal_refuses_every_credential(self):
        """Fail closed: a manifest whose seal does not verify grants nothing."""
        self.write_manifest(seal="sha256:" + "0" * 64)
        man = self.cred.load_manifest()
        self.assertEqual(man.get("_assurance"), "ALTERED")
        allowed, refused = self.cred.adjudicate(man, "deploy_agent.py",
                                                ["azure/storage-key"])
        self.assertEqual(allowed, [])
        self.assertIn("seal does not verify", refused[0][1])

    def test_absent_manifest_grants_nothing(self):
        os.unlink(self.manifest)
        man = self.cred.load_manifest()
        allowed, _ = self.cred.adjudicate(man, "deploy_agent.py",
                                          ["azure/storage-key"])
        self.assertEqual(allowed, [])

    def test_no_grants_at_all_is_explicit_about_it(self):
        self.write_manifest(grants={})
        man = self.cred.load_manifest()
        _allowed, refused = self.cred.adjudicate(man, "deploy_agent.py",
                                                 ["azure/storage-key"])
        self.assertIn("no credentials at all", refused[0][1])


# ── the organ's surface ──────────────────────────────────────────────────────

class TestOrganSurface(StrainFixture):
    def test_there_is_no_action_that_returns_a_secret(self):
        """The central claim. If a `get`-shaped action ever appears, this fails."""
        agent = self.cred.StrainCredentialAgent()
        actions = agent.metadata["parameters"]["properties"]["action"]["enum"]
        for forbidden in ("get", "read", "reveal", "show", "value", "fetch"):
            self.assertNotIn(forbidden, actions)
        self.assertEqual(set(actions), {"available", "check", "use", "explain"})

    def test_perform_never_raises(self):
        """An organ that throws takes down the brainstem it is protecting."""
        agent = self.cred.StrainCredentialAgent()
        for bad in ({}, {"action": "nonsense"}, {"action": "use"},
                    {"action": "check"}, {"action": "use", "command": "not-a-list"}):
            out = agent.perform(**bad)
            self.assertIsInstance(out, str)
            json.loads(out)  # always valid JSON, even on failure

    def test_system_context_never_invites_pasting_a_secret(self):
        """Assert the BEHAVIOUR, not one exact phrasing.

        This asserted the literal string "never ask the user to paste" while
        the organ says "do not ask the user to paste a secret into the
        conversation" — same instruction, different words, and the test was
        red. A prompt-wording test that pins an exact sentence breaks every
        time someone improves the sentence, which teaches people to edit the
        test instead of reading it."""
        agent = self.cred.StrainCredentialAgent()
        text = agent.system_context().lower()
        self.assertIn("paste", text)
        self.assertTrue(
            any(neg in text for neg in ("do not ask", "never ask", "don't ask")),
            f"system_context must instruct against soliciting a pasted secret; "
            f"got: {text[:200]!r}")

    def test_check_action_explains_a_refusal(self):
        agent = self.cred.StrainCredentialAgent()
        out = json.loads(agent.perform(action="check", agent="rogue.py",
                                       credential="azure/storage-key"))
        self.assertEqual(out["granted"], [])
        self.assertTrue(out["refused"][0]["reason"])

    def test_declared_capabilities_match_its_own_code(self):
        """The organ is subject to the same check 4 it helps enforce."""
        path = os.path.join(ORGANS, "strain_credential_agent.py")
        observed, _ev = POLICY.observed_capabilities(path)
        declared = set((POLICY.declared_capabilities(path) or {})
                       .get("capabilities") or [])
        self.assertEqual(sorted(observed - declared), [])

    def test_both_organs_resolve_the_same_strain_path(self):
        """If the two organs disagree about where the strain lives, one enforces
        a policy the other cannot see."""
        pol = _load("_pol2", os.path.join(self.agents, "aa_strain_policy_agent.py"))
        cred = _load("_cred2", os.path.join(self.agents, "strain_credential_agent.py"))
        os.environ.pop("RAPP_STRAIN_MANIFEST", None)
        try:
            self.assertEqual(pol._strain_path(), cred._strain_path())
        finally:
            os.environ["RAPP_STRAIN_MANIFEST"] = self.manifest


# ── the audit record ─────────────────────────────────────────────────────────

class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rl-audit-")
        self.path = os.path.join(self.dir, "strain-audit.jsonl")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _records(self):
        with open(self.path) as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def test_chain_verifies(self):
        for i in range(5):
            POLICY.chain_append(self.path, {"at": i, "event": "agent.withheld",
                                            "file": f"a{i}.py"})
        ok, detail, count = POLICY.verify_audit_chain(self._records())
        self.assertTrue(ok, detail)
        self.assertEqual(count, 5)

    def test_modified_record_detected(self):
        for i in range(4):
            POLICY.chain_append(self.path, {"at": i, "event": "x", "file": f"a{i}"})
        records = self._records()
        records[1]["file"] = "tampered.py"
        with open(self.path, "w") as fh:
            for rec in records:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        ok, detail, _ = POLICY.verify_audit_chain(self._records())
        self.assertFalse(ok)
        self.assertIn("2", detail)

    def test_deleted_record_detected(self):
        for i in range(4):
            POLICY.chain_append(self.path, {"at": i, "event": "x", "file": f"a{i}"})
        records = self._records()
        del records[1]
        with open(self.path, "w") as fh:
            for rec in records:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        self.assertFalse(POLICY.verify_audit_chain(self._records())[0])

    def test_forged_append_detected(self):
        POLICY.chain_append(self.path, {"at": 1, "event": "x"})
        with open(self.path, "a") as fh:
            fh.write(json.dumps({"at": 2, "event": "credential.used",
                                 "prev": "0" * 64, "hash": "f" * 64},
                                sort_keys=True) + "\n")
        self.assertFalse(POLICY.verify_audit_chain(self._records())[0])

    def test_legacy_unchained_records_are_not_called_tampering(self):
        """An old record predating chaining is reported as legacy. Calling an
        old format an attack is how an audit tool loses its reader."""
        with open(self.path, "w") as fh:
            fh.write(json.dumps({"at": 1, "event": "agent.withheld"}) + "\n")
        ok, detail, _ = POLICY.verify_audit_chain(self._records())
        self.assertTrue(ok)
        self.assertIn("predate chaining", detail)

    def test_record_never_contains_a_credential_value(self):
        POLICY.chain_append(self.path, {"at": 1, "event": "credential.used",
                                        "agent": "deploy_agent.py",
                                        "credentials": ["azure/storage-key"]})
        with open(self.path) as fh:
            blob = fh.read()
        self.assertIn("azure/storage-key", blob)   # the NAME is the point
        self.assertNotIn("SECRET", blob.upper().replace("AZURE/STORAGE-KEY", ""))


# ── end to end, with a real broker ───────────────────────────────────────────

@unittest.skipUnless(broker_available(), "rapp-keyring is not installed")
class TestEndToEnd(StrainFixture):
    SECRET = "e2e-strain-secret-value-7788990011"
    NAME = "azure/rapp-light-e2e"

    def setUp(self):
        super().setUp()
        self.kr_home = tempfile.mkdtemp(prefix="rl-kr-")
        self.env = dict(os.environ,
                        RAPP_KEYRING_HOME=self.kr_home,
                        RAPP_KEYRING_CALLER="shell")
        self._kr(["init"])
        self._kr(["set", self.NAME, "--stdin"], stdin=self.SECRET)
        self.write_manifest(grants={self.sha: ["azure/*"]})

    def tearDown(self):
        self._kr(["rm", self.NAME, "--yes"])
        shutil.rmtree(self.kr_home, ignore_errors=True)
        super().tearDown()

    def _kr(self, args, stdin=None):
        binary = shutil.which("rapp-keyring") or \
            os.path.expanduser("~/.local/bin/rapp-keyring")
        return subprocess.run([binary] + args, capture_output=True, text=True,
                              env=self.env, input=stdin)

    def test_credential_reaches_the_command_but_not_the_organ(self):
        agent = self.cred.StrainCredentialAgent()
        os.environ.update(RAPP_KEYRING_HOME=self.kr_home,
                          RAPP_KEYRING_CALLER="shell")
        out = agent.perform(action="use", agent="deploy_agent.py",
                            credential=self.NAME,
                            command=["sh", "-c", 'echo "using $AZURE_RAPP_LIGHT_E2E"'])
        result = json.loads(out)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["credentials_injected"], [self.NAME])
        # The command ran with the real value...
        self.assertIn("using", result["stdout"])
        # ...and the value came back masked, so it never enters model context.
        self.assertNotIn(self.SECRET, out)
        self.assertIn("redacted", result["stdout"])

    def test_refused_credential_never_runs_the_command(self):
        agent = self.cred.StrainCredentialAgent()
        marker = os.path.join(self.home, "should-not-exist")
        out = json.loads(agent.perform(
            action="use", agent="rogue_agent.py", credential=self.NAME,
            command=["sh", "-c", f"touch {marker}"]))
        self.assertEqual(out["status"], "refused")
        self.assertFalse(os.path.exists(marker),
                         "the command ran despite the credential being refused")


if __name__ == "__main__":
    unittest.main(verbosity=2)
