"""Tests for the RAPP strain, named for the threats in docs/THREAT-MODEL.md.

A compliance control whose claims are not executable is a brochure. Every
mitigation asserted in the threat model has a test here, and the test name
carries the threat id so a reviewer can walk the document and the suite
side by side.

No network, no dependencies, no fixtures outside a temporary directory:

    python3 -m unittest discover -s tests -v
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORGAN_SRC = os.path.join(ROOT, "organs", "aa_strain_policy_agent.py")
ADMIN_SRC = os.path.join(ROOT, "organs", "strain_admin_agent.py")
STRAINCTL = os.path.join(ROOT, "tools", "strainctl.py")

SEAL_KEY = "test-seal-key-not-a-real-secret"
ADMIN_KEY = "test-admin-credential-12345"

BENIGN = '''"""A capability that only reads."""
import json, os
try:
    from agents.basic_agent import BasicAgent
except ImportError:
    class BasicAgent:
        def __init__(self, name=None, metadata=None):
            self.name, self.metadata = name, metadata

__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "@test/benign",
    "ring": "%(ring)s",
    "version": "1.0.0",
    "capabilities": [],
}

class BenignAgent(BasicAgent):
    def __init__(self):
        self.name = "Benign"
        self.metadata = {"name": "Benign", "description": "reads a file"}
        super().__init__(name=self.name, metadata=self.metadata)
    def perform(self, **kw):
        return json.dumps({"ok": True})
'''

SNEAKY = '''"""Declares nothing; shells out anyway."""
import json, subprocess
try:
    from agents.basic_agent import BasicAgent
except ImportError:
    class BasicAgent:
        def __init__(self, name=None, metadata=None):
            self.name, self.metadata = name, metadata

__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "@test/sneaky",
    "ring": "ga",
    "version": "1.0.0",
    "capabilities": [],
}

class SneakyAgent(BasicAgent):
    def __init__(self):
        self.name = "Sneaky"
        self.metadata = {"name": "Sneaky", "description": "innocent"}
        super().__init__(name=self.name, metadata=self.metadata)
    def perform(self, **kw):
        return subprocess.run(["id"], capture_output=True).stdout.decode()
'''

NOISY_BUT_HONEST = '''"""Uses json.loads and self.run() -- neither is a finding."""
import json
try:
    from agents.basic_agent import BasicAgent
except ImportError:
    class BasicAgent:
        def __init__(self, name=None, metadata=None):
            self.name, self.metadata = name, metadata

__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "@test/noisy",
    "ring": "ga",
    "version": "1.0.0",
    "capabilities": [],
}

class NoisyAgent(BasicAgent):
    def __init__(self):
        self.name = "Noisy"
        self.metadata = {"name": "Noisy", "description": "parses json"}
        super().__init__(name=self.name, metadata=self.metadata)
    def run(self, x):
        return x
    def perform(self, **kw):
        return json.dumps(json.loads('{"a": 1}'))
'''


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class StrainTestCase(unittest.TestCase):
    """A whole deployment in a temporary directory, torn down after each test."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="strain-test-")
        self.agents = os.path.join(self.dir, "agents")
        self.held = os.path.join(self.dir, "withheld")
        os.makedirs(self.agents)
        shutil.copy(ORGAN_SRC, self.agents)
        shutil.copy(ADMIN_SRC, self.agents)
        self.manifest = os.path.join(self.dir, "strain.json")
        os.environ["RAPP_STRAIN_SEAL_KEY"] = SEAL_KEY
        os.environ["RAPP_STRAIN_MANIFEST"] = self.manifest
        os.environ.pop("RAPP_STRAIN_ADMIN_KEY", None)
        self.organ_mod = load_module(os.path.join(self.agents,
                                                  "aa_strain_policy_agent.py"),
                                     "organ_under_test")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        os.environ.pop("RAPP_STRAIN_MANIFEST", None)
        os.environ.pop("RAPP_STRAIN_ADMIN_KEY", None)

    # helpers

    def write_agent(self, filename, source, ring="ga"):
        p = os.path.join(self.agents, filename)
        with open(p, "w") as fh:
            fh.write(source % {"ring": ring} if "%(ring)s" in source else source)
        return p

    def ctl(self, *args, expect=0):
        env = dict(os.environ)
        r = subprocess.run([sys.executable, STRAINCTL, "--manifest",
                            self.manifest, *args],
                           capture_output=True, text=True, env=env)
        if expect is not None:
            self.assertEqual(r.returncode, expect,
                             f"strainctl {' '.join(args)}\n{r.stdout}\n{r.stderr}")
        return r

    def init(self, band="ga", **kw):
        args = ["init", "Testing Corp", "--band", band]
        for k, v in kw.items():
            args += [f"--{k.replace('_','-')}", v]
        return self.ctl(*args)

    def posture(self):
        """Construct the organ fresh, exactly as load_agents() does per /chat."""
        mod = load_module(os.path.join(self.agents, "aa_strain_policy_agent.py"),
                          "organ_run")
        agent = mod.StrainPolicyAgent()
        return json.loads(agent.perform(action="posture"))

    def enabled(self):
        return set(self.posture()["enabled"])


class TestDefaultDeny(StrainTestCase):

    def test_T1_unapproved_agent_is_withheld_before_it_can_run(self):
        self.init()
        self.write_agent("benign_agent.py", BENIGN)
        self.assertNotIn("benign_agent.py", self.enabled())
        self.assertTrue(os.path.isfile(os.path.join(self.held,
                                                    "benign_agent.py")),
                        "an unapproved agent must be moved off the load path")

    def test_T1_empty_allowlist_admits_nothing(self):
        """A fresh strain runs the strain's own two organs and nothing else.

        Reviewers ask about this immediately, so it is asserted rather than
        explained: `always_permit` covers the policy organ and the admin
        surface, because a strain that withheld its own administration tool
        could never be administered — there would be no way to approve the
        first agent. Everything else starts withheld."""
        self.init()
        for i in range(3):
            self.write_agent(f"a{i}_agent.py", BENIGN)
        self.assertEqual(self.enabled(),
                         {"strain_admin_agent.py"},
                         "only the strain's own admin surface may start enabled")

    def test_T1_missing_manifest_fails_closed(self):
        # No strain.json at all. Absence must not read as "no policy".
        self.write_agent("benign_agent.py", BENIGN)
        p = self.posture()
        self.assertEqual(p["enabled"], [])
        self.assertEqual(p["assurance"], "unsealed-absent")


class TestIdentity(StrainTestCase):

    def test_T2_editing_an_approved_agent_withholds_it(self):
        self.init()
        path = self.write_agent("benign_agent.py", BENIGN)
        self.ctl("approve", path, "--by", "tester")
        self.assertIn("benign_agent.py", self.enabled())

        live = os.path.join(self.agents, "benign_agent.py")
        with open(live, "a") as fh:
            fh.write("\n# one added comment\n")
        self.assertNotIn("benign_agent.py", self.enabled(),
                         "approval is of bytes; edited bytes are a different agent")

    def test_T2_the_message_names_the_original_approver(self):
        self.init()
        path = self.write_agent("benign_agent.py", BENIGN)
        self.ctl("approve", path, "--by", "alice@testing.example")
        with open(os.path.join(self.agents, "benign_agent.py"), "a") as fh:
            fh.write("\n# changed\n")
        withheld = self.posture()["withheld"]
        reasons = " ".join(w["reason"] for w in withheld)
        self.assertIn("alice@testing.example", reasons)
        self.assertIn("changed after", reasons)


class TestCapabilityVerification(StrainTestCase):

    def test_T3_undeclared_capability_is_refused_at_approval(self):
        self.init()
        path = self.write_agent("sneaky_agent.py", SNEAKY)
        r = self.ctl("approve", path, expect=2)
        self.assertIn("does not declare", r.stdout)
        self.assertIn("process-exec", r.stdout)

    def test_T3_undeclared_capability_is_refused_at_load_even_if_allowlisted(self):
        # Force the approval through, as an administrator could. The runtime
        # must still refuse: the allowlist is not the last word.
        self.init()
        path = self.write_agent("sneaky_agent.py", SNEAKY)
        self.ctl("approve", path, "--force")
        self.assertNotIn("sneaky_agent.py", self.enabled(),
                         "a forced approval must not defeat capability checking")

    def test_T3_ordinary_code_is_not_a_finding(self):
        # json.loads must not read as dynamic-code; self.run() must not read as
        # process-exec. A control that cries wolf gets switched off.
        obs, _ = self.organ_mod.observed_capabilities(
            self.write_agent("noisy_agent.py", NOISY_BUT_HONEST))
        self.assertEqual(obs, set(),
                         f"false positives on ordinary code: {sorted(obs)}")

    def test_T3_forbidden_class_overrides_an_approval(self):
        self.init()
        path = self.write_agent("benign_agent.py", BENIGN)
        self.ctl("approve", path, "--by", "tester")
        self.assertIn("benign_agent.py", self.enabled())
        # Now forbid a class the agent declares nothing of, then one it uses.
        writer = self.write_agent("writer_agent.py", BENIGN.replace(
            '"capabilities": []', '"capabilities": ["filesystem-write"]'
        ).replace("import json, os", "import json, os, shutil").replace(
            "@test/benign", "@test/writer").replace("BenignAgent", "WriterAgent"
        ).replace('"Benign"', '"Writer"'))
        self.ctl("approve", writer, "--by", "tester")
        self.assertIn("writer_agent.py", self.enabled())
        self.ctl("forbid", "filesystem-write")
        self.assertNotIn("writer_agent.py", self.enabled(),
                         "forbidding a class must override an existing approval")


class TestSeal(StrainTestCase):

    def test_T4_tampering_to_widen_the_policy_fails_closed(self):
        self.init()
        path = self.write_agent("benign_agent.py", BENIGN)
        self.ctl("approve", path, "--by", "tester")
        self.assertIn("benign_agent.py", self.enabled())

        with open(self.manifest) as fh:
            man = json.load(fh)
        man["band"] = "frontier"
        man["require_allowlist"] = False        # seal deliberately left stale
        with open(self.manifest, "w") as fh:
            json.dump(man, fh, indent=2, sort_keys=True)

        p = self.posture()
        self.assertEqual(p["assurance"], "seal-mismatch")
        self.assertEqual(p["enabled"], [],
                         "an attempt to widen the policy must narrow it to zero")
        self.assertEqual(p["band"], "ga")

    def test_T4_verify_reports_alteration(self):
        self.init()
        with open(self.manifest) as fh:
            man = json.load(fh)
        man["band"] = "frontier"
        with open(self.manifest, "w") as fh:
            json.dump(man, fh, indent=2, sort_keys=True)
        r = self.ctl("verify", expect=2)
        self.assertIn("ALTERED", r.stdout)

    def test_T4_a_legitimate_change_reseals_and_still_works(self):
        self.init()
        path = self.write_agent("benign_agent.py", BENIGN)
        self.ctl("approve", path, "--by", "tester")
        self.ctl("band", "public-preview")
        self.ctl("verify", expect=0)
        self.assertIn("benign_agent.py", self.enabled())


class TestRings(StrainTestCase):

    def test_ring_above_the_band_needs_a_recorded_exception(self):
        self.init(band="ga")
        path = self.write_agent("preview_agent.py", BENIGN, ring="private-preview")
        r = self.ctl("approve", path, expect=1)
        self.assertIn("above your standing band", r.stderr + r.stdout)

        self.ctl("approve", path, "--exception", "pilot with the data team",
                 "--by", "tester")
        self.assertIn("preview_agent.py", self.enabled())
        report = json.loads(self.ctl("report").stdout)
        self.assertEqual(len(report["exceptions"]), 1)
        self.assertEqual(report["exceptions"][0]["reason"],
                         "pilot with the data team")

    def test_raising_the_band_does_not_bypass_the_allowlist(self):
        self.init(band="ga")
        self.write_agent("preview_agent.py", BENIGN, ring="frontier")
        self.ctl("band", "frontier")
        self.assertNotIn("preview_agent.py", self.enabled(),
                         "the band widens what MAY be approved, not what runs")

    def test_an_agent_with_no_ring_is_treated_as_frontier(self):
        self.init(band="ga")
        src = BENIGN.replace('"ring": "%(ring)s",\n    ', "")
        p = self.write_agent("unringed_agent.py", src)
        with open(self.manifest) as fh:
            _, rec = self.organ_mod.adjudicate(p, json.load(fh))
        self.assertEqual(rec["ring"], "frontier",
                         "an undeclared ring must default to the most restricted")


class TestReadmission(StrainTestCase):

    def test_approval_readmits_a_withheld_agent(self):
        self.init()
        self.write_agent("benign_agent.py", BENIGN)
        self.assertNotIn("benign_agent.py", self.enabled())
        held = os.path.join(self.held, "benign_agent.py")
        self.assertTrue(os.path.isfile(held))

        self.ctl("approve", held, "--by", "tester")
        self.assertIn("benign_agent.py", self.enabled(),
                      "without re-admission, approving would silently do nothing")
        self.assertTrue(os.path.isfile(os.path.join(self.agents,
                                                    "benign_agent.py")))

    def test_revocation_withholds_again(self):
        self.init()
        path = self.write_agent("benign_agent.py", BENIGN)
        self.ctl("approve", path, "--by", "tester")
        self.assertIn("benign_agent.py", self.enabled())
        self.ctl("revoke", "benign_agent.py")
        self.assertNotIn("benign_agent.py", self.enabled())

    def test_the_withheld_report_is_stable_across_sweeps(self):
        self.init()
        self.write_agent("benign_agent.py", BENIGN)
        first = self.posture()
        second = self.posture()
        self.assertEqual(len(first["withheld"]), len(second["withheld"]),
                         "an administrator asking twice must get the same answer")
        self.assertTrue(second["withheld"])


class TestElevation(StrainTestCase):

    def admin(self, **kw):
        mod = load_module(os.path.join(self.agents, "strain_admin_agent.py"),
                          "admin_run")
        return json.loads(mod.StrainAdminAgent().perform(**kw))

    def test_T5_without_the_credential_state_changes_are_refused(self):
        self.init()
        self.ctl("admin", "--set-key", ADMIN_KEY)
        self.write_agent("benign_agent.py", BENIGN)
        self.posture()          # force the withhold
        r = self.admin(action="approve", agent="benign_agent.py")
        self.assertEqual(r["status"], "refused")
        self.assertFalse(r["elevated"])

    def test_T5_without_the_credential_reading_still_works(self):
        self.init()
        self.ctl("admin", "--set-key", ADMIN_KEY)
        self.write_agent("benign_agent.py", BENIGN)
        self.posture()
        r = self.admin(action="pending")
        self.assertEqual(r["status"], "ok")
        self.assertGreaterEqual(r["pending_count"], 1)

    def test_T5_a_wrong_credential_does_not_elevate(self):
        self.init()
        self.ctl("admin", "--set-key", ADMIN_KEY)
        os.environ["RAPP_STRAIN_ADMIN_KEY"] = "not-the-right-one"
        r = self.admin(action="whoami")
        self.assertFalse(r["elevated"])

    def test_the_credential_elevates_in_session(self):
        self.init()
        self.ctl("admin", "--set-key", ADMIN_KEY)
        self.write_agent("benign_agent.py", BENIGN)
        self.posture()
        os.environ["RAPP_STRAIN_ADMIN_KEY"] = ADMIN_KEY
        r = self.admin(action="approve", agent="benign_agent.py")
        self.assertEqual(r["status"], "ok")
        self.assertIn("benign_agent.py", self.enabled())

    def test_elevation_cannot_bypass_capability_checking(self):
        self.init()
        self.ctl("admin", "--set-key", ADMIN_KEY)
        self.write_agent("sneaky_agent.py", SNEAKY)
        self.posture()
        os.environ["RAPP_STRAIN_ADMIN_KEY"] = ADMIN_KEY
        r = self.admin(action="approve", agent="sneaky_agent.py")
        self.assertEqual(r["status"], "refused",
                         "an administrator may change policy, not defeat the checks")
        self.assertIn("process-exec", r["undeclared"])


class TestAudit(StrainTestCase):

    def test_T9_withholding_and_readmission_are_both_recorded(self):
        self.init()
        self.write_agent("benign_agent.py", BENIGN)
        self.posture()
        held = os.path.join(self.held, "benign_agent.py")
        self.ctl("approve", held, "--by", "tester")
        self.posture()
        log = os.path.join(self.dir, "strain-audit.jsonl")
        with open(log) as fh:
            events = [json.loads(l)["event"] for l in fh]
        self.assertIn("agent.withheld", events)
        self.assertIn("agent.readmitted", events)

    def test_T9_the_log_never_contains_file_contents(self):
        self.init()
        self.write_agent("benign_agent.py", BENIGN)
        self.posture()
        with open(os.path.join(self.dir, "strain-audit.jsonl")) as fh:
            body = fh.read()
        self.assertNotIn("class BenignAgent", body,
                         "shipping the log must not exfiltrate capability source")

    def test_T9_a_steady_state_does_not_grow_the_log(self):
        self.init()
        self.write_agent("benign_agent.py", BENIGN)
        self.posture()
        log = os.path.join(self.dir, "strain-audit.jsonl")
        with open(log) as fh:
            n = len(fh.readlines())
        for _ in range(5):
            self.posture()
        with open(log) as fh:
            remaining = len(fh.readlines())
        self.assertEqual(remaining, n,
                         "only transitions are logged; the one line that "
                         "mattered must not be buried")


class TestNoKernelChange(StrainTestCase):

    def test_the_strain_ships_no_brainstem(self):
        """The whole premise: a strain is policy, not a fork. If a brainstem
        ever appears in this repo, the security argument in THREAT-MODEL.md §1
        stops being true and this test should fail loudly."""
        offenders = []
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            for f in files:
                if f in ("brainstem.py", "function_app.py"):
                    offenders.append(os.path.relpath(os.path.join(root, f), ROOT))
        self.assertEqual(offenders, [],
                         f"a strain must not carry a kernel: {offenders}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
