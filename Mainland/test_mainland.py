import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from Mainland import build as m
from Scripts import build as common


class MainlandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.general = (m.ROOT / "Mainland/General.conf").read_text(encoding="utf-8")
        cls.deny = (m.ROOT / "Mainland/Deny.list").read_text(encoding="utf-8")
        cls.output, cls.info = m.build(cls.general, cls.deny)
        cls.rules = [common.parse_rule(line) for line in common.active(cls.deny.splitlines())]
        cls.rules.append(("FINAL", "", "PROXY"))

    def test_domains_and_both_transports_rejected(self):
        for host in ("claude.ai", "api.anthropic.com", "sub.claudeusercontent.com",
                     "x.datadoghq.example", "api.segment.io", "stripe.com", "ip.net.coffee"):
            for protocol in ("TCP", "UDP"):
                for port in (80, 443, 3478):
                    with self.subTest(host=host, protocol=protocol, port=port):
                        self.assertEqual(common.route(self.rules, host=host, protocol=protocol, port=port), "REJECT")

    def test_network_boundaries_reject_and_outside_uses_proxy(self):
        inside = ("160.79.104.0", "160.79.105.255", "2607:6bc0::", "2607:6bc0:0:ffff:ffff:ffff:ffff:ffff")
        outside = ("160.79.103.255", "160.79.106.0", "2607:6bc0:1::", "1.1.1.1")
        for address in inside + outside:
            for protocol in ("TCP", "UDP"):
                with self.subTest(address=address, protocol=protocol):
                    self.assertEqual(common.route(self.rules, ip=address, protocol=protocol),
                                     "REJECT" if address in inside else "PROXY")

    def test_other_sites_and_suffix_boundaries_use_proxy(self):
        for host in ("example.com", "baidu.com", "openai.com", "notclaude.ai", "claude.ai.example.org"):
            self.assertEqual(common.route(self.rules, host=host), "PROXY")
        self.assertTrue(common.domain_matches("DOMAIN-SUFFIX", "claude.ai", "CHAT.CLAUDE.AI."))
        self.assertFalse(common.domain_matches("DOMAIN", "anthropic.auth0.com", "other.auth0.com"))

    def test_profile_has_one_proxy_final_and_no_inherited_allow_rules(self):
        sections = common.sections(self.output.decode(), ["General", "Rule"])
        rules = common.active(sections["Rule"])
        self.assertEqual(len(rules), 32)
        self.assertEqual(rules[-1], "FINAL,PROXY")
        self.assertEqual(sum(x.startswith("FINAL,") for x in rules), 1)
        self.assertTrue(all(common.parse_rule(x)[2] == "REJECT" for x in rules[:-1]))
        self.assertIn("update-url = " + m.UPDATE_URL, sections["General"])
        self.assertEqual(self.info["required_routing_mode"], "config")
        self.assertIs(self.info["proxy_mode_protection"], False)
        self.assertEqual(common.sha256(self.output), self.info["output"]["sha256"])
        self.assertEqual(m.build(self.general, self.deny), (self.output, self.info))

    def test_bad_or_incomplete_restrictions_fail(self):
        for deny in ("", self.deny.replace(",REJECT", ",PROXY", 1),
                     self.deny + "FINAL,PROXY\n", self.deny.replace(",no-resolve", "", 1)):
            with self.subTest(), self.assertRaises(common.BuildError):
                m.build(self.general, deny)
        with self.assertRaises(common.BuildError):
            m.build(self.general.replace("sr_mainland.conf", "sr_ios_adblock.conf"), self.deny)

    def test_validation_failure_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Mainland").mkdir()
            (root / "Mainland/General.conf").write_text(self.general, encoding="utf-8")
            (root / "Mainland/Deny.list").write_text("invalid", encoding="utf-8")
            (root / m.OUTPUT).write_bytes(self.output)
            (root / "Mainland/Build-info.json").write_text(json.dumps(self.info), encoding="utf-8")
            before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            with patch.object(m, "ROOT", root):
                self.assertEqual(m.main(["--output-dir", str(root)]), 1)
            self.assertEqual(before, {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()})


if __name__ == "__main__":
    unittest.main()
