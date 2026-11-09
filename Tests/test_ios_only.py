import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from Scripts import build as base
from Scripts import build_android as android
from Scripts import build_ios_extra as ios


class IOSOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (base.ROOT / "Upstream/Original-20261026.conf").read_bytes()
        snapshot = json.loads((base.ROOT / "Upstream/Original-20261026.json").read_text())
        cls.source_info = {key: snapshot[key] for key in ("repository", "branch", "commit", "committed_at")}
        cls.source_info["url"] = f"https://raw.githubusercontent.com/{base.UPSTREAM}/{snapshot['commit']}/{base.SOURCE_FILE}"
        cls.local = (base.ROOT / "Config/Local.conf").read_text(encoding="utf-8")
        cls.custom = (base.ROOT / "Rules/Overrides.list").read_text(encoding="utf-8")
        cls.extra = (base.ROOT / "Rules/iOS-only.list").read_text(encoding="utf-8")
        cls.shared, cls.shared_info = base.build(cls.source, cls.local, cls.custom, cls.source_info)
        cls.output, cls.info = ios.build(cls.shared, cls.shared_info, cls.extra)
        cls.before_sections = base.sections(cls.shared.decode(), ["General", "Rule", "URL Rewrite"])
        cls.after_sections = base.sections(cls.output.decode(), ["General", "Rule", "URL Rewrite"])
        cls.before_rules = [base.parse_rule(x) for x in base.active(cls.before_sections["Rule"])]
        cls.after_rules = [base.parse_rule(x) for x in base.active(cls.after_sections["Rule"])]

    def test_ip_443_policies_and_other_ports(self):
        self.assertEqual(base.route(self.after_rules, ip="1.1.1.1", protocol="TCP", port=443), "PROXY")
        self.assertEqual(base.route(self.after_rules, ip="1.1.1.1", protocol="UDP", port=443), "REJECT-NO-DROP")
        for protocol in ("TCP", "UDP"):
            for port in (53, 80, 853, 3478):
                with self.subTest(protocol=protocol, port=port):
                    self.assertEqual(base.route(self.after_rules, ip="1.1.1.1", protocol=protocol, port=port),
                                     base.route(self.before_rules, ip="1.1.1.1", protocol=protocol, port=port))
            for address in ("1.1.1.0", "1.1.1.2", "1.0.0.1", "2606:4700:4700::1111"):
                self.assertEqual(base.route(self.after_rules, ip=address, protocol=protocol),
                                 base.route(self.before_rules, ip=address, protocol=protocol))

    def test_suffix_includes_subdomains_without_matching_lookalikes(self):
        for host in ("cloudflare-cn.com", "sub.cloudflare-cn.com", "SUB.CLOUDFLARE-CN.COM.",
                     "claude.app", "sub.claude.app", "SUB.CLAUDE.APP."):
            for protocol in ("TCP", "UDP"):
                expected = "REJECT-NO-DROP" if protocol == "UDP" else "PROXY"
                self.assertEqual(base.route(self.after_rules, host=host, protocol=protocol), expected)
                self.assertEqual(base.route(self.after_rules, host=host, protocol=protocol, port=3478), "PROXY")
        for host in ("notcloudflare-cn.com", "cloudflare-cn.com.example.org", "notclaude.app", "claude.app.example.org"):
            self.assertEqual(base.route(self.after_rules, host=host), base.route(self.before_rules, host=host))

    def test_v19_network_boundaries_and_transport_scope(self):
        for address in ("153.61.224.0", "153.61.224.1", "153.61.225.255", "153.61.226.1", "153.61.227.255"):
            for protocol in ("TCP", "UDP"):
                for port in (53, 80, 443, 853, 3478):
                    with self.subTest(address=address, protocol=protocol, port=port):
                        expected = "REJECT-NO-DROP" if protocol == "UDP" and port == 443 else "PROXY"
                        self.assertEqual(base.route(self.after_rules, ip=address, protocol=protocol, port=port), expected)
        for address in ("153.61.223.255", "153.61.228.0"):
            for protocol in ("TCP", "UDP"):
                self.assertEqual(base.route(self.after_rules, ip=address, protocol=protocol),
                                 base.route(self.before_rules, ip=address, protocol=protocol))

    def test_v20_exact_service_hosts_use_proxy_without_expanding_to_subdomains(self):
        for host in ("featuregates.org", "api.statsigcdn.com", "featureassets.org",
                     "assetsconfigcdn.org", "prodregistryv2.org", "beyondwickedmapping.org"):
            with self.subTest(host=host):
                for name in (host, host.upper() + "."):
                    self.assertEqual(base.route(self.after_rules, host=name), "PROXY")
                    self.assertEqual(base.route(self.after_rules, host=name, protocol="UDP"), "REJECT-NO-DROP")
                    self.assertEqual(base.route(self.after_rules, host=name, protocol="UDP", port=3478), "PROXY")
                for name in ("sub." + host, "not" + host, host + ".example"):
                    for protocol in ("TCP", "UDP"):
                        self.assertEqual(base.route(self.after_rules, host=name, protocol=protocol),
                                         base.route(self.before_rules, host=name, protocol=protocol))

    def test_shared_rules_dns_and_rewrite_are_unchanged(self):
        self.assertEqual(self.after_rules[20:], self.before_rules)
        for section in ("General", "URL Rewrite"):
            self.assertEqual(self.before_sections[section], self.after_sections[section])
        self.assertEqual(self.info["inputs"], self.shared_info["inputs"])
        self.assertEqual(self.info["source"], self.shared_info["source"])
        self.assertEqual(self.info["shared_output"], self.shared_info["output"])
        self.assertEqual(self.info["shared_rules"], self.shared_info["rules"])
        self.assertEqual(self.info["output"]["sha256"], base.sha256(self.output))
        self.assertEqual(self.info["rules"]["custom"], 91)
        self.assertEqual(self.info["rules"]["ios_only"], 20)

    def test_android_payloads_do_not_inherit_ios_additions(self):
        services = (base.ROOT / "Rules/Android-services.list").read_text(encoding="utf-8")
        direct = (base.ROOT / "Rules/Android-direct.list").read_text(encoding="utf-8")
        before, _ = android.build(self.shared, self.shared_info, self.custom, services, direct)
        after, _ = android.build(self.output, self.info, self.custom, services, direct)
        for filename in before:
            if filename != "Build-info.json":
                self.assertEqual(before[filename], after[filename], filename)

    def test_overlay_is_idempotent_and_rejects_unreviewed_inputs(self):
        self.assertEqual(ios.build(self.output, self.info, self.extra), (self.output, self.info))
        for extra in ("", self.extra.replace("DST-PORT,443", "DST-PORT,53", 1),
                      self.extra.replace("1.1.1.1/32", "1.1.1.0/24", 1),
                      self.extra.replace("153.61.224.0/22", "153.61.224.0/21", 1),
                      self.extra.replace("DOMAIN,featuregates.org", "DOMAIN-SUFFIX,featuregates.org", 1)):
            with self.subTest(), self.assertRaises(base.BuildError):
                ios.build(self.shared, self.shared_info, extra)
        with self.assertRaises(base.BuildError):
            ios.build(self.shared + b"tampered", self.shared_info, self.extra)

    def test_recorded_source_rebuild_uses_only_the_pinned_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base.publish(root, self.output, self.info)
            with patch.object(base, "fetch", return_value=self.source) as fetch:
                self.assertEqual(base.main(["--reuse-upstream", "--output-dir", str(root)]), 0)
            fetch.assert_called_once_with(self.source_info["url"])
            self.assertEqual((root / base.OUTPUT).read_bytes(), self.shared)
            self.assertEqual(json.loads((root / "Build-info.json").read_text()), self.shared_info)

    def test_recorded_source_checksum_failure_preserves_previous_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base.publish(root, self.output, self.info)
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            with patch.object(base, "fetch", return_value=b"bad source"):
                self.assertEqual(base.main(["--reuse-upstream", "--output-dir", str(root)]), 1)
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})
        bad = copy.deepcopy(self.shared_info)
        bad["source"]["url"] = "https://example.invalid/unreviewed"
        with patch.object(base, "fetch") as fetch, self.assertRaises(base.BuildError):
            base.download_recorded(bad)
        fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
