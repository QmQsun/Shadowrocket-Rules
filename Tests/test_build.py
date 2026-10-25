import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from Scripts import build as b


class BuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (b.ROOT / "Upstream/Original-20261026.conf").read_bytes()
        cls.local = (b.ROOT / "Config/Local.conf").read_text(encoding="utf-8")
        cls.custom = (b.ROOT / "Rules/Overrides.list").read_text(encoding="utf-8")
        cls.output, cls.info = b.build(cls.source, cls.local, cls.custom, {"mode": "test"})
        cls.merged = [b.parse_rule(x) for x in b.active(
            b.sections(cls.output.decode(), ["General", "Rule", "URL Rewrite"])["Rule"])]

    def make(self, source=None, local=None, custom=None, previous=None):
        return b.build(self.source if source is None else source,
                       self.local if local is None else local,
                       self.custom if custom is None else custom, {"mode": "test"}, previous)

    def test_real_snapshot_reconciles_and_repeats(self):
        self.assertEqual(self.info["rules"], {"upstream": 62653, "custom": 64, "removed": 5, "merged": 62712})
        self.assertEqual(self.make(), (self.output, self.info))
        self.assertEqual(b.sha256(self.output), self.info["output"]["sha256"])

    def test_user_exceptions_precede_ad_blocking(self):
        # An intentionally hostile upstream ad rule must still lose to each exception.
        hostile = self.source.replace(b"[Rule]", b"[Rule]\nDOMAIN-SUFFIX,ip.net.coffee,Reject\n"
                                      b"DOMAIN-SUFFIX,api.segment.io,Reject\nDOMAIN-SUFFIX,segment.com,Reject", 1)
        result, _ = self.make(source=hostile)
        rules = [b.parse_rule(x) for x in b.active(b.sections(result.decode(), ["General", "Rule", "URL Rewrite"])["Rule"])]
        for host in ("ip.net.coffee", "api.segment.io", "segment.com"):
            with self.subTest(host=host):
                self.assertEqual(b.route(rules, host=host), "PROXY")
                self.assertEqual(b.route(rules, host=host, protocol="UDP"), "REJECT-NO-DROP")

    def test_domain_suffix_boundaries_and_case(self):
        rules = [b.parse_rule("DOMAIN-SUFFIX,service.example,PROXY"), b.parse_rule("FINAL,DIRECT")]
        for host in ("service.example", "chat.service.example", "CHAT.SERVICE.EXAMPLE."):
            self.assertEqual(b.route(rules, host=host), "PROXY")
        for host in ("notservice.example", "service.example.evil.example"):
            self.assertEqual(b.route(rules, host=host), "DIRECT")

    def test_exact_hosts_do_not_expand_shared_providers(self):
        rules = [b.parse_rule(x) for x in b.active(self.custom.splitlines())] + [b.parse_rule("FINAL,DIRECT")]
        for host in ("other.auth0.com", "other.b-cdn.net", "other.cloudflare.net"):
            self.assertEqual(b.route(rules, host=host), "DIRECT")
        self.assertEqual(b.route(rules, host="anthropic.auth0.com"), "PROXY")

    def test_udp_rejection_is_limited_to_matched_domain_port(self):
        self.assertEqual(b.route(self.merged, host="ip.net.coffee", protocol="UDP"), "REJECT-NO-DROP")
        self.assertEqual(b.route(self.merged, host="ip.net.coffee", protocol="UDP", port=3478), "PROXY")
        self.assertEqual(b.route(self.merged, host="ip.net.coffee", protocol="TCP"), "PROXY")

    def test_ipv4_ipv6_fallback_and_boundaries(self):
        rules = [b.parse_rule(x) for x in b.active(self.custom.splitlines())] + [b.parse_rule("FINAL,DIRECT")]
        for address in ("160.79.104.0", "160.79.105.255", "2607:6bc0::1", "2607:6bc0:0:ffff::1"):
            self.assertEqual(b.route(rules, ip=address), "PROXY")
            # IP-only QUIC remains PROXY; never falsely claim equivalent domain rejection.
            self.assertEqual(b.route(rules, ip=address, protocol="UDP"), "PROXY")
        for address in ("160.79.103.255", "160.79.106.0", "2607:6bc0:1::1"):
            self.assertEqual(b.route(rules, ip=address), "DIRECT")

    def test_dns_and_rewrite_remain_local(self):
        result = b.sections(self.output.decode(), ["General", "Rule", "URL Rewrite"])
        local = b.sections(self.local, ["General", "URL Rewrite"])
        for section in local:
            self.assertEqual(b.active(result[section]), b.active(local[section]))
        self.assertIn("update-url = https://raw.githubusercontent.com/QmQsun/Shadowrocket-Rules/main/sr_ios_adblock.conf",
                      b.active(result["General"]))

    def test_only_identical_selectors_removed_and_order_preserved(self):
        original = b.active(b.sections(self.source.decode(), ["General", "Rule", "URL Rewrite"])["Rule"])
        selectors = {(x[0], x[1]) for x in map(b.parse_rule, b.active(self.custom.splitlines()))}
        expected = [line for line in original if b.parse_rule(line)[:2] not in selectors]
        merged = b.active(b.sections(self.output.decode(), ["General", "Rule", "URL Rewrite"])["Rule"])
        self.assertEqual(merged[64:], expected)

    def test_final_unique_and_last(self):
        b.validate_final(self.merged)
        for extra in (b"FINAL,direct\nFINAL,DIRECT", b"FINAL,direct\nDOMAIN-SUFFIX,example.com,Proxy", b"# missing final"):
            with self.subTest(extra=extra), self.assertRaises(b.BuildError):
                self.make(source=self.source.replace(b"FINAL,direct", extra))

    def test_unknown_structure_fails(self):
        for data in (b"<html>Error</html>", self.source + b"\n[Script]\nx=y\n",
                     self.source.replace(b"[Rule]", b"[Rule]\n[Rule]", 1)):
            with self.subTest(), self.assertRaises(b.BuildError):
                self.make(source=data)

    def test_empty_truncated_or_oversized_source_fails(self):
        for data in (b"", b"x" * (b.MAX_BYTES + 1), b"[General]\n[Rule]\nFINAL,DIRECT\n[URL Rewrite]\n"):
            with self.subTest(), self.assertRaises(b.BuildError):
                self.make(source=data)

    def test_new_rule_or_policy_fails(self):
        for bad in (b"GEOIP,CN,DIRECT", b"DOMAIN-SUFFIX,example.com,Unknown", b"IP-CIDR,garbage,Proxy"):
            with self.subTest(bad=bad), self.assertRaises(b.BuildError):
                self.make(source=self.source.replace(b"[Rule]", b"[Rule]\n" + bad, 1))

    def test_large_count_drift_fails(self):
        with self.assertRaisesRegex(b.BuildError, "10%"):
            self.make(previous={"rules": {"upstream": 75000}})

    def test_incomplete_custom_rules_fail(self):
        with self.assertRaises(b.BuildError):
            self.make(custom="\n".join(self.custom.splitlines()[6:]))

    def test_network_error_keeps_previous_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            b.publish(root, self.output, self.info)
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            with patch.object(b, "download", side_effect=OSError("simulated network failure")):
                self.assertEqual(b.main(["--output-dir", str(root)]), 1)
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_invalid_download_keeps_previous_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            b.publish(root, self.output, self.info)
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            with patch.object(b, "download", return_value=(b"<html>bad</html>", {})):
                self.assertEqual(b.main(["--output-dir", str(root)]), 1)
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_publish_failure_restores_both_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            b.publish(root, self.output, self.info)
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            real_replace = b.os.replace
            def replace(source, target):
                if Path(target).name == "Build-info.json":
                    raise OSError("simulated metadata replacement failure")
                real_replace(source, target)
            with patch.object(b.os, "replace", side_effect=replace), self.assertRaises(OSError):
                b.publish(root, b"new output", {"new": True})
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_download_pins_raw_url_to_resolved_sha(self):
        commit = "a" * 40
        with patch.object(b, "fetch", side_effect=[json.dumps({"sha": commit, "commit": {"committer": {"date": "2026-10-26T00:00:00Z"}}}).encode(), self.source]) as fetch:
            source, info = b.download()
        self.assertEqual(source, self.source)
        self.assertEqual(info["commit"], commit)
        self.assertIn("/" + commit + "/", fetch.call_args_list[1].args[0])


if __name__ == "__main__":
    unittest.main()
