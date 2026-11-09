import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from Scripts import build as base
from Scripts import build_android as android


class AndroidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ios = (base.ROOT / base.OUTPUT).read_bytes()
        cls.info = json.loads((base.ROOT / "Build-info.json").read_text())
        cls.custom = (base.ROOT / "Rules/Overrides.list").read_text(encoding="utf-8")
        cls.services = (base.ROOT / "Rules/Android-services.list").read_text(encoding="utf-8")
        cls.direct = (base.ROOT / "Rules/Android-direct.list").read_text(encoding="utf-8")
        cls.extra = (base.ROOT / "Rules/Android-extra.list").read_text(encoding="utf-8")
        cls.files, cls.manifest = android.build(cls.ios, cls.info, cls.custom, cls.services, cls.direct, cls.extra)

    def test_priority_translation_preserves_scope_and_policy(self):
        reject = json.loads(self.files["Priority-reject.yaml"])["payload"]
        proxy = json.loads(self.files["Priority-proxy.yaml"])["payload"]
        self.assertEqual(len(reject), 43)
        self.assertEqual(len(proxy), 48)
        self.assertIn("AND,((NETWORK,udp),(DST-PORT,443),(IP-CIDR6,2607:6bc0::/48,no-resolve))", reject)
        self.assertIn("IP-CIDR6,2607:6bc0::/48,no-resolve", proxy)
        self.assertIn("DOMAIN-SUFFIX,oaistatic.com", proxy)
        self.assertIn("IP-CIDR,153.61.224.0/22,no-resolve", proxy)
        self.assertIn("AND,((NETWORK,udp),(DST-PORT,443),(IP-CIDR,153.61.224.0/22,no-resolve))", reject)
        self.assertIn("AND,((NETWORK,tcp),(DST-PORT,443),(IP-CIDR,1.1.1.1/32,no-resolve))", proxy)
        for host in ("featuregates.org", "api.statsigcdn.com", "featureassets.org",
                     "assetsconfigcdn.org", "prodregistryv2.org", "beyondwickedmapping.org"):
            self.assertIn("DOMAIN," + host, proxy)
            self.assertNotIn("DOMAIN-SUFFIX," + host, proxy)
            self.assertIn(f"AND,((NETWORK,udp),(DST-PORT,443),(DOMAIN,{host}))", reject)
        self.assertEqual(proxy.count("DOMAIN-SUFFIX,segment.com"), 1)
        self.assertEqual(len(proxy), len(set(proxy)))
        self.assertEqual(len(reject), len(set(reject)))
        for line in reject + proxy:
            self.assertNotIn("PROTOCOL", line)
            self.assertNotIn("REJECT-NO-DROP", line)
            self.assertNotIn("FINAL", line)
            self.assertNotIn(",PROXY", line)

    def test_template_defaults_to_global_through_manual_proxy_and_keeps_rules(self):
        config = json.loads(self.files["Profile-template.yaml"])
        self.assertEqual(config["mode"], "global")
        self.assertEqual(len(config["proxy-groups"]), 2)
        self.assertEqual(config["proxy-groups"][0],
                         {"name": "PROXY", "type": "select", "proxies": ["REJECT"], "use": ["PandaFan"]})
        self.assertEqual(config["proxy-groups"][1],
                         {"name": "GLOBAL", "type": "select", "proxies": ["PROXY"]})
        rules = config["rules"]
        self.assertLess(rules.index("RULE-SET,Priority-proxy,PROXY"), rules.index("RULE-SET,Ads,REJECT"))
        self.assertLess(rules.index("RULE-SET,Ads,REJECT"), rules.index("RULE-SET,Services,PROXY"))
        self.assertEqual(rules[-2:], ["GEOIP,CN,DIRECT", "MATCH,PROXY"])
        self.assertFalse(config["ipv6"])
        self.assertTrue(all(x.endswith("#PROXY") for x in config["dns"]["nameserver"]))
        self.assertNotIn("tun", config)

    def test_ad_domains_are_not_exempted_by_general_service_rules(self):
        ads = json.loads(self.files["Ads.yaml"])["payload"]
        services = json.loads(self.files["Services.yaml"])["payload"]
        for domain in ("google-analytics.com", "googlesyndication.com", "gvt2.com"):
            self.assertIn("DOMAIN-SUFFIX," + domain, ads)
            self.assertIn("DOMAIN-SUFFIX," + domain, services)
        for host in ("teamviewer.com", "teamviewer.cn", "dyngate.com", "ima.qq.com"):
            self.assertIn("DOMAIN-SUFFIX," + host, json.loads(self.files["Direct.yaml"])["payload"])

    def test_provider_payloads_match_manifest_and_are_reproducible(self):
        for name, details in self.manifest["providers"].items():
            data = self.files[name + ".yaml"]
            self.assertEqual(base.sha256(data), details["sha256"])
            self.assertEqual(len(json.loads(data)["payload"]), details["rules"])
        self.assertEqual(android.build(self.ios, self.info, self.custom, self.services, self.direct, self.extra),
                         (self.files, self.manifest))

    def test_changed_or_unvalidated_inputs_fail(self):
        for ios, custom, services in ((self.ios + b"changed", self.custom, self.services),
                                      (self.ios, self.custom + "# changed", self.services),
                                      (self.ios, self.custom, self.services.replace(",PROXY", ",DIRECT", 1))):
            with self.subTest(), self.assertRaises(base.BuildError):
                android.build(ios, self.info, custom, services, self.direct, self.extra)
        for extra in ("", self.extra.replace("153.61.224.0/22", "153.61.224.0/21"),
                      self.extra.replace("DOMAIN,featuregates.org", "DOMAIN-SUFFIX,featuregates.org")):
            with self.subTest(), self.assertRaises(base.BuildError):
                android.build(self.ios, self.info, self.custom, self.services, self.direct, extra)

    def test_failed_android_publication_restores_prior_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base.publish_files(root, self.files)
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            replace = base.os.replace
            def fail(source, target):
                if Path(target).name == "Ads.yaml":
                    raise OSError("simulated failure")
                replace(source, target)
            with patch.object(base.os, "replace", side_effect=fail), self.assertRaises(OSError):
                base.publish_files(root, {name: b"changed" for name in self.files})
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})

    def test_profile_does_not_mutate_provider_and_bootstraps_its_hostname(self):
        provider = {"url": "https://subscription.example/private-placeholder", "header": {"User-Agent": ["test"]}}
        original = json.loads(json.dumps(provider))
        config = android.profile(provider)
        self.assertEqual(provider, original)
        self.assertIn("subscription.example", config["dns"]["nameserver-policy"])
        self.assertEqual(config["proxy-providers"]["PandaFan"]["proxy"], "DIRECT")
        self.assertFalse(config["proxy-providers"]["PandaFan"]["health-check"]["enable"])
        for item in config["rule-providers"].values():
            self.assertEqual(item["proxy"], "PROXY")
            self.assertEqual(item["interval"], 86400)
        for name in ("Priority-reject", "Priority-proxy"):
            self.assertEqual(config["rule-providers"][name]["path"], "./Rules/" + name + "-v20.yaml")


if __name__ == "__main__":
    unittest.main()
