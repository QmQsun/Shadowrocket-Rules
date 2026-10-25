"""Generate credential-free Clash Meta rule providers from validated inputs."""

import argparse
import copy
import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

if __package__:
    from . import build as base
else:
    import build as base

ROOT = base.ROOT
REMOTE = "https://raw.githubusercontent.com/QmQsun/Shadowrocket-Rules/main/Android/"
FILES = {
    "Priority-reject": "REJECT",
    "Priority-proxy": "PROXY",
    "Ads": "REJECT",
    "Services": "PROXY",
    "Direct": "DIRECT",
}
LAN_RULES = [f"IP-CIDR,{network},DIRECT,no-resolve" for network in
             ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]
LAN_RULES += [f"IP-CIDR6,{network},DIRECT,no-resolve" for network in ("::1/128", "fc00::/7", "fe80::/10")]


def encode_yaml(value):
    # JSON is a YAML-compatible representation; avoids a dependency in weekly CI.
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def selector(line):
    """Translate one reviewed selector, omitting the policy for classical providers."""
    kind, target, policy = base.parse_rule(line)
    if kind == "AND":
        child_kind, child_target = target
        if child_kind == "IP-CIDR":
            child_kind = "IP-CIDR6" if ipaddress.ip_network(child_target).version == 6 else "IP-CIDR"
            child_target += ",no-resolve"
        return f"AND,((NETWORK,udp),(DST-PORT,443),({child_kind},{child_target}))"
    if kind == "IP-CIDR":
        kind = "IP-CIDR6" if ipaddress.ip_network(target, strict=False).version == 6 else "IP-CIDR"
        return f"{kind},{target}" + (",no-resolve" if line.endswith(",no-resolve") else "")
    if kind in base.DOMAIN_TYPES:
        return f"{kind},{target}"
    raise base.BuildError("A final rule cannot be embedded in a provider")


def profile(provider):
    """One manually selected proxy group; subscription details remain caller-owned."""
    provider = copy.deepcopy(provider)
    provider.update({"type": "http", "path": "./Providers/PandaFan.yaml", "proxy": "DIRECT"})
    provider.setdefault("interval", 86400)
    provider["health-check"] = {"enable": False}
    host = urlsplit(provider["url"]).hostname
    if urlsplit(provider["url"]).scheme != "https" or not host:
        raise base.BuildError("Subscription must use an HTTPS URL")
    rules = LAN_RULES + [f"RULE-SET,{name},{policy}" for name, policy in FILES.items()]
    rules += ["GEOIP,CN,DIRECT", "MATCH,PROXY"]
    return {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "warning",
        "ipv6": False, "profile": {"store-selected": True},
        "dns": {
            "enable": True, "ipv6": False, "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16", "fake-ip-filter": ["*.lan", "localhost.ptlogin2.qq.com"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://8.8.8.8/dns-query#PROXY", "https://1.1.1.1/dns-query#PROXY"],
            "fallback": [],
            # Bootstrap the subscription before a proxy has been selected.
            "nameserver-policy": {host: ["223.5.5.5", "119.29.29.29"]},
        },
        "proxy-providers": {"PandaFan": provider},
        "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["REJECT"], "use": ["PandaFan"]}],
        "rule-providers": {
            name: {"type": "http", "behavior": "classical", "format": "yaml",
                   "url": REMOTE + name + ".yaml", "path": "./Rules/" + name + ".yaml",
                   "interval": 86400, "proxy": "PROXY"}
            for name in FILES
        },
        "rules": rules,
    }


def build(ios_data, ios_info, custom_text, services_text, direct_text):
    if base.sha256(ios_data) != ios_info["output"]["sha256"]:
        raise base.BuildError("iOS artifact does not match its validated manifest")
    if base.sha256(custom_text.encode()) != ios_info["inputs"]["custom_sha256"]:
        raise base.BuildError("Priority rules differ from the validated build")
    merged_lines = base.active(base.sections(ios_data.decode(), ["General", "Rule", "URL Rewrite"])["Rule"])
    merged = [base.parse_rule(x) for x in merged_lines]
    custom_lines = base.active(custom_text.splitlines())
    base.validate_final(merged)
    base.validate_priority([base.parse_rule(x) for x in custom_lines], merged)
    groups = {name: [] for name in FILES}
    for line in custom_lines:
        policy = base.parse_rule(line)[2]
        groups["Priority-reject" if policy == "REJECT-NO-DROP" else "Priority-proxy"].append(selector(line))
    groups["Ads"] = [selector(line) for line in merged_lines if base.parse_rule(line)[2] == "REJECT"]
    if not 45_000 <= len(groups["Ads"]) <= 75_000:
        raise base.BuildError("Ad provider count outside reviewed range")
    for name, text, expected, count in (("Services", services_text, "PROXY", 56),
                                         ("Direct", direct_text, "DIRECT", 4)):
        lines = base.active(text.splitlines())
        if len(lines) != count:
            raise base.BuildError("Unexpected mobile service rule count")
        for line in lines:
            kind, target, policy = base.parse_rule(line)
            if kind not in base.DOMAIN_TYPES or policy != expected:
                raise base.BuildError("Only reviewed service-domain policies may be published")
            groups[name].append(selector(line))
    files = {name + ".yaml": encode_yaml({"payload": rules}) for name, rules in groups.items()}
    files["Profile-template.yaml"] = encode_yaml(profile({"url": "https://example.invalid/subscription", "interval": 86400}))
    info = {
        "schema_version": 1, "upstream_commit": ios_info["source"]["commit"],
        "source_config_sha256": base.sha256(ios_data),
        "inputs": {"services_sha256": base.sha256(services_text.encode()),
                   "direct_sha256": base.sha256(direct_text.encode())},
        "providers": {name: {"rules": len(groups[name]), "policy": FILES[name],
                              "sha256": base.sha256(files[name + ".yaml"])} for name in FILES},
        "profile_template_sha256": base.sha256(files["Profile-template.yaml"]),
    }
    files["Build-info.json"] = encode_yaml(info)
    return files, info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "Android")
    args = parser.parse_args()
    try:
        files, info = build((ROOT / base.OUTPUT).read_bytes(), json.loads((ROOT / "Build-info.json").read_text()),
                            (ROOT / "Rules/Overrides.list").read_text(encoding="utf-8"),
                            (ROOT / "Rules/Android-services.list").read_text(encoding="utf-8"),
                            (ROOT / "Rules/Android-direct.list").read_text(encoding="utf-8"))
        base.publish_files(args.output_dir, files)
    except (base.BuildError, OSError, ValueError, KeyError) as exc:
        print(f"Android build failed ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1
    print(json.dumps({name: value["rules"] for name, value in info["providers"].items()}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
