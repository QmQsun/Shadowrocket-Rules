"""Build a separate Config-mode profile with reviewed destination restrictions."""

import argparse
import ipaddress
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from Scripts import build as common

OUTPUT = "sr_mainland.conf"
UPDATE_URL = "https://raw.githubusercontent.com/QmQsun/Shadowrocket-Rules/main/" + OUTPUT
NETWORKS = {"160.79.104.0/23", "2607:6bc0::/48"}


def build(general_text, deny_text):
    sections = common.sections(general_text, ["General"])
    settings = common.active(sections["General"])
    keys = [line.split("=", 1)[0].strip() for line in settings]
    if set(keys) != common.GENERAL_KEYS or len(keys) != len(common.GENERAL_KEYS):
        raise common.BuildError("Unexpected General settings")
    values = dict(line.split("=", 1) for line in settings)
    values = {key.strip(): value.strip() for key, value in values.items()}
    if values["update-url"] != UPDATE_URL or values["udp-policy-not-supported-behaviour"] != "REJECT":
        raise common.BuildError("Update URL or UDP fallback changed")
    lines = common.active(deny_text.splitlines())
    rules = [common.parse_rule(line) for line in lines]
    if len(rules) != 31 or len(set(rules)) != 31:
        raise common.BuildError("Expected 31 distinct reviewed restrictions")
    domains = [rule for rule in rules if rule[0] in common.DOMAIN_TYPES]
    networks = {target for kind, target, _ in rules if kind == "IP-CIDR"}
    if len(domains) != 29 or networks != NETWORKS:
        raise common.BuildError("Restriction coverage changed; review required")
    if any(policy != "REJECT" for _, _, policy in rules):
        raise common.BuildError("All destination restrictions must reject")
    if any(not line.endswith(",no-resolve") for line in lines if line.startswith("IP-CIDR,")):
        raise common.BuildError("IP rules must retain no-resolve")
    effective = rules + [("FINAL", "", "PROXY")]
    for kind, target, _ in domains:
        sample = f"test-{target}.invalid" if kind == "DOMAIN-KEYWORD" else target
        hosts = [sample] + (["sub." + sample] if kind == "DOMAIN-SUFFIX" else [])
        for host in hosts:
            for protocol in ("TCP", "UDP"):
                for port in (80, 443, 3478):
                    if common.route(effective, host=host, protocol=protocol, port=port) != "REJECT":
                        raise common.BuildError("A restricted domain escaped rejection")
    for network in NETWORKS:
        net = ipaddress.ip_network(network)
        for address in (net.network_address, net.broadcast_address):
            for protocol in ("TCP", "UDP"):
                if common.route(effective, ip=str(address), protocol=protocol) != "REJECT":
                    raise common.BuildError("A restricted IP escaped rejection")
    for host in ("example.com", "baidu.com", "notclaude.ai", "claude.ai.example.org"):
        if common.route(effective, host=host) != "PROXY":
            raise common.BuildError("Unrelated traffic must reach the selected proxy")
    output = (
        "# Mainland routing profile. CONFIG MODE ONLY.\n"
        "# Select the intended mainland node and use Global Routing > Config.\n"
        "# Proxy/Global mode bypasses these restrictions; do not use it with this profile.\n"
        "# Shared destinations in the deny list can affect unrelated websites.\n"
        "# No account, subscription, node or interception certificate is included.\n\n"
        + general_text.strip() + "\n\n[Rule]\n"
        + "\n".join(lines) + "\nFINAL,PROXY\n"
    ).encode("utf-8")
    info = {
        "schema_version": 1,
        "source": "Reviewed selectors from user-supplied desktop policy, extracted 2026-10-30",
        "inputs": {"general_sha256": common.sha256(general_text.encode()),
                   "deny_sha256": common.sha256(deny_text.encode())},
        "rules": {"domain_or_keyword": 29, "ip_networks": 2, "restricted": 31, "total": 32},
        "output": {"filename": OUTPUT, "sha256": common.sha256(output), "bytes": len(output)},
        "required_routing_mode": "config",
        "proxy_mode_protection": False,
        "updating": "Weekly validation and rebuild of curated inputs; no automatic discovery of new destinations",
        "validation": "Static checks only; device import and runtime routing require verification",
    }
    return output, info


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        output, info = build((ROOT / "Mainland/General.conf").read_text(encoding="utf-8"),
                             (ROOT / "Mainland/Deny.list").read_text(encoding="utf-8"))
        (args.output_dir / "Mainland").mkdir(parents=True, exist_ok=True)
        common.publish_files(args.output_dir, {
            OUTPUT: output,
            "Mainland/Build-info.json": (json.dumps(info, indent=2) + "\n").encode(),
        })
    except (common.BuildError, OSError, ValueError, KeyError) as exc:
        print(f"Mainland build failed; no valid replacement published: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(info["rules"]))
    print("Configuration SHA256: " + info["output"]["sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
