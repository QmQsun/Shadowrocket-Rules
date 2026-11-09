"""Apply reviewed iOS-only additions after the shared and Android builds."""

import copy
import json
from pathlib import Path
import sys

if __package__:
    from . import build as base
else:
    import build as base

EXACT_SERVICE_HOSTS = (
    "featuregates.org", "api.statsigcdn.com", "featureassets.org",
    "assetsconfigcdn.org", "prodregistryv2.org", "beyondwickedmapping.org",
)
EXPECTED_RULES = [
    "AND,((PROTOCOL,UDP),(DST-PORT,443),(IP-CIDR,1.1.1.1/32,no-resolve)),REJECT-NO-DROP",
    "AND,((PROTOCOL,UDP),(DST-PORT,443),(IP-CIDR,153.61.224.0/22,no-resolve)),REJECT-NO-DROP",
    "AND,((PROTOCOL,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,claude.app)),REJECT-NO-DROP",
    "AND,((PROTOCOL,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,cloudflare-cn.com)),REJECT-NO-DROP",
    *[f"AND,((PROTOCOL,UDP),(DST-PORT,443),(DOMAIN,{host})),REJECT-NO-DROP" for host in EXACT_SERVICE_HOSTS],
    "AND,((PROTOCOL,TCP),(DST-PORT,443),(IP-CIDR,1.1.1.1/32,no-resolve)),PROXY",
    "DOMAIN-SUFFIX,claude.app,PROXY",
    "DOMAIN-SUFFIX,cloudflare-cn.com,PROXY",
    *[f"DOMAIN,{host},PROXY" for host in EXACT_SERVICE_HOSTS],
    "IP-CIDR,153.61.224.0/22,PROXY,no-resolve",
]


def build(data, info, extra_text):
    if base.sha256(data) != info["output"]["sha256"]:
        raise base.BuildError("iOS source checksum mismatch")
    lines = base.active(extra_text.splitlines())
    if lines != EXPECTED_RULES:
        raise base.BuildError(f"iOS-only rules differ from the reviewed {len(EXPECTED_RULES)}-rule scope")
    extra_hash = base.sha256(extra_text.encode())
    if "ios_only" in info:
        if info["ios_only"]["sha256"] != extra_hash:
            raise base.BuildError("Rebuild shared inputs before changing iOS-only rules")
        return data, info
    text = data.decode("utf-8")
    sections = base.sections(text, ["General", "Rule", "URL Rewrite"])
    shared = [base.parse_rule(line) for line in base.active(sections["Rule"])]
    extra = [base.parse_rule(line) for line in lines]
    merged = extra + shared
    base.validate_final(merged)
    if base.route(merged, ip="1.1.1.1", protocol="TCP", port=443) != "PROXY":
        raise base.BuildError("iOS HTTPS IP route did not win")
    if base.route(merged, ip="1.1.1.1", protocol="UDP", port=443) != "REJECT-NO-DROP":
        raise base.BuildError("iOS QUIC IP rejection did not win")
    for protocol in ("TCP", "UDP"):
        for port in (53, 80, 853, 3478):
            if base.route(merged, ip="1.1.1.1", protocol=protocol, port=port) != base.route(shared, ip="1.1.1.1", protocol=protocol, port=port):
                raise base.BuildError("iOS addition changed a non-443 port")
        for host in ("cloudflare-cn.com", "sub.cloudflare-cn.com", "claude.app", "sub.claude.app"):
            expected = "REJECT-NO-DROP" if protocol == "UDP" else "PROXY"
            if base.route(merged, host=host, protocol=protocol) != expected:
                raise base.BuildError("iOS suffix route did not win")
        for host in EXACT_SERVICE_HOSTS:
            expected = "REJECT-NO-DROP" if protocol == "UDP" else "PROXY"
            if base.route(merged, host=host, protocol=protocol) != expected:
                raise base.BuildError("iOS exact service route did not win")
            if base.route(merged, host=host, protocol=protocol, port=3478) != "PROXY":
                raise base.BuildError("iOS exact service non-443 route changed")
            for unrelated in ("sub." + host, "not" + host, host + ".example"):
                if base.route(merged, host=unrelated, protocol=protocol) != base.route(shared, host=unrelated, protocol=protocol):
                    raise base.BuildError("iOS exact service rule expanded its hostname scope")
        for address in ("153.61.224.0", "153.61.227.255"):
            for port in (53, 80, 443, 853, 3478):
                expected = "REJECT-NO-DROP" if protocol == "UDP" and port == 443 else "PROXY"
                if base.route(merged, ip=address, protocol=protocol, port=port) != expected:
                    raise base.BuildError("iOS supplemental network route did not win")
    block = ("# BEGIN iOS-only rules\n" + "\n".join(lines)
             + "\n# END iOS-only rules\n\n")
    output = text.replace("[Rule]\n", "[Rule]\n" + block, 1).encode("utf-8")
    result = copy.deepcopy(info)
    result["shared_output"] = info["output"].copy()
    result["shared_rules"] = info["rules"].copy()
    result["ios_only"] = {"source": "Rules/iOS-only.list", "sha256": extra_hash, "rules": len(extra)}
    result["rules"]["custom"] += len(extra)
    result["rules"]["merged"] += len(extra)
    result["rules"]["ios_only"] = len(extra)
    result["output"] = {"filename": base.OUTPUT, "sha256": base.sha256(output), "bytes": len(output)}
    return output, result


def main():
    try:
        output, info = build((base.ROOT / base.OUTPUT).read_bytes(),
                             json.loads((base.ROOT / "Build-info.json").read_text()),
                             (base.ROOT / "Rules/iOS-only.list").read_text(encoding="utf-8"))
        base.publish(base.ROOT, output, info)
    except (base.BuildError, OSError, ValueError, KeyError) as exc:
        print(f"iOS-only build failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("Applied iOS-only rules: " + str(info["ios_only"]["rules"]))
    print("iOS SHA256: " + info["output"]["sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
