"""Build the iOS ad-blocking configuration using only the standard library.

The rule evaluator is a bounded static check, not the Shadowrocket runtime.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "nthack/Shadowrocket-ADBlock-Rules-Easy"
BRANCH = "master"
SOURCE_FILE = "sr_banlist_ad.conf"
OUTPUT = "sr_ios_adblock.conf"
MAX_BYTES = 8_000_000
MIN_RULES, MAX_RULES = 50_000, 80_000
POLICIES = {"PROXY", "DIRECT", "REJECT", "REJECT-NO-DROP"}
DOMAIN_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
PROXY_ONLY_DOMAINS = {("DOMAIN-SUFFIX", host) for host in
                      ("oaistatic.com", "oaiusercontent.com", "hf.co", "groq.com", "recaptcha.net")}
SOURCE_TYPES = {"DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "FINAL"}
GENERAL_KEYS = {
    "udp-policy-not-supported-behaviour", "dns-server", "bypass-system",
    "skip-proxy", "bypass-tun", "update-url",
}


class BuildError(ValueError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sections(text, expected):
    result = {}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            if not re.fullmatch(r"\[[A-Za-z ]+\]", stripped):
                raise BuildError("Malformed section header")
            current = stripped[1:-1]
            if current in result or current not in expected:
                raise BuildError("Unexpected or duplicate section: " + current)
            result[current] = []
        elif current is not None:
            result[current].append(line)
        elif stripped and not stripped.startswith("#"):
            raise BuildError("Unexpected content before first section")
    if set(result) != set(expected):
        raise BuildError("Missing configuration section")
    return result


def active(lines):
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def parse_rule(line):
    """Return (kind, target, policy); only accept this project's reviewed syntax."""
    if line.startswith("AND,"):
        ip_match = re.fullmatch(
            r"AND,\(\(PROTOCOL,UDP\),\(DST-PORT,443\),"
            r"\(IP-CIDR,([^(),\s]+),no-resolve\)\),REJECT-NO-DROP",
            line,
        )
        if ip_match:
            parse_rule(f"IP-CIDR,{ip_match[1]},PROXY,no-resolve")
            return "AND", ("IP-CIDR", ip_match[1].lower()), "REJECT-NO-DROP"
        match = re.fullmatch(
            r"AND,\(\(PROTOCOL,UDP\),\(DST-PORT,443\),"
            r"\((DOMAIN(?:-SUFFIX|-KEYWORD)?),([^(),\s]+)\)\),REJECT-NO-DROP",
            line,
        )
        if not match:
            raise BuildError("Unreviewed logical rule")
        parse_rule(f"{match[1]},{match[2]},PROXY")
        return "AND", (match[1], match[2].lower()), "REJECT-NO-DROP"
    fields = [part.strip() for part in line.split(",")]
    kind = fields[0]
    if kind == "FINAL":
        if len(fields) != 2 or fields[1].upper() != "DIRECT":
            raise BuildError("Expected FINAL,DIRECT")
        return kind, "", "DIRECT"
    if len(fields) not in (3, 4) or fields[2].upper() not in POLICIES:
        raise BuildError("Invalid rule or policy")
    target = fields[1].lower()
    if kind in DOMAIN_TYPES:
        if len(fields) != 3 or not re.fullmatch(r"[a-z0-9_.*-]+", target):
            raise BuildError("Invalid domain selector")
        # Upstream contains literal wildcard labels; preserve them without interpreting
        # them as a wildcard in the bounded suffix evaluator.
    elif kind == "IP-CIDR":
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise BuildError("Invalid IP network") from exc
        if len(fields) == 4 and fields[3] != "no-resolve":
            raise BuildError("Unreviewed IP option")
    else:
        raise BuildError("Unreviewed rule type: " + kind)
    return kind, target, fields[2].upper()


def validate_final(rules):
    finals = [index for index, rule in enumerate(rules) if rule[0] == "FINAL"]
    if finals != [len(rules) - 1]:
        raise BuildError("FINAL must occur exactly once at the end")


def domain_matches(kind, target, host):
    host = host.lower().rstrip(".")
    if kind == "DOMAIN":
        return host == target
    if kind == "DOMAIN-SUFFIX":
        return host == target or host.endswith("." + target)
    return target in host


def route(rules, host="", ip=None, protocol="TCP", port=443):
    """Evaluate known rules without DNS, SNI inference or native kernel semantics."""
    address = ipaddress.ip_address(ip) if ip else None
    for kind, target, policy in rules:
        if kind == "AND":
            if protocol == "UDP" and port == 443:
                if target[0] == "IP-CIDR":
                    if address is not None and address in ipaddress.ip_network(target[1], strict=False):
                        return policy
                elif host and domain_matches(*target, host):
                    return policy
        elif kind in DOMAIN_TYPES and host and domain_matches(kind, target, host):
            return policy
        elif kind == "IP-CIDR" and address is not None:
            if address in ipaddress.ip_network(target, strict=False):
                return policy
        elif kind == "FINAL":
            return policy
    raise BuildError("No final rule matched")


def validate_priority(custom, merged):
    if not custom or len(custom) != 71 or len(set(custom)) != len(custom):
        raise BuildError("Expected the reviewed 71 distinct custom rules")
    proxy_domains = {(kind, target) for kind, target, policy in custom
                     if kind in DOMAIN_TYPES and policy == "PROXY"}
    udp_domains = {target for kind, target, policy in custom
                   if kind == "AND" and target[0] in DOMAIN_TYPES}
    if (len(proxy_domains) != 36 or not PROXY_ONLY_DOMAINS <= proxy_domains
            or proxy_domains - PROXY_ONLY_DOMAINS != udp_domains):
        raise BuildError("Custom domain/UDP coverage is incomplete")
    for kind, target in proxy_domains:
        host = "test-" + target + ".example" if kind == "DOMAIN-KEYWORD" else target
        for sample in [host] + (["sub." + host] if kind == "DOMAIN-SUFFIX" else []):
            if route(merged, host=sample) != "PROXY":
                raise BuildError("Custom TCP route did not win")
            udp_policy = "PROXY" if (kind, target) in PROXY_ONLY_DOMAINS else "REJECT-NO-DROP"
            if route(merged, host=sample, protocol="UDP") != udp_policy:
                raise BuildError("Custom QUIC route did not win")
    for host in ("ip.net.coffee", "api.segment.io", "segment.com"):
        if route(merged, host=host) != "PROXY":
            raise BuildError("Required user exception lost priority")
    networks = {target for kind, target, policy in custom if kind == "IP-CIDR" and policy == "PROXY"}
    if networks != {"160.79.104.0/23", "2607:6bc0::/48"}:
        raise BuildError("Required ingress networks missing")
    udp_networks = {target[1] for kind, target, policy in custom
                    if kind == "AND" and target[0] == "IP-CIDR"}
    if udp_networks != networks:
        raise BuildError("Required ingress UDP coverage is incomplete")
    for ip in ("160.79.104.1", "160.79.105.254", "2607:6bc0::1"):
        for protocol, port, expected in (("TCP", 443, "PROXY"), ("UDP", 443, "REJECT-NO-DROP"),
                                         ("UDP", 3478, "PROXY")):
            if route(merged, ip=ip, protocol=protocol, port=port) != expected:
                raise BuildError("IP fallback did not win")


def build(source, local_text, custom_text, source_info, previous=None):
    if not source or len(source) > MAX_BYTES:
        raise BuildError("Invalid upstream download size")
    try:
        text = source.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise BuildError("Upstream is not UTF-8") from exc
    upstream = sections(text, ["General", "Rule", "URL Rewrite"])
    source_lines = active(upstream["Rule"])
    source_rules = [parse_rule(line) for line in source_lines]
    if any(rule[0] not in SOURCE_TYPES for rule in source_rules):
        raise BuildError("Upstream rule type changed")
    validate_final(source_rules)
    count = len(source_rules)
    if not MIN_RULES <= count <= MAX_RULES:
        raise BuildError("Upstream rule count outside reviewed range")
    if previous:
        old_count = previous["rules"]["upstream"]
        if abs(count / old_count - 1) > 0.10:
            raise BuildError("Upstream rule count changed by more than 10%; review required")
    local = sections(local_text, ["General", "URL Rewrite"])
    settings = active(local["General"])
    keys = [line.split("=", 1)[0].strip() for line in settings]
    if set(keys) != GENERAL_KEYS or len(keys) != len(GENERAL_KEYS):
        raise BuildError("Local General settings changed; review the allowed keys")
    custom_lines = active(custom_text.splitlines())
    custom_rules = [parse_rule(line) for line in custom_lines]
    selectors = {(kind, target) for kind, target, _ in custom_rules}
    retained = [line for line, rule in zip(source_lines, source_rules)
                if (rule[0], rule[1]) not in selectors]
    merged = custom_rules + [parse_rule(line) for line in retained]
    validate_final(merged)
    validate_priority(custom_rules, merged)
    output = (
        "# iOS Shadowrocket ad-blocking configuration.\n"
        f"# Source: https://github.com/{UPSTREAM}\n"
        f"# Upstream SHA256: {sha256(source)}\n"
        "# CC BY-SA 4.0; see LICENSE and README.md for attribution.\n\n"
        "[General]\n" + "\n".join(local["General"]).strip() + "\n\n"
        "[Rule]\n" + custom_text.strip() + "\n\n"
        "# Upstream rules in their original order, exact overridden selectors removed.\n"
        + "\n".join(retained) + "\n\n[URL Rewrite]\n"
        + "\n".join(local["URL Rewrite"]).strip() + "\n"
    ).encode("utf-8")
    info = {
        "schema_version": 1,
        "source": {**source_info, "sha256": sha256(source), "bytes": len(source)},
        "inputs": {"local_sha256": sha256(local_text.encode()),
                   "custom_sha256": sha256(custom_text.encode())},
        "rules": {"upstream": count, "custom": len(custom_rules),
                  "removed": count - len(retained), "merged": len(merged)},
        "output": {"filename": OUTPUT, "sha256": sha256(output), "bytes": len(output)},
        "validation": "bounded static checks only; iOS verification required",
    }
    return output, info


def fetch(url):
    # Credentials are sent only to the GitHub API, never to upstream raw content.
    headers = {"User-Agent": "Shadowrocket-Rules", "Accept": "application/vnd.github+json"}
    if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise BuildError("Download exceeds size limit")
    return data


def download():
    commit = json.loads(fetch(f"https://api.github.com/repos/{UPSTREAM}/commits/{BRANCH}"))
    sha = commit["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise BuildError("Invalid upstream commit SHA")
    url = f"https://raw.githubusercontent.com/{UPSTREAM}/{sha}/{SOURCE_FILE}"
    return fetch(url), {"repository": UPSTREAM, "branch": BRANCH, "commit": sha,
                        "committed_at": commit["commit"]["committer"]["date"], "url": url}


def publish(output_dir, output, info):
    """Stage both files before replacement; restore prior files on ordinary I/O failure.

    A sudden process/power loss between replacements is not a two-file transaction.
    Remote publication is a single Git commit after all steps succeed.
    """
    payloads = {OUTPUT: output, "Build-info.json": (json.dumps(info, indent=2) + "\n").encode()}
    publish_files(output_dir, payloads)


def publish_files(output_dir, payloads):
    """Replace a validated group of files, restoring previous files on I/O failure."""
    output_dir.mkdir(parents=True, exist_ok=True)
    old = {name: (output_dir / name).read_bytes() if (output_dir / name).exists() else None
           for name in payloads}
    staged, replaced = {}, []
    try:
        for name, data in payloads.items():
            with tempfile.NamedTemporaryFile(dir=output_dir, suffix=".tmp", delete=False) as stream:
                staged[name] = Path(stream.name)
                stream.write(data)
        for name, path in staged.items():
            os.replace(path, output_dir / name)
            replaced.append(name)
    except OSError:
        for name in reversed(replaced):
            target = output_dir / name
            if old[name] is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(old[name])
        raise
    finally:
        for path in staged.values():
            path.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-file", type=Path)
    parser.add_argument("--upstream-commit", help="Optional provenance for a known offline snapshot")
    parser.add_argument("--output-dir", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        if args.upstream_commit and not re.fullmatch(r"[0-9a-f]{40}", args.upstream_commit):
            raise BuildError("Invalid offline commit SHA")
        if args.upstream_file:
            source = args.upstream_file.read_bytes()
            source_info = {"mode": "offline", "repository": UPSTREAM, "commit": args.upstream_commit}
        else:
            source, source_info = download()
        previous_path = args.output_dir / "Build-info.json"
        previous = json.loads(previous_path.read_text()) if previous_path.exists() else None
        output, info = build(source, (ROOT / "Config/Local.conf").read_text(encoding="utf-8"),
                             (ROOT / "Rules/Overrides.list").read_text(encoding="utf-8"), source_info, previous)
        publish(args.output_dir, output, info)
    except (BuildError, OSError, ValueError, KeyError, urllib.error.URLError) as exc:
        print(f"Build failed; no validated replacement published ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1
    print(json.dumps(info["rules"]))
    print("Validated configuration SHA256: " + info["output"]["sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
