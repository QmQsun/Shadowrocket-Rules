"""Create a private Android profile from a user-owned desktop YAML (requires PyYAML)."""

import argparse
from pathlib import Path
import sys

if __package__:
    from .build_android import ROOT, profile, encode_yaml
else:
    from build_android import ROOT, profile, encode_yaml


def create(source_path, output_path):
    import yaml

    private = (ROOT / "Output/Private").resolve()
    target = output_path.resolve()
    if not target.is_relative_to(private):
        raise ValueError("Private profiles must stay inside the ignored Output/Private directory")
    source = yaml.safe_load(source_path.read_text(encoding="utf-8-sig"))
    provider = source["proxy-providers"]["pandafan-user"]
    # Do not copy desktop nodes, home subscription, controller credentials or extras.
    selected = {key: provider[key] for key in ("url", "header", "interval") if key in provider}
    result = profile(selected)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(encode_yaml(result))
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "Output/Private/Android-PandaFan.yaml")
    args = parser.parse_args()
    try:
        target = create(args.source, args.output)
    except Exception as exc:
        # YAML errors can contain subscription tokens; never print exception contents.
        print(f"Private profile not created ({type(exc).__name__}). Check source and output path.", file=sys.stderr)
        return 1
    print("Private Android profile created: " + str(target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
