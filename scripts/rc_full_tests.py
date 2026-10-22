#!/usr/bin/env python3
"""Run the complete stable-built net10 test assembly on an exact runtime.

This qualifies runtime execution, not net11 target compilation or a NuGet release.
"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from release_smoke import verify_sdk


def validate_runtime(info, runtime):
    expected = {"runtime-framework": ".NET " + runtime, "arch-process": "X64",
                "target-framework": ".NETCoreApp,Version=v10.0"}
    if any(info.get(key) != value for key, value in expected.items()):
        raise ValueError(f"Test process runtime/architecture/target mismatch: {info}")


def validate_report(path):
    counters = ET.parse(path).getroot().find(".//{*}Counters")
    if counters is None:
        raise ValueError("Full suite report has no counters")
    counts = {key: int(counters.get(key, "-1"))
              for key in ("total", "executed", "passed", "failed", "notExecuted")}
    if (min(counts.values()) < 0 or counts["executed"] == 0 or counts["failed"] != 0
            or counts["passed"] != counts["executed"]
            or counts["total"] != counts["executed"] + counts["notExecuted"]):
        raise ValueError(f"Full suite report is empty, failed or inconsistent: {counts}")
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", type=Path, required=True)
    parser.add_argument("--sdk-version", required=True)
    parser.add_argument("--runtime-version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.dotnet.is_absolute() or not args.dotnet.is_file():
        parser.error("--dotnet must be an existing absolute executable")
    for version in (args.sdk_version, args.runtime_version):
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", version):
            parser.error("SDK/runtime versions must be exact")
    root = Path(__file__).resolve().parents[1]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit) or commit != args.commit:
        parser.error("Checkout/source SHA mismatch")
    subprocess.run(["git", "diff", "--exit-code", "HEAD"], cwd=root, check=True)
    assembly = root / "tests/HeroCrypt.Tests/bin/Release/net10.0/HeroCrypt.Tests.dll"
    library = assembly.parent / "HeroCrypt.dll"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Refuse stale result files instead of letting a previous success satisfy this run.
    report = output / "full-suite.trx"
    if report.exists():
        parser.error("Output already contains a test report; use a fresh output directory")
    dotnet = str(args.dotnet.resolve())
    env = {key: value for key, value in os.environ.items() if not key.startswith("DOTNET_ROOT")}
    env.update(DOTNET_ROOT=str(Path(dotnet).parent), DOTNET_HOST_PATH=dotnet,
               PATH=str(Path(dotnet).parent) + os.pathsep + env.get("PATH", ""),
               DOTNET_ROLL_FORWARD="Disable")
    with tempfile.TemporaryDirectory(prefix="herocrypt-full-tests-") as directory:
        temporary = Path(directory)
        (temporary / "global.json").write_text(json.dumps({"sdk": {
            "version": args.sdk_version, "rollForward": "disable",
            "allowPrerelease": "-" in args.sdk_version}}))
        verify_sdk(dotnet, temporary, env, args.sdk_version)
    command = [dotnet, "exec", "--fx-version", args.runtime_version,
               "--roll-forward", "Disable", str(assembly)]
    info = json.loads(subprocess.check_output(command + ["-assemblyInfo"], cwd=root, env=env, text=True))
    validate_runtime(info, args.runtime_version)
    identity = dict(source_sha=commit, tree=subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip(),
        sdk=args.sdk_version, runtime=info, dotnet=dotnet, os=platform.platform(),
        rid="linux-x64" if platform.system() == "Linux" else platform.system(),
        assembly_sha256=hashlib.sha256(assembly.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
        scope="Complete net10-compiled suite on exact runtime; not net11 compilation or package publication")
    (output / "identity.json").write_text(json.dumps(identity, indent=2))
    print(json.dumps(identity, indent=2), flush=True)
    # No test filter: execute every test exposed by this assembly with its existing skip policy.
    with (output / "full-suite.log").open("w") as log:
        result = subprocess.run(command + ["-noColor", "-result-trx", str(report)],
                                cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    print((output / "full-suite.log").read_text(), flush=True)
    result.check_returncode()
    print("Verified full suite counters: " + json.dumps(validate_report(report)), flush=True)


if __name__ == "__main__":
    main()
