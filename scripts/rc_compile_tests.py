#!/usr/bin/env python3
"""Compile original library/test TFMs with an exact SDK in a disposable source copy."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import zipfile

from release_smoke import verify_sdk
from rc_full_tests import validate_report, validate_runtime


def select_sdk(root, version):
    path = root / "global.json"
    config = json.loads(path.read_text())
    config["sdk"] = {"version": version, "rollForward": "disable", "allowPrerelease": "-" in version}
    path.write_text(json.dumps(config, indent=2) + "\n")


def lock_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("packages.lock.json"))}


def verify_locks(root, before):
    if not before or lock_hashes(root) != before:
        raise ValueError("Lock files changed or missing during compiler validation")


def compile_commands(dotnet, commit):
    tests = "tests/HeroCrypt.Tests/HeroCrypt.Tests.csproj"
    return [[dotnet, "restore", tests, "--locked-mode", "-p:NuGetAudit=true",
             "-p:NuGetAuditMode=all", "-p:TreatWarningsAsErrors=true"]] + [
        [dotnet, "build", project, "--configuration", "Release", "--no-restore",
         "-p:SourceRevisionId=" + commit, "-p:UseSharedCompilation=false", "--verbosity", "normal"]
        for project in ("src/HeroCrypt/HeroCrypt.csproj", tests)]


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
    def git(*arguments):
        return subprocess.check_output(["git", *arguments], cwd=root).decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit) or git("rev-parse", "HEAD") != args.commit:
        parser.error("Checkout/source SHA mismatch")
    subprocess.run(["git", "diff", "--exit-code", "HEAD"], cwd=root, check=True)
    output = args.output.resolve()
    if output.exists():
        parser.error("Use a fresh output directory")
    output.mkdir(parents=True)
    dotnet = str(args.dotnet.resolve())
    env = {key: value for key, value in os.environ.items() if not key.startswith("DOTNET_ROOT")}
    for key in ("MSBuildSDKsPath", "MSBUILD_EXE_PATH", "MSBuildExtensionsPath", "CscToolPath", "CscToolExe", "RoslynTargetsPath"):
        if key in env:
            parser.error("Compiler environment override is not allowed: " + key)
    env.update(DOTNET_ROOT=str(Path(dotnet).parent), DOTNET_HOST_PATH=dotnet,
               PATH=str(Path(dotnet).parent) + os.pathsep + env.get("PATH", ""), DOTNET_ROLL_FORWARD="Disable")
    identity = dict(source_sha=args.commit, tree=git("rev-parse", "HEAD^{tree}"),
                    sdk=args.sdk_version, runtime=args.runtime_version, dotnet=dotnet, commands=[], os=platform.platform(),
                    scope="Exact SDK compilation of original library/test TFMs; net10 full suite execution; no package publication")
    def record():
        (output / "identity.json").write_text(json.dumps(identity, indent=2))
        print(json.dumps(identity, indent=2), flush=True)
    record()
    with tempfile.TemporaryDirectory(prefix="herocrypt-compiler-") as directory:
        isolated = Path(directory)
        archive = subprocess.check_output(["git", "archive", "--format=zip", args.commit], cwd=root)
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            source.extractall(isolated)
        before = lock_hashes(isolated)
        select_sdk(isolated, args.sdk_version)
        verify_sdk(dotnet, isolated, env, args.sdk_version)
        compiler = Path(dotnet).parent / "sdk" / args.sdk_version / "Roslyn/bincore/csc.dll"
        identity.update(lock_sha256=before, compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(),
                        compiler_version=subprocess.check_output([dotnet, str(compiler), "-version"], cwd=isolated, env=env, text=True).strip())
        record()
        try:
            for index, command in enumerate(compile_commands(dotnet, args.commit)):
                print(json.dumps(command), flush=True)
                with (output / f"compile-{index}.log").open("w") as log:
                    result = subprocess.run(command, cwd=isolated, env=env, stdout=log, stderr=subprocess.STDOUT)
                build_log = (output / f"compile-{index}.log").read_text()
                print(build_log[-12000:], flush=True)
                identity["commands"].append(dict(command=command, exit_code=result.returncode))
                record()
                print(f"Command {index} exit: {result.returncode}", flush=True)
                result.check_returncode()
                if index:
                    invocations = [line.strip() for line in build_log.splitlines()
                                   if str(compiler) in line and " /out:" in line]
                    if not invocations:
                        raise ValueError("Build log does not prove expected compiler invocation")
                    identity.setdefault("compiler_invocations", {})[str(index)] = invocations
                    record()
        finally:
            verify_locks(isolated, before)
        assembly = isolated / "tests/HeroCrypt.Tests/bin/Release/net10.0/HeroCrypt.Tests.dll"
        command = [dotnet, "exec", "--fx-version", args.runtime_version, "--roll-forward", "Disable", str(assembly)]
        info = json.loads(subprocess.check_output(command + ["-assemblyInfo"], cwd=isolated, env=env, text=True))
        validate_runtime(info, args.runtime_version)
        identity.update(runtime_info=info, binaries_sha256={str(path.relative_to(isolated)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in sorted(isolated.glob("**/bin/Release/*/HeroCrypt*.dll"))})
        record()
        report = output / "full-suite.trx"
        with (output / "full-suite.log").open("w") as log:
            result = subprocess.run(command + ["-noColor", "-result-trx", str(report)], cwd=isolated, env=env, stdout=log, stderr=subprocess.STDOUT)
        print((output / "full-suite.log").read_text(), flush=True)
        identity["commands"].append(dict(command=command + ["-noColor", "-result-trx", str(report)], exit_code=result.returncode))
        record()
        result.check_returncode()
        identity["counts"] = validate_report(report)
        record()
    subprocess.run(["git", "diff", "--exit-code", "HEAD"], cwd=root, check=True)


if __name__ == "__main__":
    main()
