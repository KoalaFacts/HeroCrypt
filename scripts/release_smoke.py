#!/usr/bin/env python3
"""Consume the actual nupkg from an isolated cache; requires installed .NET SDKs."""
import argparse
import hashlib
import json
import re
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

PROGRAM = r'''
using System.Reflection;
using System.Text;
using HeroCrypt;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.OpenPgp;

var info = typeof(HeroCryptBuilder).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
if (info != args[0] + "+" + args[1])
    throw new Exception("Loaded assembly version/source commit mismatch: " + info);
if (args.Length > 2)
{
    var runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
    if (runtime != ".NET " + args[2])
        throw new Exception("Runtime identity mismatch: " + runtime);
    Console.WriteLine("Verified runtime: " + runtime);
}
if (args.Length > 3)
{
    var supported = System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported;
    var compiled = System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeCompiled;
    Console.WriteLine($"Execution: {args[3]}; DynamicCodeSupported={supported}; DynamicCodeCompiled={compiled}");
    var expected = args[3] == "jit";
    if ((args[3] != "jit" && args[3] != "aot") || supported != expected || compiled != expected)
        throw new Exception("Execution mode mismatch");
}
using var hasher = HeroCryptBuilder.Blake2b().WithOutputLength(32);
var hash = Convert.ToHexString(hasher.ComputeHash(Encoding.UTF8.GetBytes("abc")));
if (hash != "BDDD813C634239723171EF3FEE98579B94964E3BB1CB3E427262C8C068D52319")
    throw new Exception("BLAKE2b-256 known-answer smoke test failed");
const string password = "packaged OpenPGP GCM smoke fixture";
foreach (var length in new[] { 0, 4087, 4088 })
{
    var data = Enumerable.Repeat((byte)0x42, length).ToArray();
    using var encryptor = PgpMessageEncryptor.Create().WithPassphrase(password)
        .WithAead(AeadAlgorithm.Gcm).WithFileName(string.Empty)
        .WithFileDate(DateTimeOffset.FromUnixTimeSeconds(1700000000));
    var message = encryptor.Encrypt(data).ToArray();
    using var decryptor = PgpMessageDecryptor.Create().WithMessagePassphrase(password);
    if (!decryptor.Decrypt(message).Data.Span.SequenceEqual(data))
        throw new Exception("Packaged OpenPGP GCM round trip failed");
    using var input = new MemoryStream(message);
    using var reader = new PgpPacketReader(input);
    using var output = new MemoryStream();
    using (var writer = new PgpPacketWriter(output, leaveOpen: true))
    {
        while (reader.ReadNextPacket(out var tag, out var body))
        {
            if (tag == PgpPacketTag.SymmetricallyEncryptedIntegrityProtectedData)
            {
                var packet = PgpSymEncryptedIntegrityProtectedDataPacket.Read(body.Span);
                var encrypted = packet.EncryptedData.ToArray();
                encrypted[^1] ^= 1;
                var modified = PgpSymEncryptedIntegrityProtectedDataPacket.CreateV2(
                    packet.CipherAlgorithm, packet.AeadAlgorithm, packet.ChunkSize, packet.Salt, encrypted);
                writer.WritePacket(tag, modified.ToArray());
            }
            else writer.WritePacket(tag, body.Span);
        }
    }
    using var verifier = PgpMessageDecryptor.Create().WithMessagePassphrase(password);
    if (verifier.TryDecrypt(output.ToArray(), out var plaintext, out var error)
        || !plaintext.Data.IsEmpty || string.IsNullOrEmpty(error))
        throw new Exception("Packaged OpenPGP accepted a modified authentication tag");
    VerifyRecovery();
    foreach (var invalid in new byte[][] { [], [0], message[..^1], message[..(message.Length / 2)] })
    {
        if (verifier.TryDecrypt(invalid, out plaintext, out error)
            || !plaintext.Data.IsEmpty || string.IsNullOrEmpty(error))
            throw new Exception("Packaged OpenPGP invalid input did not fail closed");
        VerifyRecovery();
    }
    void VerifyRecovery()
    {
        if (!verifier.TryDecrypt(message, out var recovered, out var recoveryError)
            || !recovered.Data.Span.SequenceEqual(data) || recoveryError != null)
            throw new Exception("Packaged OpenPGP same-instance recovery failed");
    }
    verifier.Dispose();
    verifier.Dispose();
    ExpectDisposed(() => verifier.TryDecrypt(message, out _, out _));
    ExpectDisposed(() => verifier.Decrypt(message));
    ExpectDisposed(() => verifier.WithMessagePassphrase(password));
}
Console.WriteLine("Package consumer: source identity, BLAKE2b vector, OpenPGP GCM boundaries/tamper rejection passed");
Console.WriteLine("Package consumer: invalid-input rejection, same-instance recovery and disposal passed");

// Compiled against the exact nupkg, rather than linked source or a guessed API.
// These cover the Ed25519 signing/verification and password-verifier builder
// chains corrected in README.md. They do NOT validate every README example.
{
    using var signer = HeroCryptBuilder.Ed25519();
    var (privateKey, publicKey) = signer.GenerateKeyPair();
    var message = Encoding.UTF8.GetBytes("HeroCrypt packaged README Ed25519");
    try
    {
        var signature = signer.WithPrivateKey(privateKey).WithMessage(message).Sign();
        if (!signer.WithPublicKey(publicKey).WithMessage(message).WithSignature(signature).Verify())
            throw new Exception("Packaged README-pattern Ed25519 signature failed verification");

        var altered = (byte[])message.Clone();
        altered[0] ^= 1;
        if (signer.WithMessage(altered).Verify())
            throw new Exception("Packaged README-pattern Ed25519 accepted a changed message");
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(signature);
    }
    finally
    {
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(privateKey);
    }
}
{
    const string password = "HeroCrypt packaged README Argon2 verifier";
    string saltHex;
    string storedKeyHex;
    using (var kdf = HeroCryptBuilder.DeriveKey().WithArgon2id()
        .WithPassword(password).WithRandomSalt(16))
    {
        saltHex = kdf.GetSaltAsHex();
        byte[] key = kdf.DeriveKey();
        try
        {
            storedKeyHex = Convert.ToHexString(key);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(key);
        }
    }

    using var verifier = HeroCryptBuilder.DeriveKey().WithArgon2id()
        .WithPassword(password).WithSaltFromHex(saltHex);
    byte[] candidate = verifier.DeriveKey();
    byte[] stored = Convert.FromHexString(storedKeyHex);
    try
    {
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(candidate, stored))
            throw new Exception("Packaged README-pattern Argon2 password verification failed");
    }
    finally
    {
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(candidate);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(stored);
    }
}
Console.WriteLine("Packaged README-pattern Ed25519 and Argon2 verifier builder chains passed");

static void ExpectDisposed(Action operation)
{
    try { operation(); }
    catch (ObjectDisposedException) { return; }
    throw new Exception("Packaged OpenPGP operation after disposal was accepted");
}
'''


def write_project(root, package_dir, version, frameworks=("net8.0", "net9.0", "net10.0"),
                  sdk_version=None, runtime_version=None):
    root, package_dir = Path(root), Path(package_dir)
    (root / "global.json").write_bytes((Path(__file__).resolve().parents[1] / "global.json").read_bytes())
    if sdk_version:
        config = json.loads((root / "global.json").read_text())
        config["sdk"] = {"version": sdk_version, "rollForward": "disable", "allowPrerelease": "-" in sdk_version}
        (root / "global.json").write_text(json.dumps(config, indent=2) + "\n")
    project = ET.Element("Project", Sdk="Microsoft.NET.Sdk")
    props = ET.SubElement(project, "PropertyGroup")
    for key, value in (("OutputType", "Exe"), ("TargetFrameworks", ";".join(frameworks)),
                       ("ImplicitUsings", "enable"), ("Nullable", "enable")):
        ET.SubElement(props, key).text = value
    if runtime_version:
        for key, value in (("RuntimeFrameworkVersion", runtime_version), ("RollForward", "Disable"),
                           ("TargetLatestRuntimePatch", "false")):
            ET.SubElement(props, key).text = value
    ET.SubElement(ET.SubElement(project, "ItemGroup"), "PackageReference", Include="HeroCrypt", Version=f"[{version}]")
    ET.ElementTree(project).write(root / "Smoke.csproj", encoding="utf-8", xml_declaration=True)
    config = ET.Element("configuration")
    sources = ET.SubElement(config, "packageSources")
    ET.SubElement(sources, "clear")
    ET.SubElement(sources, "add", key="release", value=str(package_dir.resolve()))
    ET.SubElement(sources, "add", key="nuget.org", value="https://api.nuget.org/v3/index.json")
    mapping = ET.SubElement(config, "packageSourceMapping")
    ET.SubElement(ET.SubElement(mapping, "packageSource", key="release"), "package", pattern="HeroCrypt")
    ET.SubElement(ET.SubElement(mapping, "packageSource", key="nuget.org"), "package", pattern="*")
    audit = ET.SubElement(config, "auditSources")
    ET.SubElement(audit, "clear")
    ET.SubElement(audit, "add", key="nuget.org", value="https://api.nuget.org/v3/index.json")
    ET.ElementTree(config).write(root / "NuGet.Config", encoding="utf-8", xml_declaration=True)
    (root / "Program.cs").write_text(PROGRAM, encoding="utf-8")


def verify_sdk(dotnet, root, env, expected):
    actual = subprocess.run([dotnet, "--version"], cwd=root, env=env, check=True,
                            capture_output=True, text=True).stdout.strip()
    if actual != expected:
        raise ValueError(f"SDK identity mismatch: expected {expected}, got {actual}")
    print(f"Verified SDK: {actual}; executable: {dotnet}", flush=True)


def verify_linux_elf(path):
    header = path.read_bytes()[:20]
    if len(header) < 20 or header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
        raise ValueError("Expected Linux x64 ELF native executable")
    print("Verified native ELF: Linux x64", flush=True)


def expect_failure(command, expected, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    output = result.stdout + result.stderr
    print(f"Negative control: {expected}; exit={result.returncode}", flush=True)
    if result.returncode == 0 or expected not in output:
        raise ValueError(f"Expected failure {expected}; exit={result.returncode}: {output}")


def verify_controls(command, root, env):
    for index, value, error in ((-3, "0" * 40, "Loaded assembly version/source commit mismatch"),
                                (-2, "0.0.0", "Runtime identity mismatch"),
                                (-1, "jit" if command[-1] == "aot" else "aot", "Execution mode mismatch")):
        negative = list(command)
        negative[index] = value
        expect_failure(negative, error, cwd=root, env=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--framework", action="append", help="Explicit consumer TFM (repeatable for JIT)")
    parser.add_argument("--aot", action="store_true", help="Publish and execute a native consumer")
    parser.add_argument("--rid", help="Native consumer runtime identifier")
    parser.add_argument("--sha256", help="Expected SHA256 of the exact nupkg")
    parser.add_argument("--dotnet", type=Path, help="Absolute path to an already installed dotnet executable")
    parser.add_argument("--sdk-version", help="Exact SDK version; no roll-forward")
    parser.add_argument("--runtime-version", help="Exact runtime version, checked inside the consumer")
    parser.add_argument("--verify-execution", action="store_true",
                        help="Verify JIT/AOT mode and source/runtime/mode negative controls (AOT: Linux x64 ELF)")
    args = parser.parse_args()
    explicit_toolchain = any((args.dotnet, args.sdk_version, args.runtime_version))
    if explicit_toolchain:
        if not all((args.dotnet, args.sdk_version, args.runtime_version, args.sha256, args.framework)) or len(args.framework) != 1:
            parser.error("Exact toolchain requires --dotnet, --sdk-version, --runtime-version, --sha256 and one --framework")
        if not args.dotnet.is_absolute() or not args.dotnet.is_file():
            parser.error("--dotnet must be an existing absolute executable path")
        for version in (args.sdk_version, args.runtime_version):
            if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", version):
                parser.error("SDK/runtime versions must be exact versions")
    if args.verify_execution and (not explicit_toolchain or (args.aot and args.rid != "linux-x64")):
        parser.error("--verify-execution requires exact toolchain inputs; AOT requires linux-x64")
    if args.aot and (not args.framework or not args.rid or not args.sha256):
        parser.error("AOT requires --framework, --rid and --sha256")
    if args.aot and len(args.framework) != 1:
        parser.error("AOT requires exactly one --framework")
    if args.rid and not args.aot:
        parser.error("--rid requires --aot")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9]+)?", args.version):
        parser.error("Invalid version")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("Invalid source commit")
    frameworks = args.framework or ("net8.0", "net9.0", "net10.0")
    if args.sha256:
        package = args.package_dir / f"HeroCrypt.{args.version}.nupkg"
        if not re.fullmatch(r"[0-9a-f]{64}", args.sha256) or hashlib.sha256(package.read_bytes()).hexdigest() != args.sha256:
            parser.error("Package SHA256 mismatch")
        print(f"Package: HeroCrypt {args.version} source={args.commit} sha256={args.sha256}", flush=True)
    with tempfile.TemporaryDirectory(prefix="herocrypt-consumer-") as directory:
        root = Path(directory)
        write_project(root, args.package_dir, args.version, frameworks=frameworks,
                      sdk_version=args.sdk_version, runtime_version=args.runtime_version)
        env = dict(os.environ, NUGET_PACKAGES=str(root / ".packages"))
        dotnet = str(args.dotnet.resolve()) if explicit_toolchain else "dotnet"
        consumer_args = [args.version, args.commit]
        if explicit_toolchain:
            # Prevent an inherited architecture-specific root from selecting another installation.
            env = {key: value for key, value in env.items() if not key.startswith("DOTNET_ROOT")}
            env.update(DOTNET_ROOT=str(Path(dotnet).parent), DOTNET_HOST_PATH=dotnet,
                       PATH=str(Path(dotnet).parent) + os.pathsep + env.get("PATH", ""),
                       DOTNET_ROLL_FORWARD="Disable")
            verify_sdk(dotnet, root, env, args.sdk_version)
            consumer_args.append(args.runtime_version)
        if args.verify_execution:
            consumer_args.append("aot" if args.aot else "jit")
        native_args = ["--runtime", args.rid, "-p:PublishAot=true"] if args.aot else []
        subprocess.run([dotnet, "restore", "Smoke.csproj", *native_args, "--configfile", "NuGet.Config",
                        "-p:NuGetAudit=true", "-p:NuGetAuditMode=all", "-p:TreatWarningsAsErrors=true"],
                       cwd=root, env=env, check=True)
        if args.aot:
            output = root / "native"
            subprocess.run([dotnet, "publish", "Smoke.csproj", "--configuration", "Release",
                            "--framework", frameworks[0], *native_args, "--no-restore",
                            "-p:TreatWarningsAsErrors=true", "--output", str(output)], cwd=root, env=env, check=True)
            executable = output / ("Smoke.exe" if args.rid.startswith("win-") else "Smoke")
            print(f"Native artifact SHA256: {hashlib.sha256(executable.read_bytes()).hexdigest()}", flush=True)
            if args.verify_execution:
                verify_linux_elf(executable)
            command = [str(executable), *consumer_args]
            subprocess.run(command, cwd=root, env=env, check=True)
            if args.verify_execution:
                verify_controls(command, root, env)
            return
        for framework in frameworks:
            command = [dotnet, "run", "--project", "Smoke.csproj", "--configuration", "Release",
                       "--framework", framework, "--no-restore", "--", *consumer_args]
            subprocess.run(command, cwd=root, env=env, check=True)
            if args.verify_execution:
                command.insert(command.index("--no-restore"), "--no-build")
                verify_controls(command, root, env)


if __name__ == "__main__":
    main()
