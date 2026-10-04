#!/usr/bin/env python3
"""Consume the actual nupkg from an isolated cache; requires installed .NET SDKs."""
import argparse
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
}
Console.WriteLine("Package consumer: source identity, BLAKE2b vector, OpenPGP GCM boundaries/tamper rejection passed");
'''


def write_project(root, package_dir, version):
    root, package_dir = Path(root), Path(package_dir)
    (root / "global.json").write_bytes((Path(__file__).resolve().parents[1] / "global.json").read_bytes())
    project = ET.Element("Project", Sdk="Microsoft.NET.Sdk")
    props = ET.SubElement(project, "PropertyGroup")
    for key, value in (("OutputType", "Exe"), ("TargetFrameworks", "net8.0;net9.0;net10.0"),
                       ("ImplicitUsings", "enable"), ("Nullable", "enable")):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="herocrypt-consumer-") as directory:
        root = Path(directory)
        write_project(root, args.package_dir, args.version)
        env = dict(os.environ, NUGET_PACKAGES=str(root / ".packages"))
        subprocess.run(["dotnet", "restore", "Smoke.csproj", "--configfile", "NuGet.Config",
                        "-p:NuGetAudit=true", "-p:NuGetAuditMode=all", "-p:TreatWarningsAsErrors=true"],
                       cwd=root, env=env, check=True)
        for framework in ("net8.0", "net9.0", "net10.0"):
            subprocess.run(["dotnet", "run", "--project", "Smoke.csproj", "--configuration", "Release",
                            "--framework", framework, "--no-restore", "--", args.version, args.commit],
                           cwd=root, env=env, check=True)


if __name__ == "__main__":
    main()
