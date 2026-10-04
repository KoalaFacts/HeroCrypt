#!/usr/bin/env python3
"""Validate release package provenance, required payloads, and rebuild equivalence.

Uses only the Python standard library. Container metadata/timestamps are excluded
from rebuild comparisons; every shipped payload byte (including nuspec) must match.
"""
import argparse
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath

FRAMEWORKS = {"netstandard2.0", "net8.0", "net9.0", "net10.0"}
DOCUMENTS = ("README.md", "LICENSE", "THIRD-PARTY-NOTICES.md", "SECURITY.md", "PRODUCTION_READINESS.md")


def read_archive(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError(f"Duplicate ZIP entries: {path}")
        for name in names:
            if "\\" in name or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
                raise ValueError(f"Unsafe ZIP path: {name}")
        return {name: archive.read(name) for name in names if not name.endswith("/")}


def validate_package(path, version, commit, repository, source_root):
    path, source_root = Path(path), Path(source_root)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected a full lowercase source commit SHA")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9]+)?", version):
        raise ValueError("Invalid version")
    symbols = path.suffix == ".snupkg"
    if path.name != f"HeroCrypt.{version}.{'snupkg' if symbols else 'nupkg'}":
        raise ValueError(f"Unexpected package filename: {path.name}")
    files = read_archive(path)
    nuspecs = [name for name in files if name.endswith(".nuspec")]
    if nuspecs != ["HeroCrypt.nuspec"]:
        raise ValueError("Expected exactly HeroCrypt.nuspec")
    try:
        root = ET.fromstring(files["HeroCrypt.nuspec"])
    except ET.ParseError as error:
        raise ValueError("Invalid nuspec XML") from error
    metadata = root.find("{*}metadata")
    if metadata is None:
        raise ValueError("Missing package metadata")
    for key, expected in (("id", "HeroCrypt"), ("version", version)):
        if metadata.findtext(f"{{*}}{key}") != expected:
            raise ValueError(f"Package {key} does not match {expected}")
    repo = metadata.find("{*}repository")
    if repo is None or any(repo.get(key) != value for key, value in (("type", "git"), ("url", repository), ("commit", commit))):
        raise ValueError("Package repository provenance does not match the verified source SHA")
    required = set()
    for tfm in FRAMEWORKS:
        for suffix in (("pdb",) if symbols else ("dll", "xml")):
            required.add(f"lib/{tfm}/HeroCrypt.{suffix}")
    if not symbols:
        required.update(DOCUMENTS)
        license_node = metadata.find("{*}license")
        if license_node is None or license_node.get("type") != "expression" or license_node.text != "MIT":
            raise ValueError("Expected the declared MIT license expression")
        if metadata.findtext("{*}readme") != "README.md":
            raise ValueError("Expected README.md package readme metadata")
    missing = required - files.keys()
    if missing:
        raise ValueError(f"Missing required files: {sorted(missing)}")
    actual_frameworks = {name.split("/")[1] for name in files if name.startswith("lib/") and len(name.split("/")) >= 3}
    if actual_frameworks != FRAMEWORKS:
        raise ValueError(f"Unexpected framework set: {sorted(actual_frameworks)}")
    for name in required:
        if not files[name]:
            raise ValueError(f"Required file is empty: {name}")
        if name.endswith(".dll") and not files[name].startswith(b"MZ"):
            raise ValueError(f"Invalid assembly header: {name}")
        if name.endswith(".pdb") and not files[name].startswith(b"BSJB"):
            raise ValueError(f"Invalid portable PDB header: {name}")
        if name.endswith(".xml"):
            try:
                doc = ET.fromstring(files[name])
            except ET.ParseError as error:
                raise ValueError(f"Invalid documentation XML: {name}") from error
            if doc.tag != "doc" or doc.findtext("assembly/name") != "HeroCrypt":
                raise ValueError(f"Invalid assembly documentation: {name}")
    if not symbols:
        for name in DOCUMENTS:
            if files[name] != (source_root / name).read_bytes():
                raise ValueError(f"Package document differs from source: {name}")


def compare_packages(first, second):
    def payload(path):
        return {name: data for name, data in read_archive(path).items()
                if name not in {"[Content_Types].xml", "_rels/.rels"}
                and not name.startswith("package/services/metadata/core-properties/")}
    left, right = payload(first), payload(second)
    differences = sorted(name for name in left.keys() | right.keys() if left.get(name) != right.get(name))
    if differences:
        raise ValueError(f"Package payload is not reproducible: {differences}")


def release_notes_section(changelog, version, repository, commit):
    heading = re.search(rf"^## \[{re.escape(version)}\] - .+$", changelog, re.MULTILINE)
    if heading is None:
        raise ValueError("Prepared release notes are missing")
    section = re.split(r"^## ", changelog[heading.end():], maxsplit=1, flags=re.MULTILINE)[0].strip()
    if not section:
        raise ValueError("Prepared release notes are empty")
    return re.sub(
        r"\]\(((?:docs/[^)]+)|(?:SECURITY\.md|PRODUCTION_READINESS\.md)(?:#[^)]*)?)\)",
        lambda match: f"](https://github.com/{repository}/blob/{commit}/{match[1]})",
        section,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("packages", nargs="+", type=Path)
    validate.add_argument("--version", required=True)
    validate.add_argument("--commit", required=True)
    validate.add_argument("--repository", required=True)
    validate.add_argument("--source-root", type=Path, default=Path("."))
    compare = commands.add_parser("compare")
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            for package in args.packages:
                validate_package(package, args.version, args.commit, args.repository, args.source_root)
                print(f"Verified identity, provenance and payloads: {package.name}")
        else:
            compare_packages(args.first, args.second)
            print(f"Verified reproducible payload: {args.first.name}")
    except (ValueError, OSError, ET.ParseError, zipfile.BadZipFile) as error:
        parser.exit(1, f"Release validation failed: {error}\n")


if __name__ == "__main__":
    main()
