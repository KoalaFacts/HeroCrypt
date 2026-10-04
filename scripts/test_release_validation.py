"""Contract tests for the package gates; run with Python's unittest."""
import tempfile
import unittest
import zipfile
from pathlib import Path

import release_validation as release

SHA = "a" * 40
VERSION = "1.0.0"
REPOSITORY = "https://github.com/KoalaFacts/HeroCrypt"
FRAMEWORKS = ("netstandard2.0", "net8.0", "net9.0", "net10.0")
DOCS = ("README.md", "LICENSE", "THIRD-PARTY-NOTICES.md", "SECURITY.md", "PRODUCTION_READINESS.md")


def contents(symbols=False):
    nuspec = f'''<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>
    <id>HeroCrypt</id><version>{VERSION}</version><license type="expression">MIT</license>
    <readme>README.md</readme><repository type="git" url="{REPOSITORY}" commit="{SHA}"/>
    </metadata></package>'''
    files = {"HeroCrypt.nuspec": nuspec.encode(), "_rels/.rels": b"container metadata"}
    for tfm in FRAMEWORKS:
        if symbols:
            files[f"lib/{tfm}/HeroCrypt.pdb"] = b"BSJB portable-pdb-fixture"
        else:
            files[f"lib/{tfm}/HeroCrypt.dll"] = b"MZ assembly-fixture"
            files[f"lib/{tfm}/HeroCrypt.xml"] = b"<doc><assembly><name>HeroCrypt</name></assembly></doc>"
    if not symbols:
        files.update({name: (name + " contents").encode() for name in DOCS})
    return files


class PackageValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in DOCS:
            (self.root / name).write_bytes((name + " contents").encode())

    def write(self, files, name="HeroCrypt.1.0.0.nupkg"):
        path = self.root / name
        with zipfile.ZipFile(path, "w") as archive:
            for key, value in files.items():
                archive.writestr(key, value)
        return path

    def validate(self, files=None, symbols=False):
        name = "HeroCrypt.1.0.0.snupkg" if symbols else "HeroCrypt.1.0.0.nupkg"
        return release.validate_package(self.write(files or contents(symbols), name), VERSION, SHA, REPOSITORY, self.root)

    def test_valid_package_and_symbols(self):
        self.validate()
        self.validate(symbols=True)

    def test_each_framework_assembly_documentation_and_symbol_is_required(self):
        for tfm in FRAMEWORKS:
            for suffix in ("dll", "xml", "pdb"):
                with self.subTest(tfm=tfm, suffix=suffix):
                    files = contents(symbols=suffix == "pdb")
                    del files[f"lib/{tfm}/HeroCrypt.{suffix}"]
                    with self.assertRaisesRegex(ValueError, "Missing"):
                        self.validate(files, symbols=suffix == "pdb")

    def test_each_document_must_match_checked_out_source(self):
        for name in DOCS:
            with self.subTest(name=name):
                files = contents()
                files[name] = b"stale or substituted document"
                with self.assertRaisesRegex(ValueError, "source"):
                    self.validate(files)

    def test_missing_license_rejected(self):
        files = contents()
        del files["LICENSE"]
        with self.assertRaisesRegex(ValueError, "Missing"):
            self.validate(files)

    def test_wrong_identity_version_repository_commit_license_or_readme_rejected(self):
        replacements = [(b">HeroCrypt</id>", b">Other</id>"), (b">1.0.0</version>", b">0.9.0</version>"),
                        (SHA.encode(), b"b" * 40), (REPOSITORY.encode(), b"https://example.com/repo"),
                        (b">MIT</license>", b">UNLICENSED</license>"), (b">README.md</readme>", b">other.md</readme>")]
        for before, after in replacements:
            with self.subTest(before=before):
                files = contents()
                files["HeroCrypt.nuspec"] = files["HeroCrypt.nuspec"].replace(before, after)
                with self.assertRaises(ValueError):
                    self.validate(files)

    def test_rejects_wrong_archive_name(self):
        path = self.write(contents(), "Other.1.0.0.nupkg")
        with self.assertRaisesRegex(ValueError, "filename"):
            release.validate_package(path, VERSION, SHA, REPOSITORY, self.root)

    def test_rejects_short_expected_sha(self):
        with self.assertRaisesRegex(ValueError, "SHA"):
            release.validate_package(self.write(contents()), VERSION, "aaaaaaa", REPOSITORY, self.root)

    def test_rejects_extra_framework(self):
        files = contents()
        files["lib/net7.0/HeroCrypt.dll"] = b"MZ assembly-fixture"
        with self.assertRaisesRegex(ValueError, "framework"):
            self.validate(files)

    def test_rejects_empty_required_file(self):
        files = contents()
        files["lib/net8.0/HeroCrypt.dll"] = b""
        with self.assertRaisesRegex(ValueError, "empty"):
            self.validate(files)

    def test_rejects_invalid_assembly_and_portable_pdb_magic(self):
        for suffix in ("dll", "pdb"):
            files = contents(symbols=suffix == "pdb")
            files[f"lib/netstandard2.0/HeroCrypt.{suffix}"] = b"not a managed artifact"
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError, "Invalid"):
                self.validate(files, symbols=suffix == "pdb")

    def test_rejects_malformed_xml_documentation(self):
        files = contents()
        files["lib/net8.0/HeroCrypt.xml"] = b"not XML"
        with self.assertRaises(ValueError):
            self.validate(files)

    def test_rejects_duplicate_zip_entries(self):
        import warnings
        path = self.write(contents())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "a") as archive:
                archive.writestr("HeroCrypt.nuspec", contents()["HeroCrypt.nuspec"])
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            release.validate_package(path, VERSION, SHA, REPOSITORY, self.root)

    def test_rejects_traversal_or_absolute_zip_paths(self):
        for name in ("../escape", "/absolute", "lib\\net8.0\\HeroCrypt.dll"):
            files = contents()
            files[name] = b"unsafe"
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Unsafe"):
                self.validate(files)

    def test_reproducible_payload_ignores_only_zip_container_metadata(self):
        first = self.write(contents(), "first.nupkg")
        files = contents()
        files["_rels/.rels"] = b"different relationship UUID"
        files["package/services/metadata/core-properties/new.psmdcp"] = b"new timestamp"
        release.compare_packages(first, self.write(files, "second.nupkg"))

    def test_reproducibility_rejects_different_payload_and_file_set(self):
        first = self.write(contents(), "first.nupkg")
        for key in ("lib/net8.0/HeroCrypt.dll", "HeroCrypt.nuspec", "LICENSE"):
            files = contents()
            files[key] += b"tampered"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "reproducible"):
                release.compare_packages(first, self.write(files, "second.nupkg"))
        files = contents()
        files["extra.txt"] = b"extra"
        with self.assertRaisesRegex(ValueError, "reproducible"):
            release.compare_packages(first, self.write(files, "second.nupkg"))


class ReleaseNotesTests(unittest.TestCase):
    def test_prepared_notes_are_scoped_and_relative_links_use_exact_commit(self):
        changelog = """# Changelog
## [1.0.0] - 2026-10-04
See [readiness](PRODUCTION_READINESS.md), [security](SECURITY.md#scope),
[migration](docs/migration-guide.md), and [upstream](https://example.com/doc.md).
## [0.9.0] - 2026-09-01
Old notes.
"""
        result = release.release_notes_section(changelog, VERSION, "KoalaFacts/HeroCrypt", SHA)
        self.assertIn(f"https://github.com/KoalaFacts/HeroCrypt/blob/{SHA}/PRODUCTION_READINESS.md", result)
        self.assertIn(f"https://github.com/KoalaFacts/HeroCrypt/blob/{SHA}/SECURITY.md#scope", result)
        self.assertIn(f"https://github.com/KoalaFacts/HeroCrypt/blob/{SHA}/docs/migration-guide.md", result)
        self.assertIn("https://example.com/doc.md", result)
        self.assertNotIn("Old notes", result)

    def test_missing_or_empty_release_notes_fail(self):
        for changelog in ("# Changelog", "## [1.0.0] - 2026-10-04\n\n## [0.9.0] - 2026-09-01\nOld notes"):
            with self.subTest(changelog=changelog), self.assertRaisesRegex(ValueError, "release notes"):
                release.release_notes_section(changelog, VERSION, "KoalaFacts/HeroCrypt", SHA)


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]

    def workflow(self, name):
        return (self.root / ".github" / "workflows" / name).read_text()

    def test_ci_and_release_test_release_build_without_rebuilding_debug(self):
        for name in ("ci.yml", "create-release.yml"):
            workflow = self.workflow(name)
            with self.subTest(workflow=name):
                test_lines = [line for line in workflow.splitlines() if "run: dotnet test " in line]
                self.assertTrue(test_lines)
                for line in test_lines:
                    self.assertIn("--configuration Release", line)
                    self.assertIn("--no-build", line)

    def test_package_validation_runs_on_linux_and_windows_with_distinct_artifacts(self):
        workflow = self.workflow("ci.yml")
        job = workflow.split("  package-validation:", 1)[1].split("  dependency-review:", 1)[0]
        self.assertIn("name: Validate Release Package (${{ matrix.os }})", job)
        self.assertIn("runs-on: ${{ matrix.os }}", job)
        self.assertIn("os: [ubuntu-latest, windows-latest]", job)
        self.assertIn("shell: bash", job)
        self.assertIn("name: validated-release-packages-${{ matrix.os }}", job)
        self.assertIn("python scripts/release_smoke.py", job)
        import release_ci
        for os in ("ubuntu-latest", "windows-latest"):
            self.assertIn(f"Validate Release Package ({os})", release_ci.REQUIRED_JOBS)

    def test_publisher_compares_rebuilt_source_payload_before_oidc(self):
        workflow = self.workflow("publish-nuget.yml")
        self.assertIn("dotnet build src/HeroCrypt/HeroCrypt.csproj", workflow)
        self.assertIn("--locked-mode", workflow)
        self.assertIn("release_validation.py compare", workflow)
        self.assertLess(workflow.index("release_validation.py compare"), workflow.index("uses: NuGet/login@"))
        self.assertNotIn("attest-build-provenance", workflow)
        self.assertIn('test "$GITHUB_REF" = refs/heads/main', workflow)
        self.assertIn("-p:RepositoryBranch=refs/heads/main", workflow)

    def test_release_requires_exact_sha_ci_before_creating_tag(self):
        workflow = self.workflow("create-release.yml")
        self.assertIn("actions: read", workflow)
        self.assertIn("scripts/release_ci.py", workflow)
        self.assertLess(workflow.index("scripts/release_ci.py"), workflow.index('gh api "repos/$GITHUB_REPOSITORY/git/refs"'))
        self.assertIn("name: Build and Test (${{ matrix.os }}, ${{ matrix.framework }})", self.workflow("ci.yml"))

    def test_release_temp_path_is_set_after_runner_starts(self):
        workflow = self.workflow("create-release.yml")
        self.assertNotIn("RELEASE_ARTIFACTS: ${{ runner.temp }}", workflow)
        self.assertIn('echo "RELEASE_ARTIFACTS=$RUNNER_TEMP/release-artifacts" >> "$GITHUB_ENV"', workflow)

    def test_release_never_commits_workflow_mutated_sources(self):
        workflow = self.workflow("create-release.yml")
        for command in ("git add", "git commit", "git push", "sed -i"):
            self.assertNotIn(command, workflow)
        self.assertIn("git diff --exit-code", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)

    def test_release_and_ci_lock_and_audit_restore(self):
        for name in ("create-release.yml", "ci.yml"):
            workflow = self.workflow(name)
            with self.subTest(workflow=name):
                self.assertIn("--locked-mode", workflow)
                self.assertIn("-p:NuGetAuditMode=all", workflow)
                self.assertIn("-p:TreatWarningsAsErrors=true", workflow)
                self.assertIn("<auditSources>", workflow)

    def test_release_guards_existing_tag_and_verifies_artifacts_before_publication(self):
        workflow = self.workflow("create-release.yml")
        self.assertIn("git ls-remote --tags origin", workflow)
        self.assertIn('releases" --paginate', workflow)
        self.assertLess(workflow.index("release_validation.py validate"), workflow.index("gh release create"))
        self.assertIn("release_validation.py compare", workflow)
        self.assertIn("netstandard2.0 net8.0 net9.0 net10.0", workflow)

    def test_publish_uses_verified_sha_and_validates_before_oidc(self):
        workflow = self.workflow("publish-nuget.yml")
        self.assertIn("ref: ${{ needs.get-version.outputs.sha }}", workflow)
        self.assertIn("sha256sum --check --strict SHA256SUMS", workflow)
        self.assertLess(workflow.index("release_validation.py validate"), workflow.index("uses: NuGet/login@"))
        self.assertNotIn("--skip-duplicate", workflow)


class CiGateTests(unittest.TestCase):
    def setUp(self):
        import release_ci
        self.ci = release_ci
        self.repository = "KoalaFacts/HeroCrypt"
        self.workflow = {"id": 42, "name": "Build and Test", "path": ".github/workflows/ci.yml", "state": "active"}
        self.run = {"id": 123, "run_attempt": 2, "workflow_id": 42, "name": "Build and Test",
                    "path": ".github/workflows/ci.yml", "event": "push", "head_branch": "main",
                    "head_sha": SHA, "status": "completed", "conclusion": "success",
                    "head_repository": {"full_name": self.repository}}
        self.jobs = [{"id": index, "run_id": 123, "head_sha": SHA, "name": name,
                      "status": "completed", "conclusion": "success",
                      "steps": [{"name": step, "status": "completed", "conclusion": "success"} for step in steps]}
                     for index, (name, steps) in enumerate(self.ci.REQUIRED_JOBS.items(), 1)]

    def test_accepts_latest_exact_main_push_and_all_required_jobs(self):
        chosen = self.ci.select_run(self.workflow, [self.run], SHA, self.repository)
        self.assertEqual(chosen["run_attempt"], 2)
        self.ci.validate_jobs(chosen, self.jobs)
        self.assertEqual(len(self.jobs), 15)

    def test_rejects_wrong_workflow_event_branch_sha_repository_and_incomplete_runs(self):
        import copy
        for key, value in (("workflow_id", 99), ("path", ".github/workflows/other.yml"), ("name", "Other"),
                           ("event", "pull_request"), ("head_branch", "feature"), ("head_sha", "b" * 40),
                           ("head_repository", {"full_name": "Other/Repository"}), ("status", "in_progress"),
                           ("conclusion", "failure"), ("conclusion", "cancelled"), ("run_attempt", 0)):
            run = copy.deepcopy(self.run)
            run[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.ci.select_run(self.workflow, [run], SHA, self.repository)

    def test_rejects_absent_run_and_changed_workflow_identity(self):
        with self.assertRaises(ValueError):
            self.ci.select_run(self.workflow, [], SHA, self.repository)
        for key, value in (("path", "other.yml"), ("name", "Other"), ("state", "disabled_manually")):
            workflow = dict(self.workflow, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.ci.select_run(workflow, [self.run], SHA, self.repository)

    def test_newer_failure_or_pending_run_cannot_fall_back_to_old_success(self):
        for status, conclusion in (("completed", "failure"), ("in_progress", None)):
            newer = dict(self.run, id=124, status=status, conclusion=conclusion)
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.ci.select_run(self.workflow, [self.run, newer], SHA, self.repository)

    def test_every_required_job_and_step_must_succeed(self):
        import copy
        for index, original in enumerate(self.jobs):
            with self.subTest(missing=original["name"]), self.assertRaises(ValueError):
                self.ci.validate_jobs(self.run, self.jobs[:index] + self.jobs[index + 1:])
            for conclusion in ("failure", "skipped", None):
                jobs = copy.deepcopy(self.jobs)
                jobs[index]["conclusion"] = conclusion
                with self.subTest(job=original["name"], conclusion=conclusion), self.assertRaises(ValueError):
                    self.ci.validate_jobs(self.run, jobs)
            jobs = copy.deepcopy(self.jobs)
            jobs[index]["steps"][0]["conclusion"] = "skipped"
            with self.subTest(skipped_step=original["name"]), self.assertRaises(ValueError):
                self.ci.validate_jobs(self.run, jobs)

    def test_wrong_commit_run_or_duplicate_jobs_fail(self):
        for key, value in (("run_id", 321), ("head_sha", "b" * 40), ("status", "queued")):
            jobs = [dict(job) for job in self.jobs]
            jobs[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.ci.validate_jobs(self.run, jobs)
        with self.assertRaises(ValueError):
            self.ci.validate_jobs(self.run, self.jobs + [self.jobs[0]])



class SmokeProjectTests(unittest.TestCase):
    def test_consumer_has_only_exact_package_reference_and_local_source_mapping(self):
        import xml.etree.ElementTree as ET
        import release_smoke
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_smoke.write_project(root, root / "packages", VERSION)
            self.assertEqual((root / "global.json").read_bytes(), (Path(__file__).resolve().parents[1] / "global.json").read_bytes())
            project = ET.parse(root / "Smoke.csproj").getroot()
            refs = project.findall(".//PackageReference")
            self.assertEqual([(p.get("Include"), p.get("Version")) for p in refs], [("HeroCrypt", "[1.0.0]")])
            self.assertFalse(project.findall(".//ProjectReference"))
            config = ET.parse(root / "NuGet.Config").getroot()
            mapping = config.find("packageSourceMapping/packageSource[@key='release']/package")
            self.assertEqual(mapping.get("pattern"), "HeroCrypt")
            program = (root / "Program.cs").read_text()
            self.assertIn("TryDecrypt", program)
            self.assertIn("AssemblyInformationalVersionAttribute", program)


if __name__ == "__main__":
    unittest.main()
