# CI and Release Workflows

HeroCrypt uses the existing GitHub Actions release and NuGet trusted-publishing
pipeline. The workflow files are authoritative. Releases must use a new immutable
version and source commit; never overwrite or move an existing release tag.

## Build and Test

`ci.yml` builds and tests Release on Windows, Linux and macOS for .NET 8, 9 and 10.
Code quality builds all targets with warnings as errors and checks formatting.
The .NET Standard 2.0 library is compiled and packed; it is not an executable test
target. TRX results and coverage artifacts record platform skips explicitly.

The package-validation matrix on Ubuntu and Windows builds candidate packages from the exact checked-out
SHA, validates metadata and bundled documents, compares a repeated build's payload,
and runs an isolated consumer against that package. These jobs do not publish.

SDKs are pinned in `global.json` and `Directory.Build.props`; restores use committed
lock files. Update SDKs and lock files together through a reviewed change. A failed
restore or audit is a failed gate, not a reason to disable verification.

## Security and documentation

`scan-security.yml` runs dependency audits and Microsoft Security DevOps, alongside
GitHub-managed code scanning. `documentation-check.yml` checks public API XML
documentation. These automated checks do not constitute an independent security
audit. Review the exact commit's findings before release.

## Create Release

`create-release.yml` accepts one `version` input and runs only from `main`. Prepare
and merge the matching dated CHANGELOG section and migration notes first. Confirm
all required checks are green on the exact current main SHA.

```bash
gh workflow run create-release.yml --ref main -f version=1.0.5
```

The GitHub UI equivalent is Actions → Create Release → Run workflow, branch `main`,
version `1.0.5`. Verify the current SHA immediately before dispatch. Do not run an
old workflow attempt against a newer source tree.

The workflow:

1. Checks out the triggering immutable SHA and refuses an existing version tag
   or release
2. Requires committed release notes, a clean source tree and the latest successful
   exact-SHA main-push CI attempt with all 15 jobs and their critical steps
3. Restores locked dependencies with fail-closed vulnerability auditing
4. Builds the exact release version, runs the Release tests and packs that build
5. Validates package ID/version/source SHA, all four target-framework DLL/XML
   payloads, symbol PDBs, license, README, notices and security/readiness documents
6. Rebuilds and compares payload bytes, excluding ZIP container metadata
7. Runs packaged public API smoke tests on .NET 8/9/10 in a fresh NuGet cache
8. Creates SPDX 2.2 and 3.0 SBOMs for all four framework output directories using a
   shared multi-target project dependency inventory, plus toolchain information
9. Records SHA-256 checksums, reserves the new tag atomically and creates the release
10. Downloads the published assets again and verifies their checksums and source

No source files are changed or committed by the workflow. The test matrix before
dispatch and the release-local checks serve different purposes; both are required.

## Publish to NuGet

`publish-nuget.yml` runs after a successful Create Release workflow on `main`.
It identifies that run's version, requires a full immutable release target SHA,
and compares it to the completed workflow's source SHA. It verifies the tag, exact-source CI gate, downloaded package checksums, metadata
and source documents. It then independently rebuilds and packs the verified source
with the pinned SDKs and locked dependencies, comparing both package payloads
before requesting the existing NuGet trusted-publisher OIDC credential. It publishes the validated package
and paired symbols without silently accepting a preexisting version.

No signed build-attestation claim is made by this pipeline; package/source evidence
comes from exact-SHA verification and independent payload rebuilding.

The existing `production` environment may require approval configured by repository
maintainers. Do not remove environment protections or create replacement credentials
to bypass a blocked run.

A manual dispatch is available only for a verified release not yet submitted:

```bash
gh workflow run publish-nuget.yml --ref main -f version=1.0.5
```

Afterward, verify the NuGet package version and repository SHA, and compare package
payloads to the GitHub release. NuGet may add its repository signature; that changes
the ZIP hash without changing the library payload. Do not report publication until
the expected package is available and verified.

## Failure and recovery

- The latest CI attempt must contain every required job. A partial rerun does not
  establish that complete evidence; use **Re-run all jobs** and wait for success
- A test, audit, reproducibility or package-validation failure blocks release.
  Diagnose it and prepare a reviewed correction; do not weaken the gate
- An existing tag or release is refused. If a run reserved a tag but failed before
  completing the GitHub release, stop for verified maintainer recovery. Do not
  automatically delete or repoint the tag, replace assets or overwrite a release
- If NuGet accepted the package before a later step failed, inspect the published
  bytes before retrying. A symbols-only failure may require an explicitly scoped
  recovery; resubmitting the main package is not a successful new publication
- Authentication or environment-approval failures require the existing authorized
  maintainer flow. Do not generate a new API key as an automatic fallback
- A corrected published package needs a new version. Rolling back to a vulnerable
  package can restore the vulnerability; disable the affected feature if necessary
  and follow the security migration guidance

## Local validation helpers

```bash
python3 -m unittest discover -s scripts -p 'test_release_validation.py' -v
python3 scripts/release_validation.py --help
python3 scripts/release_smoke.py --help
```

The Python validators use the standard library. The smoke test additionally needs
the pinned .NET SDK and supported runtimes. See [test status](../../TEST_STATUS.md)
and [production scope](../../PRODUCTION_READINESS.md) for evidence and limitations.
