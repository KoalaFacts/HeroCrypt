# Test Status

Test evidence applies to one source commit and execution environment. Use the
[Build and Test workflow](https://github.com/KoalaFacts/HeroCrypt/actions/workflows/ci.yml)
and its uploaded TRX/Cobertura artifacts for current results. A green workflow
includes skipped tests; skipped platform features are not verified by that run.

## Reproducing checks

The SDK is pinned in `global.json`; runtime SDKs are listed in
`Directory.Build.props`. Install those official SDK versions, then run:

```bash
dotnet restore --locked-mode
dotnet build --configuration Release --no-restore /p:TreatWarningsAsErrors=true
dotnet test --project tests/HeroCrypt.Tests/HeroCrypt.Tests.csproj --configuration Release --no-restore
dotnet format --verify-no-changes --no-restore
python3 -m unittest discover -s scripts -p 'test_release_validation.py'
```

The project uses Microsoft.Testing.Platform and xUnit v3. Do not assume VSTest
`--filter` command examples apply. To target a runtime, add `--framework net8.0`,
`net9.0` or `net10.0` to the test command.

CI executes the runtime matrix on Windows, Linux and macOS. .NET Standard 2.0 is
compiled and packed, but is not a separate executable test target. Package consumer
smoke checks on Ubuntu and Windows exercise the actual package independently of
the source project on each of the three runtimes.

## Historical pre-hardening baseline

The following is the observed baseline for commit
[`206187f`](https://github.com/KoalaFacts/HeroCrypt/commit/206187fe7ccb67b3387f65c6af9f5d7b376c145a),
from [run 37121623449](https://github.com/KoalaFacts/HeroCrypt/actions/runs/37121623449)
on 2026-10-03. That workflow built Release but executed tests in Debug. These
numbers do not certify later changes or the new Release test configuration.

| OS | Runtime | Passed | Failed | Skipped |
|----|---------|--------|--------|---------|
| Linux | .NET 8 | 4026 | 0 | 1 |
| Linux | .NET 9 | 4035 | 0 | 1 |
| Linux | .NET 10 | 4087 | 0 | 10 |
| Windows | .NET 8 | 4026 | 0 | 1 |
| Windows | .NET 9 | 4035 | 0 | 1 |
| Windows | .NET 10 | 4096 | 0 | 1 |
| macOS | .NET 8 | 3976 | 0 | 51 |
| macOS | .NET 9 | 3976 | 0 | 60 |
| macOS | .NET 10 | 4028 | 0 | 69 |

SDKs observed in that baseline were 8.0.425, 9.0.318 and 10.0.401. Platform skips
include runtime/provider-dependent cryptography; inspect individual TRX results
before relying on a particular feature. New regressions can reveal defects even
when all existing tests passed.

## Security and interoperability checks

The suite includes standards vectors, independently constructed signature/envelope
checks, tamper rejection, key-policy boundaries, malformed packet handling and
memory/disposal checks. The release pipeline also validates package metadata,
source SHA, framework assemblies, documentation, license/notices and deterministic
payload comparison, then runs package smoke checks before publication.

Coverage reports measure executed lines, not security assurance. Self-round trips
alone do not establish interoperability. See the [supported production profile](PRODUCTION_READINESS.md)
for the exact external evidence and remaining protocol limits.

No completed independent professional security audit or exhaustive timing/side-channel
analysis is represented by these tests. Applications must test their own trust,
key lifecycle, resource limits, replay handling and complete wire protocol.
