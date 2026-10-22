# HeroCrypt Build Scripts

This directory contains code-quality and release-validation helpers. Python package validation and XML-source checks do not require .NET; the package consumer smoke test requires the pinned .NET SDK and runtimes.

## check-xml-docs.sh

Systematic XML documentation checker that verifies all public APIs have documentation comments.

### Features

- ✅ **No .NET SDK Required** - Uses regex pattern matching with AWK
- ✅ **Fast** - Scans entire codebase in seconds
- ✅ **Accurate** - Handles edge cases like auto-properties, method calls, variables named "publicKey"
- ✅ **CI/CD Ready** - Returns proper exit codes (0 = success, 1 = failure)
- ✅ **Color-Coded Output** - Easy to read results
- ✅ **Detailed Reporting** - Shows exact file and line numbers

### Usage

```bash
# Run from project root
./scripts/check-xml-docs.sh

# Run from scripts directory
cd scripts && ./check-xml-docs.sh

# Run with custom directory
./scripts/check-xml-docs.sh /path/to/project
```

### Output

**Success (all documented):**
```
========================================
XML Documentation Checker
========================================

Project root: /home/user/HeroCrypt
Source directory: /home/user/HeroCrypt/src

----------------------------------------
Results:
----------------------------------------

✓ All public members are documented!

========================================
SUCCESS: Zero documentation warnings
========================================
```

**Failure (missing documentation):**
```
========================================
XML Documentation Checker
========================================

Project root: /home/user/HeroCrypt
Source directory: /home/user/HeroCrypt/src

----------------------------------------
Results:
----------------------------------------

./src/HeroCrypt/Services/MyService.cs:
  Line 15: public class MyService
  Line 20:     public void DoSomething()

========================================
FAILED: Missing XML Documentation
========================================
Files with issues: 1
Total undocumented members: 2

Please add XML documentation (///) to all public members.
Example:
  /// <summary>
  /// Description of the member
  /// </summary>
  public void MyMethod() { }
```

### Integration with CI/CD

The script returns appropriate exit codes for automated builds:
- **Exit 0**: All public members documented ✅
- **Exit 1**: Missing documentation found ❌

#### GitHub Actions Example

```yaml
name: Documentation Check

on: [push, pull_request]

jobs:
  check-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check XML Documentation
        run: |
          chmod +x ./scripts/check-xml-docs.sh
          ./scripts/check-xml-docs.sh
```

#### GitLab CI Example

```yaml
check-documentation:
  stage: test
  script:
    - chmod +x ./scripts/check-xml-docs.sh
    - ./scripts/check-xml-docs.sh
```

#### Pre-commit Hook Example

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Checking XML documentation..."
./scripts/check-xml-docs.sh

if [ $? -ne 0 ]; then
    echo "❌ Commit rejected: Add XML documentation to public members"
    exit 1
fi

echo "✅ Documentation check passed"
```

### What It Checks

The script identifies undocumented public members including:

- **Classes**: `public class MyClass`
- **Interfaces**: `public interface IMyInterface`
- **Enums**: `public enum MyEnum`
- **Structs**: `public struct MyStruct`
- **Records**: `public record MyRecord`
- **Methods**: `public void MyMethod()`
- **Properties**: `public string MyProperty { get; set; }`
- **Fields**: `public readonly int MyField`
- **Events**: `public event EventHandler MyEvent`
- **Delegates**: `public delegate void MyDelegate()`
- **Operators**: `public static MyClass operator +(MyClass a, MyClass b)`
- **Constructors**: `public MyClass()`

### What It Ignores

The script intelligently skips false positives:

- ❌ Method calls containing "public": `DoSomething(publicKey)`
- ❌ Variable assignments: `var key = publicKey;`
- ❌ Method parameters: `void Method(byte[] publicKey)`
- ❌ Variables named "publicSomething": `publicKey.CopyTo(buffer)`
- ❌ Auto-property accessors: `public get; set;`
- ❌ Comments and preprocessor directives
- ❌ Using statements and namespaces

### How It Works

The script uses AWK to:

1. **Parse each C# file** line by line
2. **Track previous 5 lines** to detect XML comments (`///`)
3. **Pattern match** for public declarations
4. **Filter false positives** using intelligent heuristics
5. **Report** any public member without `///` above it

### Requirements

- **Bash 4.0+** (for regex support)
- **AWK** (usually pre-installed on Unix systems)
- **Find** command (standard Unix tool)

Works on:
- ✅ Linux
- ✅ macOS
- ✅ Windows (WSL, Git Bash, Cygwin)
- ✅ CI/CD platforms (GitHub Actions, GitLab CI, Azure Pipelines, Jenkins)

### Troubleshooting

**"No such file or directory: src"**
- Ensure you're running from the project root
- Or provide the correct path: `./check-xml-docs.sh /path/to/project`

**False positives**
- The script uses heuristics to avoid false positives
- If you find one, it's likely an edge case
- File an issue with the specific code pattern

**Script not executable**
- Run: `chmod +x ./scripts/check-xml-docs.sh`

### Comparison with dotnet build

| Feature | check-xml-docs.sh | dotnet build |
|---------|-------------------|--------------|
| **Requires .NET SDK** | ❌ No | ✅ Yes |
| **Speed** | ⚡ Fast (< 1 second) | 🐌 Slow (full build) |
| **Checks XML docs** | ✅ Yes | ✅ Yes (with flags) |
| **Compiles code** | ❌ No | ✅ Yes |
| **Type checking** | ❌ No | ✅ Yes |
| **CI/CD friendly** | ✅ Yes | ⚠️ Requires SDK |
| **Offline mode** | ✅ Yes | ⚠️ Needs packages |

**Recommendation**: Use both!
- Use `check-xml-docs.sh` for quick feedback during development
- Use `dotnet build` for full validation before release

### Contributing

To improve the script:
1. Test your changes on various codebases
2. Ensure it handles edge cases correctly
3. Maintain backward compatibility
4. Update this README with changes

### License

Apache License 2.0 - Same as HeroCrypt project


## Release validation

- `release_ci.py`: requires a complete successful latest main-push CI attempt for
  the exact source SHA before creating or publishing a release
- `release_validation.py`: verifies package identity, source SHA, framework payloads,
  symbols and source-matching documents; compares repeated-build payloads
- `release_smoke.py`: creates a temporary consumer with an exact package reference
  and isolated NuGet cache, then checks the actual package on .NET 8/9/10.
  Its synthetic OpenPGP GCM fixture checks authentication/input rejection without
  plaintext, recovery on the same decryptor after each failure, repeated disposal,
  and rejection of calls after disposal. These assertions also run in the existing
  explicit RC JIT/AOT modes; they do not establish memory zeroization.
- `test_release_validation.py`: Python standard-library regressions for validators,
  smoke-project configuration and workflow contracts

Run `python3 -m unittest discover -s scripts -p 'test_release_validation.py' -v`.
An explicit Native AOT baseline can use the same package checks and public API
vectors (this does not establish .NET 11 compatibility):

```bash
python3 scripts/release_smoke.py /path/to/packages --version 1.1.0 \
  --commit <full-source-sha> --sha256 <nupkg-sha256> \
  --aot --framework net10.0 --rid linux-x64
```

AOT requires one explicit framework, a host-compatible RID, the matching SDK and
native compiler prerequisites. It runs `dotnet publish -p:PublishAot=true`, then
executes the native output; failures are fatal. The default remains JIT on
.NET 8/9/10. `--framework` can also select explicit JIT targets. The repository's
pinned SDK still applies unless an exact toolchain is explicitly supplied.

To use an already installed toolchain, provide all three identity inputs, one
framework, and the package hash. For example, a stable verification uses:

```bash
python3 scripts/release_smoke.py /path/to/packages --version 1.1.0 \
  --commit <full-source-sha> --sha256 <nupkg-sha256> --framework net10.0 \
  --dotnet /absolute/path/to/dotnet --sdk-version 10.0.402 --runtime-version 10.0.13
```

Add `--aot --rid linux-x64` to publish and execute a native consumer separately.
The temporary consumer pins the exact SDK with SDK roll-forward disabled and
allows prereleases only for an explicitly supplied prerelease SDK version. It
also pins the runtime without runtime roll-forward, verifies `dotnet --version`
using the specified executable, and checks the executing consumer's exact
`RuntimeInformation.FrameworkDescription` (including prerelease suffix). SDK,
runtime, package hash or assembly source mismatches fail the check. The repository
SDK and library TFMs remain unchanged.

An RC run requires an actually available, authorized official SDK/runtime and
native prerequisites for AOT. These options neither install a toolchain nor prove
its official provenance. RC-shaped versions in regression fixtures test only
configuration generation; stable runs do not establish .NET 11 compatibility,
and RC results do not establish GA qualification.

For publication and partial-failure recovery, follow the
[workflow guide](../.github/workflows/README.md).


The ordinary Build and Test workflow also has a Linux x64 RC2 consumer job. It
uses this same run's validated, stable-SDK-built package, then official
`actions/setup-dotnet` with SDK `11.0.100-rc.2.26504.105` and runtime
`11.0.0-rc.2.26504.105`. An unavailable or mismatched version fails; no fallback
version is accepted. `--verify-execution` additionally checks JIT/AOT dynamic-code
state, Linux x64 native ELF identity, and expected source/runtime/mode rejection
controls. Default consumer invocations remain unchanged.

The retained CI evidence identifies checkout/PR head/base/tree, package version,
source SHA/hash, SDK/runtime and OS/RID, with separate JIT and AOT logs. This is
only a Linux x64 consumer compatibility check, not full .NET 11 library test,
all-OS, WASM or GA qualification. It creates no NuGet publication, tag or release.

A separate Windows x64 RC2 managed/JIT job consumes this same run's validated
Windows-built package with the same pinned official SDK/runtime. It checks the
selected host RID is `win-x64`, reuses the package hash/source identity and
source/runtime/execution-mode negative controls, and retains Windows toolchain,
identity and JIT logs. Both RC2 jobs and their critical steps are required by the
release CI completeness gate. Windows NativeAOT, WASM and GA qualification are
not covered; stable library TFMs and default consumer invocations are unchanged.

The Linux RC2 full-suite job builds the complete net10 test assembly with the
stable SDK and committed locks, then executes all tests on the exact RC2 runtime
using `rc_full_tests.py`. It verifies the actual test process runtime, X64
architecture and net10 compilation target before running without a filter.
TRX counters must describe nonempty successful execution; existing skips remain
visible. Evidence records source/tree, assembly/library hashes, SDK/runtime and
OS/RID. This validates full-suite runtime compatibility, not net11 target
compilation: the test locks still cover net8/net9/net10. It does not publish or
change the library TFMs. The release CI completeness gate requires this job.

### Exact SDK compilation without changing released targets

`rc_compile_tests.py` archives the exact clean checkout into a disposable directory,
changes only that copy's SDK selector, and verifies the exact SDK and Roslyn identity.
It restores the original locks with audit enabled and locked mode, then builds all
existing library and test TFMs with that SDK. It executes the newly compiled full
net10 test assembly on the requested exact runtime without a filter. Lock hashes,
compiler and output hashes, source/tree, commands, logs and TRX counts are retained.
The normal Linux RC2 compiler job uses SDK `11.0.100-rc.2.26504.105` and runtime
`11.0.0-rc.2.26504.105`. A lock incompatibility fails closed; this does not update
release locks, add net11 targets, publish packages, or qualify GA/all platforms.
