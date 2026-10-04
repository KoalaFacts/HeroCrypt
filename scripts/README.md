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

MIT License - Same as HeroCrypt project


## Release validation

- `release_ci.py`: requires a complete successful latest main-push CI attempt for
  the exact source SHA before creating or publishing a release
- `release_validation.py`: verifies package identity, source SHA, framework payloads,
  symbols and source-matching documents; compares repeated-build payloads
- `release_smoke.py`: creates a temporary consumer with an exact package reference
  and isolated NuGet cache, then checks the actual package on .NET 8/9/10
- `test_release_validation.py`: Python standard-library regressions for validators,
  smoke-project configuration and workflow contracts

Run `python3 -m unittest discover -s scripts -p 'test_release_validation.py' -v`.
For publication and partial-failure recovery, follow the
[workflow guide](../.github/workflows/README.md).
