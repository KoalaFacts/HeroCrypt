# How to Run AES-CCM Tests

## Quick Start

### Option 1: Use Test Scripts (Recommended)

**Linux/macOS:**
```bash
chmod +x test-aes-ccm.sh
./test-aes-ccm.sh
```

**Windows (PowerShell):**
```powershell
.\test-aes-ccm.ps1
```

### Option 2: Manual Commands

**Basic test run:**
```bash
dotnet test --filter "FullyQualifiedName~AesCcmTests"
```

**Detailed output:**
```bash
dotnet test --filter "FullyQualifiedName~AesCcmTests" --logger "console;verbosity=detailed"
```

---

## Prerequisites

### Install .NET SDK

If you don't have .NET SDK installed:

**Linux (Ubuntu/Debian):**
```bash
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --channel 8.0
```

**macOS:**
```bash
brew install dotnet-sdk
```

**Windows:**
Download from https://dotnet.microsoft.com/download

**Verify installation:**
```bash
dotnet --version
```

---

## Test Categories

### 1. All AES-CCM Tests (Complete Suite)

```bash
dotnet test \
  --filter "FullyQualifiedName~AesCcmTests" \
  --logger "console;verbosity=normal"
```

**Expected:** 18+ tests pass

**Tests include:**
- RFC 3610 compliance (3 vectors)
- Round-trip encryption/decryption
- Authentication failures
- Parameter validation
- Edge cases (empty data, large data)
- Variable tag sizes

---

### 2. RFC 3610 Compliance Tests (Critical)

```bash
dotnet test \
  --filter "Category=Compliance&FullyQualifiedName~AesCcmTests" \
  --logger "console;verbosity=detailed"
```

**Expected Output:**
```
✅ Passed: Rfc3610_TestVector1_Success
✅ Passed: Rfc3610_TestVector1_Decrypt_Success
✅ Passed: Rfc3610_TestVector2_Success
✅ Passed: Rfc3610_TestVector3_Success ← Verifies AAD bug fix!
```

**What this validates:**
- RFC 3610 Packet Vector #1 (8-byte tag, 13-byte nonce)
- RFC 3610 Packet Vector #2 (different nonce)
- RFC 3610 Packet Vector #3 (12-byte AAD - tests bug fix!)

**IMPORTANT:** Test Vector #3 would **FAIL** before the bug fix!

---

### 3. Authentication Security Tests

```bash
dotnet test \
  --filter "FullyQualifiedName~AesCcmTests.AesCcm_*Authentication*"
```

**Expected:** 4 tests pass

**Validates:**
- ✅ Tampered ciphertext is detected and rejected
- ✅ Wrong key fails authentication
- ✅ Wrong nonce fails authentication
- ✅ Wrong associated data fails authentication

---

### 4. Fast Tests Only (Development)

```bash
dotnet test \
  --filter "Category=Fast&FullyQualifiedName~AesCcmTests"
```

**Expected:** ~15 tests in <1 second

---

### 5. With Code Coverage

```bash
dotnet test \
  --filter "FullyQualifiedName~AesCcmTests" \
  --collect:"XPlat Code Coverage" \
  --results-directory ./TestResults
```

**Generate HTML Report:**
```bash
# Install report generator (one time)
dotnet tool install -g dotnet-reportgenerator-globaltool

# Generate report
reportgenerator \
  -reports:"./TestResults/**/coverage.cobertura.xml" \
  -targetdir:"./TestResults/CoverageReport" \
  -reporttypes:Html

# Open report
open ./TestResults/CoverageReport/index.html  # macOS
xdg-open ./TestResults/CoverageReport/index.html  # Linux
start ./TestResults/CoverageReport/index.html  # Windows
```

**Expected Coverage:** >95% for AesCcmCore.cs

---

## Expected Test Results

### ✅ Success Criteria

All of these must pass:

1. **Build succeeds** with no errors
2. **All 18+ tests pass** with no failures
3. **RFC 3610 test vectors pass** (4 tests)
4. **Authentication tests pass** (4 tests)
5. **Code coverage >95%** for AesCcmCore.cs

### Example Successful Output

```
Test run for /path/to/HeroCrypt.Tests.dll (.NET 8.0)
Microsoft (R) Test Execution Command Line Tool Version 17.x

Starting test execution, please wait...
A total of 1 test files matched the specified pattern.

Passed!  - Failed:     0, Passed:    18, Skipped:     0, Total:    18
```

---

## Troubleshooting

### Issue: Build Fails

**Solution 1:** Restore dependencies
```bash
dotnet restore
dotnet build
```

**Solution 2:** Clean and rebuild
```bash
dotnet clean
dotnet restore
dotnet build --configuration Release
```

### Issue: "dotnet: command not found"

**Solution:** Install .NET SDK (see Prerequisites above)

### Issue: RFC Test Vector #3 Fails

**Symptom:**
```
Failed: Rfc3610_TestVector3_Success
Expected: 51B1E5F44A197D...
Actual:   <different value>
```

**Cause:** The CBC-MAC AAD processing bug is not fixed

**Solution:** Verify you have the latest code with the bug fix:
```bash
git log --oneline -1
# Should show: "fix(aes-ccm): critical bug in CBC-MAC computation"
```

### Issue: Coverage Report Not Generated

**Solution:** Install ReportGenerator
```bash
dotnet tool install -g dotnet-reportgenerator-globaltool
```

### Issue: Tests Pass But Coverage is Low

**Action:** Review the coverage report to identify untested code paths

Common untested paths:
- Error handling branches
- Edge cases
- Platform-specific code paths

---

## Validation Checklist

After running tests, verify:

- [ ] All 18+ AES-CCM tests pass
- [ ] RFC 3610 Test Vector #1 passes
- [ ] RFC 3610 Test Vector #2 passes
- [ ] RFC 3610 Test Vector #3 passes ← **Critical: validates bug fix**
- [ ] Authentication tests pass (4 tests)
- [ ] Code coverage >95%
- [ ] Build succeeds without warnings
- [ ] No memory leaks (if using profiler)

---

## Performance Testing (Optional)

### Basic Performance Test

```bash
cd /path/to/HeroCrypt
dotnet run --project examples/HeroCrypt.Examples --configuration Release
```

### Benchmark (if you create benchmark project)

```bash
# Create benchmark project
dotnet new console -n HeroCrypt.Benchmarks
cd HeroCrypt.Benchmarks
dotnet add package BenchmarkDotNet
dotnet add reference ../src/HeroCrypt/HeroCrypt.csproj

# Run benchmarks
dotnet run -c Release
```

---

## What to Look For

### ✅ Good Signs

- All tests pass
- Coverage >95%
- Fast execution (<2 seconds for all tests)
- No warnings or errors
- RFC test vectors match exactly

### ⚠️ Warning Signs

- Any test failures
- Coverage <90%
- Slow test execution (>5 seconds)
- Build warnings
- RFC test vectors don't match

### 🔴 Critical Issues

- RFC 3610 Test Vector #3 fails → Bug not fixed
- Authentication tests fail → Security issue
- Memory corruption → Memory safety issue
- Constant failures → Implementation bug

---

## Next Steps After Tests Pass

1. **Review Coverage Report**
   - Identify any untested code paths
   - Add tests for edge cases

2. **Performance Benchmarks** (Optional)
   - Compare with AES-GCM
   - Measure throughput

3. **Create Pull Request**
   - Include test results
   - Link to testing documentation

4. **Continue Phase 3C**
   - AES-SIV implementation
   - Rabbit stream cipher
   - Or other algorithms

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `./test-aes-ccm.sh` | Run all tests (Linux/macOS) |
| `.\test-aes-ccm.ps1` | Run all tests (Windows) |
| `dotnet test --filter "FullyQualifiedName~AesCcmTests"` | Manual test run |
| `dotnet test --filter "Category=Compliance"` | RFC tests only |
| `dotnet test --collect:"XPlat Code Coverage"` | With coverage |

---

**Status:** Ready to test
**Confidence:** High (after bug fix)
**Blocker:** None - all prerequisites documented
