# AES-CCM Test Runner Script (PowerShell)
# Comprehensive testing suite for HeroCrypt AES-CCM implementation

$ErrorActionPreference = "Stop"

# Colors
function Write-Success { Write-Host $args -ForegroundColor Green }
function Write-Info { Write-Host $args -ForegroundColor Cyan }
function Write-Warning { Write-Host $args -ForegroundColor Yellow }
function Write-Error { Write-Host $args -ForegroundColor Red }
function Write-Step { param($num, $total, $msg) Write-Host "[$num/$total] $msg" -ForegroundColor Yellow }

Write-Info "================================================"
Write-Info "  HeroCrypt AES-CCM Test Suite"
Write-Info "================================================"
Write-Host ""

# Check for .NET SDK
try {
    $dotnetVersion = dotnet --version
    Write-Success "✓ .NET SDK found: $dotnetVersion"
} catch {
    Write-Error "ERROR: .NET SDK not found!"
    Write-Host "Please install .NET SDK from: https://dotnet.microsoft.com/download"
    exit 1
}
Write-Host ""

# Navigate to script directory
Set-Location $PSScriptRoot

# Restore dependencies
Write-Step 1 7 "Restoring dependencies..."
dotnet restore --verbosity quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "✗ Restore failed"
    exit 1
}
Write-Success "✓ Dependencies restored"
Write-Host ""

# Build the project
Write-Step 2 7 "Building project..."
dotnet build --configuration Release --no-restore --verbosity quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "✗ Build failed"
    exit 1
}
Write-Success "✓ Build successful"
Write-Host ""

# Run all AES-CCM tests
Write-Step 3 7 "Running all AES-CCM tests..."
dotnet test `
    --configuration Release `
    --no-build `
    --filter "FullyQualifiedName~AesCcmTests" `
    --logger "console;verbosity=normal" `
    --collect:"XPlat Code Coverage" `
    --results-directory ./TestResults

$testExitCode = $LASTEXITCODE
Write-Host ""

if ($testExitCode -eq 0) {
    Write-Success "✓ All AES-CCM tests passed!"
} else {
    Write-Error "✗ Some tests failed (exit code: $testExitCode)"
    Write-Host ""
    Write-Host "Run with --verbosity=detailed for more information:"
    Write-Host '  dotnet test --filter "FullyQualifiedName~AesCcmTests" --logger "console;verbosity=detailed"'
    exit 1
}
Write-Host ""

# Run RFC 3610 compliance tests
Write-Step 4 7 "Verifying RFC 3610 compliance..."
$rfcResult = dotnet test `
    --configuration Release `
    --no-build `
    --filter "Category=Compliance&FullyQualifiedName~AesCcmTests" `
    --logger "console;verbosity=minimal" 2>&1

if ($rfcResult -match "Passed!") {
    Write-Success "✓ RFC 3610 test vectors passed"
    $rfcResult | Select-String -Pattern "(Rfc3610|Passed|Failed)"
} else {
    Write-Error "✗ RFC 3610 test vectors failed"
    Write-Host $rfcResult
    exit 1
}
Write-Host ""

# Run authentication tests
Write-Step 5 7 "Verifying authentication security..."
$authResult = dotnet test `
    --configuration Release `
    --no-build `
    --filter "FullyQualifiedName~AesCcmTests.AesCcm_*Authentication*" `
    --logger "console;verbosity=minimal" 2>&1

if ($authResult -match "Passed!") {
    Write-Success "✓ Authentication tests passed"
} else {
    Write-Error "✗ Authentication tests failed"
    Write-Host $authResult
    exit 1
}
Write-Host ""

# Generate coverage report
Write-Step 6 7 "Generating code coverage report..."
$reportGeneratorInstalled = Get-Command reportgenerator -ErrorAction SilentlyContinue
if ($reportGeneratorInstalled) {
    reportgenerator `
        -reports:"./TestResults/**/coverage.cobertura.xml" `
        -targetdir:"./TestResults/CoverageReport" `
        -reporttypes:Html

    Write-Success "✓ Coverage report generated"
    Write-Host "   View at: .\TestResults\CoverageReport\index.html"
} else {
    Write-Warning "⚠  ReportGenerator not installed (skipping coverage report)"
    Write-Host "   Install with: dotnet tool install -g dotnet-reportgenerator-globaltool"
}
Write-Host ""

# Summary
Write-Step 7 7 "Test Summary"
Write-Info "================================================"

# Count tests
$totalTests = ($rfcResult | Select-String -Pattern 'Passed: (\d+)').Matches.Groups[1].Value
if (-not $totalTests) { $totalTests = "0" }

Write-Host "Total Tests:        " -NoNewline; Write-Success $totalTests
Write-Host "RFC Compliance:     " -NoNewline; Write-Success "✓ PASS"
Write-Host "Authentication:     " -NoNewline; Write-Success "✓ PASS"
Write-Host "Build Status:       " -NoNewline; Write-Success "✓ SUCCESS"

# Check coverage
$coverageFile = Get-ChildItem -Path ./TestResults -Filter "coverage.cobertura.xml" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($coverageFile) {
    $coverageXml = [xml](Get-Content $coverageFile.FullName)
    $lineRate = [double]$coverageXml.'coverage'.'line-rate'
    $coveragePct = [math]::Round($lineRate * 100, 1)

    Write-Host "Code Coverage:      " -NoNewline
    if ($coveragePct -ge 95) {
        Write-Success "${coveragePct}%"
    } elseif ($coveragePct -ge 80) {
        Write-Warning "${coveragePct}% (target: 95%)"
    } else {
        Write-Error "${coveragePct}% (target: 95%)"
    }
}

Write-Info "================================================"
Write-Host ""
Write-Success "✓ AES-CCM implementation validated successfully!"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Review coverage report (if generated)"
Write-Host "  2. Run performance benchmarks (optional)"
Write-Host "  3. Create pull request"
Write-Host "  4. Continue with Phase 3C (AES-SIV, Rabbit, etc.)"
Write-Host ""

exit 0
