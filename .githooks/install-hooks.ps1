# PowerShell script to install git hooks
# Run this once after cloning the repository

$ErrorActionPreference = "Stop"

Write-Host "Installing git hooks..." -ForegroundColor Cyan

# Configure git to use the .githooks directory
git config core.hooksPath .githooks

Write-Host "Git hooks installed successfully!" -ForegroundColor Green
Write-Host "The pre-commit hook will now run 'dotnet format' on staged C# files." -ForegroundColor Gray
