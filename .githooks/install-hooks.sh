#!/bin/bash
# Bash script to install git hooks
# Run this once after cloning the repository

set -e

echo "Installing git hooks..."

# Configure git to use the .githooks directory
git config core.hooksPath .githooks

# Make hooks executable (for Unix systems)
chmod +x .githooks/pre-commit 2>/dev/null || true

echo "Git hooks installed successfully!"
echo "The pre-commit hook will now run 'dotnet format' on staged C# files."
