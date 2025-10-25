# HeroCrypt CI/CD Workflows

This directory contains the GitHub Actions workflows for building, testing, releasing, and publishing HeroCrypt.

## 📋 Workflow Overview

The CI/CD pipeline consists of three main workflows:

```
┌─────────────────────────────────────────────────────────────┐
│                    1. Build and Test                         │
│  Trigger: Every commit/push                                  │
│  Output: Versioned build artifacts                           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    2. Create Release                         │
│  Trigger: Manual (select build artifacts)                    │
│  Output: GitHub Release + Git Tag                            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   3. Publish to NuGet                        │
│  Trigger: Automatic (on release published)                   │
│  Output: Package on NuGet.org                                │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔨 1. Build and Test Workflow

**File:** `build-and-test.yml`

### Purpose
Builds and tests the codebase on every commit across multiple .NET frameworks and operating systems.

### Triggers
- Push to any branch
- Pull requests to any branch
- Manual workflow dispatch

### Build Number Format
```
{branch-name}-{date}.{run-number}.{commit-hash}

Examples:
  main-20241025.123.abc1234
  develop-20241025.45.def5678
  feature-auth-20241025.12.ghi9012
```

### Build Matrix
| Framework | Ubuntu | Windows | macOS | Tests |
|-----------|--------|---------|-------|-------|
| net9.0 | ✅ | ✅ | ✅ | Full |
| net8.0 | ✅ | ✅ | ✅ | Full |
| net7.0 | ✅ | ✅ | ✅ | Compile only |
| net6.0 | ✅ | ✅ | ✅ | Compile only |
| netstandard2.0 | ✅ | ✅ | ✅ | Compile only |

**Total:** 15 build configurations

### Artifacts Produced
Each successful build creates an artifact package containing:
- `*.nupkg` - NuGet package (multi-framework)
- `*.snupkg` - Symbol package for debugging
- `build-manifest.json` - Build metadata
- `sbom.spdx.json` - SBOM (Software Bill of Materials) - optional

**Artifact Name:** `herocrypt-{build-number}`

**Retention:** 90 days

**Note:** SBOM generation is optional and uses Anchore SBOM Action. If SBOM generation fails, the build will continue successfully.

### Validation Steps
Every build includes:
- ✅ Multi-framework compilation
- ✅ Unit tests (net8.0, net9.0)
- ✅ **RFC Compliance Tests** (Argon2, Blake2b, ChaCha20-Poly1305, etc.)
- ✅ **Security Validation Tests** (constant-time ops, secure memory, etc.)
- ✅ Code coverage collection

### Outputs
- Test results (`.trx` files)
- Code coverage reports (Cobertura format)
- Packaged artifacts ready for release (only if all tests pass)

---

## 🚀 2. Create Release Workflow

**File:** `create-release.yml`

### Purpose
Creates a GitHub release from previously built artifacts.

### Trigger
Manual workflow dispatch only

### Required Inputs
| Input | Description | Example |
|-------|-------------|---------|
| `version` | Semantic version number | `1.0.0` or `1.0.0-beta.1` |
| `build-number` | Build artifacts to use | `main-20241025.123.abc1234` |
| `prerelease` | Mark as pre-release | `true` / `false` |
| `release-notes` | Additional notes (optional) | Feature description |

### Process
1. ✅ Validates version format
2. ✅ Checks tag doesn't already exist
3. ✅ Downloads specified build artifacts
4. ✅ Verifies artifact integrity
5. ✅ Generates release notes (from input + build manifest)
6. ✅ Creates GitHub Release with git tag (`v{version}`)
7. ✅ Attaches artifacts (.nupkg, .snupkg, build-manifest.json)

**Simple and Clean:** No code changes, no test runs, no version updates. Just takes your pre-validated build artifacts and creates a release.

### Environment
- **Name:** `production`
- **Protection:** Recommended to require manual approval

### Example Usage

#### Via GitHub UI:
1. Go to **Actions** → **Create Release**
2. Click **Run workflow**
3. Fill in:
   - Version: `1.0.0`
   - Build number: `main-20241025.123.abc1234`
   - Pre-release: `false`
   - Release notes: Optional description
4. Click **Run workflow**

#### Via GitHub CLI:
```bash
gh workflow run create-release.yml \
  -f version=1.0.0 \
  -f build-number=main-20241025.123.abc1234 \
  -f prerelease=false \
  -f release-notes="Initial stable release"
```

### What Gets Created
- ✅ Git tag: `v{version}`
- ✅ GitHub Release with:
  - Auto-generated release notes
  - NuGet package (.nupkg)
  - Symbol package (.snupkg)
  - Build manifest
  - SBOM

---

## 📦 3. Publish to NuGet Workflow

**File:** `publish-nuget.yml`

### Purpose
Automatically publishes a GitHub release to NuGet.org using **Trusted Publishing**.

### Triggers
- **Automatic:** When a GitHub release is published
- **Manual:** Workflow dispatch with release tag input

### Authentication Method
**NuGet Trusted Publishing (OIDC)**
- ✅ No API keys required
- ✅ Secure GitHub-NuGet authentication
- ✅ Automatic token management via OIDC

### Required Permissions
```yaml
permissions:
  id-token: write  # Required for OIDC
  contents: read
  actions: read
```

### Process
1. ✅ Determines release tag and version
2. ✅ Checks out code at release tag
3. ✅ Downloads release assets (.nupkg, .snupkg)
4. ✅ Verifies package integrity
5. ✅ Publishes to NuGet.org via OIDC
6. ✅ Verifies package availability
7. ✅ Publishes workflow summary

### Environment
- **Name:** `production` (same as create-release workflow)
- **URL:** `https://www.nuget.org/packages/HeroCrypt`

### NuGet Trusted Publishing Setup

Before using this workflow, you **must** configure NuGet Trusted Publishing:

#### 1. Configure on NuGet.org
1. Log in to [NuGet.org](https://www.nuget.org)
2. Go to your account settings
3. Navigate to **Trusted Publishers**
4. Click **Add a new Trusted Publisher**
5. Select **GitHub Actions**
6. Configure:
   - **Repository owner:** `BeingCiteable` (or your username)
   - **Repository name:** `HeroCrypt`
   - **Workflow file:** `publish-nuget.yml`
   - **Environment name:** `production`
7. Save the configuration

#### 2. Verify GitHub Environment
The `production` environment is shared between the `create-release.yml` and `publish-nuget.yml` workflows.

1. Go to your repository **Settings** → **Environments**
2. Verify environment: `production` exists (created during release setup)
3. (Optional) Add protection rules:
   - Required reviewers
   - Wait timer
   - Deployment branches

### Manual Publishing
If automatic publishing fails, you can manually trigger:

```bash
gh workflow run publish-nuget.yml \
  -f release-tag=v1.0.0
```

---

## 🔒 Security & Quality

### GitHub Security Features
GitHub provides built-in security features that you can enable:

1. **CodeQL Analysis** (Recommended)
   - Go to **Settings** → **Code security and analysis**
   - Enable **CodeQL analysis** (default setup)
   - Select **C#** as the language
   - Automatic security scanning with always up-to-date rules

2. **Dependabot Alerts** (Recommended)
   - Automatic vulnerability detection in dependencies
   - Security advisories and patch suggestions

3. **Secret Scanning** (Recommended)
   - Automatic detection of exposed secrets
   - Prevents accidental credential commits

4. **Dependency Graph**
   - Visualize project dependencies
   - Track dependency updates

**Note:** All these features are configured in **Settings** → **Code security and analysis**

### RFC Compliance & Security Tests
Built into the **Build and Test** workflow:
- ✅ RFC 9106 (Argon2) compliance tests
- ✅ RFC 7693 (Blake2b) compliance tests
- ✅ RFC 8439 (ChaCha20-Poly1305) compliance tests
- ✅ RFC 7748 (Curve25519) compliance tests
- ✅ Security validation (constant-time ops, secure memory)

These tests run on **every build** before artifacts are created.

### Dependabot Auto-merge
**File:** `dependabot-automerge.yml`

Automatically approves and merges:
- Minor version updates
- Patch version updates

**Requires manual review:**
- Major version updates

---

## 📊 Complete Release Process

### Step-by-Step Guide

#### Step 1: Development & Testing
1. Create feature branch
2. Commit changes
3. Push to GitHub
4. **Build and Test workflow** runs automatically
5. Review test results and code coverage

#### Step 2: Prepare for Release
1. Merge feature branch to `main`
2. **Build and Test workflow** runs on main
3. Note the build number (e.g., `main-20241025.123.abc1234`)
4. Download and manually test artifacts (optional)

#### Step 3: Create Release
1. Go to **Actions** → **Create Release**
2. Run workflow with:
   - Version: `1.0.0`
   - Build number: `main-20241025.123.abc1234`
   - Pre-release: `false`
3. Wait for completion
4. Verify GitHub release is created

#### Step 4: Automatic Publishing
1. **Publish to NuGet workflow** triggers automatically
2. Package is published to NuGet.org via Trusted Publishing
3. Verify package at: `https://www.nuget.org/packages/HeroCrypt/1.0.0`

#### Step 5: Verification
```bash
# Test installation
dotnet new console -n TestHeroCrypt
cd TestHeroCrypt
dotnet add package HeroCrypt --version 1.0.0
dotnet build
```

---

## 🎯 Quick Reference

### Common Tasks

#### Find a Build Artifact
1. Go to **Actions** tab
2. Click on a workflow run
3. Scroll to **Artifacts** section
4. Download `herocrypt-{build-number}`

#### Create a Pre-release
```bash
gh workflow run create-release.yml \
  -f version=1.0.0-rc.1 \
  -f build-number=main-20241025.123.abc1234 \
  -f prerelease=true
```

#### Publish an Existing Release
```bash
gh workflow run publish-nuget.yml \
  -f release-tag=v1.0.0
```

#### Check Build Status
```bash
gh run list --workflow=build-and-test.yml --limit 5
```

#### View Latest Artifacts
```bash
gh run list --workflow=build-and-test.yml --limit 1
gh run view {run-id} --log
```

---

## 🔧 Configuration Files

### Related Configuration
- `Directory.Build.props` - Version management and build properties
- `coverlet.runsettings` - Code coverage configuration
- `.github/dependabot.yml` - Dependency update configuration

### Environment Variables
| Variable | Set By | Used For |
|----------|--------|----------|
| `CI` | All workflows | Detect CI environment |
| `BUILD_NUMBER` | Build workflow | File versioning |
| `GITHUB_REF` | GitHub | Branch/tag detection |
| `GITHUB_RUN_NUMBER` | GitHub | Sequential build numbering |

---

## 📝 Best Practices

### Version Numbering
- **Stable releases:** `1.0.0`, `1.2.3`, `2.0.0`
- **Pre-releases:** `1.0.0-alpha.1`, `1.0.0-beta.2`, `1.0.0-rc.1`
- **Development:** Automatically handled by `Directory.Build.props`

### Release Checklist
- [ ] All tests passing on main branch (check build workflow)
- [ ] Code review completed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if exists)
- [ ] Build artifacts available and verified
- [ ] NuGet Trusted Publishing configured
- [ ] Release notes prepared

### Rollback Process
If you need to rollback a release:

1. **Unlist package on NuGet.org** (don't delete)
   ```bash
   # Via nuget.org web UI
   # Package Settings → Unlist
   ```

2. **Create new patch release**
   ```bash
   # Revert changes in code
   git revert <commit-hash>
   git push

   # Create new release with reverted code
   gh workflow run create-release.yml \
     -f version=1.0.1 \
     -f build-number={new-build-number}
   ```

---

## 🆘 Troubleshooting

### Build Failures
- Check test results in workflow logs
- Review code coverage reports
- Verify all frameworks compile

### Release Creation Fails
- Verify build artifact exists and is correct
- Check version format (must be semver)
- Ensure tag doesn't already exist
- Check artifact name matches build number

### NuGet Publishing Fails
**Error: "Authentication failed"**
- Verify NuGet Trusted Publishing is configured
- Check environment name matches: `production`
- Verify workflow file name is correct: `publish-nuget.yml`

**Error: "Package version already exists"**
- NuGet doesn't allow overwriting versions
- Create a new patch version

**Error: "Package validation failed"**
- Check package metadata in .csproj
- Verify .nuspec is valid
- Check framework compatibility

### Manual NuGet Publishing (Fallback)
If Trusted Publishing fails, you can publish manually:

```bash
# Generate API key on nuget.org
# Then use:
dotnet nuget push *.nupkg \
  --api-key YOUR_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

---

## 📚 Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [NuGet Trusted Publishing](https://docs.microsoft.com/en-us/nuget/nuget-org/publish-a-package#trusted-publishers)
- [Semantic Versioning](https://semver.org/)
- [HeroCrypt Documentation](../../README.md)

---

## 📜 Archived Workflows

Old workflows have been moved to `archive/` for reference:
- `archive/build.yml` - Old build pipeline
- `archive/release.yml` - Old release pipeline (included version updates and test re-runs)
- `archive/nightly.yml` - Nightly test suite
- `archive/hotfix-release.yml` - Hotfix workflow
- `archive/rollback.yml` - Rollback workflow
- `archive/security-scan.yml` - Custom security scanning (replaced by GitHub's built-in features)

These workflows are kept for reference but are no longer active.

---

**Last Updated:** 2024-10-25
**Maintained By:** HeroCrypt Team
