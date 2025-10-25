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
{branch-name}-{date}-{run-number}-{commit-hash}

Examples:
  main-20241025-123-abc1234
  feature-auth-20241025-45-def5678
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
- SBOM (Software Bill of Materials)

**Artifact Name:** `herocrypt-{build-number}`

**Retention:** 90 days

### Outputs
- Test results (`.trx` files)
- Code coverage reports (Cobertura format)
- Packaged artifacts ready for release

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
| `build-number` | Build artifacts to use | `main-20241025-123-abc1234` |
| `prerelease` | Mark as pre-release | `true` / `false` |
| `release-notes` | Additional notes (optional) | Feature description |

### Process
1. ✅ Validates version format
2. ✅ Checks tag doesn't already exist
3. ✅ Downloads specified build artifacts
4. ✅ Verifies artifact integrity
5. ✅ Updates version in `Directory.Build.props`
6. ✅ Runs RFC compliance tests
7. ✅ Runs security validation tests
8. ✅ Commits version update
9. ✅ Creates git tag (`v{version}`)
10. ✅ Pushes changes and tag
11. ✅ Creates GitHub Release with artifacts

### Environment
- **Name:** `production`
- **Protection:** Recommended to require manual approval

### Example Usage

#### Via GitHub UI:
1. Go to **Actions** → **Create Release**
2. Click **Run workflow**
3. Fill in:
   - Version: `1.0.0`
   - Build number: `main-20241025-123-abc1234`
   - Pre-release: `false`
   - Release notes: Optional description
4. Click **Run workflow**

#### Via GitHub CLI:
```bash
gh workflow run create-release.yml \
  -f version=1.0.0 \
  -f build-number=main-20241025-123-abc1234 \
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
- **Name:** `nuget-production`
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
   - **Environment name:** `nuget-production`
7. Save the configuration

#### 2. Verify GitHub Environment
1. Go to your repository **Settings** → **Environments**
2. Create environment: `nuget-production`
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

## 🔒 Security Workflows

### Security Scan Workflow
**File:** `security-scan.yml`

Runs automated security checks:
- **CodeQL Analysis:** Security and quality scanning
- **Dependency Review:** Vulnerability detection
- **Secrets Scanning:** TruffleHog for exposed credentials
- **Cryptographic Validation:** RFC compliance tests

**Triggers:**
- Push to main/develop
- Pull requests
- Weekly schedule (Mondays)
- Manual dispatch

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
3. Note the build number (e.g., `main-20241025-123-abc1234`)
4. Download and manually test artifacts (optional)

#### Step 3: Create Release
1. Go to **Actions** → **Create Release**
2. Run workflow with:
   - Version: `1.0.0`
   - Build number: `main-20241025-123-abc1234`
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
  -f build-number=main-20241025-123-abc1234 \
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
- [ ] All tests passing on main branch
- [ ] Code review completed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if exists)
- [ ] RFC compliance tests passing
- [ ] Security tests passing
- [ ] Build artifacts verified
- [ ] NuGet Trusted Publishing configured

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
- Verify RFC compliance tests pass

### NuGet Publishing Fails
**Error: "Authentication failed"**
- Verify NuGet Trusted Publishing is configured
- Check environment name matches: `nuget-production`
- Verify workflow file name is correct

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
- `archive/release.yml` - Old release pipeline
- `archive/nightly.yml` - Nightly test suite
- `archive/hotfix-release.yml` - Hotfix workflow
- `archive/rollback.yml` - Rollback workflow

These workflows are kept for reference but are no longer active.

---

**Last Updated:** 2024-10-25
**Maintained By:** HeroCrypt Team
