# Contributing to HeroCrypt

First off, thank you for considering contributing to HeroCrypt! 🎉

HeroCrypt is a community-driven cryptographic library, and we welcome contributions from developers of all skill levels. This document provides guidelines for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Cryptographic Implementation Guidelines](#cryptographic-implementation-guidelines)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)

## 📜 Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please be respectful, inclusive, and professional in all interactions.

**Expected Behavior:**
- Be respectful and considerate
- Welcome newcomers and help them learn
- Focus on what is best for the community
- Show empathy towards other community members

**Unacceptable Behavior:**
- Harassment, discrimination, or offensive comments
- Trolling, insulting, or derogatory comments
- Publishing others' private information
- Any conduct that could be considered inappropriate in a professional setting

## 🚀 Getting Started

### Prerequisites

- **.NET SDK**: Version 8.0 or later
- **Git**: For version control
- **IDE**: Visual Studio 2022, VS Code, or JetBrains Rider
- **Understanding of C#**: Intermediate to advanced level
- **Cryptography knowledge**: Basic understanding helpful but not required for all contributions

### First-Time Contributors

If this is your first time contributing:

1. Look for issues tagged with `good first issue` or `help wanted`
2. Read through the documentation to understand the project structure
3. Ask questions in GitHub Discussions if you need help
4. Start with small changes to familiarize yourself with the codebase

## 🤝 How Can I Contribute?

### 1. Reporting Bugs

**Before submitting a bug report:**
- Check the existing issues to avoid duplicates
- Verify the bug exists in the latest version
- Collect relevant information (OS, .NET version, error messages)

**When submitting a bug report, include:**
- Clear, descriptive title
- Step-by-step reproduction instructions
- Expected vs. actual behavior
- Code samples demonstrating the issue
- Environment details (.NET version, OS, hardware)
- Stack traces or error messages

### 2. Suggesting Enhancements

**Before suggesting an enhancement:**
- Check if it's already been suggested
- Ensure it aligns with the project's goals
- Consider if it's broadly useful to users

**When suggesting an enhancement:**
- Use a clear, descriptive title
- Provide detailed explanation of the proposed feature
- Explain the use case and benefits
- Include code examples if applicable
- Suggest implementation approach if you have ideas

### 3. Contributing Code

**Types of contributions we welcome:**
- **Bug fixes**: Fix reported issues
- **New algorithms**: Implement cryptographic algorithms following standards
- **Performance improvements**: Optimize existing implementations
- **Tests**: Add or improve test coverage
- **Documentation**: Improve docs, examples, or comments
- **Tooling**: Enhance build scripts, CI/CD, or development tools

## 💻 Development Setup

### Clone the Repository

```bash
git clone https://github.com/KoalaFacts/HeroCrypt.git
cd HeroCrypt
```

### Build the Project

```bash
dotnet restore
dotnet build
```

### Run Tests

```bash
dotnet test
```

### Project Structure

```
HeroCrypt/
├── src/
│   └── HeroCrypt/           # Main library
│       ├── Cryptography/    # Cryptographic implementations
│       ├── Services/        # High-level service APIs
│       └── Utilities/       # Helper classes
├── tests/
│   └── HeroCrypt.Tests/     # Unit and integration tests
├── benchmarks/
│   └── HeroCrypt.Benchmarks/ # Performance benchmarks (planned)
└── docs/                    # Documentation
```

## 📝 Coding Standards

### C# Style Guidelines

We follow standard .NET coding conventions with some specific guidelines:

#### Naming Conventions
- **Classes**: PascalCase (`Argon2HashingService`)
- **Methods**: PascalCase (`ComputeHash`)
- **Parameters**: camelCase (`hashLength`)
- **Private fields**: camelCase with underscore (`_context`)
- **Constants**: PascalCase (`DefaultIterations`)
- **Interfaces**: I prefix (`IHashingService`)

#### Code Style
```csharp
// ✅ Good
public byte[] ComputeHash(ReadOnlySpan<byte> data, int outputLength)
{
    if (data.Length == 0)
        throw new ArgumentException("Data cannot be empty", nameof(data));

    var result = new byte[outputLength];
    // Implementation...
    return result;
}

// ❌ Bad
public byte[] compute_hash(byte[] data,int len) {
    if(data.Length==0) throw new Exception("empty");
    byte[] result=new byte[len];
    return result;
}
```

#### Code Organization
- One class per file
- Related classes in same namespace
- Keep methods focused and concise (< 50 lines ideally)
- Use regions sparingly, prefer clear class structure

#### XML Documentation
All public APIs must have XML documentation:

```csharp
/// <summary>
/// Computes a Blake2b hash of the input data.
/// </summary>
/// <param name="data">The data to hash</param>
/// <param name="outputLength">Desired hash length in bytes (1-64)</param>
/// <returns>The computed hash</returns>
/// <exception cref="ArgumentException">Thrown when outputLength is invalid</exception>
public static byte[] ComputeHash(ReadOnlySpan<byte> data, int outputLength)
{
    // Implementation...
}
```

### EditorConfig

The project includes an `.editorconfig` file. Configure your IDE to use it for automatic formatting.

## 📌 Commit Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring (no functional change)
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Build process, dependencies, tooling
- `security`: Security-related changes

### Examples

```
feat(argon2): add support for custom salt length

Allow users to specify custom salt lengths for Argon2 hashing,
with validation to ensure security requirements are met.

Closes #123
```

```
fix(aes-gcm): correct nonce size validation

Fixed issue where 96-bit nonces were incorrectly rejected.
Updated tests to cover all valid nonce sizes.

Fixes #456
```

```
docs(readme): add ChaCha20-Poly1305 usage example

Added comprehensive example showing proper usage of
ChaCha20-Poly1305 with random nonce generation.
```

## 🔄 Pull Request Process

### Before Submitting

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feat/my-new-feature
   ```

2. **Make your changes** following the coding standards

3. **Add tests** for new functionality

4. **Update documentation** if needed

5. **Run all tests** and ensure they pass:
   ```bash
   dotnet test
   ```

6. **Commit your changes** using conventional commits

### Submitting the PR

1. **Push your branch** to GitHub:
   ```bash
   git push origin feat/my-new-feature
   ```

2. **Open a Pull Request** with:
   - Clear title describing the change
   - Detailed description of what and why
   - Link to related issues
   - Screenshots/examples if applicable

3. **Fill out the PR template** completely

4. **Wait for review** and address feedback

### PR Review Process

- At least one maintainer must approve the PR
- All CI checks must pass
- Code must meet quality standards
- Cryptographic implementations require additional security review

### After Approval

- Maintainer will merge using "Squash and merge"
- Your contribution will be included in the next release
- You'll be credited in release notes

## 🔐 Cryptographic Implementation Guidelines

**Special requirements for cryptographic code:**

### 1. **Follow Standards**
- Implement according to published RFC, NIST FIPS, or ISO standards
- Document the exact specification being implemented
- Include references to the standard in code comments

### 2. **Test Vectors**
- Include official test vectors from the specification
- Test vectors must pass 100%
- Add test cases for edge cases and error conditions

### 3. **Security Considerations**
- **Constant-time operations**: Critical for preventing timing attacks
- **Memory security**: Zero sensitive data after use
- **Input validation**: Validate all inputs thoroughly
- **Side-channel resistance**: Be aware of cache-timing, power analysis
- **No unsafe code**: Avoid `unsafe` unless absolutely necessary and well-justified

### 4. **Documentation**
- Explain the algorithm's purpose and use cases
- Document security parameters (key sizes, iterations, etc.)
- Include security warnings where appropriate
- Provide usage examples

### 5. **Code Review**
- All cryptographic code requires review by another developer
- Complex implementations may require review by cryptography expert
- Be prepared to explain security properties

### Example Structure

```csharp
/// <summary>
/// AES-GCM (Galois/Counter Mode) authenticated encryption.
///
/// Provides confidentiality and authenticity in a single operation.
/// WARNING: Never reuse a nonce with the same key.
///
/// Reference: NIST SP 800-38D
/// </summary>
public static class AesGcm
{
    /// <summary>
    /// Encrypts plaintext and produces authentication tag.
    /// </summary>
    public static void Encrypt(
        ReadOnlySpan<byte> key,          // Must be 128, 192, or 256 bits
        ReadOnlySpan<byte> nonce,        // 96 bits recommended
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> ciphertext,
        Span<byte> tag)                  // 128 bits recommended
    {
        // Validate inputs
        ValidateKeySize(key.Length);
        ValidateNonceSize(nonce.Length);

        // Implementation following NIST SP 800-38D
        // ...
    }
}
```

## ✅ Testing Requirements

### Test Coverage
- **Minimum**: 90% code coverage for new code
- **Critical paths**: 100% coverage for cryptographic cores
- **Edge cases**: Test boundary conditions, invalid inputs
- **Performance**: Benchmark critical paths

### Test Organization

```csharp
[Fact]
public void Argon2_ValidPassword_ReturnsExpectedHash()
{
    // Arrange
    var password = "test-password";
    var salt = new byte[16];
    var options = new Argon2Options { /* ... */ };

    // Act
    var hash = Argon2.Hash(password, salt, options);

    // Assert
    Assert.NotNull(hash);
    Assert.Equal(32, hash.Length);
}

[Theory]
[InlineData(0)]
[InlineData(-1)]
[InlineData(65)]
public void Blake2b_InvalidOutputLength_ThrowsException(int length)
{
    // Arrange
    var data = new byte[10];

    // Act & Assert
    Assert.Throws<ArgumentException>(() =>
        Blake2b.ComputeHash(data, length));
}
```

### Test Vectors

```csharp
[Fact]
public void Blake2b_RFC7693_TestVector1_Matches()
{
    // Arrange - Test vector from RFC 7693 Appendix A
    var input = Encoding.ASCII.GetBytes("abc");
    var expected = Convert.FromHexString(
        "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923"
    );

    // Act
    var actual = Blake2b.ComputeHash(input, 64);

    // Assert
    Assert.Equal(expected, actual);
}
```

## 📚 Documentation

### Code Documentation
- All public APIs must have XML documentation
- Include `<summary>`, `<param>`, `<returns>`, `<exception>`
- Add `<remarks>` for important details
- Include usage examples in doc comments

### README Updates
- Update README.md for new features
- Add usage examples for significant additions
- Keep feature list current

### Additional Documentation
- Update STANDARDS_COMPLIANCE.md for new algorithms
- Add entries to CHANGELOG.md
- Update DEVELOPMENT_ROADMAP.md progress

## 🎯 Quality Checklist

Before submitting your PR, verify:

- [ ] Code follows project style guidelines
- [ ] All tests pass locally
- [ ] New tests added for new functionality
- [ ] Test coverage meets minimum requirements
- [ ] XML documentation added for public APIs
- [ ] README updated if needed
- [ ] CHANGELOG.md updated
- [ ] No compiler warnings introduced
- [ ] Code has been reviewed by yourself first
- [ ] Commit messages follow conventional commits
- [ ] Branch is up to date with main

### For Cryptographic Implementations:
- [ ] Follows published standard (RFC, NIST, ISO)
- [ ] Official test vectors included and passing
- [ ] Constant-time operations used where necessary
- [ ] Memory securely cleared after use
- [ ] Input validation is comprehensive
- [ ] Security warnings documented
- [ ] Reference to specification included

## 💬 Getting Help

- **GitHub Discussions**: Ask questions, share ideas
- **GitHub Issues**: Report bugs or request features
- **Code Review**: Request feedback on your approach before implementing

## 🙏 Recognition

Contributors will be:
- Listed in release notes
- Credited in CHANGELOG.md
- Mentioned in the repository's contributor list

## 📄 License

By contributing to HeroCrypt, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for making HeroCrypt better! 🚀**

Questions? Feel free to open a discussion or reach out to the maintainers.

*Last Updated: 2025-10-26*
