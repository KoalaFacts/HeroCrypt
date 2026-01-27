namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Validates OpenPGP public and secret key rings for structural integrity
/// and cryptographic correctness.
/// </summary>
/// <remarks>
/// <para>
/// This class performs comprehensive validation of imported keys including:
/// <list type="bullet">
///   <item>Structural validation (required components present)</item>
///   <item>Self-signature verification (user ID certifications)</item>
///   <item>Subkey binding signature verification</item>
///   <item>Expiration checking (optional)</item>
///   <item>Revocation status checking (optional)</item>
/// </list>
/// </para>
/// <para>
/// <b>Usage:</b>
/// <code>
/// var result = PgpKeyValidator.Create()
///     .WithPublicKeyRing(publicKeyRing)
///     .VerifySelfSignatures()
///     .VerifySubkeyBindings()
///     .CheckExpiration()
///     .Validate();
///
/// if (result.IsValid)
/// {
///     Console.WriteLine("Key is valid!");
/// }
/// else
/// {
///     foreach (var issue in result.Issues)
///     {
///         Console.WriteLine($"{issue.Severity}: {issue.Message}");
///     }
/// }
/// </code>
/// </para>
/// </remarks>
public sealed class PgpKeyValidator : IDisposable
{
    private PgpPublicKeyRing? publicKeyRing;
    private bool verifySelfSignatures;
    private bool verifySubkeyBindings;
    private bool checkExpiration;
    private bool checkRevocation;
    private DateTimeOffset? validationTime;
    private bool disposed;

    private PgpKeyValidator()
    {
    }

    /// <summary>
    /// Creates a new key validator.
    /// </summary>
    /// <returns>A new validator instance.</returns>
    public static PgpKeyValidator Create() => new();

    /// <summary>
    /// Sets the public key ring to validate.
    /// </summary>
    /// <param name="keyRing">The public key ring.</param>
    /// <returns>This validator for chaining.</returns>
    public PgpKeyValidator WithPublicKeyRing(PgpPublicKeyRing keyRing)
    {
        ThrowIfDisposed();
        publicKeyRing = keyRing;
        return this;
    }

    /// <summary>
    /// Sets the secret key ring to validate.
    /// </summary>
    /// <param name="keyRing">The secret key ring.</param>
    /// <returns>This validator for chaining.</returns>
    /// <remarks>
    /// When a secret key ring is provided, its public key components are
    /// extracted and used for validation. The secret material itself is
    /// not validated (use decryption to verify passphrase correctness).
    /// </remarks>
    public PgpKeyValidator WithSecretKeyRing(PgpSecretKeyRing keyRing)
    {
        ThrowIfDisposed();
        publicKeyRing = keyRing.ExtractPublicKeyRing();
        return this;
    }

    /// <summary>
    /// Enables verification of self-certification signatures.
    /// </summary>
    /// <returns>This validator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// Self-certification signatures bind User IDs to the master key.
    /// A valid key should have at least one valid self-certification
    /// for each User ID.
    /// </para>
    /// </remarks>
    public PgpKeyValidator VerifySelfSignatures()
    {
        ThrowIfDisposed();
        verifySelfSignatures = true;
        return this;
    }

    /// <summary>
    /// Enables verification of subkey binding signatures.
    /// </summary>
    /// <returns>This validator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// Subkey binding signatures (type 0x18) bind subkeys to the master key.
    /// Each subkey should have a valid binding signature from the master key.
    /// </para>
    /// </remarks>
    public PgpKeyValidator VerifySubkeyBindings()
    {
        ThrowIfDisposed();
        verifySubkeyBindings = true;
        return this;
    }

    /// <summary>
    /// Enables expiration checking.
    /// </summary>
    /// <returns>This validator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// When enabled, expired keys will result in a warning (not an error).
    /// Use <see cref="AtTime"/> to check expiration at a specific time.
    /// </para>
    /// </remarks>
    public PgpKeyValidator CheckExpiration()
    {
        ThrowIfDisposed();
        checkExpiration = true;
        return this;
    }

    /// <summary>
    /// Enables revocation status checking.
    /// </summary>
    /// <returns>This validator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// When enabled, revoked keys will result in a warning (not an error).
    /// This checks for the presence of a key revocation signature but does
    /// not verify the revocation signature cryptographically unless
    /// <see cref="VerifySelfSignatures"/> is also enabled.
    /// </para>
    /// </remarks>
    public PgpKeyValidator CheckRevocation()
    {
        ThrowIfDisposed();
        checkRevocation = true;
        return this;
    }

    /// <summary>
    /// Sets the time at which to perform validation checks.
    /// </summary>
    /// <param name="time">The validation time.</param>
    /// <returns>This validator for chaining.</returns>
    /// <remarks>
    /// <para>
    /// This affects expiration checking. If not set, the current time is used.
    /// </para>
    /// </remarks>
    public PgpKeyValidator AtTime(DateTimeOffset time)
    {
        ThrowIfDisposed();
        validationTime = time;
        return this;
    }

    /// <summary>
    /// Enables all validation checks.
    /// </summary>
    /// <returns>This validator for chaining.</returns>
    public PgpKeyValidator FullValidation()
    {
        ThrowIfDisposed();
        verifySelfSignatures = true;
        verifySubkeyBindings = true;
        checkExpiration = true;
        checkRevocation = true;
        return this;
    }

    /// <summary>
    /// Performs validation and returns the result.
    /// </summary>
    /// <returns>The validation result.</returns>
    /// <exception cref="InvalidOperationException">If no key ring is configured.</exception>
    public PgpKeyValidationResult Validate()
    {
        ThrowIfDisposed();

        if (publicKeyRing == null)
        {
            throw new InvalidOperationException("A key ring must be configured using WithPublicKeyRing() or WithSecretKeyRing().");
        }

        var issues = new List<PgpKeyValidationIssue>();
        var effectiveTime = validationTime ?? DateTimeOffset.UtcNow;

        // Structural validation (always performed)
        ValidateStructure(publicKeyRing.Value, issues);

        // Self-signature verification
        if (verifySelfSignatures && issues.All(i => i.Severity != PgpValidationSeverity.Error))
        {
            ValidateSelfSignatures(publicKeyRing.Value, issues);
        }

        // Subkey binding verification
        if (verifySubkeyBindings && issues.All(i => i.Severity != PgpValidationSeverity.Error))
        {
            ValidateSubkeyBindings(publicKeyRing.Value, issues);
        }

        // Expiration check
        if (checkExpiration)
        {
            ValidateExpiration(publicKeyRing.Value, effectiveTime, issues);
        }

        // Revocation check
        if (checkRevocation)
        {
            ValidateRevocation(publicKeyRing.Value, issues);
        }

        return new PgpKeyValidationResult(issues);
    }

    /// <summary>
    /// Performs a quick structural validation without cryptographic checks.
    /// </summary>
    /// <returns>The validation result.</returns>
    public PgpKeyValidationResult ValidateStructureOnly()
    {
        ThrowIfDisposed();

        if (publicKeyRing == null)
        {
            throw new InvalidOperationException("A key ring must be configured using WithPublicKeyRing() or WithSecretKeyRing().");
        }

        var issues = new List<PgpKeyValidationIssue>();
        ValidateStructure(publicKeyRing.Value, issues);
        return new PgpKeyValidationResult(issues);
    }

    private static void ValidateStructure(PgpPublicKeyRing keyRing, List<PgpKeyValidationIssue> issues)
    {
        // Check for master key (always present due to struct construction)
        // Verify it's not marked as a subkey
        if (keyRing.MasterKey.IsSubkey)
        {
            issues.Add(PgpKeyValidationIssue.Error(
                PgpValidationCode.InvalidMasterKey,
                "Master key is marked as a subkey."));
        }

        // Check for at least one User ID
        if (keyRing.UserIds.Count == 0)
        {
            issues.Add(PgpKeyValidationIssue.Error(
                PgpValidationCode.NoUserIds,
                "Key ring has no User IDs."));
        }

        // Check for at least one self-certification signature
        bool hasSelfCertification = keyRing.Signatures.Any(IsCertificationSignature);
        if (!hasSelfCertification && keyRing.UserIds.Count > 0)
        {
            issues.Add(PgpKeyValidationIssue.Error(
                PgpValidationCode.NoSelfCertification,
                "Key ring has no self-certification signature for User IDs."));
        }

        // Check subkeys have binding signatures
        foreach (var subkey in keyRing.Subkeys)
        {
            var subkeyId = subkey.GetKeyId();
            bool hasBinding = keyRing.Signatures.Any(s =>
                s.SignatureType == PgpSignatureType.SubkeyBinding &&
                IsSignedByMasterKey(s, keyRing.MasterKey));

            if (!hasBinding)
            {
                issues.Add(PgpKeyValidationIssue.Warning(
                    PgpValidationCode.MissingSubkeyBinding,
                    $"Subkey {Convert.ToHexString(subkeyId)} has no binding signature."));
            }
        }

        // Check key algorithm is supported
        if (!IsSupportedAlgorithm(keyRing.MasterKey.Algorithm))
        {
            issues.Add(PgpKeyValidationIssue.Warning(
                PgpValidationCode.UnsupportedAlgorithm,
                $"Master key uses unsupported algorithm: {keyRing.MasterKey.Algorithm}."));
        }

        foreach (var subkey in keyRing.Subkeys)
        {
            if (!IsSupportedAlgorithm(subkey.Algorithm))
            {
                issues.Add(PgpKeyValidationIssue.Warning(
                    PgpValidationCode.UnsupportedAlgorithm,
                    $"Subkey {Convert.ToHexString(subkey.GetKeyId())} uses unsupported algorithm: {subkey.Algorithm}."));
            }
        }
    }

    private static void ValidateSelfSignatures(PgpPublicKeyRing keyRing, List<PgpKeyValidationIssue> issues)
    {
        using var verifier = PgpSignatureVerifier.Create();

        // For each User ID, verify at least one self-certification
        foreach (var userId in keyRing.UserIds)
        {
            bool hasValidCertification = false;
            var certifications = keyRing.Signatures.Where(IsCertificationSignature).ToList();

            foreach (var cert in certifications)
            {
                var result = verifier.VerifySelfCertification(cert, keyRing.MasterKey, userId);
                if (result.IsValid)
                {
                    hasValidCertification = true;
                    break;
                }
            }

            if (!hasValidCertification && certifications.Count > 0)
            {
                issues.Add(PgpKeyValidationIssue.Error(
                    PgpValidationCode.InvalidSelfCertification,
                    $"No valid self-certification found for User ID: {userId.UserId}"));
            }
        }
    }

    private static void ValidateSubkeyBindings(PgpPublicKeyRing keyRing, List<PgpKeyValidationIssue> issues)
    {
        using var verifier = PgpSignatureVerifier.Create();

        foreach (var subkey in keyRing.Subkeys)
        {
            var subkeyId = subkey.GetKeyId();
            var bindings = keyRing.Signatures
                .Where(s => s.SignatureType == PgpSignatureType.SubkeyBinding)
                .ToList();

            bool hasValidBinding = false;
            foreach (var binding in bindings)
            {
                var result = verifier.VerifySubkeyBinding(binding, keyRing.MasterKey, subkey);
                if (result.IsValid)
                {
                    hasValidBinding = true;
                    break;
                }
            }

            if (!hasValidBinding && bindings.Count > 0)
            {
                issues.Add(PgpKeyValidationIssue.Error(
                    PgpValidationCode.InvalidSubkeyBinding,
                    $"Subkey {Convert.ToHexString(subkeyId)} has no valid binding signature."));
            }
        }
    }

    private static void ValidateExpiration(PgpPublicKeyRing keyRing, DateTimeOffset atTime, List<PgpKeyValidationIssue> issues)
    {
        if (keyRing.IsExpiredAt(atTime))
        {
            var expirationTime = keyRing.GetExpirationTime();
            issues.Add(PgpKeyValidationIssue.Warning(
                PgpValidationCode.KeyExpired,
                $"Key expired at {expirationTime:yyyy-MM-dd HH:mm:ss} UTC."));
        }
    }

    private static void ValidateRevocation(PgpPublicKeyRing keyRing, List<PgpKeyValidationIssue> issues)
    {
        if (keyRing.IsRevoked)
        {
            var reason = keyRing.GetRevocationReason();
            var reasonText = reason.HasValue
                ? $"{reason.Value.Reason.GetDescription()}: {reason.Value.ReasonText ?? "No reason given"}"
                : "Key has been revoked";
            issues.Add(PgpKeyValidationIssue.Warning(
                PgpValidationCode.KeyRevoked,
                reasonText));
        }

        // Check for revoked subkeys
        foreach (var subkey in keyRing.Subkeys)
        {
            var subkeyId = subkey.GetKeyId();
            bool isRevoked = keyRing.Signatures.Any(s =>
                s.SignatureType == PgpSignatureType.SubkeyRevocation);

            if (isRevoked)
            {
                issues.Add(PgpKeyValidationIssue.Warning(
                    PgpValidationCode.SubkeyRevoked,
                    $"Subkey {Convert.ToHexString(subkeyId)} has been revoked."));
            }
        }
    }

    private static bool IsCertificationSignature(PgpSignaturePacket sig) =>
        sig.SignatureType == PgpSignatureType.GenericCertification ||
        sig.SignatureType == PgpSignatureType.PersonaCertification ||
        sig.SignatureType == PgpSignatureType.CasualCertification ||
        sig.SignatureType == PgpSignatureType.PositiveCertification;

    private static bool IsSignedByMasterKey(PgpSignaturePacket sig, PgpPublicKeyPacket masterKey)
    {
        // Check if the signature's issuer matches the master key
        var issuerKeyId = sig.GetIssuerKeyId();
        var issuerFingerprint = sig.GetIssuerFingerprint();
        var masterKeyId = masterKey.GetKeyId();
        var masterFingerprint = masterKey.ComputeFingerprint();

        if (issuerFingerprint != null)
        {
            return issuerFingerprint.SequenceEqual(masterFingerprint);
        }

        if (issuerKeyId != null)
        {
            return issuerKeyId.SequenceEqual(masterKeyId);
        }

        return true; // If no issuer info, assume it might match
    }

    private static bool IsSupportedAlgorithm(PgpPublicKeyAlgorithm algorithm) =>
        algorithm switch
        {
            PgpPublicKeyAlgorithm.RsaEncryptOrSign => true,
#pragma warning disable CS0618 // Obsolete
            PgpPublicKeyAlgorithm.RsaEncryptOnly => true,
            PgpPublicKeyAlgorithm.RsaSignOnly => true,
#pragma warning restore CS0618
            PgpPublicKeyAlgorithm.Ed25519 => true,
            PgpPublicKeyAlgorithm.X25519 => true,
            PgpPublicKeyAlgorithm.Ecdsa => true,
            PgpPublicKeyAlgorithm.Ecdh => true,
            _ => false
        };

    private void ThrowIfDisposed()
    {
#if NET8_0_OR_GREATER
        ObjectDisposedException.ThrowIf(disposed, this);
#else
        if (disposed)
        {
            throw new ObjectDisposedException(nameof(PgpKeyValidator));
        }
#endif
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!disposed)
        {
            disposed = true;
        }
    }
}

/// <summary>
/// Result of key validation.
/// </summary>
public readonly struct PgpKeyValidationResult
{
    /// <summary>
    /// Gets the validation issues found.
    /// </summary>
    public IReadOnlyList<PgpKeyValidationIssue> Issues { get; }

    /// <summary>
    /// Gets whether the key is valid (no errors).
    /// </summary>
    /// <remarks>
    /// A key is considered valid if there are no errors. Warnings do not
    /// affect validity but indicate potential concerns.
    /// </remarks>
    public bool IsValid => !Issues.Any(i => i.Severity == PgpValidationSeverity.Error);

    /// <summary>
    /// Gets whether there are any warnings.
    /// </summary>
    public bool HasWarnings => Issues.Any(i => i.Severity == PgpValidationSeverity.Warning);

    /// <summary>
    /// Gets only the error issues.
    /// </summary>
    public IEnumerable<PgpKeyValidationIssue> Errors =>
        Issues.Where(i => i.Severity == PgpValidationSeverity.Error);

    /// <summary>
    /// Gets only the warning issues.
    /// </summary>
    public IEnumerable<PgpKeyValidationIssue> Warnings =>
        Issues.Where(i => i.Severity == PgpValidationSeverity.Warning);

    /// <summary>
    /// Creates a new validation result.
    /// </summary>
    /// <param name="issues">The validation issues.</param>
    internal PgpKeyValidationResult(IReadOnlyList<PgpKeyValidationIssue> issues)
    {
        Issues = issues;
    }

    /// <summary>
    /// Returns a string representation of the validation result.
    /// </summary>
    public override string ToString()
    {
        if (Issues.Count == 0)
        {
            return "Valid (no issues)";
        }

        var errors = Errors.Count();
        var warnings = Warnings.Count();

        if (IsValid)
        {
            return $"Valid with {warnings} warning(s)";
        }
        else
        {
            return $"Invalid: {errors} error(s), {warnings} warning(s)";
        }
    }
}

/// <summary>
/// A single validation issue.
/// </summary>
public readonly struct PgpKeyValidationIssue
{
    /// <summary>
    /// Gets the severity of the issue.
    /// </summary>
    public PgpValidationSeverity Severity { get; }

    /// <summary>
    /// Gets the validation code.
    /// </summary>
    public PgpValidationCode Code { get; }

    /// <summary>
    /// Gets the human-readable message describing the issue.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Creates a new validation issue.
    /// </summary>
    /// <param name="severity">The severity.</param>
    /// <param name="code">The validation code.</param>
    /// <param name="message">The message.</param>
    public PgpKeyValidationIssue(PgpValidationSeverity severity, PgpValidationCode code, string message)
    {
        Severity = severity;
        Code = code;
        Message = message;
    }

    /// <summary>
    /// Creates an error issue.
    /// </summary>
    public static PgpKeyValidationIssue Error(PgpValidationCode code, string message) =>
        new(PgpValidationSeverity.Error, code, message);

    /// <summary>
    /// Creates a warning issue.
    /// </summary>
    public static PgpKeyValidationIssue Warning(PgpValidationCode code, string message) =>
        new(PgpValidationSeverity.Warning, code, message);

    /// <summary>
    /// Creates an info issue.
    /// </summary>
    public static PgpKeyValidationIssue Info(PgpValidationCode code, string message) =>
        new(PgpValidationSeverity.Info, code, message);

    /// <inheritdoc/>
    public override string ToString() => $"[{Severity}] {Code}: {Message}";
}

/// <summary>
/// Severity levels for validation issues.
/// </summary>
public enum PgpValidationSeverity
{
    /// <summary>
    /// Informational note that doesn't affect validity.
    /// </summary>
    Info,

    /// <summary>
    /// Warning that doesn't prevent use but indicates potential issues.
    /// </summary>
    Warning,

    /// <summary>
    /// Error that makes the key invalid for use.
    /// </summary>
    Error
}

/// <summary>
/// Specific validation issue codes.
/// </summary>
public enum PgpValidationCode
{
    /// <summary>
    /// The master key is invalid.
    /// </summary>
    InvalidMasterKey,

    /// <summary>
    /// No User IDs are present.
    /// </summary>
    NoUserIds,

    /// <summary>
    /// No self-certification signature is present.
    /// </summary>
    NoSelfCertification,

    /// <summary>
    /// Self-certification signature verification failed.
    /// </summary>
    InvalidSelfCertification,

    /// <summary>
    /// Subkey has no binding signature.
    /// </summary>
    MissingSubkeyBinding,

    /// <summary>
    /// Subkey binding signature verification failed.
    /// </summary>
    InvalidSubkeyBinding,

    /// <summary>
    /// Key uses an unsupported algorithm.
    /// </summary>
    UnsupportedAlgorithm,

    /// <summary>
    /// Key has expired.
    /// </summary>
    KeyExpired,

    /// <summary>
    /// Key has been revoked.
    /// </summary>
    KeyRevoked,

    /// <summary>
    /// Subkey has been revoked.
    /// </summary>
    SubkeyRevoked
}
