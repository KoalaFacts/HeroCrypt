namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents the result of a signature verification operation.
/// </summary>
public readonly struct PgpSignatureResult
{
    /// <summary>
    /// Gets whether the signature is valid.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the signature type.
    /// </summary>
    public PgpSignatureType SignatureType { get; }

    /// <summary>
    /// Gets the signature creation time (if available).
    /// </summary>
    public DateTimeOffset? SignatureTime { get; }

    /// <summary>
    /// Gets the signer's key ID (8 bytes).
    /// </summary>
    public byte[]? SignerKeyId { get; }

    /// <summary>
    /// Gets the signer's fingerprint (if available).
    /// </summary>
    public byte[]? SignerFingerprint { get; }

    /// <summary>
    /// Gets the hash algorithm used.
    /// </summary>
    public PgpHashAlgorithmId HashAlgorithm { get; }

    /// <summary>
    /// Gets the public key algorithm used.
    /// </summary>
    public PgpPublicKeyAlgorithm PublicKeyAlgorithm { get; }

    /// <summary>
    /// Gets the signature version (4 or 6).
    /// </summary>
    public byte SignatureVersion { get; }

    /// <summary>
    /// Gets the error message if verification failed.
    /// </summary>
    public string? ErrorMessage { get; }

    /// <summary>
    /// Creates a successful verification result.
    /// </summary>
    /// <param name="signatureType">The signature type.</param>
    /// <param name="signatureTime">The signature creation time.</param>
    /// <param name="signerKeyId">The signer's key ID.</param>
    /// <param name="signerFingerprint">The signer's fingerprint.</param>
    /// <param name="hashAlgorithm">The hash algorithm used.</param>
    /// <param name="publicKeyAlgorithm">The public key algorithm used.</param>
    /// <param name="signatureVersion">The signature version.</param>
    /// <returns>A successful verification result.</returns>
    public static PgpSignatureResult Valid(
        PgpSignatureType signatureType,
        DateTimeOffset? signatureTime,
        byte[]? signerKeyId,
        byte[]? signerFingerprint,
        PgpHashAlgorithmId hashAlgorithm,
        PgpPublicKeyAlgorithm publicKeyAlgorithm,
        byte signatureVersion)
    {
        return new PgpSignatureResult(
            isValid: true,
            signatureType,
            signatureTime,
            signerKeyId,
            signerFingerprint,
            hashAlgorithm,
            publicKeyAlgorithm,
            signatureVersion,
            errorMessage: null);
    }

    /// <summary>
    /// Creates a failed verification result.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <param name="signatureType">The signature type (if known).</param>
    /// <param name="hashAlgorithm">The hash algorithm (if known).</param>
    /// <param name="publicKeyAlgorithm">The public key algorithm (if known).</param>
    /// <param name="signatureVersion">The signature version (if known).</param>
    /// <returns>A failed verification result.</returns>
    public static PgpSignatureResult Invalid(
        string errorMessage,
        PgpSignatureType signatureType = default,
        PgpHashAlgorithmId hashAlgorithm = default,
        PgpPublicKeyAlgorithm publicKeyAlgorithm = default,
        byte signatureVersion = 0)
    {
        return new PgpSignatureResult(
            isValid: false,
            signatureType,
            signatureTime: null,
            signerKeyId: null,
            signerFingerprint: null,
            hashAlgorithm,
            publicKeyAlgorithm,
            signatureVersion,
            errorMessage);
    }

    private PgpSignatureResult(
        bool isValid,
        PgpSignatureType signatureType,
        DateTimeOffset? signatureTime,
        byte[]? signerKeyId,
        byte[]? signerFingerprint,
        PgpHashAlgorithmId hashAlgorithm,
        PgpPublicKeyAlgorithm publicKeyAlgorithm,
        byte signatureVersion,
        string? errorMessage)
    {
        IsValid = isValid;
        SignatureType = signatureType;
        SignatureTime = signatureTime;
        SignerKeyId = signerKeyId;
        SignerFingerprint = signerFingerprint;
        HashAlgorithm = hashAlgorithm;
        PublicKeyAlgorithm = publicKeyAlgorithm;
        SignatureVersion = signatureVersion;
        ErrorMessage = errorMessage;
    }

    /// <summary>
    /// Gets the signer's key ID as a hexadecimal string.
    /// </summary>
    /// <returns>The key ID as hex, or null if not available.</returns>
    public string? GetKeyIdHex()
    {
        return SignerKeyId != null ? Convert.ToHexString(SignerKeyId).ToUpperInvariant() : null;
    }

    /// <summary>
    /// Gets the signer's fingerprint as a hexadecimal string.
    /// </summary>
    /// <returns>The fingerprint as hex, or null if not available.</returns>
    public string? GetFingerprintHex()
    {
        return SignerFingerprint != null ? Convert.ToHexString(SignerFingerprint).ToUpperInvariant() : null;
    }

    /// <summary>
    /// Returns a string representation of this result.
    /// </summary>
    public override string ToString()
    {
        if (IsValid)
        {
            var keyIdHex = GetKeyIdHex() ?? "unknown";
            var timeStr = SignatureTime?.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture) ?? "unknown";
            return $"Valid({SignatureType}, {HashAlgorithm}, key={keyIdHex}, time={timeStr})";
        }
        else
        {
            return $"Invalid({ErrorMessage})";
        }
    }
}
