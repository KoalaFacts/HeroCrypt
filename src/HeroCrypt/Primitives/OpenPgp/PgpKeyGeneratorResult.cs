namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents the result of PGP key generation, containing both public and secret key rings.
/// </summary>
/// <remarks>
/// <para>
/// This struct provides access to:
/// <list type="bullet">
///   <item>The complete key rings (public and secret)</item>
///   <item>Direct access to master key packets</item>
///   <item>Key metadata (fingerprint, key ID, creation time)</item>
///   <item>Export methods for serialization</item>
/// </list>
/// </para>
/// </remarks>
public readonly struct PgpKeyGeneratorResult
{
    /// <summary>
    /// Gets the secret key ring containing the master key and any subkeys.
    /// </summary>
    public PgpSecretKeyRing SecretKeyRing { get; }

    /// <summary>
    /// Gets the public key ring containing the master key and any subkeys.
    /// </summary>
    public PgpPublicKeyRing PublicKeyRing { get; }

    /// <summary>
    /// Gets the master secret key packet.
    /// </summary>
    public PgpSecretKeyPacket MasterSecretKey => SecretKeyRing.MasterKey;

    /// <summary>
    /// Gets the master public key packet.
    /// </summary>
    public PgpPublicKeyPacket MasterPublicKey => PublicKeyRing.MasterKey;

    /// <summary>
    /// Gets the primary user ID string.
    /// </summary>
    public string UserId { get; }

    /// <summary>
    /// Gets the key creation time.
    /// </summary>
    public DateTimeOffset CreationTime => MasterPublicKey.CreationTime;

    /// <summary>
    /// Gets the 8-byte key ID of the master key.
    /// </summary>
    public byte[] KeyId => MasterPublicKey.GetKeyId();

    /// <summary>
    /// Gets the fingerprint of the master key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For V4 keys: 20-byte SHA-1 fingerprint.
    /// For V6 keys: 32-byte SHA-256 fingerprint.
    /// </para>
    /// </remarks>
    public byte[] Fingerprint => MasterPublicKey.ComputeFingerprint();

    /// <summary>
    /// Gets the key version (4 or 6).
    /// </summary>
    public byte Version => MasterPublicKey.Version;

    /// <summary>
    /// Gets the public key algorithm.
    /// </summary>
    public PgpPublicKeyAlgorithm Algorithm => MasterPublicKey.Algorithm;

    /// <summary>
    /// Initializes a new key generator result.
    /// </summary>
    /// <param name="secretKeyRing">The secret key ring.</param>
    /// <param name="publicKeyRing">The public key ring.</param>
    /// <param name="userId">The primary user ID.</param>
    internal PgpKeyGeneratorResult(
        PgpSecretKeyRing secretKeyRing,
        PgpPublicKeyRing publicKeyRing,
        string userId)
    {
        SecretKeyRing = secretKeyRing;
        PublicKeyRing = publicKeyRing;
        UserId = userId;
    }

    /// <summary>
    /// Exports the public key ring to a byte array.
    /// </summary>
    /// <returns>The serialized public key ring.</returns>
    public byte[] ExportPublicKey()
    {
        return PublicKeyRing.ToArray();
    }

    /// <summary>
    /// Exports the secret key ring to a byte array.
    /// </summary>
    /// <returns>The serialized secret key ring.</returns>
    public byte[] ExportSecretKey()
    {
        return SecretKeyRing.ToArray();
    }

    /// <summary>
    /// Exports the public key ring to a stream.
    /// </summary>
    /// <param name="stream">The destination stream.</param>
    public void ExportPublicKey(Stream stream)
    {
        var data = ExportPublicKey();
        stream.Write(data, 0, data.Length);
    }

    /// <summary>
    /// Exports the secret key ring to a stream.
    /// </summary>
    /// <param name="stream">The destination stream.</param>
    public void ExportSecretKey(Stream stream)
    {
        var data = ExportSecretKey();
        stream.Write(data, 0, data.Length);
    }

    /// <summary>
    /// Securely clears all sensitive key material from memory.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Call this method when the keys are no longer needed to minimize the window
    /// during which sensitive data resides in memory.
    /// </para>
    /// </remarks>
    public void ClearSensitiveData()
    {
        SecretKeyRing.ClearSensitiveData();
    }

    /// <summary>
    /// Returns a string representation of this key generation result.
    /// </summary>
    public override string ToString()
    {
        var keyId = Convert.ToHexString(KeyId);
        return $"PgpKeyGeneratorResult(v{Version}, {Algorithm}, ID:{keyId}, {UserId})";
    }
}
