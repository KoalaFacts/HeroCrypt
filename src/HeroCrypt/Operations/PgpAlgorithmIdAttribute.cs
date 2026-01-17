namespace HeroCrypt.Operations;

/// <summary>
/// Specifies the OpenPGP algorithm ID for an algorithm enum value.
/// </summary>
/// <remarks>
/// <para>
/// OpenPGP (RFC 4880, RFC 9580) uses specific byte IDs to identify algorithms
/// in packet headers and other structures. This attribute maps general algorithm
/// enum values to their corresponding OpenPGP wire-format IDs.
/// </para>
/// <para>
/// Use <see cref="PgpAlgorithmIdExtensions"/> to retrieve the PGP ID for an algorithm
/// or to look up an algorithm by its PGP ID.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Get PGP ID for an algorithm
/// byte pgpId = HashingAlgorithm.Sha256.GetPgpId(); // Returns 8
///
/// // Look up algorithm by PGP ID
/// var algo = PgpAlgorithmIdExtensions.GetHashingAlgorithmByPgpId(8); // Returns Sha256
/// </code>
/// </example>
[AttributeUsage(AttributeTargets.Field, AllowMultiple = false)]
public sealed class PgpAlgorithmIdAttribute : Attribute
{
    /// <summary>
    /// Gets the OpenPGP algorithm ID.
    /// </summary>
    public byte Id { get; }

    /// <summary>
    /// Gets the RFC that defines this algorithm ID.
    /// </summary>
    public string? Rfc { get; set; }

    /// <summary>
    /// Initializes a new instance with the specified PGP algorithm ID.
    /// </summary>
    /// <param name="id">The OpenPGP algorithm ID (0-255).</param>
    public PgpAlgorithmIdAttribute(byte id)
    {
        Id = id;
    }
}

/// <summary>
/// Extension methods for retrieving OpenPGP algorithm IDs from enum values.
/// </summary>
public static class PgpAlgorithmIdExtensions
{
    private static readonly Dictionary<HashingAlgorithm, byte> HashingToPgpId = [];
    private static readonly Dictionary<byte, HashingAlgorithm> PgpIdToHashing = [];
    private static readonly Dictionary<SymmetricCipherAlgorithm, byte> SymmetricToPgpId = [];
    private static readonly Dictionary<byte, SymmetricCipherAlgorithm> PgpIdToSymmetric = [];
    private static readonly Dictionary<SignatureAlgorithm, byte> SignatureToPgpId = [];
    private static readonly Dictionary<byte, SignatureAlgorithm> PgpIdToSignature = [];
    private static readonly Dictionary<CompressionAlgorithm, byte> CompressionToPgpId = [];
    private static readonly Dictionary<byte, CompressionAlgorithm> PgpIdToCompression = [];
    private static readonly Dictionary<AeadAlgorithm, byte> AeadToPgpId = [];
    private static readonly Dictionary<byte, AeadAlgorithm> PgpIdToAead = [];

    static PgpAlgorithmIdExtensions()
    {
        BuildLookupFor(typeof(HashingAlgorithm), HashingToPgpId, PgpIdToHashing);
        BuildLookupFor(typeof(SymmetricCipherAlgorithm), SymmetricToPgpId, PgpIdToSymmetric);
        BuildLookupFor(typeof(SignatureAlgorithm), SignatureToPgpId, PgpIdToSignature);
        BuildLookupFor(typeof(CompressionAlgorithm), CompressionToPgpId, PgpIdToCompression);
        BuildLookupFor(typeof(AeadAlgorithm), AeadToPgpId, PgpIdToAead);
    }

    private static void BuildLookupFor<T>(
#if NET5_0_OR_GREATER
        [System.Diagnostics.CodeAnalysis.DynamicallyAccessedMembers(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicFields)]
#endif
        Type enumType,
        Dictionary<T, byte> enumToId,
        Dictionary<byte, T> idToEnum) where T : struct, Enum
    {
        foreach (var field in enumType.GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static))
        {
            if (field.GetCustomAttributes(typeof(PgpAlgorithmIdAttribute), false)
                .FirstOrDefault() is PgpAlgorithmIdAttribute attr)
            {
                var value = (T)field.GetValue(null)!;
                enumToId[value] = attr.Id;
                idToEnum[attr.Id] = value;
            }
        }
    }

    /// <summary>
    /// Gets the OpenPGP algorithm ID for a hashing algorithm.
    /// </summary>
    /// <param name="algorithm">The hashing algorithm.</param>
    /// <returns>The PGP algorithm ID.</returns>
    /// <exception cref="ArgumentException">If the algorithm has no PGP ID.</exception>
    public static byte GetPgpId(this HashingAlgorithm algorithm)
        => HashingToPgpId.TryGetValue(algorithm, out var id)
            ? id
            : throw new ArgumentException($"No PGP algorithm ID defined for {algorithm}", nameof(algorithm));

    /// <summary>
    /// Tries to get the OpenPGP algorithm ID for a hashing algorithm.
    /// </summary>
    public static bool TryGetPgpId(this HashingAlgorithm algorithm, out byte id)
        => HashingToPgpId.TryGetValue(algorithm, out id);

    /// <summary>
    /// Gets the hashing algorithm for an OpenPGP algorithm ID.
    /// </summary>
    public static HashingAlgorithm GetHashingAlgorithmByPgpId(byte pgpId)
        => PgpIdToHashing.TryGetValue(pgpId, out var algo)
            ? algo
            : throw new ArgumentException($"Unknown PGP hash algorithm ID: {pgpId}", nameof(pgpId));

    /// <summary>
    /// Tries to get the hashing algorithm for an OpenPGP algorithm ID.
    /// </summary>
    public static bool TryGetHashingAlgorithmByPgpId(byte pgpId, out HashingAlgorithm algorithm)
        => PgpIdToHashing.TryGetValue(pgpId, out algorithm);

    /// <summary>
    /// Gets the OpenPGP algorithm ID for a symmetric cipher algorithm.
    /// </summary>
    public static byte GetPgpId(this SymmetricCipherAlgorithm algorithm)
        => SymmetricToPgpId.TryGetValue(algorithm, out var id)
            ? id
            : throw new ArgumentException($"No PGP algorithm ID defined for {algorithm}", nameof(algorithm));

    /// <summary>
    /// Tries to get the OpenPGP algorithm ID for a symmetric cipher algorithm.
    /// </summary>
    public static bool TryGetPgpId(this SymmetricCipherAlgorithm algorithm, out byte id)
        => SymmetricToPgpId.TryGetValue(algorithm, out id);

    /// <summary>
    /// Gets the symmetric cipher algorithm for an OpenPGP algorithm ID.
    /// </summary>
    public static SymmetricCipherAlgorithm GetSymmetricCipherAlgorithmByPgpId(byte pgpId)
        => PgpIdToSymmetric.TryGetValue(pgpId, out var algo)
            ? algo
            : throw new ArgumentException($"Unknown PGP symmetric algorithm ID: {pgpId}", nameof(pgpId));

    /// <summary>
    /// Tries to get the symmetric cipher algorithm for an OpenPGP algorithm ID.
    /// </summary>
    public static bool TryGetSymmetricCipherAlgorithmByPgpId(byte pgpId, out SymmetricCipherAlgorithm algorithm)
        => PgpIdToSymmetric.TryGetValue(pgpId, out algorithm);

    /// <summary>
    /// Gets the OpenPGP algorithm ID for a signature/public-key algorithm.
    /// </summary>
    public static byte GetPgpId(this SignatureAlgorithm algorithm)
        => SignatureToPgpId.TryGetValue(algorithm, out var id)
            ? id
            : throw new ArgumentException($"No PGP algorithm ID defined for {algorithm}", nameof(algorithm));

    /// <summary>
    /// Tries to get the OpenPGP algorithm ID for a signature algorithm.
    /// </summary>
    public static bool TryGetPgpId(this SignatureAlgorithm algorithm, out byte id)
        => SignatureToPgpId.TryGetValue(algorithm, out id);

    /// <summary>
    /// Gets the signature algorithm for an OpenPGP public-key algorithm ID.
    /// </summary>
    public static SignatureAlgorithm GetSignatureAlgorithmByPgpId(byte pgpId)
        => PgpIdToSignature.TryGetValue(pgpId, out var algo)
            ? algo
            : throw new ArgumentException($"Unknown PGP public-key algorithm ID: {pgpId}", nameof(pgpId));

    /// <summary>
    /// Tries to get the signature algorithm for an OpenPGP public-key algorithm ID.
    /// </summary>
    public static bool TryGetSignatureAlgorithmByPgpId(byte pgpId, out SignatureAlgorithm algorithm)
        => PgpIdToSignature.TryGetValue(pgpId, out algorithm);

    /// <summary>
    /// Gets the OpenPGP algorithm ID for a compression algorithm.
    /// </summary>
    public static byte GetPgpId(this CompressionAlgorithm algorithm)
        => CompressionToPgpId.TryGetValue(algorithm, out var id)
            ? id
            : throw new ArgumentException($"No PGP algorithm ID defined for {algorithm}", nameof(algorithm));

    /// <summary>
    /// Tries to get the OpenPGP algorithm ID for a compression algorithm.
    /// </summary>
    public static bool TryGetPgpId(this CompressionAlgorithm algorithm, out byte id)
        => CompressionToPgpId.TryGetValue(algorithm, out id);

    /// <summary>
    /// Gets the compression algorithm for an OpenPGP algorithm ID.
    /// </summary>
    public static CompressionAlgorithm GetCompressionAlgorithmByPgpId(byte pgpId)
        => PgpIdToCompression.TryGetValue(pgpId, out var algo)
            ? algo
            : throw new ArgumentException($"Unknown PGP compression algorithm ID: {pgpId}", nameof(pgpId));

    /// <summary>
    /// Tries to get the compression algorithm for an OpenPGP algorithm ID.
    /// </summary>
    public static bool TryGetCompressionAlgorithmByPgpId(byte pgpId, out CompressionAlgorithm algorithm)
        => PgpIdToCompression.TryGetValue(pgpId, out algorithm);

    /// <summary>
    /// Gets the OpenPGP algorithm ID for an AEAD algorithm.
    /// </summary>
    public static byte GetPgpId(this AeadAlgorithm algorithm)
        => AeadToPgpId.TryGetValue(algorithm, out var id)
            ? id
            : throw new ArgumentException($"No PGP algorithm ID defined for {algorithm}", nameof(algorithm));

    /// <summary>
    /// Tries to get the OpenPGP algorithm ID for an AEAD algorithm.
    /// </summary>
    public static bool TryGetPgpId(this AeadAlgorithm algorithm, out byte id)
        => AeadToPgpId.TryGetValue(algorithm, out id);

    /// <summary>
    /// Gets the AEAD algorithm for an OpenPGP algorithm ID.
    /// </summary>
    public static AeadAlgorithm GetAeadAlgorithmByPgpId(byte pgpId)
        => PgpIdToAead.TryGetValue(pgpId, out var algo)
            ? algo
            : throw new ArgumentException($"Unknown PGP AEAD algorithm ID: {pgpId}", nameof(pgpId));

    /// <summary>
    /// Tries to get the AEAD algorithm for an OpenPGP algorithm ID.
    /// </summary>
    public static bool TryGetAeadAlgorithmByPgpId(byte pgpId, out AeadAlgorithm algorithm)
        => PgpIdToAead.TryGetValue(pgpId, out algorithm);
}
