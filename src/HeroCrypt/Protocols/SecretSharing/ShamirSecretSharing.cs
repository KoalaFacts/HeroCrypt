using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Shamir's Secret Sharing (SSS) implementation
/// Allows splitting a secret into N shares where any K shares can reconstruct the secret
///
/// Based on Shamir's paper "How to Share a Secret" (1979)
/// Uses finite field arithmetic over GF(256) for byte-level operations
///
/// Key features:
/// - Perfect secrecy of secret bytes in the trusted-dealer model; length is visible
/// - Information-theoretic confidentiality with fewer than K shares
/// - Threshold and share count between 2 and 255
/// Requires a trusted dealer and uniformly random coefficients. Shares do not carry
/// their original threshold, authenticated origin, or sharing-session identity.
/// This is not verifiable secret sharing or an authenticated MPC protocol.
/// No managed-runtime constant-time guarantee is made.
/// </summary>
public sealed class ShamirSecretSharing
{
    /// <summary>
    /// Initializes a new instance of the ShamirSecretSharing class.
    /// </summary>
    /// <param name="policy">Reserved policy parameter; does not authenticate shares,
    /// enforce algorithm restrictions, or provide compliance certification.</param>
    public ShamirSecretSharing(SecurityPolicyOptions? policy = null)
    {
        _ = policy;
    }
    private const int MaxShares = 255;
    private const int MinThreshold = 2;

    /// <summary>
    /// Represents a single share in Shamir's Secret Sharing
    /// </summary>
    public readonly struct Share
    {
        /// <summary>
        /// Share index (X coordinate, 1-255)
        /// </summary>
        public byte Index { get; }

        /// <summary>
        /// Share data (Y coordinates)
        /// </summary>
        public byte[] Data { get; }

        /// <summary>
        /// Initializes a new instance of the Share class.
        /// </summary>
        /// <param name="index">The share index (must be between 1 and 255)</param>
        /// <param name="data">The share data bytes</param>
        public Share(byte index, byte[] data)
        {
            if (index == 0)
            {
                throw new ArgumentException("Share index must be between 1 and 255", nameof(index));
            }

            Index = index;
            Data = data ?? throw new ArgumentNullException(nameof(data));
        }

        /// <summary>
        /// Creates a deep copy of this share
        /// </summary>
        public Share Clone()
        {
            if (Index == 0 || Data == null)
            {
                throw new InvalidOperationException("Cannot clone an uninitialized share");
            }

            var dataCopy = new byte[Data.Length];
            Array.Copy(Data, dataCopy, Data.Length);
            return new Share(Index, dataCopy);
        }
    }

    /// <summary>
    /// Splits a secret into multiple shares using Shamir's Secret Sharing
    /// </summary>
    /// <param name="secret">Secret to split</param>
    /// <param name="threshold">Minimum number of shares needed to reconstruct (K)</param>
    /// <param name="shareCount">Total number of shares to generate (N)</param>
    /// <returns>Array of shares</returns>
    public Share[] Split(ReadOnlySpan<byte> secret, int threshold, int shareCount)
    {
        ValidateSplitParameters(secret.Length, threshold, shareCount);

        var shares = new Share[shareCount];
        var coefficients = new byte[threshold];

        try
        {
            // For each byte of the secret, generate a polynomial and evaluate at share points
            for (var byteIndex = 0; byteIndex < secret.Length; byteIndex++)
            {
                // Generate random polynomial coefficients
                // Coefficient[0] is the secret byte, others are random
                coefficients[0] = secret[byteIndex];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(coefficients.AsSpan(1));
                }

                // Evaluate polynomial at each share index
                for (var shareIndex = 0; shareIndex < shareCount; shareIndex++)
                {
                    var x = (byte)(shareIndex + 1); // Share indices are 1-based

                    // Initialize share data on first byte
                    if (byteIndex == 0)
                    {
                        shares[shareIndex] = new Share(x, new byte[secret.Length]);
                    }

                    // Evaluate polynomial at x
                    shares[shareIndex].Data[byteIndex] = EvaluatePolynomial(coefficients, x);
                }
            }

            return shares;
        }
        finally
        {
            // Clear coefficients
            SecureMemoryOperations.SecureClear(coefficients);
        }
    }

    /// <summary>
    /// Reconstructs a secret from shares using Lagrange interpolation
    /// </summary>
    /// <remarks>Requires at least two shares. The original split threshold cannot be
    /// inferred from raw shares; use the explicit threshold overload to enforce a
    /// trusted caller-supplied minimum. Neither overload authenticates shares.</remarks>
    /// <param name="shares">Shares to use for reconstruction</param>
    /// <returns>Reconstructed secret</returns>
    public byte[] Reconstruct(ReadOnlySpan<Share> shares) => Reconstruct(shares, MinThreshold);

    /// <summary>
    /// Reconstructs a secret after enforcing a trusted caller-supplied threshold.
    /// </summary>
    /// <remarks>The threshold is a count requirement, not proof that shares belong
    /// to one sharing session or that their values are authentic.</remarks>
    /// <param name="shares">Shares to use for reconstruction</param>
    /// <param name="threshold">Required minimum share count, between 2 and 255</param>
    /// <returns>Reconstructed secret</returns>
    public byte[] Reconstruct(ReadOnlySpan<Share> shares, int threshold)
    {
        if (threshold < MinThreshold || threshold > MaxShares)
        {
            throw new ArgumentException($"Threshold must be between {MinThreshold} and {MaxShares}", nameof(threshold));
        }

        if (shares.Length < threshold || shares.Length > MaxShares)
        {
            throw new ArgumentException($"Between {threshold} and {MaxShares} shares required", nameof(shares));
        }

        // Validate every point before dereferencing data or interpolating.
        var secretLength = 0;
        var indices = new HashSet<byte>();
        foreach (var share in shares)
        {
            if (share.Index == 0 || share.Data == null || share.Data.Length == 0)
            {
                throw new ArgumentException("Shares must be initialized and contain nonempty data", nameof(shares));
            }

            if (secretLength == 0)
            {
                secretLength = share.Data.Length;
            }
            else if (share.Data.Length != secretLength)
            {
                throw new ArgumentException("All shares must have the same length", nameof(shares));
            }

            if (!indices.Add(share.Index))
            {
                throw new ArgumentException($"Duplicate share index: {share.Index}", nameof(shares));
            }
        }

        var secret = new byte[secretLength];

        // For each byte position, perform Lagrange interpolation
        for (var byteIndex = 0; byteIndex < secretLength; byteIndex++)
        {
            secret[byteIndex] = LagrangeInterpolate(shares, byteIndex);
        }

        return secret;
    }

    /// <summary>
    /// Evaluates a polynomial at point x in GF(256)
    /// Uses Horner's method: f(x) = a0 + a1*x + a2*x^2 + ... + an*x^n
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte EvaluatePolynomial(ReadOnlySpan<byte> coefficients, byte x)
    {
        byte result = 0;

        // Horner's method: start from highest degree
        for (var i = coefficients.Length - 1; i >= 0; i--)
        {
            result = GF256Add(GF256Multiply(result, x), coefficients[i]);
        }

        return result;
    }

    /// <summary>
    /// Performs Lagrange interpolation at x=0 to find the secret in GF(256)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte LagrangeInterpolate(ReadOnlySpan<Share> shares, int byteIndex)
    {
        byte result = 0;

        // Lagrange basis polynomials
        for (var i = 0; i < shares.Length; i++)
        {
            var xi = shares[i].Index;
            var yi = shares[i].Data[byteIndex];

            byte numerator = 1;
            byte denominator = 1;

            // Compute Lagrange basis polynomial L_i(0)
            for (var j = 0; j < shares.Length; j++)
            {
                if (i == j)
                {
                    continue;
                }

                var xj = shares[j].Index;

                // L_i(0) = prod((0 - xj) / (xi - xj)) for all j != i
                numerator = GF256Multiply(numerator, xj); // (0 - xj) = -xj = xj in GF(256)
                denominator = GF256Multiply(denominator, GF256Subtract(xi, xj));
            }

            // Multiply by y_i and add to result
            var basis = GF256Multiply(numerator, GF256Invert(denominator));
            var term = GF256Multiply(yi, basis);
            result = GF256Add(result, term);
        }

        return result;
    }

    // GF(256) Arithmetic Operations

    /// <summary>
    /// Addition in GF(256) is XOR
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte GF256Add(byte a, byte b) => (byte)(a ^ b);

    /// <summary>
    /// Subtraction in GF(256) is also XOR (additive inverse is identity)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte GF256Subtract(byte a, byte b) => (byte)(a ^ b);

    /// <summary>
    /// Multiplication in GF(256) using Rijndael's finite field
    /// Uses Russian peasant multiplication with reduction polynomial 0x11B
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte GF256Multiply(byte a, byte b)
    {
        uint result = 0;
        uint temp = a;
        uint multiplier = b;

        for (var i = 0; i < 8; i++)
        {
            // Mask selection avoids branches on secret field elements in source.
            // Explicit wrapping subtraction also works in checked builds.
            result ^= temp & unchecked(0u - (multiplier & 1u));
            var reduction = unchecked(0u - (temp >> 7)) & 0x1Bu;
            temp = ((temp << 1) & 0xFFu) ^ reduction;
            multiplier >>= 1;
        }

        return (byte)result;
    }

    /// <summary>
    /// Multiplicative inverse in GF(256) using Fermat's Little Theorem
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte GF256Invert(byte a)
    {
        if (a == 0)
        {
            throw new DivideByZeroException("Cannot invert zero in GF(256)");
        }

        // Fermat's Little Theorem: a^254 = a^(-1) in GF(256)
        // Use binary exponentiation to compute a^254
        byte result = 1;
        byte power = a;
        int exponent = 254;

        // Binary exponentiation
        while (exponent > 0)
        {
            if ((exponent & 1) == 1)
            {
                result = GF256Multiply(result, power);
            }
            power = GF256Multiply(power, power);
            exponent >>= 1;
        }

        return result;
    }

    /// <summary>
    /// Validates parameters for secret splitting
    /// </summary>
    private static void ValidateSplitParameters(int secretLength, int threshold, int shareCount)
    {
        if (secretLength == 0)
        {
            throw new ArgumentException("Secret cannot be empty", nameof(secretLength));
        }

        if (threshold < MinThreshold)
        {
            throw new ArgumentException($"Threshold must be at least {MinThreshold}", nameof(threshold));
        }

        if (shareCount > MaxShares)
        {
            throw new ArgumentException($"Share count cannot exceed {MaxShares}", nameof(shareCount));
        }

        if (threshold > shareCount)
        {
            throw new ArgumentException("Threshold cannot exceed share count", nameof(threshold));
        }
    }

    /// <summary>
    /// Compares a reconstructed value with an expected secret using at least two shares.
    /// </summary>
    /// <param name="shares">Shares to verify</param>
    /// <remarks>Does not authenticate shares or infer their original threshold.
    /// Use the explicit threshold overload to enforce a trusted minimum count.</remarks>
    /// <param name="expectedSecret">Expected secret</param>
    /// <returns>True if the reconstructed value matches; false for invalid shares</returns>
    public bool Verify(ReadOnlySpan<Share> shares, ReadOnlySpan<byte> expectedSecret) =>
        Verify(shares, expectedSecret, MinThreshold);

    /// <summary>
    /// Enforces a trusted minimum share count and compares the reconstructed value.
    /// </summary>
    /// <remarks>A matching value is not proof of share provenance, dealer honesty,
    /// participant honesty, or membership in a single sharing session.</remarks>
    /// <param name="shares">Shares to compare</param>
    /// <param name="expectedSecret">Expected secret</param>
    /// <param name="threshold">Required minimum share count, between 2 and 255</param>
    /// <returns>True if the value matches; false for invalid shares or threshold</returns>
    public bool Verify(ReadOnlySpan<Share> shares, ReadOnlySpan<byte> expectedSecret, int threshold)
    {
        byte[]? reconstructed = null;
        try
        {
            reconstructed = Reconstruct(shares, threshold);
            return SecureMemoryOperations.ConstantTimeEquals(reconstructed.AsSpan(), expectedSecret);
        }
        catch (ArgumentException)
        {
            return false;
        }
        finally
        {
            if (reconstructed != null)
            {
                SecureMemoryOperations.SecureClear(reconstructed);
            }
        }
    }
}
#endif
