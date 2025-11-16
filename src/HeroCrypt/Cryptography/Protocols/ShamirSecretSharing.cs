using HeroCrypt.Security;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Protocols;

#if !NETSTANDARD2_0

/// <summary>
/// Shamir's Secret Sharing (SSS) implementation
/// Allows splitting a secret into N shares where any K shares can reconstruct the secret
///
/// Based on Shamir's paper "How to Share a Secret" (1979)
/// Uses finite field arithmetic over GF(256) for byte-level operations
///
/// Key features:
/// - Perfect secrecy: K-1 shares reveal no information about the secret
/// - Information-theoretically secure
/// - Arbitrary threshold and share count
/// - Constant-time operations where applicable
/// </summary>
public static class ShamirSecretSharing
{
    /// <summary>
    /// Maximum number of shares that can be generated
    /// </summary>
    public const int MaxShares = 255;

    /// <summary>
    /// Minimum threshold for reconstruction
    /// </summary>
    public const int MinThreshold = 2;

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

        public Share(byte index, byte[] data)
        {
            if (index == 0)
                throw new ArgumentException("Share index must be between 1 and 255", nameof(index));

            Index = index;
            Data = data ?? throw new ArgumentNullException(nameof(data));
        }

        /// <summary>
        /// Creates a deep copy of this share
        /// </summary>
        public Share Clone()
        {
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
    public static Share[] Split(ReadOnlySpan<byte> secret, int threshold, int shareCount)
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
    /// <param name="shares">Shares to use for reconstruction (minimum threshold required)</param>
    /// <returns>Reconstructed secret</returns>
    public static byte[] Reconstruct(ReadOnlySpan<Share> shares)
    {
        if (shares.Length < MinThreshold)
            throw new ArgumentException($"At least {MinThreshold} shares required", nameof(shares));

        // Validate all shares have same length
        var secretLength = shares[0].Data.Length;
        for (var i = 1; i < shares.Length; i++)
        {
            if (shares[i].Data.Length != secretLength)
                throw new ArgumentException("All shares must have the same length", nameof(shares));
        }

        // Check for duplicate share indices
        var indices = new HashSet<byte>();
        foreach (var share in shares)
        {
            if (!indices.Add(share.Index))
                throw new ArgumentException($"Duplicate share index: {share.Index}", nameof(shares));
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
                if (i == j) continue;

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

    #region GF(256) Arithmetic Operations

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
        byte result = 0;
        byte temp = a;

        for (var i = 0; i < 8; i++)
        {
            // If bit i of b is set, add temp to result
            if ((b & 1) != 0)
            {
                result ^= temp;
            }

            // Check if high bit of temp is set
            var highBitSet = (temp & 0x80) != 0;

            // Shift temp left
            temp <<= 1;

            // If high bit was set, XOR with reduction polynomial
            if (highBitSet)
            {
                temp ^= 0x1B; // Reduction polynomial for AES field
            }

            // Shift b right
            b >>= 1;
        }

        return result;
    }

    /// <summary>
    /// Multiplicative inverse in GF(256) using Fermat's Little Theorem
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte GF256Invert(byte a)
    {
        if (a == 0)
            throw new DivideByZeroException("Cannot invert zero in GF(256)");

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

    #endregion

    /// <summary>
    /// Validates parameters for secret splitting
    /// </summary>
    private static void ValidateSplitParameters(int secretLength, int threshold, int shareCount)
    {
        if (secretLength == 0)
            throw new ArgumentException("Secret cannot be empty", nameof(secretLength));

        if (threshold < MinThreshold)
            throw new ArgumentException($"Threshold must be at least {MinThreshold}", nameof(threshold));

        if (shareCount > MaxShares)
            throw new ArgumentException($"Share count cannot exceed {MaxShares}", nameof(shareCount));

        if (threshold > shareCount)
            throw new ArgumentException("Threshold cannot exceed share count", nameof(threshold));
    }

    /// <summary>
    /// Verifies that a set of shares can reconstruct the secret
    /// </summary>
    /// <param name="shares">Shares to verify</param>
    /// <param name="expectedSecret">Expected secret (for testing)</param>
    /// <returns>True if shares correctly reconstruct the secret</returns>
    public static bool Verify(ReadOnlySpan<Share> shares, ReadOnlySpan<byte> expectedSecret)
    {
        try
        {
            var reconstructed = Reconstruct(shares);
            var result = reconstructed.AsSpan().SequenceEqual(expectedSecret);
            Array.Clear(reconstructed, 0, reconstructed.Length);
            return result;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Gets information about Shamir's Secret Sharing scheme
    /// </summary>
    public static string GetInfo()
    {
        return $"Shamir's Secret Sharing (SSS) - Information-theoretically secure secret splitting. " +
               $"Max shares: {MaxShares}, Min threshold: {MinThreshold}. " +
               $"Uses GF(256) arithmetic with AES reduction polynomial.";
    }
}
#endif
