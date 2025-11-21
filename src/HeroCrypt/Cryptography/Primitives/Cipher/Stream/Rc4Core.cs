using System.Runtime.CompilerServices;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Cipher.Stream;

/// <summary>
/// RC4 (Rivest Cipher 4) stream cipher implementation
///
/// ⚠️ SECURITY WARNING ⚠️
/// RC4 is considered CRYPTOGRAPHICALLY BROKEN and INSECURE.
/// This implementation is provided ONLY for legacy compatibility with existing systems.
/// DO NOT use RC4 for new applications or sensitive data.
///
/// Known vulnerabilities:
/// - Biased output in first bytes (requires discarding initial keystream)
/// - Statistical biases throughout keystream
/// - Related key attacks
/// - WEP and WPA-TKIP vulnerabilities
///
/// Recommended alternatives:
/// - ChaCha20 or ChaCha20-Poly1305 for stream encryption
/// - AES-GCM for authenticated encryption
///
/// References:
/// - RFC 4345 (Informational)
/// - "Weaknesses in the Key Scheduling Algorithm of RC4" (Fluhrer, Mantin, Shamir, 2001)
/// </summary>
[Obsolete("RC4 is cryptographically broken. Use only for legacy compatibility. Prefer ChaCha20 or AES-GCM for new applications.")]
internal static class Rc4Core
{
    /// <summary>
    /// Minimum key size in bytes
    /// </summary>
    public const int MIN_KEY_SIZE = 5;

    /// <summary>
    /// Maximum key size in bytes
    /// </summary>
    public const int MAX_KEY_SIZE = 256;

    /// <summary>
    /// Recommended minimum number of initial keystream bytes to discard
    /// to mitigate known biases (RFC 4345 recommends 256-3072 bytes)
    /// </summary>
    public const int RECOMMENDED_DROP_BYTES = 3072;

    /// <summary>
    /// RC4 cipher state container.
    /// </summary>
    private class Rc4State
    {
        /// <summary>
        /// State permutation array (S-box). Contains a permutation of all 256 possible byte values.
        /// </summary>
        public byte[] S = new byte[256];

        /// <summary>
        /// First index pointer used during keystream generation.
        /// </summary>
        public int I;

        /// <summary>
        /// Second index pointer used during keystream generation.
        /// </summary>
        public int J;
    }

    /// <summary>
    /// Encrypts or decrypts data using RC4 stream cipher
    ///
    /// ⚠️ WARNING: RC4 is insecure. Use only for legacy compatibility.
    /// </summary>
    /// <param name="output">Output buffer</param>
    /// <param name="input">Input buffer</param>
    /// <param name="key">Key (5-256 bytes, 16+ bytes recommended)</param>
    /// <param name="dropBytes">Number of initial keystream bytes to discard (3072 recommended, 0 for compatibility mode)</param>
    public static void Transform(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, int dropBytes = 0)
    {
        if (key.Length < MIN_KEY_SIZE || key.Length > MAX_KEY_SIZE)
        {
            throw new ArgumentException($"Key must be between {MIN_KEY_SIZE} and {MAX_KEY_SIZE} bytes", nameof(key));
        }
        if (output.Length < input.Length)
        {
            throw new ArgumentException("Output buffer too small", nameof(output));
        }
        if (dropBytes < 0)
        {
            throw new ArgumentException("Drop bytes cannot be negative", nameof(dropBytes));
        }

        var state = new Rc4State();

        try
        {
            // Key Scheduling Algorithm (KSA)
            InitializeState(state, key);

            // Drop initial bytes if requested (mitigates known biases)
            if (dropBytes > 0)
            {
                DropInitialBytes(state, dropBytes);
            }

            // Pseudo-Random Generation Algorithm (PRGA)
            GenerateKeystream(state, output, input);
        }
        finally
        {
            // Clear state
            if (state?.S != null)
            {
                SecureMemoryOperations.SecureClear(state.S.AsSpan());
            }
        }
    }

    /// <summary>
    /// Initializes RC4 state using Key Scheduling Algorithm (KSA)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InitializeState(Rc4State state, ReadOnlySpan<byte> key)
    {
        // Initialize S array (identity permutation)
        for (var i = 0; i < 256; i++)
        {
            state.S[i] = (byte)i;
        }

        // Mix key into S array
        var j = 0;
        for (var i = 0; i < 256; i++)
        {
            j = (j + state.S[i] + key[i % key.Length]) % 256;
            Swap(state.S, i, j);
        }

        state.I = 0;
        state.J = 0;
    }

    /// <summary>
    /// Drops initial keystream bytes to mitigate known biases
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DropInitialBytes(Rc4State state, int count)
    {
        for (var k = 0; k < count; k++)
        {
            state.I = (state.I + 1) % 256;
            state.J = (state.J + state.S[state.I]) % 256;
            Swap(state.S, state.I, state.J);
        }
    }

    /// <summary>
    /// Generates keystream and XORs with input using Pseudo-Random Generation Algorithm (PRGA)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GenerateKeystream(Rc4State state, Span<byte> output, ReadOnlySpan<byte> input)
    {
        for (var k = 0; k < input.Length; k++)
        {
            // Update indices
            state.I = (state.I + 1) % 256;
            state.J = (state.J + state.S[state.I]) % 256;

            // Swap
            Swap(state.S, state.I, state.J);

            // Generate keystream byte
            var t = (state.S[state.I] + state.S[state.J]) % 256;
            var keystreamByte = state.S[t];

            // XOR with input
            output[k] = (byte)(input[k] ^ keystreamByte);
        }
    }

    /// <summary>
    /// Swaps two elements in the state array
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Swap(byte[] array, int i, int j)
    {
        (array[i], array[j]) = (array[j], array[i]);
    }

    /// <summary>
    /// Validates parameters for RC4
    /// </summary>
    public static void ValidateParameters(ReadOnlySpan<byte> key, int dropBytes = 0)
    {
        if (key.Length < MIN_KEY_SIZE || key.Length > MAX_KEY_SIZE)
        {
            throw new ArgumentException($"Key must be between {MIN_KEY_SIZE} and {MAX_KEY_SIZE} bytes", nameof(key));
        }
        if (dropBytes < 0)
        {
            throw new ArgumentException("Drop bytes cannot be negative", nameof(dropBytes));
        }
    }

    /// <summary>
    /// Checks if RC4 usage is secure (it never is, but this checks if mitigations are applied)
    /// </summary>
    public static bool IsSecureConfiguration(int keySize, int dropBytes)
    {
        // RC4 is never truly secure, but this checks if basic mitigations are applied
        return keySize >= 16 && dropBytes >= RECOMMENDED_DROP_BYTES;
    }

    /// <summary>
    /// Gets security warning message
    /// </summary>
    public static string GetSecurityWarning()
    {
        return "⚠️ RC4 is cryptographically broken. Use only for legacy compatibility. " +
               "Prefer ChaCha20, XSalsa20, or AES-GCM for new applications.";
    }

    /// <summary>
    /// Gets recommended drop bytes for security
    /// </summary>
    public static int GetRecommendedDropBytes() => RECOMMENDED_DROP_BYTES;
}
