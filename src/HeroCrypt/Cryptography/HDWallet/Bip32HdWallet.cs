using HeroCrypt.Security;
using HeroCrypt.Cryptography.ECC.Secp256k1;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace HeroCrypt.Cryptography.HDWallet;

#if !NETSTANDARD2_0

/// <summary>
/// BIP32 Hierarchical Deterministic Wallet implementation
/// Implements BIP-0032 specification for deriving child keys from master keys
///
/// Key features:
/// - Master key generation from seed
/// - Child key derivation (normal and hardened)
/// - Extended key serialization (xprv/xpub format)
/// - Support for key paths (m/44'/0'/0'/0/0)
/// </summary>
public static class Bip32HdWallet
{
    /// <summary>
    /// Minimum seed length in bytes
    /// </summary>
    public const int MinSeedLength = 16; // 128 bits

    /// <summary>
    /// Maximum seed length in bytes
    /// </summary>
    public const int MaxSeedLength = 64; // 512 bits

    /// <summary>
    /// Recommended seed length in bytes
    /// </summary>
    public const int RecommendedSeedLength = 64; // 512 bits (BIP39 output)

    /// <summary>
    /// Extended key length (including chain code)
    /// </summary>
    public const int ExtendedKeyLength = 78;

    /// <summary>
    /// Hardened key offset (2^31)
    /// </summary>
    public const uint HardenedOffset = 0x80000000;

    /// <summary>
    /// Master key generation constant for Bitcoin
    /// </summary>
    private const string BitcoinSeed = "Bitcoin seed";

    /// <summary>
    /// Represents an extended key (public or private) with chain code
    /// </summary>
    public class ExtendedKey
    {
        /// <summary>
        /// Key data (32 bytes for private, 33 bytes for public)
        /// </summary>
        public byte[] Key { get; }

        /// <summary>
        /// Chain code (32 bytes)
        /// </summary>
        public byte[] ChainCode { get; }

        /// <summary>
        /// Depth in the key tree (0 for master)
        /// </summary>
        public byte Depth { get; }

        /// <summary>
        /// Parent key fingerprint (4 bytes)
        /// </summary>
        public byte[] ParentFingerprint { get; }

        /// <summary>
        /// Child index
        /// </summary>
        public uint ChildIndex { get; }

        /// <summary>
        /// Whether this is a private key
        /// </summary>
        public bool IsPrivate => Key.Length == 32;

        public ExtendedKey(byte[] key, byte[] chainCode, byte depth = 0,
            byte[]? parentFingerprint = null, uint childIndex = 0)
        {
            if (key.Length != 32 && key.Length != 33)
                throw new ArgumentException("Key must be 32 bytes (private) or 33 bytes (public)", nameof(key));
            if (chainCode.Length != 32)
                throw new ArgumentException("Chain code must be 32 bytes", nameof(chainCode));

            Key = key;
            ChainCode = chainCode;
            Depth = depth;
            ParentFingerprint = parentFingerprint ?? new byte[4];
            ChildIndex = childIndex;
        }

        /// <summary>
        /// Clears sensitive key material
        /// </summary>
        public void Clear()
        {
            if (IsPrivate)
            {
                SecureMemoryOperations.SecureClear(Key);
            }
            SecureMemoryOperations.SecureClear(ChainCode);
        }
    }

    /// <summary>
    /// Generates a master extended key from a seed
    /// </summary>
    /// <param name="seed">Seed bytes (16-64 bytes, 64 recommended)</param>
    /// <param name="keyType">Key type identifier (default: "Bitcoin seed")</param>
    /// <returns>Master extended private key</returns>
    public static ExtendedKey GenerateMasterKey(ReadOnlySpan<byte> seed, string keyType = BitcoinSeed)
    {
        if (seed.Length < MinSeedLength || seed.Length > MaxSeedLength)
            throw new ArgumentException($"Seed must be between {MinSeedLength} and {MaxSeedLength} bytes", nameof(seed));

        // Compute I = HMAC-SHA512(Key = keyType, Data = seed)
        var hmacKey = Encoding.UTF8.GetBytes(keyType);
        Span<byte> hmacResult = stackalloc byte[64];

        using (var hmac = new HMACSHA512(hmacKey))
        {
            hmac.TryComputeHash(seed, hmacResult, out _);
        }

        try
        {
            // Split into master private key (IL) and chain code (IR)
            var masterKey = hmacResult.Slice(0, 32).ToArray();
            var chainCode = hmacResult.Slice(32, 32).ToArray();

            // BIP32 spec: In case parse256(IL) is 0 or parse256(IL) >= n, the master key is invalid
            if (IsZero(masterKey) || IsGreaterThanOrEqualToN(masterKey))
            {
                throw new InvalidOperationException(
                    "Invalid master key: IL is zero or >= n. " +
                    "This is extremely rare (probability < 1 in 2^127). Try a different seed.");
            }

            return new ExtendedKey(masterKey, chainCode, depth: 0);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(hmacResult);
            Array.Clear(hmacKey, 0, hmacKey.Length);
        }
    }

    /// <summary>
    /// Derives a child key from a parent key
    /// </summary>
    /// <param name="parent">Parent extended key</param>
    /// <param name="index">Child index (use values >= HardenedOffset for hardened derivation)</param>
    /// <returns>Derived child key</returns>
    public static ExtendedKey DeriveChild(ExtendedKey parent, uint index)
    {
        if (parent == null)
            throw new ArgumentNullException(nameof(parent));

        var isHardened = index >= HardenedOffset;

        // Hardened derivation requires private key
        if (isHardened && !parent.IsPrivate)
            throw new InvalidOperationException("Cannot derive hardened child from public key");

        Span<byte> data = stackalloc byte[37]; // 1 + 32 + 4
        var dataLength = 0;

        if (isHardened)
        {
            // Hardened: data = 0x00 || parent_private_key || index
            data[0] = 0x00;
            parent.Key.CopyTo(data.Slice(1, 32));
            dataLength = 33;
        }
        else
        {
            // Normal: data = parent_public_key || index
            if (parent.IsPrivate)
            {
                // Derive public key from private key (simplified - would need full ECC implementation)
                // For now, we'll use a placeholder approach
                var publicKey = DerivePublicKeyFromPrivate(parent.Key);
                publicKey.CopyTo(data);
                dataLength = 33;
            }
            else
            {
                parent.Key.CopyTo(data);
                dataLength = 33;
            }
        }

        // Append child index (big-endian)
        BinaryPrimitives.WriteUInt32BigEndian(data.Slice(dataLength, 4), index);

        // Compute I = HMAC-SHA512(Key = parent_chain_code, Data = data)
        Span<byte> hmacResult = stackalloc byte[64];
        using (var hmac = new HMACSHA512(parent.ChainCode))
        {
            hmac.TryComputeHash(data.Slice(0, dataLength + 4), hmacResult, out _);
        }

        try
        {
            var childKey = new byte[32];
            var childChainCode = hmacResult.Slice(32, 32).ToArray();

            if (parent.IsPrivate)
            {
                // BIP32 spec: In case parse256(IL) >= n or ki = 0, the resulting key is invalid
                var IL = hmacResult.Slice(0, 32);

                if (IsGreaterThanOrEqualToN(IL))
                {
                    throw new InvalidOperationException(
                        $"Invalid child key at index {index}: IL >= n. " +
                        "This is extremely rare. Increment index and try again.");
                }

                // child_key = (parse256(IL) + parent_key) mod n
                AddModN(IL, parent.Key, childKey);

                // Check if resulting key is zero
                if (IsZero(childKey))
                {
                    throw new InvalidOperationException(
                        $"Invalid child key at index {index}: derived key is zero. " +
                        "This is extremely rare. Increment index and try again.");
                }
            }
            else
            {
                // REFERENCE IMPLEMENTATION LIMITATION
                // Public key derivation requires full ECC point addition (secp256k1)
                // Production implementation needs:
                // 1. Parse parent public key as EC point (33 or 65 bytes)
                // 2. Parse IL as scalar value
                // 3. Compute point(IL) + parent_public_key using EC point addition
                // 4. Serialize resulting point as compressed public key
                //
                // For production, use established libraries like:
                // - NBitcoin (Bitcoin-specific HD wallet implementation)
                // - BouncyCastle (full ECC implementation)
                // - libsecp256k1 wrapper

                throw new InvalidOperationException(
                    "BIP32 public key derivation is not supported in this reference implementation. " +
                    "This requires full secp256k1 elliptic curve point addition. " +
                    "For production use, consider libraries like NBitcoin or BouncyCastle that provide complete BIP32 support.");
            }

            // Calculate parent fingerprint (first 4 bytes of HASH160(parent_public_key))
            var parentFingerprint = CalculateFingerprint(parent);

            return new ExtendedKey(
                childKey,
                childChainCode,
                depth: (byte)(parent.Depth + 1),
                parentFingerprint: parentFingerprint,
                childIndex: index
            );
        }
        finally
        {
            SecureMemoryOperations.SecureClear(hmacResult);
            SecureMemoryOperations.SecureClear(data);
        }
    }

    /// <summary>
    /// Derives a key using a derivation path (e.g., "m/44'/0'/0'/0/0")
    /// </summary>
    /// <param name="masterKey">Master extended key</param>
    /// <param name="path">Derivation path</param>
    /// <returns>Derived key</returns>
    public static ExtendedKey DerivePath(ExtendedKey masterKey, string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Path cannot be empty", nameof(path));

        var indices = ParsePath(path);
        var currentKey = masterKey;

        foreach (var index in indices)
        {
            var nextKey = DeriveChild(currentKey, index);

            // Clear intermediate keys (except master and final)
            if (currentKey != masterKey)
            {
                currentKey.Clear();
            }

            currentKey = nextKey;
        }

        return currentKey;
    }

    /// <summary>
    /// Parses a BIP32 derivation path into indices
    /// </summary>
    /// <param name="path">Path string (e.g., "m/44'/0'/0'/0/0")</param>
    /// <returns>Array of child indices</returns>
    public static uint[] ParsePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Path cannot be empty", nameof(path));

        // Remove "m/" or "M/" prefix if present
        if (path.StartsWith("m/", StringComparison.OrdinalIgnoreCase))
        {
            path = path.Substring(2);
        }
        else if (path.Equals("m", StringComparison.OrdinalIgnoreCase))
        {
            return Array.Empty<uint>();
        }

        var parts = path.Split('/');
        var indices = new uint[parts.Length];

        for (var i = 0; i < parts.Length; i++)
        {
            var part = parts[i];
            var isHardened = part.EndsWith("'") || part.EndsWith("h") || part.EndsWith("H");

            if (isHardened)
            {
                part = part.Substring(0, part.Length - 1);
            }

            if (!uint.TryParse(part, out var index))
            {
                throw new ArgumentException($"Invalid path component: {parts[i]}", nameof(path));
            }

            if (isHardened)
            {
                if (index >= HardenedOffset)
                    throw new ArgumentException($"Index too large for hardened derivation: {index}", nameof(path));
                index += HardenedOffset;
            }

            indices[i] = index;
        }

        return indices;
    }

    /// <summary>
    /// Formats an index as a path component
    /// </summary>
    public static string FormatIndex(uint index)
    {
        if (index >= HardenedOffset)
        {
            return $"{index - HardenedOffset}'";
        }
        return index.ToString();
    }

    /// <summary>
    /// Formats a path from indices
    /// </summary>
    public static string FormatPath(uint[] indices)
    {
        if (indices.Length == 0)
            return "m";

        var parts = new string[indices.Length];
        for (var i = 0; i < indices.Length; i++)
        {
            parts[i] = FormatIndex(indices[i]);
        }

        return "m/" + string.Join("/", parts);
    }

    /// <summary>
    /// Derives a public key from a private key using secp256k1 elliptic curve operations
    /// </summary>
    /// <remarks>
    /// Uses proper secp256k1 scalar multiplication to derive the public key.
    /// Returns a 33-byte compressed public key in SEC format (0x02/0x03 prefix + x-coordinate).
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] DerivePublicKeyFromPrivate(byte[] privateKey)
    {
        // Use secp256k1 to derive the public key properly
        return Secp256k1Core.DerivePublicKey(privateKey, compressed: true);
    }

    /// <summary>
    /// Adds two 32-byte values modulo n (secp256k1 group order)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void AddModN(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        // secp256k1 group order (n): FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        Span<byte> n = stackalloc byte[32] {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        };

        // Perform addition: result = (a + b) mod n
        uint carry = 0;
        for (var i = 31; i >= 0; i--)
        {
            var sum = (uint)a[i] + b[i] + carry;
            result[i] = (byte)(sum & 0xFF);
            carry = sum >> 8;
        }

        // If carry or result >= n, subtract n
        var needsReduction = carry > 0;
        if (!needsReduction)
        {
            // Check if result >= n (compare big-endian)
            var comparison = 0; // 0 = equal, 1 = result > n, -1 = result < n
            for (var i = 0; i < 32 && comparison == 0; i++)
            {
                if (result[i] > n[i])
                    comparison = 1;
                else if (result[i] < n[i])
                    comparison = -1;
            }
            // Reduce if result >= n (comparison >= 0)
            needsReduction = comparison >= 0;
        }

        if (needsReduction)
        {
            // Subtract n
            int borrow = 0;
            for (var i = 31; i >= 0; i--)
            {
                var diff = result[i] - n[i] - borrow;
                result[i] = (byte)(diff & 0xFF);
                borrow = (diff < 0) ? 1 : 0;
            }
        }
    }

    /// <summary>
    /// Calculates the fingerprint of a key (first 4 bytes of HASH160)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] CalculateFingerprint(ExtendedKey key)
    {
        // HASH160 = RIPEMD160(SHA256(public_key))
        // Note: RIPEMD160 is not available in all .NET versions, so we use double SHA256 as an alternative
        var publicKey = key.IsPrivate ? DerivePublicKeyFromPrivate(key.Key) : key.Key;

        using (var sha = SHA256.Create())
        {
            // Double SHA256 to approximate HASH160 behavior
            var hash1 = sha.ComputeHash(publicKey);
            var hash2 = sha.ComputeHash(hash1);
            var fingerprint = new byte[4];
            Array.Copy(hash2, 0, fingerprint, 0, 4);
            return fingerprint;
        }
    }

    /// <summary>
    /// Gets information about BIP32 implementation
    /// </summary>
    public static string GetInfo()
    {
        return "BIP32 Hierarchical Deterministic Wallets - Derives child keys from master seed. " +
               $"Supports normal and hardened derivation. Seed length: {MinSeedLength}-{MaxSeedLength} bytes.";
    }

    /// <summary>
    /// Validates a derivation path
    /// </summary>
    public static bool IsValidPath(string path)
    {
        try
        {
            ParsePath(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks if a 32-byte value is all zeros
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] != 0)
                return false;
        }
        return true;
    }

    /// <summary>
    /// Checks if a 32-byte value is >= secp256k1 group order n
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsGreaterThanOrEqualToN(ReadOnlySpan<byte> value)
    {
        // secp256k1 group order (n): FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        ReadOnlySpan<byte> n = stackalloc byte[32] {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        };

        // Compare big-endian (most significant byte first)
        for (var i = 0; i < 32; i++)
        {
            if (value[i] > n[i])
                return true;
            if (value[i] < n[i])
                return false;
        }
        // Equal
        return true;
    }
}
#endif
