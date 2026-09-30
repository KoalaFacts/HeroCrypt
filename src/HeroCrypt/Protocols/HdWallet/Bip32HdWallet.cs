using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Secp256k1;
using HeroCrypt.Security;
using Org.BouncyCastle.Crypto.Digests;

namespace HeroCrypt.Protocols.HdWallet;

#if !NETSTANDARD2_0

/// <summary>
/// BIP32 Hierarchical Deterministic Wallet implementation.
/// Supports BIP-0032 master generation and private-parent child derivation.
/// </summary>
/// <remarks>
/// <para><b>Key Features:</b></para>
/// <list type="bullet">
///   <item>Master key generation from seed (HMAC-SHA512)</item>
///   <item>Private-parent child key derivation (normal and hardened)</item>
///   <item>HASH160 parent fingerprints</item>
///   <item>Support for key paths (e.g., m/44'/0'/0'/0/0)</item>
/// </list>
/// <para><b>Standard:</b> BIP-0032 (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)</para>
/// <para>Private derivation uses the portable secp256k1 core on Windows, Linux and macOS.
/// Public-parent child derivation and xprv/xpub import/export are not supported.</para>
/// <para>Fingerprints are identifiers, not authentication. Compliance policy rejects
/// this construction. No managed-runtime constant-time or complete zeroization guarantee
/// is made; callers must protect and clear returned key material.</para>
/// </remarks>
public sealed class Bip32HdWallet
{
    private readonly SecurityPolicyOptions policy;

    /// <summary>
    /// Initializes a new instance of the Bip32HdWallet class.
    /// </summary>
    /// <param name="policy">Optional security policy. If null, uses SecurityPolicy.CurrentPolicy.</param>
    public Bip32HdWallet(SecurityPolicyOptions? policy = null)
    {
        this.policy = policy ?? SecurityPolicy.CurrentPolicy;
    }

    /// <summary>
    /// Hardened key offset (2^31). Use this to create hardened child indices.
    /// </summary>
    public const uint HardenedOffset = 0x80000000;

    private const int MinSeedLength = 16; // 128 bits
    private const int MaxSeedLength = 64; // 512 bits

    /// <summary>
    /// Master key generation constant for Bitcoin
    /// </summary>
    private const string BITCOIN_SEED = "Bitcoin seed";

    /// <summary>
    /// Represents an extended key (public or private) with chain code
    /// </summary>
    /// <remarks>Copies constructor inputs. Exposed arrays remain mutable and must not
    /// be modified concurrently with wallet operations. Clearing this object erases
    /// its owned buffers, not the constructor's input buffers.</remarks>
    public class ExtendedKey
    {
        /// <summary>
        /// Owned key data (32 bytes for private, 33 bytes for compressed public).
        /// The array is mutable; operations revalidate it before use.
        /// </summary>
        public byte[] Key { get; }

        /// <summary>
        /// Owned chain code (32 bytes). Treat it as sensitive key material.
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

        /// <summary>
        /// Initializes a new instance of the ExtendedKey class.
        /// </summary>
        /// <param name="key">The key bytes (32 bytes for private, 33 bytes for public)</param>
        /// <param name="chainCode">The chain code (32 bytes)</param>
        /// <param name="depth">The depth level in the key hierarchy</param>
        /// <param name="parentFingerprint">The parent key fingerprint</param>
        /// <param name="childIndex">The child key index</param>
        public ExtendedKey(byte[] key, byte[] chainCode, byte depth = 0,
            byte[]? parentFingerprint = null, uint childIndex = 0)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(chainCode);
            ValidateKeyMaterial(key);
            if (chainCode.Length != 32)
            {
                throw new ArgumentException("Chain code must be 32 bytes", nameof(chainCode));
            }

            var fingerprint = parentFingerprint ?? new byte[4];
            ValidateMetadata(depth, fingerprint, childIndex);

            // Own copies so clearing this key cannot erase the caller's buffers.
            Key = key.ToArray();
            ChainCode = chainCode.ToArray();
            Depth = depth;
            ParentFingerprint = fingerprint.ToArray();
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
    /// <param name="keyType">HMAC domain (default: "Bitcoin seed"). Other values produce
    /// a custom derivation, not standard BIP32 master keys.</param>
    /// <returns>Master extended private key</returns>
    public ExtendedKey GenerateMasterKey(ReadOnlySpan<byte> seed, string keyType = BITCOIN_SEED)
    {
        if (seed.Length is < MinSeedLength or > MaxSeedLength)
        {
            throw new ArgumentException($"Seed must be between {MinSeedLength} and {MaxSeedLength} bytes", nameof(seed));
        }

        policy.ValidateSignature("SECP256K1");
        policy.ValidateHash("SHA512");

        // Compute I = HMAC-SHA512(Key = keyType, Data = seed)
        var hmacKey = Encoding.UTF8.GetBytes(keyType);
        Span<byte> hmacResult = stackalloc byte[64];
        byte[]? masterKey = null;
        byte[]? chainCode = null;

        try
        {
            using (var hmac = new HMACSHA512(hmacKey))
            {
                hmac.TryComputeHash(seed, hmacResult, out _);
            }

            // Split into master private key (IL) and chain code (IR)
            masterKey = hmacResult.Slice(0, 32).ToArray();
            chainCode = hmacResult.Slice(32, 32).ToArray();

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
            SecureMemoryOperations.SecureClear(hmacKey);
            if (masterKey != null) SecureMemoryOperations.SecureClear(masterKey);
            if (chainCode != null) SecureMemoryOperations.SecureClear(chainCode);
        }
    }

    /// <summary>
    /// Derives a child key from a parent key
    /// </summary>
    /// <param name="parent">Parent extended key</param>
    /// <param name="index">Child index (use values >= HardenedOffset for hardened derivation)</param>
    /// <returns>Derived child key</returns>
    /// <exception cref="NotSupportedException">The parent is a public key.</exception>
    /// <exception cref="InvalidOperationException">Depth would exceed 255 or the
    /// derived scalar is invalid. For an invalid scalar, retry with the next index.</exception>
    public ExtendedKey DeriveChild(ExtendedKey parent, uint index)
    {
        ArgumentNullException.ThrowIfNull(parent);
        ValidateKeyMaterial(parent.Key);
        ValidateMetadata(parent.Depth, parent.ParentFingerprint, parent.ChildIndex);
        policy.ValidateSignature("SECP256K1");
        policy.ValidateHash("SHA512");
        policy.ValidateHash("SHA256");
        policy.ValidateHash("RIPEMD160");

        if (!parent.IsPrivate)
        {
            throw new NotSupportedException("BIP32 public-parent child derivation is not supported.");
        }
        if (parent.Depth == byte.MaxValue)
        {
            throw new InvalidOperationException("BIP32 child depth cannot exceed 255.");
        }

        Span<byte> data = stackalloc byte[37];
        Span<byte> hmacResult = stackalloc byte[64];
        byte[]? childKey = null;
        byte[]? childChainCode = null;
        try
        {
            if (index >= HardenedOffset)
            {
                data[0] = 0;
                parent.Key.CopyTo(data.Slice(1, 32));
            }
            else
            {
                DerivePublicKeyFromPrivate(parent.Key).CopyTo(data);
            }
            BinaryPrimitives.WriteUInt32BigEndian(data.Slice(33, 4), index);

            using (var hmac = new HMACSHA512(parent.ChainCode))
            {
                hmac.TryComputeHash(data, hmacResult, out _);
            }

            var left = hmacResult.Slice(0, 32);
            if (IsGreaterThanOrEqualToN(left))
            {
                throw new InvalidOperationException($"Invalid child key at index {index}: IL >= n. Try the next index.");
            }

            childKey = new byte[32];
            AddModN(left, parent.Key, childKey);
            if (IsZero(childKey))
            {
                throw new InvalidOperationException($"Invalid child key at index {index}: derived key is zero. Try the next index.");
            }
            childChainCode = hmacResult.Slice(32, 32).ToArray();

            return new ExtendedKey(childKey, childChainCode, (byte)(parent.Depth + 1),
                CalculateFingerprint(parent), index);
        }
        finally
        {
            SecureMemoryOperations.SecureClear(hmacResult);
            SecureMemoryOperations.SecureClear(data);
            if (childKey != null) SecureMemoryOperations.SecureClear(childKey);
            if (childChainCode != null) SecureMemoryOperations.SecureClear(childChainCode);
        }
    }

    /// <summary>
    /// Derives a key using a derivation path (e.g., "m/44'/0'/0'/0/0")
    /// </summary>
    /// <param name="masterKey">Master extended key</param>
    /// <param name="path">Derivation path</param>
    /// <returns>Derived key</returns>
    public ExtendedKey DerivePath(ExtendedKey masterKey, string path)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        ValidateKeyMaterial(masterKey.Key);
        ValidateMetadata(masterKey.Depth, masterKey.ParentFingerprint, masterKey.ChildIndex);
        policy.ValidateSignature("SECP256K1");
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be empty", nameof(path));
        }

        var indices = ParsePath(path);
        if (indices.Length > byte.MaxValue - masterKey.Depth)
        {
            throw new ArgumentException("BIP32 path would exceed depth 255", nameof(path));
        }
        var currentKey = masterKey;

        try
        {
            foreach (var index in indices)
            {
                var nextKey = DeriveChild(currentKey, index);
                if (currentKey != masterKey)
                {
                    currentKey.Clear();
                }
                currentKey = nextKey;
            }
            return currentKey;
        }
        catch
        {
            // Own intermediate keys, but never erase the caller's root.
            if (currentKey != masterKey) currentKey.Clear();
            throw;
        }
    }

    /// <summary>
    /// Parses a BIP32 derivation path into indices
    /// </summary>
    /// <remarks>Numeric components range from 0 to 2147483647. Hardened components
    /// require an apostrophe, h or H suffix. Whitespace and signed numbers are rejected.
    /// Paths may be relative or begin with m/ or M/.</remarks>
    /// <param name="path">Path string (e.g., "m/44'/0'/0'/0/0")</param>
    /// <returns>Array of child indices</returns>
    public uint[] ParsePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be empty", nameof(path));
        }

        // Remove "m/" or "M/" prefix if present
        if (path.StartsWith("m/", StringComparison.OrdinalIgnoreCase))
        {
            path = path.Substring(2);
        }
        else if (path.Equals("m", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        var parts = path.Split('/');
        var indices = new uint[parts.Length];

        for (var i = 0; i < parts.Length; i++)
        {
            var part = parts[i];
            var isHardened = part.EndsWith('\'') || part.EndsWith('h') || part.EndsWith('H');

            if (isHardened)
            {
                part = part.Substring(0, part.Length - 1);
            }

            if (!uint.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var index)
                || index >= HardenedOffset)
            {
                throw new ArgumentException($"Invalid path component: {parts[i]}", nameof(path));
            }

            if (isHardened)
            {
                index += HardenedOffset;
            }

            indices[i] = index;
        }

        return indices;
    }

    /// <summary>
    /// Formats an index as a path component
    /// </summary>
    public string FormatIndex(uint index)
    {
        if (index >= HardenedOffset)
        {
            return $"{index - HardenedOffset}'";
        }
        return index.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Formats a path from indices
    /// </summary>
    public string FormatPath(uint[] indices)
    {
        ArgumentNullException.ThrowIfNull(indices);
        if (indices.Length == 0)
        {
            return "m";
        }

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
    /// Uses the portable secp256k1 core with this wallet's security policy.
    /// Returns a 33-byte compressed public key in SEC format (0x02/0x03 prefix + x-coordinate).
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private byte[] DerivePublicKeyFromPrivate(byte[] privateKey) =>
        new Secp256k1Core(policy).DerivePublicKey(privateKey, compressed: true);

    /// <summary>
    /// Adds two 32-byte values modulo n (secp256k1 group order)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void AddModN(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        // secp256k1 group order (n): FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        Span<byte> n =
        [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        ];

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
                {
                    comparison = 1;
                }
                else if (result[i] < n[i])
                {
                    comparison = -1;
                }
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
    private byte[] CalculateFingerprint(ExtendedKey key)
    {
        // HASH160 = RIPEMD160(SHA256(public_key))
        var publicKey = key.IsPrivate ? DerivePublicKeyFromPrivate(key.Key) : key.Key;

        var sha256 = SHA256.HashData(publicKey);
        var digest = new RipeMD160Digest();
        digest.BlockUpdate(sha256, 0, sha256.Length);
        var hash160 = new byte[digest.GetDigestSize()];
        digest.DoFinal(hash160, 0);
        return hash160.AsSpan(0, 4).ToArray();
    }

    private static void ValidateKeyMaterial(byte[] key)
    {
        if (key.Length == 32)
        {
            if (IsZero(key) || IsGreaterThanOrEqualToN(key))
            {
                throw new ArgumentException("Private key must be in the range 1..n-1", nameof(key));
            }
            return;
        }
        if (key.Length != 33 || key[0] is not 0x02 and not 0x03)
        {
            throw new ArgumentException("Key must be a 32-byte private scalar or a 33-byte compressed public point", nameof(key));
        }
        try
        {
            // Point decoding validates the curve equation without performing a wallet operation.
            _ = new Secp256k1Core().DecompressPublicKey(key);
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException("Invalid secp256k1 public point", nameof(key), exception);
        }
    }

    private static void ValidateMetadata(byte depth, byte[] parentFingerprint, uint childIndex)
    {
        if (parentFingerprint.Length != 4)
        {
            throw new ArgumentException("Parent fingerprint must be 4 bytes", nameof(parentFingerprint));
        }
        if (depth == 0 && (childIndex != 0 || !IsZero(parentFingerprint)))
        {
            throw new ArgumentException("Master keys must have a zero parent fingerprint and child index");
        }
    }

    /// <summary>
    /// Validates a derivation path
    /// </summary>
    public bool IsValidPath(string path)
    {
        try
        {
            ParsePath(path);
            return true;
        }
        catch (ArgumentException)
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
            {
                return false;
            }
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
        ReadOnlySpan<byte> n =
        [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        ];

        // Compare big-endian (most significant byte first)
        for (var i = 0; i < 32; i++)
        {
            if (value[i] > n[i])
            {
                return true;
            }
            if (value[i] < n[i])
            {
                return false;
            }
        }
        // Equal
        return true;
    }
}
#endif
