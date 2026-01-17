using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a Public Key Packet (Tag 6) or Public Subkey Packet (Tag 14) as defined in RFC 4880 Section 5.5.2.
/// </summary>
/// <remarks>
/// <para>
/// Public key packets contain the public key material for cryptographic operations.
/// Primary keys (Tag 6) establish the key identity, while subkeys (Tag 14) provide
/// additional capabilities bound to the primary key.
/// </para>
/// <para>
/// <b>Version 4 Wire format (RFC 4880):</b>
/// <code>
/// +----+---------+------+------------------+
/// |Ver |CreatTime|PubAlg| Key Material     |
/// |1 B | 4 B     | 1 B  | variable         |
/// +----+---------+------+------------------+
/// </code>
/// </para>
/// <para>
/// <b>Version 6 Wire format (RFC 9580):</b>
/// <code>
/// +----+---------+------+------+------------------+
/// |Ver |CreatTime|PubAlg|KeyLen| Key Material     |
/// |1 B | 4 B     | 1 B  | 4 B  | variable         |
/// +----+---------+------+------+------------------+
/// </code>
/// </para>
/// </remarks>
public readonly struct PgpPublicKeyPacket
{
    /// <summary>
    /// Gets the key packet version (4 or 6).
    /// </summary>
    public byte Version { get; }

    /// <summary>
    /// Gets the key creation time.
    /// </summary>
    public DateTimeOffset CreationTime { get; }

    /// <summary>
    /// Gets the public key algorithm.
    /// </summary>
    public PgpPublicKeyAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the raw public key material (algorithm-specific format).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The format depends on the algorithm:
    /// <list type="bullet">
    ///   <item><b>RSA:</b> n (MPI) + e (MPI)</item>
    ///   <item><b>DSA:</b> p + q + g + y (MPIs)</item>
    ///   <item><b>Elgamal:</b> p + g + y (MPIs)</item>
    ///   <item><b>ECDSA/ECDH:</b> OID length + OID + Q (MPI) [+ KDF params for ECDH]</item>
    ///   <item><b>Ed25519/X25519:</b> 32-byte raw public key</item>
    ///   <item><b>Ed448/X448:</b> 57/56-byte raw public key</item>
    /// </list>
    /// </para>
    /// </remarks>
    public ReadOnlyMemory<byte> KeyMaterial { get; }

    /// <summary>
    /// Gets whether this is a subkey packet (Tag 14) rather than a primary key packet (Tag 6).
    /// </summary>
    public bool IsSubkey { get; }

    /// <summary>
    /// Initializes a new public key packet.
    /// </summary>
    /// <param name="version">The key version (4 or 6).</param>
    /// <param name="creationTime">The key creation time.</param>
    /// <param name="algorithm">The public key algorithm.</param>
    /// <param name="keyMaterial">The raw public key material.</param>
    /// <param name="isSubkey">Whether this is a subkey packet.</param>
    public PgpPublicKeyPacket(
        byte version,
        DateTimeOffset creationTime,
        PgpPublicKeyAlgorithm algorithm,
        ReadOnlyMemory<byte> keyMaterial,
        bool isSubkey = false)
    {
        if (version != 4 && version != 6)
        {
            throw new ArgumentException("Only key versions 4 and 6 are supported.", nameof(version));
        }

        Version = version;
        CreationTime = creationTime;
        Algorithm = algorithm;
        KeyMaterial = keyMaterial;
        IsSubkey = isSubkey;
    }

    /// <summary>
    /// Creates a version 4 public key packet.
    /// </summary>
    /// <param name="creationTime">The key creation time.</param>
    /// <param name="algorithm">The public key algorithm.</param>
    /// <param name="keyMaterial">The raw public key material.</param>
    /// <param name="isSubkey">Whether this is a subkey packet.</param>
    /// <returns>A new version 4 public key packet.</returns>
    public static PgpPublicKeyPacket CreateV4(
        DateTimeOffset creationTime,
        PgpPublicKeyAlgorithm algorithm,
        ReadOnlyMemory<byte> keyMaterial,
        bool isSubkey = false)
    {
        return new PgpPublicKeyPacket(4, creationTime, algorithm, keyMaterial, isSubkey);
    }

    /// <summary>
    /// Creates a version 6 public key packet (RFC 9580).
    /// </summary>
    /// <param name="creationTime">The key creation time.</param>
    /// <param name="algorithm">The public key algorithm.</param>
    /// <param name="keyMaterial">The raw public key material.</param>
    /// <param name="isSubkey">Whether this is a subkey packet.</param>
    /// <returns>A new version 6 public key packet.</returns>
    public static PgpPublicKeyPacket CreateV6(
        DateTimeOffset creationTime,
        PgpPublicKeyAlgorithm algorithm,
        ReadOnlyMemory<byte> keyMaterial,
        bool isSubkey = false)
    {
        return new PgpPublicKeyPacket(6, creationTime, algorithm, keyMaterial, isSubkey);
    }

    /// <summary>
    /// Creates an RSA public key packet with the given parameters.
    /// </summary>
    /// <param name="version">The key version (4 or 6).</param>
    /// <param name="creationTime">The key creation time.</param>
    /// <param name="modulus">The RSA modulus (n).</param>
    /// <param name="exponent">The RSA public exponent (e).</param>
    /// <param name="isSubkey">Whether this is a subkey packet.</param>
    /// <returns>A new RSA public key packet.</returns>
    public static PgpPublicKeyPacket CreateRsa(
        byte version,
        DateTimeOffset creationTime,
        BigInteger modulus,
        BigInteger exponent,
        bool isSubkey = false)
    {
        int nLen = Mpi.GetEncodedLength(modulus);
        int eLen = Mpi.GetEncodedLength(exponent);
        byte[] keyMaterial = new byte[nLen + eLen];

        int offset = Mpi.Write(modulus, keyMaterial);
        Mpi.Write(exponent, keyMaterial.AsSpan(offset));

        return new PgpPublicKeyPacket(version, creationTime, PgpPublicKeyAlgorithm.RsaEncryptOrSign, keyMaterial, isSubkey);
    }

    /// <summary>
    /// Creates an Ed25519 public key packet (RFC 9580 native format).
    /// </summary>
    /// <param name="creationTime">The key creation time.</param>
    /// <param name="publicKey">The 32-byte Ed25519 public key.</param>
    /// <param name="isSubkey">Whether this is a subkey packet.</param>
    /// <returns>A new Ed25519 public key packet.</returns>
    public static PgpPublicKeyPacket CreateEd25519(
        DateTimeOffset creationTime,
        ReadOnlySpan<byte> publicKey,
        bool isSubkey = false)
    {
        if (publicKey.Length != 32)
        {
            throw new ArgumentException("Ed25519 public key must be 32 bytes.", nameof(publicKey));
        }

        return new PgpPublicKeyPacket(6, creationTime, PgpPublicKeyAlgorithm.Ed25519, publicKey.ToArray(), isSubkey);
    }

    /// <summary>
    /// Creates an X25519 public key packet (RFC 9580 native format).
    /// </summary>
    /// <param name="creationTime">The key creation time.</param>
    /// <param name="publicKey">The 32-byte X25519 public key.</param>
    /// <param name="isSubkey">Whether this is a subkey packet.</param>
    /// <returns>A new X25519 public key packet.</returns>
    public static PgpPublicKeyPacket CreateX25519(
        DateTimeOffset creationTime,
        ReadOnlySpan<byte> publicKey,
        bool isSubkey = false)
    {
        if (publicKey.Length != 32)
        {
            throw new ArgumentException("X25519 public key must be 32 bytes.", nameof(publicKey));
        }

        return new PgpPublicKeyPacket(6, creationTime, PgpPublicKeyAlgorithm.X25519, publicKey.ToArray(), isSubkey);
    }

    /// <summary>
    /// Creates an ECDSA public key packet with OID encoding (RFC 6637).
    /// </summary>
    /// <param name="version">The key version (4 or 6).</param>
    /// <param name="creationTime">The key creation time.</param>
    /// <param name="curveOid">The curve OID.</param>
    /// <param name="publicPoint">The public point Q as uncompressed point (04 || X || Y) or compressed.</param>
    /// <param name="isSubkey">Whether this is a subkey packet.</param>
    /// <returns>A new ECDSA public key packet.</returns>
    public static PgpPublicKeyPacket CreateEcdsa(
        byte version,
        DateTimeOffset creationTime,
        PgpCurveOid curveOid,
        ReadOnlySpan<byte> publicPoint,
        bool isSubkey = false)
    {
        byte[] oid = curveOid.GetOidBytes();
        int qMpiLen = Mpi.GetEncodedLength(publicPoint);
        byte[] keyMaterial = new byte[1 + oid.Length + qMpiLen];

        int offset = 0;
        keyMaterial[offset++] = (byte)oid.Length;
        oid.CopyTo(keyMaterial.AsSpan(offset));
        offset += oid.Length;
        Mpi.Write(publicPoint, keyMaterial.AsSpan(offset));

        return new PgpPublicKeyPacket(version, creationTime, PgpPublicKeyAlgorithm.Ecdsa, keyMaterial, isSubkey);
    }

    /// <summary>
    /// Reads a public key packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="isSubkey">Whether this is a subkey packet (Tag 14).</param>
    /// <returns>The parsed public key packet.</returns>
    /// <exception cref="ArgumentException">If the source is too short or malformed.</exception>
    public static PgpPublicKeyPacket Read(ReadOnlySpan<byte> source, bool isSubkey = false)
    {
        if (!TryRead(source, isSubkey, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a public key packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="isSubkey">Whether this is a subkey packet (Tag 14).</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, bool isSubkey, out PgpPublicKeyPacket packet, out string error)
    {
        packet = default;

        if (source.Length < 1)
        {
            error = "Source too short for public key packet version.";
            return false;
        }

        byte version = source[0];
        if (version == 4)
        {
            return TryReadV4(source, isSubkey, out packet, out error);
        }

        if (version == 6)
        {
            return TryReadV6(source, isSubkey, out packet, out error);
        }

        error = $"Unsupported public key version: {version}. Only versions 4 and 6 are supported.";
        return false;
    }

    private static bool TryReadV4(ReadOnlySpan<byte> source, bool isSubkey, out PgpPublicKeyPacket packet, out string error)
    {
        packet = default;
        error = string.Empty;

        // Minimum: version(1) + creation(4) + algorithm(1) = 6 bytes
        if (source.Length < 6)
        {
            error = "Source too short for v4 public key packet header.";
            return false;
        }

        int offset = 0;

        byte version = source[offset++];
        uint creationTimestamp = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(offset));
        offset += 4;
        var algorithm = (PgpPublicKeyAlgorithm)source[offset++];

        var creationTime = DateTimeOffset.FromUnixTimeSeconds(creationTimestamp);

        // Remaining data is key material
        var keyMaterial = source.Slice(offset).ToArray();

        packet = new PgpPublicKeyPacket(version, creationTime, algorithm, keyMaterial, isSubkey);
        return true;
    }

    private static bool TryReadV6(ReadOnlySpan<byte> source, bool isSubkey, out PgpPublicKeyPacket packet, out string error)
    {
        packet = default;
        error = string.Empty;

        // Minimum: version(1) + creation(4) + algorithm(1) + keylen(4) = 10 bytes
        if (source.Length < 10)
        {
            error = "Source too short for v6 public key packet header.";
            return false;
        }

        int offset = 0;

        byte version = source[offset++];
        uint creationTimestamp = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(offset));
        offset += 4;
        var algorithm = (PgpPublicKeyAlgorithm)source[offset++];
        uint keyLength = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(offset));
        offset += 4;

        if (keyLength > int.MaxValue || source.Length < offset + (int)keyLength)
        {
            error = $"Source too short for key material. Expected {keyLength} bytes.";
            return false;
        }

        var creationTime = DateTimeOffset.FromUnixTimeSeconds(creationTimestamp);
        var keyMaterial = source.Slice(offset, (int)keyLength).ToArray();

        packet = new PgpPublicKeyPacket(version, creationTime, algorithm, keyMaterial, isSubkey);
        return true;
    }

    /// <summary>
    /// Gets the total encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        if (Version == 4)
        {
            // version(1) + creation(4) + algorithm(1) + key material
            return 1 + 4 + 1 + KeyMaterial.Length;
        }
        else
        {
            // version(1) + creation(4) + algorithm(1) + keylen(4) + key material
            return 1 + 4 + 1 + 4 + KeyMaterial.Length;
        }
    }

    /// <summary>
    /// Writes the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public int Write(Span<byte> destination)
    {
        int encodedLength = GetEncodedLength();
        if (destination.Length < encodedLength)
        {
            throw new ArgumentException($"Destination too small. Need {encodedLength} bytes.", nameof(destination));
        }

        int offset = 0;

        // Write header
        destination[offset++] = Version;
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset), (uint)CreationTime.ToUnixTimeSeconds());
        offset += 4;
        destination[offset++] = (byte)Algorithm;

        if (Version == 6)
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(offset), (uint)KeyMaterial.Length);
            offset += 4;
        }

        // Write key material
        KeyMaterial.Span.CopyTo(destination.Slice(offset));
        offset += KeyMaterial.Length;

        return offset;
    }

    /// <summary>
    /// Writes the packet body to a byte array.
    /// </summary>
    /// <returns>The encoded packet body.</returns>
    public byte[] ToArray()
    {
        byte[] result = new byte[GetEncodedLength()];
        Write(result);
        return result;
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        var tag = IsSubkey ? PgpPacketTag.PublicSubkey : PgpPacketTag.PublicKey;
        writer.WritePacket(tag, body, format);
    }

    /// <summary>
    /// Computes the key fingerprint (SHA-256 for v6, SHA-1 for v4).
    /// </summary>
    /// <returns>The key fingerprint bytes.</returns>
    public byte[] ComputeFingerprint()
    {
        if (Version == 6)
        {
            return ComputeV6Fingerprint();
        }
        else
        {
            return ComputeV4Fingerprint();
        }
    }

    // SHA-1 is required by RFC 4880 for v4 key fingerprints - not a security choice
#pragma warning disable CA5350 // Do not use weak cryptographic algorithms
    private byte[] ComputeV4Fingerprint()
    {
        // V4 fingerprint = SHA-1(0x99 || 2-byte packet length || packet body)
        byte[] body = ToArray();
        byte[] hashInput = new byte[3 + body.Length];

        hashInput[0] = 0x99;
        BinaryPrimitives.WriteUInt16BigEndian(hashInput.AsSpan(1), (ushort)body.Length);
        body.CopyTo(hashInput.AsSpan(3));

#if NETSTANDARD2_0
        using var sha1 = SHA1.Create();
        return sha1.ComputeHash(hashInput);
#else
        return SHA1.HashData(hashInput);
#endif
    }
#pragma warning restore CA5350

    private byte[] ComputeV6Fingerprint()
    {
        // V6 fingerprint = SHA-256(0x9B || 4-byte packet length || packet body)
        byte[] body = ToArray();
        byte[] hashInput = new byte[5 + body.Length];

        hashInput[0] = 0x9B;
        BinaryPrimitives.WriteUInt32BigEndian(hashInput.AsSpan(1), (uint)body.Length);
        body.CopyTo(hashInput.AsSpan(5));

#if NETSTANDARD2_0
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(hashInput);
#else
        return SHA256.HashData(hashInput);
#endif
    }

    /// <summary>
    /// Gets the key ID (last 8 bytes of fingerprint for v4, first 8 bytes for v6).
    /// </summary>
    /// <returns>The 8-byte key ID.</returns>
    public byte[] GetKeyId()
    {
        byte[] fingerprint = ComputeFingerprint();

        if (Version == 6)
        {
            // V6: first 8 bytes of fingerprint
            byte[] keyId = new byte[8];
            Array.Copy(fingerprint, 0, keyId, 0, 8);
            return keyId;
        }
        else
        {
            // V4: last 8 bytes of fingerprint
            byte[] keyId = new byte[8];
            Array.Copy(fingerprint, fingerprint.Length - 8, keyId, 0, 8);
            return keyId;
        }
    }

    /// <summary>
    /// Reads RSA key material (n, e).
    /// </summary>
    /// <returns>A tuple of (modulus n, exponent e).</returns>
    /// <exception cref="InvalidOperationException">If the algorithm is not RSA.</exception>
    public (BigInteger N, BigInteger E) ReadRsaKey()
    {
        if (Algorithm != PgpPublicKeyAlgorithm.RsaEncryptOrSign &&
#pragma warning disable CS0618 // Obsolete member
            Algorithm != PgpPublicKeyAlgorithm.RsaEncryptOnly &&
            Algorithm != PgpPublicKeyAlgorithm.RsaSignOnly)
#pragma warning restore CS0618
        {
            throw new InvalidOperationException($"Cannot read RSA key from algorithm {Algorithm}.");
        }

        var span = KeyMaterial.Span;
        var n = Mpi.Read(span, out int consumed);
        var e = Mpi.Read(span.Slice(consumed), out _);
        return (n, e);
    }

    /// <summary>
    /// Reads DSA key material (p, q, g, y).
    /// </summary>
    /// <returns>A tuple of DSA parameters.</returns>
    /// <exception cref="InvalidOperationException">If the algorithm is not DSA.</exception>
    public (BigInteger P, BigInteger Q, BigInteger G, BigInteger Y) ReadDsaKey()
    {
        if (Algorithm != PgpPublicKeyAlgorithm.Dsa)
        {
            throw new InvalidOperationException($"Cannot read DSA key from algorithm {Algorithm}.");
        }

        var span = KeyMaterial.Span;
        int offset = 0;

        var p = Mpi.Read(span.Slice(offset), out int consumed);
        offset += consumed;
        var q = Mpi.Read(span.Slice(offset), out consumed);
        offset += consumed;
        var g = Mpi.Read(span.Slice(offset), out consumed);
        offset += consumed;
        var y = Mpi.Read(span.Slice(offset), out _);

        return (p, q, g, y);
    }

    /// <summary>
    /// Reads Elgamal key material (p, g, y).
    /// </summary>
    /// <returns>A tuple of Elgamal parameters.</returns>
    /// <exception cref="InvalidOperationException">If the algorithm is not Elgamal.</exception>
    public (BigInteger P, BigInteger G, BigInteger Y) ReadElgamalKey()
    {
        if (Algorithm != PgpPublicKeyAlgorithm.ElgamalEncryptOnly)
        {
            throw new InvalidOperationException($"Cannot read Elgamal key from algorithm {Algorithm}.");
        }

        var span = KeyMaterial.Span;
        int offset = 0;

        var p = Mpi.Read(span.Slice(offset), out int consumed);
        offset += consumed;
        var g = Mpi.Read(span.Slice(offset), out consumed);
        offset += consumed;
        var y = Mpi.Read(span.Slice(offset), out _);

        return (p, g, y);
    }

    /// <summary>
    /// Reads EC key material with OID (ECDSA, ECDH, EdDSA-legacy).
    /// </summary>
    /// <returns>A tuple of (OID bytes, public point Q as MPI bytes).</returns>
    /// <exception cref="InvalidOperationException">If the algorithm doesn't use OID encoding.</exception>
    public (byte[] Oid, byte[] PublicPoint) ReadEcKeyWithOid()
    {
        if (!Algorithm.UsesOidEncoding())
        {
            throw new InvalidOperationException($"Algorithm {Algorithm} does not use OID encoding.");
        }

        var span = KeyMaterial.Span;

        if (span.Length < 2)
        {
            throw new InvalidOperationException("Key material too short for OID.");
        }

        int oidLength = span[0];
        if (span.Length < 1 + oidLength + 2)
        {
            throw new InvalidOperationException("Key material too short for OID and public point.");
        }

        var oid = span.Slice(1, oidLength).ToArray();
        var publicPoint = Mpi.ReadBytes(span.Slice(1 + oidLength), out _);

        return (oid, publicPoint);
    }

    /// <summary>
    /// Reads ECDH key material including KDF parameters.
    /// </summary>
    /// <returns>A tuple of (OID bytes, public point Q, hash algorithm, cipher algorithm).</returns>
    /// <exception cref="InvalidOperationException">If the algorithm is not ECDH.</exception>
    public (byte[] Oid, byte[] PublicPoint, byte HashAlgorithm, byte CipherAlgorithm) ReadEcdhKey()
    {
        if (Algorithm != PgpPublicKeyAlgorithm.Ecdh)
        {
            throw new InvalidOperationException($"Cannot read ECDH key from algorithm {Algorithm}.");
        }

        var span = KeyMaterial.Span;

        if (span.Length < 2)
        {
            throw new InvalidOperationException("Key material too short for OID.");
        }

        int oidLength = span[0];
        int offset = 1 + oidLength;

        var oid = span.Slice(1, oidLength).ToArray();
        var publicPoint = Mpi.ReadBytes(span.Slice(offset), out int consumed);
        offset += consumed;

        // KDF parameters: 03 01 hash cipher
        if (span.Length < offset + 4 || span[offset] != 0x03 || span[offset + 1] != 0x01)
        {
            throw new InvalidOperationException("Invalid or missing KDF parameters.");
        }

        byte hashAlgorithm = span[offset + 2];
        byte cipherAlgorithm = span[offset + 3];

        return (oid, publicPoint, hashAlgorithm, cipherAlgorithm);
    }

    /// <summary>
    /// Reads native format public key (Ed25519, X25519, Ed448, X448).
    /// </summary>
    /// <returns>The raw public key bytes.</returns>
    /// <exception cref="InvalidOperationException">If the algorithm doesn't use native format.</exception>
    public byte[] ReadNativePublicKey()
    {
        if (!Algorithm.UsesNativeFormat())
        {
            throw new InvalidOperationException($"Algorithm {Algorithm} does not use native format.");
        }

        int expectedSize = Algorithm.GetNativePublicKeySize();
        if (KeyMaterial.Length != expectedSize)
        {
            throw new InvalidOperationException($"Invalid key size. Expected {expectedSize}, got {KeyMaterial.Length}.");
        }

        return KeyMaterial.ToArray();
    }

    /// <summary>
    /// Returns a string representation of this packet.
    /// </summary>
    public override string ToString()
    {
        var keyType = IsSubkey ? "Subkey" : "Key";
        var fingerprint = Convert.ToHexString(GetKeyId());
        return $"Public{keyType}(v{Version}, {Algorithm}, {CreationTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}, ID:{fingerprint})";
    }
}
