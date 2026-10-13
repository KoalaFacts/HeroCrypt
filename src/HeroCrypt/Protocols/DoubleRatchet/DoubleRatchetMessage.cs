using System.Buffers.Binary;
using HeroCrypt.Polyfills;

namespace HeroCrypt.Protocols.DoubleRatchet;

/// <summary>An immutable versioned Double Ratchet message.</summary>
public sealed class DoubleRatchetMessage
{
    internal const int HeaderSize = 53;
    internal const int MaxPayloadSize = 16 * 1024 * 1024;
    private readonly byte[] encoded;

    private DoubleRatchetMessage(byte[] encoded)
    {
        this.encoded = encoded;
    }

    /// <summary>The sender's X25519 ratchet public key.</summary>
    public byte[] RatchetPublicKey => encoded.AsSpan(1, 32).ToArray();
    /// <summary>The previous sending chain's length.</summary>
    public uint PreviousChainLength => BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(33, 4));
    /// <summary>The message number in the current sending chain.</summary>
    public uint MessageNumber => BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(37, 4));
    /// <summary>The AEAD nonce.</summary>
    public byte[] Nonce => encoded.AsSpan(41, 12).ToArray();
    /// <summary>The ciphertext and appended authentication tag.</summary>
    public byte[] Ciphertext => CiphertextSpan.ToArray();
    /// <summary>Parses a versioned message, copying the input.</summary>
    /// <exception cref="ArgumentException">The version, encoding or size is invalid.</exception>
    public static DoubleRatchetMessage FromBytes(byte[] encoded)
    {
        ArgumentHelper.ThrowIfNull(encoded);
        if (encoded.Length < HeaderSize + 16 || encoded.Length > HeaderSize + 16 + MaxPayloadSize)
            throw new ArgumentException("Invalid Double Ratchet message size.", nameof(encoded));
        var owned = encoded.AsSpan().ToArray();
        if (owned[0] != 1) throw new ArgumentException("Unsupported Double Ratchet message version.", nameof(encoded));
        ValidatePublicKey(owned.AsSpan(1, 32));
        return new DoubleRatchetMessage(owned);
    }
    /// <summary>Returns an owned copy of the serialized message.</summary>
    public byte[] ToBytes() => encoded.AsSpan().ToArray();

    internal ReadOnlySpan<byte> Header => encoded.AsSpan(0, HeaderSize);
    internal ReadOnlySpan<byte> CiphertextSpan => encoded.AsSpan(HeaderSize);
    internal ReadOnlySpan<byte> NonceSpan => encoded.AsSpan(41, 12);

    internal static byte[] CreateHeader(byte[] publicKey, uint previous, uint number, byte[] nonce)
    {
        var header = new byte[HeaderSize];
        header[0] = 1;
        publicKey.CopyTo(header, 1);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(33, 4), previous);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(37, 4), number);
        nonce.CopyTo(header, 41);
        return header;
    }

    internal static DoubleRatchetMessage Create(byte[] header, byte[] ciphertext)
    {
        var output = new byte[HeaderSize + ciphertext.Length];
        header.CopyTo(output, 0);
        ciphertext.CopyTo(output, HeaderSize);
        return new DoubleRatchetMessage(output);
    }

    internal static void ValidatePublicKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32 || (key[31] & 0x80) != 0)
            throw new ArgumentException("X25519 public key must be a canonical 32-byte coordinate.", nameof(key));
        // Canonical little-endian coordinate must be less than 2^255 - 19.
        for (var i = 31; i >= 0; i--)
        {
            var primeByte = i == 31 ? 0x7F : i == 0 ? 0xED : 0xFF;
            if (key[i] < primeByte) return;
            if (key[i] > primeByte) break;
        }
        throw new ArgumentException("X25519 public key coordinate is outside the canonical field range.", nameof(key));
    }
}
