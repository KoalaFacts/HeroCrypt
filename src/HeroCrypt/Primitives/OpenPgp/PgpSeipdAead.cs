using System.Buffers.Binary;
using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>RFC 9580 SEIPD v2 AES-GCM framing and authentication.</summary>
internal static class PgpSeipdAead
{
    internal const byte DefaultChunkSize = 6; // 2^(6 + 6) = 4096 bytes.

    internal static byte[] Encrypt(byte[] plaintext, byte[] sessionKey,
        SymmetricCipherAlgorithm cipher, AeadAlgorithm aead, byte chunkSize, byte[] salt,
        SecurityPolicyOptions? policy)
    {
#if NETSTANDARD2_0
        throw new PlatformNotSupportedException("AEAD encryption requires .NET Core 3.0 or later.");
#else
        byte[] aad = CreateHeader(sessionKey, cipher, aead, chunkSize, salt);
        var material = DeriveMaterial(sessionKey, salt, aad, policy);
        try
        {
            int size = 1 << (chunkSize + 6);
            int chunks = Math.Max(1, (int)(((long)plaintext.Length + size - 1) / size));
            var result = new byte[checked(plaintext.Length + 16 * chunks + 16)];
            var nonce = new byte[12];
            material.AsSpan(sessionKey.Length).CopyTo(nonce);
            using var gcm = new System.Security.Cryptography.AesGcm(material.AsSpan(0, sessionKey.Length), 16);
            int inputOffset = 0;
            int outputOffset = 0;
            for (int index = 0; index < chunks; index++)
            {
                int length = Math.Min(size, plaintext.Length - inputOffset);
                BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), (ulong)index);
                gcm.Encrypt(nonce, plaintext.AsSpan(inputOffset, length), result.AsSpan(outputOffset, length),
                    result.AsSpan(outputOffset + length, 16), aad);
                inputOffset += length;
                outputOffset += length + 16;
            }

            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), (ulong)chunks);
            var finalAad = FinalAad(aad, plaintext.Length);
            ReadOnlySpan<byte> empty = [];
            Span<byte> emptyOutput = [];
            gcm.Encrypt(nonce, empty, emptyOutput, result.AsSpan(outputOffset, 16), finalAad);
            return result;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(material);
        }
#endif
    }

    internal static byte[] Decrypt(PgpSymEncryptedIntegrityProtectedDataPacket packet,
        byte[] sessionKey, SecurityPolicyOptions? policy)
    {
#if NETSTANDARD2_0
        throw new PlatformNotSupportedException("AEAD decryption requires .NET Core 3.0 or later.");
#else
        byte[] aad = CreateHeader(sessionKey, packet.CipherAlgorithm, packet.AeadAlgorithm,
            packet.ChunkSize, packet.Salt.Span);
        var data = packet.EncryptedData.Span;
        if (data.Length < 32)
        {
            throw new CryptographicException("AEAD ciphertext is missing required authentication tags.");
        }

        int size = packet.GetChunkSizeBytes();
        int framedLength = data.Length - 16;
        int chunks = (int)(((long)framedLength + size + 15) / (size + 16));
        int plaintextLength = framedLength - 16 * chunks;
        int lastChunkLength = framedLength - (chunks - 1) * (size + 16) - 16;
        if (lastChunkLength <= 0 && !(chunks == 1 && framedLength == 16))
        {
            throw new CryptographicException("AEAD ciphertext contains an incomplete data chunk.");
        }

        var material = DeriveMaterial(sessionKey, packet.Salt.Span, aad, policy);
        var plaintext = new byte[plaintextLength];
        bool authenticated = false;
        try
        {
            var nonce = new byte[12];
            material.AsSpan(sessionKey.Length).CopyTo(nonce);
            using var gcm = new System.Security.Cryptography.AesGcm(material.AsSpan(0, sessionKey.Length), 16);
            int inputOffset = 0;
            int outputOffset = 0;
            for (int index = 0; index < chunks; index++)
            {
                int length = Math.Min(size, plaintext.Length - outputOffset);
                BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), (ulong)index);
                gcm.Decrypt(nonce, data.Slice(inputOffset, length), data.Slice(inputOffset + length, 16),
                    plaintext.AsSpan(outputOffset, length), aad);
                inputOffset += length + 16;
                outputOffset += length;
            }

            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), (ulong)chunks);
            ReadOnlySpan<byte> empty = [];
            Span<byte> emptyOutput = [];
            gcm.Decrypt(nonce, empty, data.Slice(framedLength, 16), emptyOutput, FinalAad(aad, plaintext.Length));
            authenticated = true;
            return plaintext;
        }
        finally
        {
            SecureMemoryOperations.SecureClear(material);
            if (!authenticated)
            {
                SecureMemoryOperations.SecureClear(plaintext);
            }
        }
#endif
    }

#if !NETSTANDARD2_0
    private static byte[] CreateHeader(byte[] sessionKey, SymmetricCipherAlgorithm cipher,
        AeadAlgorithm aead, byte chunkSize, ReadOnlySpan<byte> salt)
    {
        if (cipher is not (SymmetricCipherAlgorithm.Aes128 or SymmetricCipherAlgorithm.Aes192 or SymmetricCipherAlgorithm.Aes256)
            || aead != AeadAlgorithm.Gcm)
        {
            throw new NotSupportedException("SEIPD v2 currently supports only AES with GCM.");
        }

        if (chunkSize > 16 || salt.Length != 32 || sessionKey.Length != PgpKeyEncryption.GetSessionKeySize(cipher))
        {
            throw new CryptographicException("Invalid SEIPD v2 chunk size, salt or session key length.");
        }

        return [0xD2, 2, (byte)cipher, (byte)aead, chunkSize];
    }

    private static byte[] DeriveMaterial(byte[] sessionKey, ReadOnlySpan<byte> salt, byte[] info, SecurityPolicyOptions? policy)
        => new HkdfCore(policy).DeriveKey(sessionKey, salt.ToArray(), info, sessionKey.Length + 4, HashAlgorithmName.SHA256);

    private static byte[] FinalAad(byte[] header, int length)
    {
        var result = new byte[13];
        header.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(5), (ulong)length);
        return result;
    }
#endif
}
