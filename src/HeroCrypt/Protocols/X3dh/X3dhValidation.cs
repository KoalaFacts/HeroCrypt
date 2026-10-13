using System.Security.Cryptography;
using HeroCrypt.Polyfills;
using HeroCrypt.Protocols.DoubleRatchet;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.X3dh;

internal static class X3dhValidation
{
    internal const int MaxPayload = 16 * 1024 * 1024;
    internal const int MaxMetadata = MaxPayload - 70;
    internal static void ValidatePolicy(SecurityPolicyOptions policy)
    {
        policy.ValidateSignature("XEDDSA"); policy.ValidateKeyAgreement("X25519");
        policy.ValidateKdf("HKDF"); policy.ValidateHash("SHA256"); policy.ValidateHash("SHA512");
        policy.ValidateSymmetric("CHACHA20-POLY1305");
    }
    internal static void ValidateContext(byte[] context)
    {
        ArgumentHelper.ThrowIfNull(context);
        if (context.Length is < 1 or > 4096) throw new ArgumentException("Context must contain 1–4096 bytes.", nameof(context));
    }
    internal static void ValidatePayloadAndMetadata(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> metadata)
    {
        if (plaintext.Length > MaxPayload || metadata.Length > MaxMetadata) throw new ArgumentException("X3DH payload or metadata exceeds profile limit.");
    }
    internal static void ValidateSkippedKeyBudget(int value)
    {
        if (value is < 0 or > 10000) throw new ArgumentOutOfRangeException(nameof(value));
    }
    internal static void RequireIdentity(byte[] expected, byte[] actual)
    {
        ArgumentHelper.ThrowIfNull(expected); ArgumentHelper.ThrowIfNull(actual);
        DoubleRatchetMessage.ValidatePublicKey(expected); DoubleRatchetMessage.ValidatePublicKey(actual);
        if (!SecureMemoryOperations.ConstantTimeEquals(expected, actual)) throw new CryptographicException("Unexpected X3DH peer identity.");
    }
}
