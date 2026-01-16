using System.Runtime.CompilerServices;
using HeroCrypt.Polyfills;
using HeroCrypt.Primitives.Poly1305;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.ChaCha20Poly1305;

/// <summary>
/// Shared Poly1305 tag computation utility for AEAD constructions.
/// Used by ChaCha20-Poly1305 and XChaCha20-Poly1305.
/// </summary>
internal static class Poly1305TagComputation
{
    /// <summary>
    /// Stack allocation threshold for the message buffer
    /// </summary>
    private const int StackAllocThreshold = 1024;

    /// <summary>
    /// Computes the Poly1305 authentication tag per RFC 8439.
    /// Constructs the message as: pad(aad) || pad(ciphertext) || len(aad) || len(ciphertext)
    /// </summary>
    /// <param name="tag">Output 16-byte tag</param>
    /// <param name="associatedData">Associated data (authenticated but not encrypted)</param>
    /// <param name="ciphertext">Ciphertext to authenticate</param>
    /// <param name="poly1305Key">32-byte Poly1305 key</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> poly1305Key)
    {
        // Calculate lengths
        var aadLength = associatedData.Length;
        var ciphertextLength = ciphertext.Length;

        // Calculate padding to 16-byte boundaries
        var aadPadding = (16 - (aadLength % 16)) % 16;
        var ciphertextPadding = (16 - (ciphertextLength % 16)) % 16;

        // Total message length for Poly1305
        var totalLength = aadLength + aadPadding + ciphertextLength + ciphertextPadding + 16;

        // Build message for Poly1305 (use stackalloc for small messages)
        // For heap allocations, use try/finally to ensure cleanup on exception
        var useHeapAllocation = totalLength > StackAllocThreshold;
        Span<byte> message = useHeapAllocation ? new byte[totalLength] : stackalloc byte[totalLength];

        try
        {
            var offset = 0;

            // Copy associated data
            if (aadLength > 0)
            {
                associatedData.CopyTo(message.Slice(offset, aadLength));
                offset += aadLength;
            }

            // Add AAD padding (zeros)
            if (aadPadding > 0)
            {
                message.Slice(offset, aadPadding).Clear();
                offset += aadPadding;
            }

            // Copy ciphertext
            if (ciphertextLength > 0)
            {
                ciphertext.CopyTo(message.Slice(offset, ciphertextLength));
                offset += ciphertextLength;
            }

            // Add ciphertext padding (zeros)
            if (ciphertextPadding > 0)
            {
                message.Slice(offset, ciphertextPadding).Clear();
                offset += ciphertextPadding;
            }

            // Add lengths in little-endian format (8 bytes each)
            var lengthBytes = message.Slice(offset, 16);
            BinaryHelpers.WriteUInt64LittleEndian(lengthBytes[..8], (ulong)aadLength);
            BinaryHelpers.WriteUInt64LittleEndian(lengthBytes.Slice(8, 8), (ulong)ciphertextLength);

            // Compute Poly1305 MAC
            Poly1305Core.ComputeMac(tag, message, poly1305Key);
        }
        finally
        {
            // Clear message to prevent sensitive data from remaining in memory
            // This is especially important for heap-allocated buffers
            SecureMemoryOperations.SecureClear(message);
        }
    }
}
