using System.Runtime.CompilerServices;
using HeroCrypt.Primitives.Poly1305;
using HeroCrypt.Security;

namespace HeroCrypt.Primitives.ChaCha20Poly1305;

/// <summary>
/// Shared Poly1305 tag computation utility for ChaCha20-Poly1305 and
/// XChaCha20-Poly1305. Processes RFC 8439 AEAD segments without a temporary
/// message-sized AAD/ciphertext concatenation.
/// </summary>
internal sealed class Poly1305TagComputation
{
    private readonly SecurityPolicyOptions policy;

    public Poly1305TagComputation(SecurityPolicyOptions? policy = null)
    {
        this.policy = policy ?? SecurityPolicy.CurrentPolicy;
    }

    /// <summary>
    /// Computes pad16(AAD) || pad16(ciphertext) || le64(len(AAD)) ||
    /// le64(len(ciphertext)) as a Poly1305 authentication tag.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> poly1305Key)
    {
        var poly1305 = new Poly1305Core(policy);
        poly1305.ComputeAeadMac(tag, associatedData, ciphertext, poly1305Key);
    }
}
