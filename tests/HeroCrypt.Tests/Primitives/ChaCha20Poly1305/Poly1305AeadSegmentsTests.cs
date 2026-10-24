using HeroCrypt.Primitives.ChaCha20Poly1305;
using HeroCrypt.Primitives.Poly1305;

namespace HeroCrypt.Tests.Primitives.ChaCha20Poly1305;

[Trait("Category", TestCategories.UNIT)]
public class Poly1305AeadSegmentsTests
{
    // Vectors produced independently with cryptography.hazmat.primitives.poly1305.Poly1305
    // using key[i] = (i * 7 + 11) % 256, aad[i] = (i * 29 + 9) % 256,
    // ciphertext[i] = (i * 17 + 3) % 256 and RFC 8439 pad16/LE64 framing.
    [Theory]
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [InlineData(0, 0, "05D9A8904418E8BB835727D3C29666EA")]
    [InlineData(1, 1, "FA3B007144C1DF16A27E95AEBBFAC53D")]
    [InlineData(15, 17, "1DDA277EC49D92610AC7CCAD4815D86F")]
    [InlineData(16, 16, "EFD37DD0A975BCA82DB89768888937D4")]
    [InlineData(17, 15, "D4461A794B7172639E123D7A4775CC91")]
    [InlineData(1023, 1025, "7EE6697E564539D60967127EABBA87ED")]
    [InlineData(1024, 1024, "99FEC7DD2D49156553313A0A4F5F24FB")]
    [InlineData(1025, 0, "67E27CC029075FC40F162AD19440EC0B")]
    [InlineData(65536, 33, "CB044AF91C4F03A0C1D8C728C17AF310")]
    [InlineData(1048576, 16384, "B133025F82B4ED619DA8ACDD1951A940")]
    [InlineData(33, 65536, "F7D4D94F74723EF127DB18F1C50A4162")]
    public void SegmentedTag_MatchesIndependentVectorAndFullMessageReference(
        int ciphertextLength, int aadLength, string expectedHex)
    {
        var key = Pattern(32, 7, 11);
        var aad = Pattern(aadLength, 29, 9);
        var ciphertext = Pattern(ciphertextLength, 17, 3);
        var preservedAad = aad.ToArray();
        var preservedCiphertext = ciphertext.ToArray();

        var tag = new byte[16];
        new Poly1305TagComputation().ComputeTag(tag, aad, ciphertext, key);

        Assert.Equal(expectedHex, Convert.ToHexString(tag));
        Assert.Equal(FullMessageReferenceTag(aad, ciphertext, key), tag);
        Assert.Equal(preservedAad, aad);
        Assert.Equal(preservedCiphertext, ciphertext);
    }

    // Independent end-to-end AEAD fixtures from Python cryptography
    // ChaCha20Poly1305(key = bytes(range(32)), nonce = bytes(range(200,212))).
    [Theory]
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [InlineData(0, 0, "F06BFCC5B31046DF3974700FC8CCFA33")]
    [InlineData(15, 17, "A86A8F541BADECB33ED374ED88B5D145")]
    [InlineData(1024, 1024, "E758F11E994D7DE160653CC65E1E5DB7")]
    [InlineData(65536, 33, "53A8BD1F9D6FDB9264CF2D65EE12B640")]
    [InlineData(1048576, 16384, "16E7E707C5A3B2C71FF2FC0A1FEA741B")]
    public void ChaCha20Aead_MatchesIndependentAndPlatformResults(
        int plaintextLength, int aadLength, string expectedTag)
    {
        var key = Pattern(32, 1, 0);
        var nonce = Pattern(12, 1, 200);
        var plaintext = Pattern(plaintextLength, 17, 3);
        var aad = Pattern(aadLength, 29, 9);

        var core = new ChaCha20Poly1305Core();
        var encrypted = core.Encrypt(plaintext, key, nonce, aad);
        Assert.Equal(expectedTag, Convert.ToHexString(encrypted.Ciphertext.AsSpan(plaintext.Length, 16)));
        Assert.Equal(plaintext, core.Decrypt(encrypted.Ciphertext, key, nonce, aad));

        if (System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
        {
            using var platformCipher = new System.Security.Cryptography.ChaCha20Poly1305(key);
            var platformCiphertext = new byte[plaintext.Length];
            var platformTag = new byte[16];
            platformCipher.Encrypt(nonce, plaintext, platformCiphertext, platformTag, aad);
            Assert.Equal(platformCiphertext, encrypted.Ciphertext.AsSpan(0, plaintext.Length).ToArray());
            Assert.Equal(platformTag, encrypted.Ciphertext.AsSpan(plaintext.Length, 16).ToArray());
        }
    }

    [Fact]
    [Trait("Category", TestCategories.MEMORY)]
    [Trait("Category", TestCategories.SLOW)]
    public void ComputeTag_LargeCiphertext_DoesNotAllocateWholeMessageStagingBuffer()
    {
        var key = Pattern(32, 7, 11);
        var aad = Pattern(33, 29, 9);
        var ciphertext = Pattern(128 * 1024, 17, 3);
        var segmented = new Poly1305TagComputation();
        var tag = new byte[16];
        for (int i = 0; i < 2; i++)
        {
            segmented.ComputeTag(tag, aad, ciphertext, key);
            _ = FullMessageReferenceTag(aad, ciphertext, key);
        }

        long beforeReference = GC.GetAllocatedBytesForCurrentThread();
        var referenceTag = Array.Empty<byte>();
        for (int i = 0; i < 2; i++)
        {
            referenceTag = FullMessageReferenceTag(aad, ciphertext, key);
        }

        long referenceBytes = GC.GetAllocatedBytesForCurrentThread() - beforeReference;
        long beforeSegmented = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 2; i++)
        {
            segmented.ComputeTag(tag, aad, ciphertext, key);
        }

        long segmentedBytes = GC.GetAllocatedBytesForCurrentThread() - beforeSegmented;
        Assert.Equal(referenceTag, tag);
        // Both paths use the same BigInteger block computation. The material
        // difference is the whole-message array allocated only by the reference.
        Assert.True(referenceBytes - segmentedBytes > ciphertext.Length,
            $"Expected two avoided full-message copies; reference {referenceBytes}, segmented {segmentedBytes} bytes.");
    }

    private static byte[] FullMessageReferenceTag(byte[] aad, byte[] ciphertext, byte[] key)
    {
        var aadPadded = (aad.Length + 15) / 16 * 16;
        var ciphertextPadded = (ciphertext.Length + 15) / 16 * 16;
        var message = new byte[checked(aadPadded + ciphertextPadded + 16)];
        aad.CopyTo(message, 0);
        ciphertext.CopyTo(message, aadPadded);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(
            message.AsSpan(aadPadded + ciphertextPadded, 8), (ulong)aad.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(
            message.AsSpan(aadPadded + ciphertextPadded + 8, 8), (ulong)ciphertext.Length);
        var tag = new byte[16];
        new Poly1305Core().ComputeMac(tag, message, key);
        return tag;
    }

    private static byte[] Pattern(int length, int factor, int shift)
    {
        var output = new byte[length];
        for (int i = 0; i < length; i++)
        {
            output[i] = (byte)((i * factor + shift) & 0xFF);
        }

        return output;
    }
}
