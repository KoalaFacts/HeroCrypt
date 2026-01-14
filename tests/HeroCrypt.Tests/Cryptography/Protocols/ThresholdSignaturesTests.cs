using System.Text;
using HeroCrypt.Cryptography.Protocols;

namespace HeroCrypt.Tests.Cryptography.Protocols;

/// <summary>
/// Tests for Threshold Signature Schemes (TSS).
/// Note: The implementation is a simplified reference, so we test the protocol flow.
/// </summary>
public class ThresholdSignaturesTests
{
    private const int TOTAL_PARTIES = 5;
    private const int THRESHOLD = 3; // t+1 = 4 signatures needed

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void ThresholdSignatureFlow_Success()
    {
        // 1. Generate Keys (Distribution Phase)
        var keyGen = ThresholdSignatures.GenerateKeys(TOTAL_PARTIES, THRESHOLD);

        Assert.True(keyGen.Success);
        Assert.NotNull(keyGen.PublicKey);
        Assert.Equal(TOTAL_PARTIES, keyGen.KeyShares.Length);

        // 2. Sign (Partial Signing Phase)
        // We need t+1 signers. Let's use parties 0, 1, 2, 3.
        var message = Encoding.UTF8.GetBytes("Transaction 12345");
        var signers = new int[] { 0, 1, 2, 3 };

        var partialSigs = new ThresholdSignatures.PartialSignature[signers.Length];
        for (int i = 0; i < signers.Length; i++)
        {
            int partyId = signers[i];
            partialSigs[i] = ThresholdSignatures.SignPartial(message, keyGen.KeyShares[partyId], signers);

            Assert.Equal(partyId, partialSigs[i].PartyId);
            Assert.NotNull(partialSigs[i].Value);
            Assert.NotNull(partialSigs[i].Commitment);
        }

        // 3. Combine (Aggregation Phase)
        var signature = ThresholdSignatures.CombineSignatures(
            message,
            partialSigs,
            keyGen.PublicKey,
            ThresholdSignatures.SignatureScheme.Schnorr);

        Assert.NotNull(signature);
        Assert.NotNull(signature.R);
        Assert.NotNull(signature.S);
        Assert.Equal(signers, signature.Signers);

        // 4. Verify
        var isValid = ThresholdSignatures.VerifySignature(message, signature, keyGen.PublicKey);

        Assert.True(isValid, "Signature verification failed");
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void GenerateKeys_InvalidParameters_Throws()
    {
        Assert.Throws<ArgumentException>(() => ThresholdSignatures.GenerateKeys(1, 1)); // Need >= 2 parties
        Assert.Throws<ArgumentException>(() => ThresholdSignatures.GenerateKeys(3, 3)); // Threshold < n
    }

    [Fact]
    [Trait("Category", TestCategories.UNIT)]
    public void SignPartial_InvalidSignerSet_Throws()
    {
        var keyGen = ThresholdSignatures.GenerateKeys(TOTAL_PARTIES, THRESHOLD);
        var message = Encoding.UTF8.GetBytes("Msg");

        // Not enough signers
        var tooFewSigners = new int[] { 0, 1, 2 }; // Need 4
        Assert.Throws<ArgumentException>(() =>
            ThresholdSignatures.SignPartial(message, keyGen.KeyShares[0], tooFewSigners));

        // Signer not in set
        var validCountSigners = new int[] { 1, 2, 3, 4 };
        Assert.Throws<ArgumentException>(() =>
            ThresholdSignatures.SignPartial(message, keyGen.KeyShares[0], validCountSigners)); // Party 0 not in list
    }
}
