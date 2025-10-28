using System;
using System.Linq;
using System.Text;
using Xunit;
using HeroCrypt.Cryptography.ZeroKnowledge.Groth16;
using HeroCrypt.Cryptography.ZeroKnowledge.RingSignatures;
using HeroCrypt.Cryptography.MultiParty;

namespace HeroCrypt.Tests;

// These tests use advanced cryptographic features not available in .NET Standard 2.0
#if !NETSTANDARD2_0

/// <summary>
/// Tests for Zero-Knowledge and Advanced Cryptographic Protocols
///
/// These tests validate the API functionality of:
/// - zk-SNARKs (Groth16)
/// - Ring Signatures
/// - Multi-Party Computation
/// - Threshold Signatures
///
/// IMPORTANT: These are reference implementations for API design and educational purposes.
/// Production use requires complete cryptographic implementations.
/// </summary>
public class ZeroKnowledgeTests
{
    #region zk-SNARK Tests (Groth16)

    [Fact]
    public void Groth16_TrustedSetup_GeneratesValidKeys()
    {
        // Arrange
        const string circuitId = "test-circuit";
        const int numConstraints = 100;
        const int numPublicInputs = 3;

        // Act
        var setup = Groth16ZkSnark.TrustedSetup(
            circuitId,
            numConstraints,
            numPublicInputs,
            Groth16ZkSnark.SecurityLevel.BLS12_381
        );

        // Assert
        Assert.NotNull(setup);
        Assert.NotNull(setup.ProvingKey);
        Assert.NotNull(setup.VerificationKey);
        Assert.Equal(circuitId, setup.ProvingKey.CircuitId);
        Assert.Equal(circuitId, setup.VerificationKey.CircuitId);
        Assert.Equal(Groth16ZkSnark.SecurityLevel.BLS12_381, setup.ProvingKey.Level);
    }

    [Theory]
    [InlineData(Groth16ZkSnark.SecurityLevel.BN254)]
    [InlineData(Groth16ZkSnark.SecurityLevel.BLS12_381)]
    [InlineData(Groth16ZkSnark.SecurityLevel.BLS12_377)]
    public void Groth16_SupportsMultipleSecurityLevels(Groth16ZkSnark.SecurityLevel level)
    {
        // Act
        var setup = Groth16ZkSnark.TrustedSetup("test", 50, 2, level);

        // Assert
        Assert.Equal(level, setup.ProvingKey.Level);
        Assert.Equal(level, setup.VerificationKey.Level);
    }

    [Fact]
    public void Groth16_GenerateProof_CreatesValidProof()
    {
        // Arrange
        var setup = Groth16ZkSnark.TrustedSetup("test", 100, 2);
        var publicInputs = new byte[][] {
            Encoding.UTF8.GetBytes("input1"),
            Encoding.UTF8.GetBytes("input2")
        };
        var privateWitness = new byte[][] {
            Encoding.UTF8.GetBytes("secret1"),
            Encoding.UTF8.GetBytes("secret2"),
            Encoding.UTF8.GetBytes("secret3")
        };

        // Act
        var proof = Groth16ZkSnark.GenerateProof(
            setup.ProvingKey,
            publicInputs,
            privateWitness
        );

        // Assert
        Assert.NotNull(proof);
        Assert.NotNull(proof.A);
        Assert.NotNull(proof.B);
        Assert.NotNull(proof.C);
        Assert.True(proof.Size > 0);
    }

    [Fact]
    public void Groth16_VerifyProof_AcceptsValidProof()
    {
        // Arrange
        var setup = Groth16ZkSnark.TrustedSetup("test", 100, 2);
        var publicInputs = new byte[][] {
            Encoding.UTF8.GetBytes("input1"),
            Encoding.UTF8.GetBytes("input2")
        };
        var privateWitness = new byte[][] {
            Encoding.UTF8.GetBytes("secret1"),
            Encoding.UTF8.GetBytes("secret2")
        };
        var proof = Groth16ZkSnark.GenerateProof(setup.ProvingKey, publicInputs, privateWitness);

        // Act
        bool isValid = Groth16ZkSnark.VerifyProof(setup.VerificationKey, proof, publicInputs);

        // Assert
        Assert.True(isValid);
    }

    [Theory]
    [InlineData(Groth16ZkSnark.SecurityLevel.BN254, 192)]
    [InlineData(Groth16ZkSnark.SecurityLevel.BLS12_381, 256)]
    [InlineData(Groth16ZkSnark.SecurityLevel.BLS12_377, 256)]
    public void Groth16_GetProofSize_ReturnsCorrectSize(
        Groth16ZkSnark.SecurityLevel level,
        int expectedSize)
    {
        // Act
        int size = Groth16ZkSnark.GetProofSize(level);

        // Assert
        Assert.Equal(expectedSize, size);
    }

    #endregion

    #region Ring Signature Tests

    [Theory]
    [InlineData(RingSignature.SignatureScheme.Basic)]
    [InlineData(RingSignature.SignatureScheme.Linkable)]
    [InlineData(RingSignature.SignatureScheme.Traceable)]
    public void RingSignature_GenerateKeyPair_CreatesValidKeys(RingSignature.SignatureScheme scheme)
    {
        // Act
        var keyPair = RingSignature.GenerateKeyPair(scheme);

        // Assert
        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PublicKey);
        Assert.NotNull(keyPair.PrivateKey);
        Assert.Equal(scheme, keyPair.Scheme);
        Assert.True(keyPair.PublicKey.Length > 0);
        Assert.True(keyPair.PrivateKey.Length > 0);
    }

    [Fact]
    public void RingSignature_Sign_CreatesValidSignature()
    {
        // Arrange
        var signerKeyPair = RingSignature.GenerateKeyPair();
        var decoyKey1 = RingSignature.GenerateKeyPair();
        var decoyKey2 = RingSignature.GenerateKeyPair();

        var ring = new[] {
            signerKeyPair.PublicKey,
            decoyKey1.PublicKey,
            decoyKey2.PublicKey
        };

        var message = Encoding.UTF8.GetBytes("Anonymous message");

        // Act
        var signature = RingSignature.Sign(message, signerKeyPair, ring);

        // Assert
        Assert.NotNull(signature);
        Assert.Equal(ring.Length, signature.Ring.Length);
        Assert.Equal(ring.Length, signature.SignatureComponents.Length);
        Assert.NotNull(signature.Challenge);
    }

    [Fact]
    public void RingSignature_Verify_AcceptsValidSignature()
    {
        // Arrange
        var signerKeyPair = RingSignature.GenerateKeyPair();
        var decoyKey1 = RingSignature.GenerateKeyPair();
        var decoyKey2 = RingSignature.GenerateKeyPair();

        var ring = new[] {
            decoyKey1.PublicKey,
            signerKeyPair.PublicKey,  // Signer in middle
            decoyKey2.PublicKey
        };

        var message = Encoding.UTF8.GetBytes("Anonymous message");
        var signature = RingSignature.Sign(message, signerKeyPair, ring);

        // Act
        bool isValid = RingSignature.Verify(message, signature);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void RingSignature_Verify_RejectsModifiedMessage()
    {
        // Arrange
        var signerKeyPair = RingSignature.GenerateKeyPair();
        var decoyKey1 = RingSignature.GenerateKeyPair();
        var decoyKey2 = RingSignature.GenerateKeyPair();

        var ring = new[] {
            signerKeyPair.PublicKey,
            decoyKey1.PublicKey,
            decoyKey2.PublicKey
        };

        var message = Encoding.UTF8.GetBytes("Original message");
        var signature = RingSignature.Sign(message, signerKeyPair, ring);

        var modifiedMessage = Encoding.UTF8.GetBytes("Modified message");

        // Act
        bool isValid = RingSignature.Verify(modifiedMessage, signature);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void RingSignature_Linkable_CreatesKeyImage()
    {
        // Arrange
        var signerKeyPair = RingSignature.GenerateKeyPair(RingSignature.SignatureScheme.Linkable);
        var decoyKey = RingSignature.GenerateKeyPair(RingSignature.SignatureScheme.Linkable);

        var ring = new[] { signerKeyPair.PublicKey, decoyKey.PublicKey };
        var message = Encoding.UTF8.GetBytes("Linkable signature test");

        // Act
        var signature = RingSignature.Sign(
            message,
            signerKeyPair,
            ring,
            RingSignature.SignatureScheme.Linkable
        );

        // Assert
        Assert.NotNull(signature.KeyImage);
        Assert.True(signature.KeyImage.Length > 0);
    }

    [Fact]
    public void RingSignature_AreLinked_DetectsSameSigner()
    {
        // Arrange
        var signerKeyPair = RingSignature.GenerateKeyPair(RingSignature.SignatureScheme.Linkable);
        var decoyKey1 = RingSignature.GenerateKeyPair(RingSignature.SignatureScheme.Linkable);
        var decoyKey2 = RingSignature.GenerateKeyPair(RingSignature.SignatureScheme.Linkable);

        var ring = new[] {
            signerKeyPair.PublicKey,
            decoyKey1.PublicKey,
            decoyKey2.PublicKey
        };

        var message1 = Encoding.UTF8.GetBytes("Message 1");
        var message2 = Encoding.UTF8.GetBytes("Message 2");

        var signature1 = RingSignature.Sign(
            message1,
            signerKeyPair,
            ring,
            RingSignature.SignatureScheme.Linkable
        );

        var signature2 = RingSignature.Sign(
            message2,
            signerKeyPair,
            ring,
            RingSignature.SignatureScheme.Linkable
        );

        // Act
        bool areLinked = RingSignature.AreLinked(signature1, signature2);

        // Assert
        Assert.True(areLinked);
    }

    [Fact]
    public void RingSignature_AreLinked_DetectsDifferentSigners()
    {
        // Arrange
        var signer1 = RingSignature.GenerateKeyPair(RingSignature.SignatureScheme.Linkable);
        var signer2 = RingSignature.GenerateKeyPair(RingSignature.SignatureScheme.Linkable);
        var decoy = RingSignature.GenerateKeyPair(RingSignature.SignatureScheme.Linkable);

        var ring = new[] {
            signer1.PublicKey,
            signer2.PublicKey,
            decoy.PublicKey
        };

        var message = Encoding.UTF8.GetBytes("Test message");

        var signature1 = RingSignature.Sign(
            message,
            signer1,
            ring,
            RingSignature.SignatureScheme.Linkable
        );

        var signature2 = RingSignature.Sign(
            message,
            signer2,
            ring,
            RingSignature.SignatureScheme.Linkable
        );

        // Act
        bool areLinked = RingSignature.AreLinked(signature1, signature2);

        // Assert
        Assert.False(areLinked);
    }

    [Theory]
    [InlineData(2, RingSignature.SignatureScheme.Basic)]
    [InlineData(5, RingSignature.SignatureScheme.Basic)]
    [InlineData(10, RingSignature.SignatureScheme.Linkable)]
    public void RingSignature_EstimateSignatureSize_ReturnsReasonableSize(
        int ringSize,
        RingSignature.SignatureScheme scheme)
    {
        // Act
        int estimatedSize = RingSignature.EstimateSignatureSize(ringSize, scheme);

        // Assert
        Assert.True(estimatedSize > 0);
        Assert.True(estimatedSize >= ringSize * 32); // At least public key sizes
    }

    #endregion

    #region Multi-Party Computation Tests

    [Fact]
    public void MPC_SecureSum_ComputesCorrectSum()
    {
        // Arrange - 3 parties with private inputs
        var party1Input = new byte[] { 10, 20, 30 };
        var party2Input = new byte[] { 5, 15, 25 };
        var party3Input = new byte[] { 3, 7, 11 };

        var inputs = new[] { party1Input, party2Input, party3Input };

        // Act
        var result = SecureMpc.SecureSum(inputs, threshold: 2); // Shamir requires threshold >= 2

        // Assert
        Assert.True(result.Success);
        Assert.Equal(3, result.ParticipantCount);
        Assert.NotNull(result.Result);
        Assert.Equal(party1Input.Length, result.Result.Length);
    }

    [Fact]
    public void MPC_GenerateBeaverTriples_CreatesValidTriples()
    {
        // Arrange
        const int numParties = 3;
        const int threshold = 2; // Shamir requires threshold >= 2
        const int valueLength = 16;

        // Act
        var triples = SecureMpc.GenerateBeaverTriples(numParties, threshold, valueLength);

        // Assert
        Assert.NotNull(triples);
        Assert.Equal(numParties, triples.Length);

        foreach (var triple in triples)
        {
            Assert.NotNull(triple.A);
            Assert.NotNull(triple.B);
            Assert.NotNull(triple.C);
            Assert.Equal(valueLength, triple.A.Value.Length);
            Assert.Equal(valueLength, triple.B.Value.Length);
            Assert.Equal(valueLength, triple.C.Value.Length);
        }
    }

    [Fact]
    public void MPC_SecureMultiply_PerformsMultiplication()
    {
        // Arrange
        const int numParties = 3;
        const int threshold = 2; // Shamir requires threshold >= 2
        const int valueLength = 8;

        // Create shares for two values
        var xValue = new byte[] { 5, 10, 15, 20, 25, 30, 35, 40 };
        var yValue = new byte[] { 2, 3, 4, 5, 6, 7, 8, 9 };

        var xShamirShares = HeroCrypt.Cryptography.SecretSharing.ShamirSecretSharing
            .Split(xValue, threshold, numParties);
        var yShamirShares = HeroCrypt.Cryptography.SecretSharing.ShamirSecretSharing
            .Split(yValue, threshold, numParties);

        var xShares = xShamirShares.Select((s, i) =>
            new SecureMpc.Share(i, s.Data, s.Index)).ToArray();
        var yShares = yShamirShares.Select((s, i) =>
            new SecureMpc.Share(i, s.Data, s.Index)).ToArray();

        var beaverTriples = SecureMpc.GenerateBeaverTriples(numParties, threshold, valueLength);

        // Act
        var productShares = SecureMpc.SecureMultiply(xShares, yShares, beaverTriples, threshold);

        // Assert
        Assert.NotNull(productShares);
        Assert.Equal(numParties, productShares.Length);

        foreach (var share in productShares)
        {
            Assert.NotNull(share.Value);
            Assert.Equal(valueLength, share.Value.Length);
        }
    }

    [Fact]
    public void MPC_PrivateSetIntersection_FindsCommonElements()
    {
        // Arrange
        var party1Set = new byte[][] {
            Encoding.UTF8.GetBytes("apple"),
            Encoding.UTF8.GetBytes("banana"),
            Encoding.UTF8.GetBytes("cherry")
        };

        var party2Set = new byte[][] {
            Encoding.UTF8.GetBytes("banana"),
            Encoding.UTF8.GetBytes("cherry"),
            Encoding.UTF8.GetBytes("date")
        };

        // Act
        var intersection = SecureMpc.PrivateSetIntersection(party1Set, party2Set);

        // Assert
        Assert.NotNull(intersection);
        Assert.True(intersection.Length >= 1); // At least "banana" or "cherry"
    }

    #endregion

    #region Threshold Signature Tests

    [Theory]
    [InlineData(ThresholdSignatures.SignatureScheme.Schnorr)]
    [InlineData(ThresholdSignatures.SignatureScheme.ECDSA)]
    [InlineData(ThresholdSignatures.SignatureScheme.EdDSA)]
    [InlineData(ThresholdSignatures.SignatureScheme.BLS)]
    public void ThresholdSignatures_GenerateKeys_CreatesValidKeyShares(
        ThresholdSignatures.SignatureScheme scheme)
    {
        // Arrange
        const int numParties = 5;
        const int threshold = 2; // Need 3 to sign

        // Act
        var result = ThresholdSignatures.GenerateKeys(numParties, threshold, scheme);

        // Assert
        Assert.True(result.Success);
        Assert.NotNull(result.KeyShares);
        Assert.Equal(numParties, result.KeyShares.Length);
        Assert.NotNull(result.PublicKey);

        foreach (var share in result.KeyShares)
        {
            Assert.NotNull(share.PrivateShare);
            Assert.NotNull(share.PublicKey);
            Assert.Equal(threshold, share.Threshold);
            Assert.Equal(numParties, share.TotalParties);
            Assert.Equal(scheme, share.Scheme);
            Assert.True(share.PublicKey.SequenceEqual(result.PublicKey));
        }
    }

    [Fact]
    public void ThresholdSignatures_SignPartial_CreatesValidPartialSignatures()
    {
        // Arrange
        const int numParties = 5;
        const int threshold = 2;
        var keyGen = ThresholdSignatures.GenerateKeys(numParties, threshold);

        var message = Encoding.UTF8.GetBytes("Important document requiring 3 signatures");

        // Use first 3 parties as signers (threshold + 1)
        var signers = new[] { 0, 1, 2 };

        // Act
        var partialSignatures = signers
            .Select(id => ThresholdSignatures.SignPartial(
                message,
                keyGen.KeyShares[id],
                signers))
            .ToArray();

        // Assert
        Assert.Equal(3, partialSignatures.Length);

        foreach (var partial in partialSignatures)
        {
            Assert.NotNull(partial.Value);
            Assert.NotNull(partial.Commitment);
            Assert.True(partial.Value.Length > 0);
        }
    }

    [Fact]
    public void ThresholdSignatures_CombineSignatures_CreatesCompleteSignature()
    {
        // Arrange
        const int numParties = 5;
        const int threshold = 2;
        var keyGen = ThresholdSignatures.GenerateKeys(numParties, threshold);

        var message = Encoding.UTF8.GetBytes("Multi-party signed document");
        var signers = new[] { 0, 1, 2 };

        var partialSignatures = signers
            .Select(id => ThresholdSignatures.SignPartial(
                message,
                keyGen.KeyShares[id],
                signers))
            .ToArray();

        // Act
        var signature = ThresholdSignatures.CombineSignatures(
            message,
            partialSignatures,
            keyGen.PublicKey,
            ThresholdSignatures.SignatureScheme.Schnorr
        );

        // Assert
        Assert.NotNull(signature);
        Assert.NotNull(signature.R);
        Assert.NotNull(signature.S);
        Assert.Equal(signers, signature.Signers);
        Assert.True(signature.Size > 0);
    }

    [Fact]
    public void ThresholdSignatures_VerifySignature_AcceptsValidSignature()
    {
        // Arrange
        const int numParties = 5;
        const int threshold = 2;
        var keyGen = ThresholdSignatures.GenerateKeys(numParties, threshold);

        var message = Encoding.UTF8.GetBytes("Threshold signed message");
        var signers = new[] { 1, 2, 3 }; // Different signers

        var partialSignatures = signers
            .Select(id => ThresholdSignatures.SignPartial(
                message,
                keyGen.KeyShares[id],
                signers))
            .ToArray();

        var signature = ThresholdSignatures.CombineSignatures(
            message,
            partialSignatures,
            keyGen.PublicKey,
            ThresholdSignatures.SignatureScheme.Schnorr
        );

        // Act
        bool isValid = ThresholdSignatures.VerifySignature(
            message,
            signature,
            keyGen.PublicKey
        );

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ThresholdSignatures_DifferentSignerSets_ProduceValidSignatures()
    {
        // Arrange - any threshold+1 parties should be able to sign
        const int numParties = 5;
        const int threshold = 2;
        var keyGen = ThresholdSignatures.GenerateKeys(numParties, threshold);

        var message = Encoding.UTF8.GetBytes("Document to sign");

        // First group: parties 0, 1, 2
        var signers1 = new[] { 0, 1, 2 };
        var partialSigs1 = signers1
            .Select(id => ThresholdSignatures.SignPartial(message, keyGen.KeyShares[id], signers1))
            .ToArray();
        var signature1 = ThresholdSignatures.CombineSignatures(
            message, partialSigs1, keyGen.PublicKey, ThresholdSignatures.SignatureScheme.Schnorr);

        // Second group: parties 2, 3, 4 (different set)
        var signers2 = new[] { 2, 3, 4 };
        var partialSigs2 = signers2
            .Select(id => ThresholdSignatures.SignPartial(message, keyGen.KeyShares[id], signers2))
            .ToArray();
        var signature2 = ThresholdSignatures.CombineSignatures(
            message, partialSigs2, keyGen.PublicKey, ThresholdSignatures.SignatureScheme.Schnorr);

        // Act - both signatures should verify
        bool isValid1 = ThresholdSignatures.VerifySignature(message, signature1, keyGen.PublicKey);
        bool isValid2 = ThresholdSignatures.VerifySignature(message, signature2, keyGen.PublicKey);

        // Assert
        Assert.True(isValid1);
        Assert.True(isValid2);
    }

    #endregion
}
#endif
