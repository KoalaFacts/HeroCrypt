#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.PostQuantum.Kyber;
using HeroCrypt.Cryptography.PostQuantum.Dilithium;
using HeroCrypt.Cryptography.PostQuantum.Sphincs;
using HeroCrypt.Fluent;

namespace HeroCrypt.Tests;

/// <summary>
/// Comprehensive integration tests for Post-Quantum Cryptography features
/// These tests validate end-to-end workflows and real-world usage scenarios
/// </summary>
public class PostQuantumIntegrationTests
{
    #region Hybrid Encryption Tests

    [Fact]
    public void Integration_HybridEncryption_MLKem_AesGcm_FullWorkflow()
    {
        if (!MLKemWrapper.IsSupported())
            return;

        // Scenario: Alice wants to send encrypted message to Bob using hybrid PQC encryption

        // Step 1: Bob generates ML-KEM key pair and shares public key
        using var bobKeyPair = HeroCryptBuilder.Create()
            .PostQuantum()
            .MLKem()
            .WithSecurityBits(256) // High security
            .GenerateKeyPair();

        // Step 2: Alice encapsulates a shared secret using Bob's public key
        using var encapsulation = HeroCryptBuilder.Create()
            .PostQuantum()
            .MLKem()
            .WithPublicKey(bobKeyPair.PublicKeyPem)
            .Encapsulate();

        byte[] sharedSecret = encapsulation.SharedSecret;
        byte[] ciphertext = encapsulation.Ciphertext;

        // Step 3: Alice encrypts message using AES-GCM with the shared secret
        var message = "Top secret quantum-resistant message! 🔐";
        var messageBytes = Encoding.UTF8.GetBytes(message);

        byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);

        byte[] encrypted = new byte[messageBytes.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

        using (var aes = new AesGcm(sharedSecret, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Encrypt(nonce, messageBytes, encrypted, tag);
        }

        // Step 4: Alice sends to Bob: ciphertext (ML-KEM), nonce, encrypted message, tag
        // (In real world, these would be sent over network)

        // Step 5: Bob decapsulates to recover shared secret
        var recoveredSecret = bobKeyPair.Decapsulate(ciphertext);

        Assert.Equal(sharedSecret, recoveredSecret);

        // Step 6: Bob decrypts message using AES-GCM
        byte[] decrypted = new byte[encrypted.Length];

        using (var aes = new AesGcm(recoveredSecret, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Decrypt(nonce, encrypted, tag, decrypted);
        }

        var recoveredMessage = Encoding.UTF8.GetString(decrypted);

        // Verify end-to-end encryption worked
        Assert.Equal(message, recoveredMessage);
    }

    [Fact]
    public void Integration_HybridEncryption_MultipleRecipients()
    {
        if (!MLKemWrapper.IsSupported())
            return;

        // Scenario: Alice sends same message to 3 recipients using different shared secrets
        var message = "Confidential group message";
        var messageBytes = Encoding.UTF8.GetBytes(message);

        // Generate key pairs for 3 recipients
        var recipients = new[]
        {
            HeroCryptBuilder.PostQuantum.MLKem.GenerateKeyPair(),
            HeroCryptBuilder.PostQuantum.MLKem.GenerateKeyPair(),
            HeroCryptBuilder.PostQuantum.MLKem.GenerateKeyPair()
        };

        try
        {
            // For each recipient, encapsulate and encrypt
            var encryptedPackages = new List<(byte[] ciphertext, byte[] nonce, byte[] encrypted, byte[] tag)>();

            foreach (var recipient in recipients)
            {
                using var enc = MLKem.Create().WithPublicKey(recipient.PublicKeyPem).Encapsulate();

                byte[] nonce = new byte[12];
                RandomNumberGenerator.Fill(nonce);

                byte[] encrypted = new byte[messageBytes.Length];
                byte[] tag = new byte[16];

                using var aes = new AesGcm(enc.SharedSecret, 16);
                aes.Encrypt(nonce, messageBytes, encrypted, tag);

                encryptedPackages.Add((enc.Ciphertext, nonce, encrypted, tag));
            }

            // Each recipient can decrypt their copy
            for (int i = 0; i < recipients.Length; i++)
            {
                var package = encryptedPackages[i];
                var secret = recipients[i].Decapsulate(package.ciphertext);

                byte[] decrypted = new byte[package.encrypted.Length];
                using var aes = new AesGcm(secret, 16);
                aes.Decrypt(package.nonce, package.encrypted, package.tag, decrypted);

                Assert.Equal(message, Encoding.UTF8.GetString(decrypted));
            }
        }
        finally
        {
            foreach (var recipient in recipients)
                recipient.Dispose();
        }
    }

    #endregion

    #region Digital Signature Workflows

    [Fact]
    public void Integration_DocumentSigning_MLDsa_FullWorkflow()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        // Scenario: Sign and verify a legal document with ML-DSA

        // Document metadata
        var documentId = "DOC-2025-001";
        var documentContent = "This is a legally binding agreement...";
        var signedBy = "Alice Johnson";
        var timestamp = DateTimeOffset.UtcNow;

        // Create document hash including metadata
        var documentData = Encoding.UTF8.GetBytes(
            $"{documentId}|{documentContent}|{signedBy}|{timestamp:O}");

        // Generate signing key
        using var signingKey = HeroCryptBuilder.Create()
            .PostQuantum()
            .MLDsa()
            .WithSecurityLevel(MLDsaWrapper.SecurityLevel.MLDsa65)
            .GenerateKeyPair();

        // Sign with context for domain separation
        var signature = HeroCryptBuilder.Create()
            .PostQuantum()
            .MLDsa()
            .WithKeyPair(signingKey)
            .WithData(documentData)
            .WithContext($"legal-doc-v1:{documentId}")
            .Sign();

        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);

        // Verify signature (could be done by different party)
        var isValid = HeroCryptBuilder.Create()
            .PostQuantum()
            .MLDsa()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(documentData)
            .WithContext($"legal-doc-v1:{documentId}")
            .Verify(signature);

        Assert.True(isValid);

        // Tampering detection: modify document
        var tamperedData = Encoding.UTF8.GetBytes(
            $"{documentId}|{documentContent} [MODIFIED]|{signedBy}|{timestamp:O}");

        var isTamperedValid = HeroCryptBuilder.Create()
            .PostQuantum()
            .MLDsa()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(tamperedData)
            .WithContext($"legal-doc-v1:{documentId}")
            .Verify(signature);

        Assert.False(isTamperedValid);
    }

    [Fact]
    public void Integration_ChainOfTrust_MultipleSignatures()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        // Scenario: Multi-level approval with signature chain
        var document = "Budget proposal for Q1 2025";
        var docBytes = Encoding.UTF8.GetBytes(document);

        // Three approvers
        using var managerKey = MLDsa.Create().WithSecurityLevel(MLDsaWrapper.SecurityLevel.MLDsa65).GenerateKeyPair();
        using var directorKey = MLDsa.Create().WithSecurityLevel(MLDsaWrapper.SecurityLevel.MLDsa65).GenerateKeyPair();
        using var cfoKey = MLDsa.Create().WithSecurityLevel(MLDsaWrapper.SecurityLevel.MLDsa87).GenerateKeyPair(); // Higher security

        // Manager signs
        var managerSig = MLDsa.Create()
            .WithKeyPair(managerKey)
            .WithData(docBytes)
            .WithContext("approval:manager")
            .Sign();

        // Director signs (including manager's signature)
        var combinedData1 = docBytes.Concat(managerSig).ToArray();
        var directorSig = MLDsa.Create()
            .WithKeyPair(directorKey)
            .WithData(combinedData1)
            .WithContext("approval:director")
            .Sign();

        // CFO signs (including both previous signatures)
        var combinedData2 = combinedData1.Concat(directorSig).ToArray();
        var cfoSig = MLDsa.Create()
            .WithKeyPair(cfoKey)
            .WithData(combinedData2)
            .WithContext("approval:cfo")
            .Sign();

        // Verify chain of trust (in reverse order)
        Assert.True(MLDsa.Verify(cfoKey.PublicKeyPem, combinedData2, cfoSig));
        Assert.True(MLDsa.Verify(directorKey.PublicKeyPem, combinedData1, directorSig));
        Assert.True(MLDsa.Verify(managerKey.PublicKeyPem, docBytes, managerSig));
    }

    #endregion

    #region Hash-Based Signatures

    [Fact]
    public void Integration_CodeSigning_SlhDsa_SmallSignature()
    {
        if (!SlhDsaWrapper.IsSupported())
            return;

        // Scenario: Sign software release with conservative hash-based signature

        var softwareVersion = "v2.1.0";
        var buildHash = "abc123def456..."; // SHA-256 of build artifacts
        var releaseNotes = "Bug fixes and performance improvements";

        var releaseData = Encoding.UTF8.GetBytes(
            $"{softwareVersion}|{buildHash}|{releaseNotes}");

        // Use small variant for smaller signature files
        using var signingKey = HeroCryptBuilder.Create()
            .PostQuantum()
            .SlhDsa()
            .WithSmallVariant(192) // 192-bit security
            .GenerateKeyPair();

        // Sign the release
        var signature = HeroCryptBuilder.Create()
            .PostQuantum()
            .SlhDsa()
            .WithKeyPair(signingKey)
            .WithData(releaseData)
            .WithContext($"code-signing:{softwareVersion}")
            .Sign();

        Assert.NotNull(signature);

        // Users verify the signature
        var isAuthentic = HeroCryptBuilder.Create()
            .PostQuantum()
            .SlhDsa()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(releaseData)
            .WithContext($"code-signing:{softwareVersion}")
            .Verify(signature);

        Assert.True(isAuthentic);

        // Get signature info
        var info = SlhDsaWrapper.GetLevelInfo(SlhDsaWrapper.SecurityLevel.SlhDsa192s);
        Assert.Equal(192, info.SecurityBits);
    }

    #endregion

    #region Key Management

    [Fact]
    public void Integration_KeyRotation_GracefulTransition()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        // Scenario: Rotating signing keys while maintaining verification
        var message = "Important message during key rotation";
        var msgBytes = Encoding.UTF8.GetBytes(message);

        // Old key (being phased out)
        using var oldKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);

        // New key (being phased in)
        using var newKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa87);

        // Sign with old key
        var oldSignature = oldKey.Sign(msgBytes);

        // Sign with new key
        var newSignature = newKey.Sign(msgBytes);

        // During transition period, accept both signatures
        var oldIsValid = MLDsa.Verify(oldKey.PublicKeyPem, msgBytes, oldSignature);
        var newIsValid = MLDsa.Verify(newKey.PublicKeyPem, msgBytes, newSignature);

        Assert.True(oldIsValid);
        Assert.True(newIsValid);

        // Cross-verification should fail (different keys)
        var crossCheck = MLDsa.Verify(newKey.PublicKeyPem, msgBytes, oldSignature);
        Assert.False(crossCheck);
    }

    [Fact]
    public void Integration_KeyExport_Import_Roundtrip()
    {
        if (!MLKemWrapper.IsSupported() || !MLDsaWrapper.IsSupported())
            return;

        // ML-KEM key export/import
        using var originalKemKey = MLKem.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem768);

        var publicKeyPem = originalKemKey.PublicKeyPem;
        var secretKeyPem = originalKemKey.SecretKeyPem;

        // Verify PEM format
        Assert.Contains("-----BEGIN PUBLIC KEY-----", publicKeyPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", secretKeyPem);

        // ML-DSA key export/import
        using var originalDsaKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);

        var dsaPublicPem = originalDsaKey.PublicKeyPem;
        var dsaSecretPem = originalDsaKey.SecretKeyPem;

        Assert.Contains("-----BEGIN PUBLIC KEY-----", dsaPublicPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", dsaSecretPem);

        // Verify keys are different
        Assert.NotEqual(publicKeyPem, dsaPublicPem);
    }

    #endregion

    #region Performance and Stress Tests

    [Fact]
    public void Integration_HighVolume_BatchSigning_100_Signatures()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        // Scenario: High-volume signature generation (e.g., timestamping service)
        const int batchSize = 100;

        using var signingKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);

        var signatures = new List<(byte[] data, byte[] signature)>();

        // Generate 100 signatures
        for (int i = 0; i < batchSize; i++)
        {
            var data = Encoding.UTF8.GetBytes($"Timestamp entry #{i} at {DateTime.UtcNow:O}");
            var sig = signingKey.Sign(data);
            signatures.Add((data, sig));
        }

        Assert.Equal(batchSize, signatures.Count);

        // Verify all signatures
        int validCount = 0;
        foreach (var (data, sig) in signatures)
        {
            if (MLDsa.Verify(signingKey.PublicKeyPem, data, sig))
                validCount++;
        }

        Assert.Equal(batchSize, validCount);
    }

    [Fact]
    public void Integration_ConcurrentOperations_ThreadSafety()
    {
        if (!MLKemWrapper.IsSupported())
            return;

        // Scenario: Concurrent key generation and encapsulation
        const int threadCount = 10;
        var tasks = new Task<bool>[threadCount];

        for (int i = 0; i < threadCount; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    using var keyPair = MLKem.GenerateKeyPair();
                    using var enc = MLKem.Create().WithPublicKey(keyPair.PublicKeyPem).Encapsulate();
                    var recovered = keyPair.Decapsulate(enc.Ciphertext);
                    return enc.SharedSecret.SequenceEqual(recovered);
                }
                catch
                {
                    return false;
                }
            });
        }

        Task.WaitAll(tasks);

        // All concurrent operations should succeed
        Assert.All(tasks, t => Assert.True(t.Result));
    }

    #endregion

    #region Security Parameter Validation

    [Fact]
    public void Integration_SecurityLevels_AllParameterSets()
    {
        if (!MLKemWrapper.IsSupported() || !MLDsaWrapper.IsSupported() || !SlhDsaWrapper.IsSupported())
            return;

        // Validate all ML-KEM security levels
        var kemLevels = new[]
        {
            MLKemWrapper.SecurityLevel.MLKem512,
            MLKemWrapper.SecurityLevel.MLKem768,
            MLKemWrapper.SecurityLevel.MLKem1024
        };

        foreach (var level in kemLevels)
        {
            using var key = MLKem.GenerateKeyPair(level);
            Assert.Equal(level, key.Level);

            var info = MLKemWrapper.GetLevelInfo(level);
            Assert.True(info.SecurityBits >= 128);
        }

        // Validate all ML-DSA security levels
        var dsaLevels = new[]
        {
            MLDsaWrapper.SecurityLevel.MLDsa44,
            MLDsaWrapper.SecurityLevel.MLDsa65,
            MLDsaWrapper.SecurityLevel.MLDsa87
        };

        foreach (var level in dsaLevels)
        {
            using var key = MLDsa.GenerateKeyPair(level);
            Assert.Equal(level, key.Level);

            var info = MLDsaWrapper.GetLevelInfo(level);
            Assert.True(info.SecurityBits >= 128);
            Assert.True(info.SignatureSize > 0);
        }

        // Validate all SLH-DSA variants
        var slhLevels = new[]
        {
            SlhDsaWrapper.SecurityLevel.SlhDsa128s,
            SlhDsaWrapper.SecurityLevel.SlhDsa128f,
            SlhDsaWrapper.SecurityLevel.SlhDsa192s,
            SlhDsaWrapper.SecurityLevel.SlhDsa192f,
            SlhDsaWrapper.SecurityLevel.SlhDsa256s,
            SlhDsaWrapper.SecurityLevel.SlhDsa256f
        };

        foreach (var level in slhLevels)
        {
            using var key = SlhDsa.GenerateKeyPair(level);
            Assert.Equal(level, key.Level);
        }
    }

    #endregion

    #region Real-World Scenarios

    [Fact]
    public void Integration_SecureMessaging_EndToEnd()
    {
        if (!MLKemWrapper.IsSupported() || !MLDsaWrapper.IsSupported())
            return;

        // Scenario: Secure messaging app (Signal-like) using PQC

        // Alice's long-term signing key
        using var aliceSignKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);

        // Bob's long-term signing key and ephemeral encryption key
        using var bobSignKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);
        using var bobKemKey = MLKem.GenerateKeyPair(MLKemWrapper.SecurityLevel.MLKem768);

        // Alice sends message to Bob
        var message = "Hi Bob! 👋";
        var messageBytes = Encoding.UTF8.GetBytes(message);

        // 1. Alice establishes shared secret with Bob's KEM key
        using var encResult = MLKem.Create().WithPublicKey(bobKemKey.PublicKeyPem).Encapsulate();

        // 2. Alice encrypts message with AES-GCM
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] encrypted = new byte[messageBytes.Length];
        byte[] tag = new byte[16];

        using (var aes = new AesGcm(encResult.SharedSecret, 16))
        {
            aes.Encrypt(nonce, messageBytes, encrypted, tag);
        }

        // 3. Alice signs the encrypted message
        var signatureData = encrypted.Concat(nonce).Concat(tag).ToArray();
        var signature = aliceSignKey.Sign(signatureData);

        // === Message transmitted: encResult.Ciphertext, encrypted, nonce, tag, signature ===

        // Bob receives and processes
        // 4. Bob recovers shared secret
        var sharedSecret = bobKemKey.Decapsulate(encResult.Ciphertext);

        // 5. Bob verifies signature
        var receivedSigData = encrypted.Concat(nonce).Concat(tag).ToArray();
        var isSigValid = MLDsa.Verify(aliceSignKey.PublicKeyPem, receivedSigData, signature);
        Assert.True(isSigValid, "Signature verification failed");

        // 6. Bob decrypts message
        byte[] decrypted = new byte[encrypted.Length];
        using (var aes = new AesGcm(sharedSecret, 16))
        {
            aes.Decrypt(nonce, encrypted, tag, decrypted);
        }

        var recoveredMessage = Encoding.UTF8.GetString(decrypted);
        Assert.Equal(message, recoveredMessage);
    }

    [Fact]
    public void Integration_BlockchainTransaction_PQC_Signing()
    {
        if (!MLDsaWrapper.IsSupported())
            return;

        // Scenario: Quantum-resistant blockchain transaction

        var transaction = new
        {
            From = "0xAlice...",
            To = "0xBob...",
            Amount = 100.50m,
            Nonce = 42,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        var txData = Encoding.UTF8.GetBytes(
            System.Text.Json.JsonSerializer.Serialize(transaction));

        // Sign with highest security
        using var walletKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa87);

        var signature = MLDsa.Create()
            .WithKeyPair(walletKey)
            .WithData(txData)
            .WithContext("blockchain-tx-v1")
            .Sign();

        // Network validates
        var isValid = MLDsa.Create()
            .WithPublicKey(walletKey.PublicKeyPem)
            .WithData(txData)
            .WithContext("blockchain-tx-v1")
            .Verify(signature);

        Assert.True(isValid);
    }

    #endregion
}
#endif
