#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.MLDsa;
using HeroCrypt.Primitives.MLKem;
using HeroCrypt.Primitives.SlhDsa;

namespace HeroCrypt.Tests.Primitives;

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
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        // Scenario: Alice wants to send encrypted message to Bob using hybrid PQC encryption

        // Step 1: Bob generates ML-KEM key pair and shares public key
        using var bobKeyPair = MLKemBuilder.Create()
            .WithSecurityBits(256) // High security
            .GenerateKeyPair();

        // Step 2: Alice encapsulates a shared secret using Bob's public key
        using var encapsulation = MLKemBuilder.Create()
            .WithPublicKey(bobKeyPair.PublicKeyPem)
            .Encapsulate();

        byte[] sharedSecret = encapsulation.SharedSecret;
        byte[] ciphertext = encapsulation.Ciphertext;

        // Step 3: Alice encrypts message using AES-GCM with the shared secret
        var message = "Top secret quantum-resistant message! 🔐";
        var messageBytes = Encoding.UTF8.GetBytes(message);

        byte[] nonce = new byte[System.Security.Cryptography.AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);

        byte[] encrypted = new byte[messageBytes.Length];
        byte[] tag = new byte[System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize];
        using (var aes = new System.Security.Cryptography.AesGcm(sharedSecret, System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize))
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

        using (var aes = new System.Security.Cryptography.AesGcm(recoveredSecret, System.Security.Cryptography.AesGcm.TagByteSizes.MaxSize))
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
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        // Scenario: Alice sends same message to 3 recipients using different shared secrets
        var message = "Confidential group message";
        var messageBytes = Encoding.UTF8.GetBytes(message);

        // Generate key pairs for 3 recipients
        var recipients = new[]
        {
            MLKemBuilder.Create().GenerateKeyPair(),
            MLKemBuilder.Create().GenerateKeyPair(),
            MLKemBuilder.Create().GenerateKeyPair()
        };

        try
        {
            // For each recipient, encapsulate and encrypt
            var encryptedPackages = new List<(byte[] ciphertext, byte[] nonce, byte[] encrypted, byte[] tag)>();

            foreach (var recipient in recipients)
            {
                using var enc = MLKemBuilder.Create().WithPublicKey(recipient.PublicKeyPem).Encapsulate();

                byte[] nonce = new byte[12];
                RandomNumberGenerator.Fill(nonce);

                byte[] encrypted = new byte[messageBytes.Length];
                byte[] tag = new byte[16];

                using var aes = new System.Security.Cryptography.AesGcm(enc.SharedSecret, 16);
                aes.Encrypt(nonce, messageBytes, encrypted, tag);

                encryptedPackages.Add((enc.Ciphertext, nonce, encrypted, tag));
            }

            // Each recipient can decrypt their copy
            for (int i = 0; i < recipients.Length; i++)
            {
                var package = encryptedPackages[i];
                var secret = recipients[i].Decapsulate(package.ciphertext);

                byte[] decrypted = new byte[package.encrypted.Length];
                using var aes = new System.Security.Cryptography.AesGcm(secret, 16);
                aes.Decrypt(package.nonce, package.encrypted, package.tag, decrypted);

                Assert.Equal(message, Encoding.UTF8.GetString(decrypted));
            }
        }
        finally
        {
            foreach (var recipient in recipients)
            {
                recipient.Dispose();
            }
        }
    }

    #endregion

    #region Digital Signature Workflows

    [Fact]
    public void Integration_DocumentSigning_MLDsa_FullWorkflow()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

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
        using var signingKey = MLDsaBuilder.Create()
            .WithSecurityLevel(MLDsaCore.SecurityLevel.MLDsa65)
            .GenerateKeyPair();

        // Sign with context for domain separation
        var signature = MLDsaBuilder.Create()
            .WithKeyPair(signingKey)
            .WithData(documentData)
            .WithContext($"legal-doc-v1:{documentId}")
            .Sign();

        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);

        // Verify signature (could be done by different party)
        var isValid = MLDsaBuilder.Create()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(documentData)
            .WithContext($"legal-doc-v1:{documentId}")
            .Verify(signature);

        Assert.True(isValid);

        // Tampering detection: modify document
        var tamperedData = Encoding.UTF8.GetBytes(
            $"{documentId}|{documentContent} [MODIFIED]|{signedBy}|{timestamp:O}");

        var isTamperedValid = MLDsaBuilder.Create()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(tamperedData)
            .WithContext($"legal-doc-v1:{documentId}")
            .Verify(signature);

        Assert.False(isTamperedValid);
    }

    [Fact]
    public void Integration_ChainOfTrust_MultipleSignatures()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        // Scenario: Multi-level approval with signature chain
        var document = "Budget proposal for Q1 2025";
        var docBytes = Encoding.UTF8.GetBytes(document);

        // Three approvers
        using var managerKey = MLDsaBuilder.Create().WithSecurityLevel(MLDsaCore.SecurityLevel.MLDsa65).GenerateKeyPair();
        using var directorKey = MLDsaBuilder.Create().WithSecurityLevel(MLDsaCore.SecurityLevel.MLDsa65).GenerateKeyPair();
        using var cfoKey = MLDsaBuilder.Create().WithSecurityLevel(MLDsaCore.SecurityLevel.MLDsa87).GenerateKeyPair(); // Higher security

        // Manager signs
        var managerSig = MLDsaBuilder.Create()
            .WithKeyPair(managerKey)
            .WithData(docBytes)
            .WithContext("approval:manager")
            .Sign();

        // Director signs (including manager's signature)
        var combinedData1 = docBytes.Concat(managerSig).ToArray();
        var directorSig = MLDsaBuilder.Create()
            .WithKeyPair(directorKey)
            .WithData(combinedData1)
            .WithContext("approval:director")
            .Sign();

        // CFO signs (including both previous signatures)
        var combinedData2 = combinedData1.Concat(directorSig).ToArray();
        var cfoSig = MLDsaBuilder.Create()
            .WithKeyPair(cfoKey)
            .WithData(combinedData2)
            .WithContext("approval:cfo")
            .Sign();

        // Verify chain of trust (in reverse order)
        Assert.True(MLDsaBuilder.Create()
            .WithPublicKey(cfoKey.PublicKeyPem)
            .WithData(combinedData2)
            .WithContext("approval:cfo")
            .Verify(cfoSig));
        Assert.True(MLDsaBuilder.Create()
            .WithPublicKey(directorKey.PublicKeyPem)
            .WithData(combinedData1)
            .WithContext("approval:director")
            .Verify(directorSig));
        Assert.True(MLDsaBuilder.Create()
            .WithPublicKey(managerKey.PublicKeyPem)
            .WithData(docBytes)
            .WithContext("approval:manager")
            .Verify(managerSig));
    }

    #endregion

    #region Hash-Based Signatures

    [Fact]
    public void Integration_CodeSigning_SlhDsa_SmallSignature()
    {
        if (!SlhDsaCore.IsSupported())
        {
            return;
        }

        // Scenario: Sign software release with conservative hash-based signature

        var softwareVersion = "v2.1.0";
        var buildHash = "abc123def456..."; // SHA-256 of build artifacts
        var releaseNotes = "Bug fixes and performance improvements";

        var releaseData = Encoding.UTF8.GetBytes(
            $"{softwareVersion}|{buildHash}|{releaseNotes}");

        // Use small variant for smaller signature files
        using var signingKey = SlhDsaBuilder.Create()
            .WithSmallVariant(192) // 192-bit security
            .GenerateKeyPair();

        // Sign the release
        var signature = SlhDsaBuilder.Create()
            .WithKeyPair(signingKey)
            .WithData(releaseData)
            .WithContext($"code-signing:{softwareVersion}")
            .Sign();

        Assert.NotNull(signature);

        // Users verify the signature
        var isAuthentic = SlhDsaBuilder.Create()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(releaseData)
            .WithContext($"code-signing:{softwareVersion}")
            .Verify(signature);

        Assert.True(isAuthentic);

        // Get signature info
        var info = SlhDsaCore.GetLevelInfo(SlhDsaCore.SecurityLevel.SlhDsa192s);
        Assert.Equal(192, info.SecurityBits);
    }

    #endregion

    #region Key Management

    [Fact]
    public void Integration_KeyRotation_GracefulTransition()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        // Scenario: Rotating signing keys while maintaining verification
        var message = "Important message during key rotation";
        var msgBytes = Encoding.UTF8.GetBytes(message);

        // Old key (being phased out)
        using var oldKey = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);

        // New key (being phased in)
        using var newKey = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa87);

        // Sign with old key
        var oldSignature = oldKey.Sign(msgBytes);

        // Sign with new key
        var newSignature = newKey.Sign(msgBytes);

        // During transition period, accept both signatures
        var oldIsValid = MLDsaBuilder.Create().WithPublicKey(oldKey.PublicKeyPem).WithData(msgBytes).Verify(oldSignature);
        var newIsValid = MLDsaBuilder.Create().WithPublicKey(newKey.PublicKeyPem).WithData(msgBytes).Verify(newSignature);

        Assert.True(oldIsValid);
        Assert.True(newIsValid);

        // Cross-verification should fail (different keys)
        var crossCheck = MLDsaBuilder.Create().WithPublicKey(newKey.PublicKeyPem).WithData(msgBytes).Verify(oldSignature);
        Assert.False(crossCheck);
    }

    [Fact]
    public void Integration_KeyExport_Import_Roundtrip()
    {
        if (!MLKemCore.IsSupported() || !MLDsaCore.IsSupported())
        {
            return;
        }

        // ML-KEM key export/import
        using var originalKemKey = MLKemCore.GenerateKeyPair(MLKemCore.SecurityLevel.MLKem768);

        var publicKeyPem = originalKemKey.PublicKeyPem;
        var secretKeyPem = originalKemKey.SecretKeyPem;

        // Verify PEM format
        Assert.Contains("-----BEGIN PUBLIC KEY-----", publicKeyPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", secretKeyPem);

        // ML-DSA key export/import
        using var originalDsaKey = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);

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
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

        // Scenario: High-volume signature generation (e.g., timestamping service)
        const int batchSize = 100;

        using var signingKey = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);

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
            if (MLDsaBuilder.Create().WithPublicKey(signingKey.PublicKeyPem).WithData(data).Verify(sig))
            {
                validCount++;
            }
        }

        Assert.Equal(batchSize, validCount);
    }

    [Fact]
    public async Task Integration_ConcurrentOperations_ThreadSafetyAsync()
    {
        if (!MLKemCore.IsSupported())
        {
            return;
        }

        // Scenario: Concurrent key generation and encapsulation
        const int threadCount = 10;
        var tasks = new Task<bool>[threadCount];

        for (int i = 0; i < threadCount; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    using var keyPair = MLKemCore.GenerateKeyPair();
                    using var enc = MLKemBuilder.Create().WithPublicKey(keyPair.PublicKeyPem).Encapsulate();
                    var recovered = keyPair.Decapsulate(enc.Ciphertext);
                    return enc.SharedSecret.SequenceEqual(recovered);
                }
                catch (CryptographicException)
                {
                    return false;
                }
                catch (ArgumentException)
                {
                    return false;
                }
            }, TestContext.Current.CancellationToken);
        }

        await Task.WhenAll(tasks);

        // All concurrent operations should succeed
        Assert.All(tasks, t => Assert.True(t.Result));
    }

    #endregion

    #region Security Parameter Validation

    [Fact]
    public void Integration_SecurityLevels_AllParameterSets()
    {
        if (!MLKemCore.IsSupported() || !MLDsaCore.IsSupported() || !SlhDsaCore.IsSupported())
        {
            return;
        }

        // Validate all ML-KEM security levels
        var kemLevels = new[]
        {
            MLKemCore.SecurityLevel.MLKem512,
            MLKemCore.SecurityLevel.MLKem768,
            MLKemCore.SecurityLevel.MLKem1024
        };

        foreach (var level in kemLevels)
        {
            using var key = MLKemCore.GenerateKeyPair(level);
            Assert.Equal(level, key.Level);

            var info = MLKemCore.GetLevelInfo(level);
            Assert.True(info.SecurityBits >= 128);
        }

        // Validate all ML-DSA security levels
        var dsaLevels = new[]
        {
            MLDsaCore.SecurityLevel.MLDsa44,
            MLDsaCore.SecurityLevel.MLDsa65,
            MLDsaCore.SecurityLevel.MLDsa87
        };

        foreach (var level in dsaLevels)
        {
            using var key = MLDsaCore.GenerateKeyPair(level);
            Assert.Equal(level, key.Level);

            var info = MLDsaCore.GetLevelInfo(level);
            Assert.True(info.SecurityBits >= 128);
            Assert.True(info.SignatureSize > 0);
        }

        // Validate all SLH-DSA variants
        var slhLevels = new[]
        {
            SlhDsaCore.SecurityLevel.SlhDsa128s,
            SlhDsaCore.SecurityLevel.SlhDsa128f,
            SlhDsaCore.SecurityLevel.SlhDsa192s,
            SlhDsaCore.SecurityLevel.SlhDsa192f,
            SlhDsaCore.SecurityLevel.SlhDsa256s,
            SlhDsaCore.SecurityLevel.SlhDsa256f
        };

        foreach (var level in slhLevels)
        {
            using var key = SlhDsaCore.GenerateKeyPair(level);
            Assert.Equal(level, key.Level);
        }
    }

    #endregion

    #region Real-World Scenarios

    [Fact]
    public void Integration_SecureMessaging_EndToEnd()
    {
        if (!MLKemCore.IsSupported() || !MLDsaCore.IsSupported())
        {
            return;
        }

        // Scenario: Secure messaging app (Signal-like) using PQC

        // Alice's long-term signing key
        using var aliceSignKey = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);

        // Bob's long-term signing key and ephemeral encryption key
        using var bobSignKey = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa65);
        using var bobKemKey = MLKemCore.GenerateKeyPair(MLKemCore.SecurityLevel.MLKem768);

        // Alice sends message to Bob
        var message = "Hi Bob! 👋";
        var messageBytes = Encoding.UTF8.GetBytes(message);

        // 1. Alice establishes shared secret with Bob's KEM key
        using var encResult = MLKemBuilder.Create().WithPublicKey(bobKemKey.PublicKeyPem).Encapsulate();

        // 2. Alice encrypts message with AES-GCM
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] encrypted = new byte[messageBytes.Length];
        byte[] tag = new byte[16];

        using (var aes = new System.Security.Cryptography.AesGcm(encResult.SharedSecret, 16))
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
        var isSigValid = MLDsaCore.Verify(aliceSignKey.PublicKeyPem, receivedSigData, signature);
        Assert.True(isSigValid, "Signature verification failed");

        // 6. Bob decrypts message
        byte[] decrypted = new byte[encrypted.Length];
        using (var aes = new System.Security.Cryptography.AesGcm(sharedSecret, 16))
        {
            aes.Decrypt(nonce, encrypted, tag, decrypted);
        }

        var recoveredMessage = Encoding.UTF8.GetString(decrypted);
        Assert.Equal(message, recoveredMessage);
    }

    [Fact]
    public void Integration_BlockchainTransaction_PQC_Signing()
    {
        if (!MLDsaCore.IsSupported())
        {
            return;
        }

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
            $"{transaction.From}|{transaction.To}|{transaction.Amount}|{transaction.Nonce}|{transaction.Timestamp}");

        // Sign with highest security
        using var walletKey = MLDsaCore.GenerateKeyPair(MLDsaCore.SecurityLevel.MLDsa87);

        var signature = MLDsaBuilder.Create()
            .WithKeyPair(walletKey)
            .WithData(txData)
            .WithContext("blockchain-tx-v1")
            .Sign();

        // Network validates
        var isValid = MLDsaBuilder.Create()
            .WithPublicKey(walletKey.PublicKeyPem)
            .WithData(txData)
            .WithContext("blockchain-tx-v1")
            .Verify(signature);

        Assert.True(isValid);
    }

    #endregion
}
#endif
