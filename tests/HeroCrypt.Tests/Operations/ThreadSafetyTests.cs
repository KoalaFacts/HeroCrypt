using System.Collections.Concurrent;
using System.Text;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.Ed25519;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Operations;

/// <summary>
/// Thread safety tests for all builder classes.
/// Verifies that concurrent access to shared builder instances works correctly.
/// </summary>
/// <remarks>
/// These tests validate the thread safety guarantees documented in iteration 21.
/// Each builder should be safe for concurrent use from multiple threads.
/// </remarks>
public class ThreadSafetyTests
{
    private const int ConcurrentOperations = 100;
    private const int ThreadCount = 10;

    /// <summary>
    /// Thread safety tests for EncryptionBuilder.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    [Trait("Category", TestCategories.SLOW)]
    public class EncryptionBuilderThreadSafety
    {
        [Fact]
        public void ConcurrentEncrypt_WithSameBuilder_AllSucceed()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var results = new ConcurrentBag<EncryptionResult>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Run concurrent encryptions
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                try
                {
                    var plaintext = $"Message {i} from thread {Environment.CurrentManagedThreadId}";
                    var result = builder.Encrypt(plaintext);
                    results.Add(result);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, results.Count);

            // Verify all ciphertexts are unique (different nonces)
            var uniqueCiphertexts = results.Select(r => Convert.ToHexString(r.Ciphertext)).Distinct().Count();
            Assert.Equal(ConcurrentOperations, uniqueCiphertexts);
        }

        [Fact]
        public void ConcurrentGetKey_WithSameBuilder_AllReturnSameKey()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var keys = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Get key concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, _ =>
            {
                try
                {
                    var keyHex = builder.GetKeyAsHex();
                    keys.Add(keyHex);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, keys.Count);

            // All keys should be identical
            var uniqueKeys = keys.Distinct().Count();
            Assert.Equal(1, uniqueKeys);
        }

        [Fact]
        public void ConcurrentEncryptAndGetKey_WithSameBuilder_AllSucceed()
        {
            // Arrange
            using var builder = HeroCryptBuilder.Encrypt()
                .WithChaCha20Poly1305()
                .WithRandomKey();

            var results = new ConcurrentBag<(string operation, bool success)>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Mix of encrypt and getKey operations
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                try
                {
                    if (i % 2 == 0)
                    {
                        var result = builder.Encrypt($"Message {i}");
                        results.Add(("encrypt", result.Ciphertext.Length > 0));
                    }
                    else
                    {
                        var key = builder.GetKey();
                        results.Add(("getKey", key.Length == 32));
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, results.Count);
            Assert.All(results, r => Assert.True(r.success));
        }
    }

    /// <summary>
    /// Thread safety tests for DecryptionBuilder.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    [Trait("Category", TestCategories.SLOW)]
    public class DecryptionBuilderThreadSafety
    {
        [Fact]
        public void ConcurrentDecrypt_WithSameBuilder_AllSucceed()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var plaintexts = Enumerable.Range(0, ConcurrentOperations)
                .Select(i => $"Message {i}")
                .ToArray();

            // Pre-encrypt all messages
            var encrypted = plaintexts.Select(p =>
            {
                var result = HeroCryptBuilder.Encrypt()
                    .WithAesGcm()
                    .WithKey(key)
                    .Encrypt(p);
                return (plaintext: p, ciphertext: result.Ciphertext, nonce: result.Nonce);
            }).ToArray();

            var decrypted = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Decrypt concurrently using separate builders (since nonce must be set per message)
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                try
                {
                    using var builder = HeroCryptBuilder.Decrypt()
                        .WithAesGcm()
                        .WithKey(key)
                        .WithNonce(encrypted[i].nonce);
                    var result = builder.DecryptToString(encrypted[i].ciphertext);
                    decrypted.Add(result);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, decrypted.Count);

            // Verify all plaintexts match
            var sortedOriginal = plaintexts.OrderBy(x => x).ToArray();
            var sortedDecrypted = decrypted.OrderBy(x => x).ToArray();
            Assert.Equal(sortedOriginal, sortedDecrypted);
        }
    }

    /// <summary>
    /// Thread safety tests for HashBuilder.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    [Trait("Category", TestCategories.SLOW)]
    public class HashBuilderThreadSafety
    {
        [Fact]
        public void ConcurrentHash_WithSameBuilder_AllSucceed()
        {
            // Arrange
            var builder = HeroCryptBuilder.Hash().WithSha256();
            var hashes = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Hash concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                try
                {
                    var hash = builder.ComputeHashToHex($"Message {i}");
                    hashes.Add(hash);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, hashes.Count);

            // All hashes should be valid SHA-256 (64 hex chars)
            Assert.All(hashes, h => Assert.Equal(64, h.Length));
        }

        [Fact]
        public void ConcurrentHash_SameInput_ProducesSameOutput()
        {
            // Arrange
            var builder = HeroCryptBuilder.Hash().WithSha256();
            var input = "Deterministic input for hash";
            var hashes = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Hash the same input concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, _ =>
            {
                try
                {
                    var hash = builder.ComputeHashToHex(input);
                    hashes.Add(hash);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, hashes.Count);

            // All hashes should be identical (deterministic)
            var uniqueHashes = hashes.Distinct().Count();
            Assert.Equal(1, uniqueHashes);
        }

        [Fact]
        public void ConcurrentKeyedHash_WithSameBuilder_AllSucceed()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            using var builder = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKey(key);

            var hashes = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Keyed hash concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                try
                {
                    var hash = builder.ComputeHashToHex($"Message {i}");
                    hashes.Add(hash);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, hashes.Count);
        }

        [Theory]
        [InlineData(HashingAlgorithm.Sha256)]
        [InlineData(HashingAlgorithm.Sha384)]
        [InlineData(HashingAlgorithm.Sha512)]
        [InlineData(HashingAlgorithm.Blake2b256)]
        public void ConcurrentHash_DifferentAlgorithms_AllSucceed(HashingAlgorithm algorithm)
        {
            // Arrange
            var builder = HeroCryptBuilder.Hash().WithAlgorithm(algorithm);
            var hashes = new ConcurrentBag<byte[]>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                try
                {
                    var hash = builder.ComputeHash($"Message {i}");
                    hashes.Add(hash);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, hashes.Count);
        }
    }

    /// <summary>
    /// Thread safety tests for SignatureBuilder.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    [Trait("Category", TestCategories.SLOW)]
    public class SignatureBuilderThreadSafety
    {
        [Fact]
        public void ConcurrentSign_Hmac_WithSameBuilder_AllSucceed()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            using var builder = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key);

            var signatures = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Sign concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                try
                {
                    var sig = builder.SignToHex($"Message {i}");
                    signatures.Add(sig);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, signatures.Count);

            // All signatures should be valid length (64 hex chars for SHA-256)
            Assert.All(signatures, s => Assert.Equal(64, s.Length));
        }

        [Fact]
        public void ConcurrentSign_Ed25519_WithSameBuilder_AllSucceed()
        {
            // Arrange
            var (privateKey, _) = Ed25519Core.GenerateKeyPair();
            using var builder = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey);

            var signatures = new ConcurrentBag<byte[]>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Sign concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                try
                {
                    var sig = builder.Sign($"Message {i}");
                    signatures.Add(sig);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, signatures.Count);

            // All signatures should be 64 bytes
            Assert.All(signatures, s => Assert.Equal(64, s.Length));
        }

        [Fact]
        public void ConcurrentSign_SameMessage_ProducesSameSignature_ForHmac()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            using var builder = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key);

            var message = "Deterministic message for HMAC";
            var signatures = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Sign same message concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, _ =>
            {
                try
                {
                    var sig = builder.SignToHex(message);
                    signatures.Add(sig);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, signatures.Count);

            // All HMAC signatures should be identical (deterministic)
            var uniqueSigs = signatures.Distinct().Count();
            Assert.Equal(1, uniqueSigs);
        }
    }

    /// <summary>
    /// Thread safety tests for VerificationBuilder.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    [Trait("Category", TestCategories.SLOW)]
    public class VerificationBuilderThreadSafety
    {
        [Fact]
        public void ConcurrentVerify_Hmac_WithSameBuilder_AllSucceed()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(64);
            var message = "Message to verify";
            var signature = HeroCryptBuilder.Sign()
                .WithHmacSha256()
                .WithKey(key)
                .Sign(message);

            using var builder = HeroCryptBuilder.Verify()
                .WithHmacSha256()
                .WithKey(key)
                .WithSignature(signature);

            var results = new ConcurrentBag<bool>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Verify concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, _ =>
            {
                try
                {
                    var isValid = builder.Verify(message);
                    results.Add(isValid);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, results.Count);
            Assert.All(results, r => Assert.True(r));
        }

        [Fact]
        public void ConcurrentVerify_Ed25519_WithSameBuilder_AllSucceed()
        {
            // Arrange
            var (privateKey, publicKey) = Ed25519Core.GenerateKeyPair();
            var message = "Message to verify with Ed25519";
            var signature = HeroCryptBuilder.Sign()
                .WithEd25519()
                .WithPrivateKey(privateKey)
                .Sign(message);

            var builder = HeroCryptBuilder.Verify()
                .WithEd25519()
                .WithPublicKey(publicKey)
                .WithSignature(signature);

            var results = new ConcurrentBag<bool>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Verify concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, _ =>
            {
                try
                {
                    var isValid = builder.Verify(message);
                    results.Add(isValid);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, results.Count);
            Assert.All(results, r => Assert.True(r));
        }
    }

    /// <summary>
    /// Thread safety tests for KeyDerivationBuilder.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    [Trait("Category", TestCategories.SLOW)]
    public class KeyDerivationBuilderThreadSafety
    {
        [Fact]
        public void ConcurrentDeriveKey_Argon2id_WithSameBuilder_AllSucceed()
        {
            // Arrange - use lower memory for faster tests
            using var builder = HeroCryptBuilder.DeriveKey()
                .WithArgon2id()
                .WithPassword("test-password")
                .WithRandomSalt();

            var keys = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Derive key concurrently (fewer iterations since Argon2id is slow)
            Parallel.For(0, 10, new ParallelOptions { MaxDegreeOfParallelism = 4 }, _ =>
            {
                try
                {
                    var key = builder.DeriveKeyToHex();
                    keys.Add(key);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(10, keys.Count);

            // All derived keys should be identical (same password + salt)
            var uniqueKeys = keys.Distinct().Count();
            Assert.Equal(1, uniqueKeys);
        }

        [Fact]
        public void ConcurrentGetSalt_WithSameBuilder_AllReturnSameSalt()
        {
            // Arrange
            using var builder = HeroCryptBuilder.DeriveKey()
                .WithArgon2id()
                .WithPassword("test-password")
                .WithRandomSalt();

            var salts = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Get salt concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, _ =>
            {
                try
                {
                    var salt = builder.GetSaltAsHex();
                    salts.Add(salt);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, salts.Count);

            // All salts should be identical
            var uniqueSalts = salts.Distinct().Count();
            Assert.Equal(1, uniqueSalts);
        }

        [Fact]
        public void ConcurrentDeriveKey_Hkdf_WithSameBuilder_AllSucceed()
        {
            // Arrange - HKDF is fast, so we can use more iterations
            using var builder = HeroCryptBuilder.DeriveKey()
                .WithHkdfSha256()
                .WithPassword("master-key")
                .WithSalt(Encoding.UTF8.GetBytes("context"))
                .WithInfo("derived-key")
                .WithOutputLength(32);

            var keys = new ConcurrentBag<string>();
            var exceptions = new ConcurrentBag<Exception>();

            // Act - Derive key concurrently
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, _ =>
            {
                try
                {
                    var key = builder.DeriveKeyToHex();
                    keys.Add(key);
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
            Assert.Equal(ConcurrentOperations, keys.Count);

            // All derived keys should be identical (deterministic)
            var uniqueKeys = keys.Distinct().Count();
            Assert.Equal(1, uniqueKeys);
        }
    }

    /// <summary>
    /// Tests for concurrent disposal safety.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    [Trait("Category", TestCategories.SLOW)]
    public class ConcurrentDisposalTests
    {
        [Fact]
        public void ConcurrentDispose_EncryptionBuilder_NoExceptions()
        {
            // Arrange
            var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            var exceptions = new ConcurrentBag<Exception>();

            // Act - Dispose concurrently
            Parallel.For(0, 100, new ParallelOptions { MaxDegreeOfParallelism = 10 }, _ =>
            {
                try
                {
                    builder.Dispose();
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert - No exceptions from concurrent dispose
            Assert.Empty(exceptions);
        }

        [Fact]
        public void ConcurrentDispose_HashBuilder_NoExceptions()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(32);
            var builder = HeroCryptBuilder.Hash()
                .WithSha256()
                .WithKey(key);

            var exceptions = new ConcurrentBag<Exception>();

            // Act - Dispose concurrently
            Parallel.For(0, 100, new ParallelOptions { MaxDegreeOfParallelism = 10 }, _ =>
            {
                try
                {
                    builder.Dispose();
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            // Assert
            Assert.Empty(exceptions);
        }

        [Fact]
        public void UseAfterDispose_ThrowsObjectDisposedException()
        {
            // Arrange
            var builder = HeroCryptBuilder.Encrypt()
                .WithAesGcm()
                .WithRandomKey();

            builder.Dispose();

            // Act & Assert
            Assert.Throws<ObjectDisposedException>(() => builder.Encrypt("test"));
        }
    }
}
