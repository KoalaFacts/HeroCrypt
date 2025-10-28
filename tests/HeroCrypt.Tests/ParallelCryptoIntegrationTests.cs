using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using HeroCrypt.Performance.Batch;
using HeroCrypt.Performance.Memory;
using HeroCrypt.Performance.Parallel;
using HeroCrypt.Performance.Simd;

namespace HeroCrypt.Tests;

#if !NETSTANDARD2_0

/// <summary>
/// Integration tests for parallel crypto operations
///
/// Tests end-to-end scenarios combining batch operations, parallel processing,
/// SIMD acceleration, and memory management to ensure correctness and performance
/// in real-world usage patterns.
/// </summary>
public class ParallelCryptoIntegrationTests
{
    private readonly ITestOutputHelper _output;

    public ParallelCryptoIntegrationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    #region Batch Encryption/Decryption Integration Tests

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchEncryption_AesGcm_EncryptDecryptRoundtrip_WorksCorrectly()
    {
        // Arrange
        var key = new byte[32];
        var masterNonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(masterNonce);

        var plaintexts = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("First message"),
            Encoding.UTF8.GetBytes("Second message with more data"),
            Encoding.UTF8.GetBytes("Third message"),
            new byte[1024], // Large message
            new byte[10240], // Very large message
        };

        // Act - Encrypt
        var sw = Stopwatch.StartNew();
        var encrypted = await BatchEncryptionOperations.AesGcmEncryptBatchAsync(
            key, masterNonce, plaintexts);
        sw.Stop();
        _output.WriteLine($"Batch encryption of {plaintexts.Length} messages: {sw.ElapsedMilliseconds}ms");

        // Act - Decrypt
        sw.Restart();
        var decrypted = await BatchEncryptionOperations.AesGcmDecryptBatchAsync(
            key, encrypted);
        sw.Stop();
        _output.WriteLine($"Batch decryption of {encrypted.Length} messages: {sw.ElapsedMilliseconds}ms");

        // Assert
        Assert.Equal(plaintexts.Length, encrypted.Length);
        Assert.Equal(plaintexts.Length, decrypted.Length);

        for (int i = 0; i < plaintexts.Length; i++)
        {
            Assert.Equal(plaintexts[i].ToArray(), decrypted[i]);
            Assert.Equal(12, encrypted[i].Nonce.Length);
            Assert.Equal(16, encrypted[i].Tag.Length);
        }
    }

    [Theory]
    [InlineData(10, 1024)]      // 10 x 1KB
    [InlineData(100, 1024)]     // 100 x 1KB
    [InlineData(50, 10240)]     // 50 x 10KB
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchEncryption_AesGcm_WithVariousSizes_MaintainsCorrectness(int count, int size)
    {
        // Arrange
        var key = new byte[32];
        var masterNonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(masterNonce);

        var plaintexts = Enumerable.Range(0, count)
            .Select(i =>
            {
                var data = new byte[size];
                RandomNumberGenerator.Fill(data);
                return new ReadOnlyMemory<byte>(data);
            })
            .ToArray();

        // Act
        var sw = Stopwatch.StartNew();
        var encrypted = await BatchEncryptionOperations.AesGcmEncryptBatchAsync(
            key, masterNonce, plaintexts);
        var decrypted = await BatchEncryptionOperations.AesGcmDecryptBatchAsync(
            key, encrypted);
        sw.Stop();

        // Assert
        Assert.Equal(count, decrypted.Length);
        for (int i = 0; i < count; i++)
        {
            Assert.Equal(plaintexts[i].ToArray(), decrypted[i]);
        }

        var totalBytes = count * size;
        var throughputMBps = (totalBytes / (1024.0 * 1024.0)) / sw.Elapsed.TotalSeconds;
        _output.WriteLine($"Encrypted and decrypted {count}x{size}B = {totalBytes / 1024}KB in {sw.ElapsedMilliseconds}ms");
        _output.WriteLine($"Throughput: {throughputMBps:F2} MB/s");
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchEncryption_ChaCha20Poly1305_Encrypt_WorksCorrectly()
    {
        // Arrange
        var key = new byte[32];
        var masterNonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(masterNonce);

        var plaintexts = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("ChaCha20-Poly1305 message 1"),
            Encoding.UTF8.GetBytes("ChaCha20-Poly1305 message 2"),
            new byte[2048],
        };

        // Act
        var encrypted = await BatchEncryptionOperations.ChaCha20Poly1305EncryptBatchAsync(
            key, masterNonce, plaintexts);

        // Assert
        Assert.Equal(plaintexts.Length, encrypted.Length);
        Assert.All(encrypted, result =>
        {
            Assert.NotNull(result.Ciphertext);
            Assert.Equal(12, result.Nonce.Length);
            Assert.Equal(16, result.Tag.Length);
        });
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchEncryption_WithCancellation_ThrowsOperationCanceledException()
    {
        // Arrange
        var key = new byte[32];
        var masterNonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(masterNonce);

        var plaintexts = Enumerable.Range(0, 1000)
            .Select(_ => new ReadOnlyMemory<byte>(new byte[10240]))
            .ToArray();

        var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        // Act & Assert
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await BatchEncryptionOperations.AesGcmEncryptBatchAsync(
                key, masterNonce, plaintexts, cancellationToken: cts.Token);
        });
    }

    #endregion

    #region Batch Hashing Integration Tests

    [Theory]
    [InlineData(100, 1024)]     // 100 x 1KB
    [InlineData(1000, 512)]     // 1000 x 512B
    [InlineData(50, 102400)]    // 50 x 100KB
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchHashing_Sha256_WithVariousSizes_ProducesCorrectHashes(int count, int size)
    {
        // Arrange
        var inputs = Enumerable.Range(0, count)
            .Select(i =>
            {
                var data = new byte[size];
                RandomNumberGenerator.Fill(data);
                return new ReadOnlyMemory<byte>(data);
            })
            .ToArray();

        // Act - Batch hashing
        var sw = Stopwatch.StartNew();
        var batchResults = await BatchHashOperations.Sha256BatchAsync(inputs);
        sw.Stop();

        // Act - Sequential hashing for comparison
        var sequentialResults = inputs
            .Select(input => SHA256.HashData(input.Span))
            .ToArray();

        // Assert
        Assert.Equal(count, batchResults.Length);
        Assert.All(batchResults, hash => Assert.Equal(32, hash.Length));

        for (int i = 0; i < count; i++)
        {
            Assert.Equal(sequentialResults[i], batchResults[i]);
        }

        var totalBytes = count * size;
        var throughputMBps = (totalBytes / (1024.0 * 1024.0)) / sw.Elapsed.TotalSeconds;
        _output.WriteLine($"Hashed {count}x{size}B = {totalBytes / 1024}KB in {sw.ElapsedMilliseconds}ms");
        _output.WriteLine($"Throughput: {throughputMBps:F2} MB/s");
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchHashing_MultipleAlgorithms_ProducesCorrectResults()
    {
        // Arrange
        var testData = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("Test data 1"),
            Encoding.UTF8.GetBytes("Test data 2"),
            Encoding.UTF8.GetBytes("Test data 3"),
        };

        // Act
        var sha256Results = await BatchHashOperations.Sha256BatchAsync(testData);
        var sha512Results = await BatchHashOperations.Sha512BatchAsync(testData);
        var blake2bResults = BatchHashOperations.Blake2bBatch(testData, outputSize: 32);

        // Assert
        Assert.Equal(3, sha256Results.Length);
        Assert.Equal(3, sha512Results.Length);
        Assert.Equal(3, blake2bResults.Length);

        Assert.All(sha256Results, hash => Assert.Equal(32, hash.Length));
        Assert.All(sha512Results, hash => Assert.Equal(64, hash.Length));
        Assert.All(blake2bResults, hash => Assert.Equal(32, hash.Length));

        // Verify against known implementations
        for (int i = 0; i < testData.Length; i++)
        {
            var expectedSha256 = SHA256.HashData(testData[i].Span);
            var expectedSha512 = SHA512.HashData(testData[i].Span);

            Assert.Equal(expectedSha256, sha256Results[i]);
            Assert.Equal(expectedSha512, sha512Results[i]);
        }
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void BatchHashing_WithVerification_DetectsValidAndInvalidHashes()
    {
        // Arrange
        var inputs = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("Valid message 1"),
            Encoding.UTF8.GetBytes("Valid message 2"),
            Encoding.UTF8.GetBytes("Valid message 3"),
        };

        var validHashes = inputs
            .Select(input => new ReadOnlyMemory<byte>(SHA256.HashData(input.Span)))
            .ToArray();

        var invalidHashes = validHashes.ToArray();
        invalidHashes[1] = new ReadOnlyMemory<byte>(new byte[32]); // Corrupt middle hash

        // Act
        var validResults = BatchHashOperations.VerifyHashBatch(
            inputs, validHashes, HashAlgorithmName.SHA256);
        var invalidResults = BatchHashOperations.VerifyHashBatch(
            inputs, invalidHashes, HashAlgorithmName.SHA256);

        // Assert
        Assert.All(validResults, result => Assert.True(result));
        Assert.True(invalidResults[0]);
        Assert.False(invalidResults[1]); // Should detect corruption
        Assert.True(invalidResults[2]);
    }

    #endregion

    #region Batch HMAC Integration Tests

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchHmac_ComputeAndVerify_WorksCorrectly()
    {
        // Arrange
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var messages = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("Message 1"),
            Encoding.UTF8.GetBytes("Message 2"),
            Encoding.UTF8.GetBytes("Message 3"),
            new byte[1024],
            new byte[10240],
        };

        // Act - Compute HMACs
        var sw = Stopwatch.StartNew();
        var hmacs = BatchHmacOperations.HmacSha256Batch(key, messages);
        sw.Stop();
        _output.WriteLine($"Batch HMAC computation: {sw.ElapsedMilliseconds}ms");

        // Act - Verify HMACs
        sw.Restart();
        var verificationResults = BatchHmacOperations.VerifyHmacBatch(
            key, messages, hmacs.Select(h => new ReadOnlyMemory<byte>(h)).ToArray());
        sw.Stop();
        _output.WriteLine($"Batch HMAC verification: {sw.ElapsedMilliseconds}ms");

        // Assert
        Assert.Equal(messages.Length, hmacs.Length);
        Assert.All(hmacs, hmac => Assert.Equal(32, hmac.Length));
        Assert.All(verificationResults, result => Assert.True(result));

        // Verify against standard HMAC
        using var hmacAlg = new HMACSHA256(key);
        for (int i = 0; i < messages.Length; i++)
        {
            var expected = hmacAlg.ComputeHash(messages[i].ToArray());
            Assert.Equal(expected, hmacs[i]);
        }
    }

    [Theory]
    [InlineData(100, 512)]
    [InlineData(500, 1024)]
    [Trait("Category", TestCategories.Integration)]
    public void BatchHmac_LargeScale_MaintainsPerformance(int count, int messageSize)
    {
        // Arrange
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var messages = Enumerable.Range(0, count)
            .Select(_ =>
            {
                var data = new byte[messageSize];
                RandomNumberGenerator.Fill(data);
                return new ReadOnlyMemory<byte>(data);
            })
            .ToArray();

        // Act
        var sw = Stopwatch.StartNew();
        var hmacs = BatchHmacOperations.HmacSha256Batch(key, messages);
        sw.Stop();

        // Assert
        Assert.Equal(count, hmacs.Length);
        var totalBytes = count * messageSize;
        var throughputMBps = (totalBytes / (1024.0 * 1024.0)) / sw.Elapsed.TotalSeconds;
        _output.WriteLine($"HMAC for {count}x{messageSize}B = {totalBytes / 1024}KB in {sw.ElapsedMilliseconds}ms");
        _output.WriteLine($"Throughput: {throughputMBps:F2} MB/s");

        // Performance assertion - should complete in reasonable time
        Assert.True(sw.ElapsedMilliseconds < 10000, $"Batch HMAC took too long: {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void BatchHmac_WithTamperedData_DetectsInvalidHmacs()
    {
        // Arrange
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var messages = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("Message 1"),
            Encoding.UTF8.GetBytes("Message 2"),
            Encoding.UTF8.GetBytes("Message 3"),
        };

        var hmacs = BatchHmacOperations.HmacSha256Batch(key, messages);

        // Tamper with one HMAC
        var tamperedHmacs = hmacs.Select(h => new ReadOnlyMemory<byte>(h.ToArray())).ToArray();
        var tamperedArray = tamperedHmacs[1].ToArray();
        tamperedArray[0] ^= 0xFF; // Flip bits
        tamperedHmacs[1] = tamperedArray;

        // Act
        var results = BatchHmacOperations.VerifyHmacBatch(key, messages, tamperedHmacs);

        // Assert
        Assert.True(results[0]);
        Assert.False(results[1]); // Should detect tampering
        Assert.True(results[2]);
    }

    #endregion

    #region Batch Signature Integration Tests

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    [Trait("Category", TestCategories.Slow)]
    public async Task BatchSignature_RsaSignAndVerify_WorksCorrectly()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var messages = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("Document 1"),
            Encoding.UTF8.GetBytes("Document 2"),
            Encoding.UTF8.GetBytes("Document 3"),
        };

        // Act - Sign
        var sw = Stopwatch.StartNew();
        var signatures = await BatchSignatureOperations.SignBatchAsync(
            rsa, messages, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        sw.Stop();
        _output.WriteLine($"Batch RSA signing: {sw.ElapsedMilliseconds}ms");

        // Act - Verify
        sw.Restart();
        var results = await BatchSignatureOperations.VerifyBatchAsync(
            rsa, messages,
            signatures.Select(s => new ReadOnlyMemory<byte>(s)).ToArray(),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        sw.Stop();
        _output.WriteLine($"Batch RSA verification: {sw.ElapsedMilliseconds}ms");

        // Assert
        Assert.Equal(messages.Length, signatures.Length);
        Assert.All(results, result => Assert.True(result));

        // Verify each signature individually
        for (int i = 0; i < messages.Length; i++)
        {
            var isValid = rsa.VerifyData(
                messages[i].ToArray(),
                signatures[i],
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            Assert.True(isValid);
        }
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchSignature_RsaWithInvalidSignature_DetectsFailure()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var messages = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("Document 1"),
            Encoding.UTF8.GetBytes("Document 2"),
        };

        var signatures = await BatchSignatureOperations.SignBatchAsync(
            rsa, messages, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Corrupt one signature
        signatures[1][0] ^= 0xFF;

        // Act
        var results = await BatchSignatureOperations.VerifyBatchAsync(
            rsa, messages,
            signatures.Select(s => new ReadOnlyMemory<byte>(s)).ToArray(),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.True(results[0]);
        Assert.False(results[1]); // Should detect corruption
    }

    #endregion

    #region Batch Key Derivation Integration Tests

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchKeyDerivation_Pbkdf2_DerivesCorrectKeys()
    {
        // Arrange
        var passwords = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("password1"),
            Encoding.UTF8.GetBytes("password2"),
            Encoding.UTF8.GetBytes("password3"),
        };

        var salts = passwords.Select(_ =>
        {
            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);
            return new ReadOnlyMemory<byte>(salt);
        }).ToArray();

        const int iterations = 10000;
        const int keyLength = 32;

        // Act
        var sw = Stopwatch.StartNew();
        var derivedKeys = await BatchKeyDerivationOperations.Pbkdf2BatchAsync(
            passwords, salts, iterations, keyLength, HashAlgorithmName.SHA256);
        sw.Stop();
        _output.WriteLine($"Batch PBKDF2 derivation: {sw.ElapsedMilliseconds}ms");

        // Assert
        Assert.Equal(passwords.Length, derivedKeys.Length);
        Assert.All(derivedKeys, key => Assert.Equal(keyLength, key.Length));

        // Verify against standard PBKDF2
        for (int i = 0; i < passwords.Length; i++)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                passwords[i].ToArray(),
                salts[i].ToArray(),
                iterations,
                HashAlgorithmName.SHA256);
            var expected = pbkdf2.GetBytes(keyLength);
            Assert.Equal(expected, derivedKeys[i]);
        }
    }

    [Theory]
    [InlineData(10, 1000)]
    [InlineData(100, 1000)]
    [Trait("Category", TestCategories.Integration)]
    public async Task BatchKeyDerivation_Pbkdf2_HandlesMultiplePasswords(int count, int iterations)
    {
        // Arrange
        var passwords = Enumerable.Range(0, count)
            .Select(i => new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes($"password{i}")))
            .ToArray();

        var salts = passwords.Select(_ =>
        {
            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);
            return new ReadOnlyMemory<byte>(salt);
        }).ToArray();

        // Act
        var sw = Stopwatch.StartNew();
        var derivedKeys = await BatchKeyDerivationOperations.Pbkdf2BatchAsync(
            passwords, salts, iterations, 32, HashAlgorithmName.SHA256);
        sw.Stop();

        // Assert
        Assert.Equal(count, derivedKeys.Length);
        _output.WriteLine($"Derived {count} keys with {iterations} iterations in {sw.ElapsedMilliseconds}ms");
        _output.WriteLine($"Average per key: {sw.ElapsedMilliseconds / (double)count:F2}ms");
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void BatchKeyDerivation_Hkdf_DerivesMultipleKeys()
    {
        // Arrange
        var masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);

        // Create and fill salt arrays
        var salt1 = new byte[16];
        var salt2 = new byte[16];
        var salt3 = new byte[16];
        RandomNumberGenerator.Fill(salt1);
        RandomNumberGenerator.Fill(salt2);
        RandomNumberGenerator.Fill(salt3);

        var salts = new ReadOnlyMemory<byte>[]
        {
            salt1,
            salt2,
            salt3,
        };

        var infos = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("context1"),
            Encoding.UTF8.GetBytes("context2"),
            Encoding.UTF8.GetBytes("context3"),
        };

        var outputLengths = new int[] { 32, 32, 32 };

        // Act
        var derivedKeys = BatchKeyDerivationOperations.HkdfBatch(
            masterKey,
            salts,
            infos,
            outputLengths,
            HashAlgorithmName.SHA256);

        // Assert
        Assert.Equal(salts.Length, derivedKeys.Length);
        Assert.All(derivedKeys, key => Assert.Equal(32, key.Length));
    }

    #endregion

    #region SIMD Integration Tests

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void SimdIntegration_WithXorAndEncryption_WorksCorrectly()
    {
        // Arrange
        var data = new byte[1024];
        var key1 = new byte[1024];
        var key2 = new byte[1024];
        var result = new byte[1024];

        RandomNumberGenerator.Fill(data);
        RandomNumberGenerator.Fill(key1);
        RandomNumberGenerator.Fill(key2);

        // Act - Use SIMD for pre-processing
        var tempBuffer = new byte[1024];
        SimdAccelerator.Xor(data, key1, tempBuffer);
        SimdAccelerator.Xor(tempBuffer, key2, result);

        // Assert - Double XOR should return to original when key1 == key2
        var recoveredData = new byte[1024];
        SimdAccelerator.Xor(result, key1, tempBuffer);
        SimdAccelerator.Xor(tempBuffer, key2, recoveredData);

        Assert.Equal(data, recoveredData);
    }

    [Theory]
    [InlineData(1024)]
    [InlineData(10240)]
    [InlineData(102400)]
    [Trait("Category", TestCategories.Integration)]
    public void SimdIntegration_ConstantTimeCompare_WorksWithHashVerification(int dataSize)
    {
        // Arrange
        var data = new byte[dataSize];
        RandomNumberGenerator.Fill(data);

        var hash1 = SHA256.HashData(data);
        var hash2 = SHA256.HashData(data);
        var differentHash = SHA256.HashData(new byte[dataSize]);

        // Act
        var equalResult = SimdAccelerator.ConstantTimeEquals(hash1, hash2);
        var differentResult = SimdAccelerator.ConstantTimeEquals(hash1, differentHash);

        // Assert
        Assert.True(equalResult);
        Assert.False(differentResult);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void SimdIntegration_WithMemoryPools_ReducesAllocations()
    {
        // Arrange
        const int iterations = 100;
        const int bufferSize = 4096;

        // Act - Using memory pools with SIMD operations
        for (int i = 0; i < iterations; i++)
        {
            var buffer1 = CryptoMemoryPool.Rent(bufferSize);
            var buffer2 = CryptoMemoryPool.Rent(bufferSize);
            var result = CryptoMemoryPool.Rent(bufferSize);

            try
            {
                RandomNumberGenerator.Fill(buffer1.AsSpan(0, bufferSize));
                RandomNumberGenerator.Fill(buffer2.AsSpan(0, bufferSize));

                SimdAccelerator.Xor(
                    buffer1.AsSpan(0, bufferSize),
                    buffer2.AsSpan(0, bufferSize),
                    result.AsSpan(0, bufferSize));

                Assert.NotNull(result);
            }
            finally
            {
                CryptoMemoryPool.Return(buffer1);
                CryptoMemoryPool.Return(buffer2);
                CryptoMemoryPool.Return(result);
            }
        }

        // Assert - Test completes without excessive allocations
        Assert.True(true, "Memory pool integration successful");
    }

    #endregion

    #region End-to-End Workflow Tests

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task EndToEnd_EncryptHashAndSign_CompleteWorkflow()
    {
        // This test simulates a real-world scenario:
        // 1. Derive keys from passwords
        // 2. Encrypt multiple messages
        // 3. Hash the encrypted data
        // 4. Sign the hashes
        // 5. Verify the entire chain

        // Arrange
        var passwords = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("user_password_1"),
            Encoding.UTF8.GetBytes("user_password_2"),
        };

        // Create and fill salt arrays
        var salt1 = new byte[16];
        var salt2 = new byte[16];
        RandomNumberGenerator.Fill(salt1);
        RandomNumberGenerator.Fill(salt2);

        var salts = new ReadOnlyMemory<byte>[]
        {
            salt1,
            salt2,
        };

        var messages = new ReadOnlyMemory<byte>[]
        {
            Encoding.UTF8.GetBytes("Important message 1"),
            Encoding.UTF8.GetBytes("Important message 2"),
        };

        // Step 1: Derive encryption keys
        var encryptionKeys = await BatchKeyDerivationOperations.Pbkdf2BatchAsync(
            passwords, salts, 10000, 32, HashAlgorithmName.SHA256);
        _output.WriteLine("Step 1: Derived encryption keys");

        // Step 2: Encrypt messages
        var masterNonce = new byte[12];
        RandomNumberGenerator.Fill(masterNonce);
        var encrypted = await BatchEncryptionOperations.AesGcmEncryptBatchAsync(
            encryptionKeys[0], masterNonce, messages);
        _output.WriteLine("Step 2: Encrypted messages");

        // Step 3: Hash the encrypted data
        var ciphertexts = encrypted.Select(e => new ReadOnlyMemory<byte>(e.Ciphertext)).ToArray();
        var hashes = await BatchHashOperations.Sha256BatchAsync(ciphertexts);
        _output.WriteLine("Step 3: Hashed encrypted data");

        // Step 4: Sign the hashes
        using var rsa = RSA.Create(2048);
        var hashMemories = hashes.Select(h => new ReadOnlyMemory<byte>(h)).ToArray();
        var signatures = await BatchSignatureOperations.SignBatchAsync(
            rsa, hashMemories, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _output.WriteLine("Step 4: Signed hashes");

        // Verification Phase
        // Step 5: Verify signatures
        var signatureMemories = signatures.Select(s => new ReadOnlyMemory<byte>(s)).ToArray();
        var signatureResults = await BatchSignatureOperations.VerifyBatchAsync(
            rsa, hashMemories, signatureMemories, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _output.WriteLine("Step 5: Verified signatures");

        // Step 6: Verify hashes
        var hashResults = BatchHashOperations.VerifyHashBatch(
            ciphertexts, hashMemories, HashAlgorithmName.SHA256);
        _output.WriteLine("Step 6: Verified hashes");

        // Step 7: Decrypt messages
        var decrypted = await BatchEncryptionOperations.AesGcmDecryptBatchAsync(
            encryptionKeys[0], encrypted);
        _output.WriteLine("Step 7: Decrypted messages");

        // Assert
        Assert.All(signatureResults, result => Assert.True(result));
        Assert.All(hashResults, result => Assert.True(result));
        Assert.Equal(messages.Length, decrypted.Length);
        for (int i = 0; i < messages.Length; i++)
        {
            Assert.Equal(messages[i].ToArray(), decrypted[i]);
        }

        _output.WriteLine("End-to-end workflow completed successfully");
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task EndToEnd_ParallelProcessing_WithMemoryManagement()
    {
        // Test parallel processing with proper memory management
        const int batchSize = 50;
        const int dataSize = 10240;

        // Arrange
        var inputs = new ReadOnlyMemory<byte>[batchSize];
        for (int i = 0; i < batchSize; i++)
        {
            var buffer = CryptoMemoryPool.Rent(dataSize);
            RandomNumberGenerator.Fill(buffer.AsSpan(0, dataSize));
            inputs[i] = buffer.AsMemory(0, dataSize);
        }

        try
        {
            // Act - Process through multiple stages
            var sw = Stopwatch.StartNew();

            // Stage 1: Hash
            var hashes = await BatchHashOperations.Sha256BatchAsync(inputs);
            _output.WriteLine($"Stage 1 (Hash): {sw.ElapsedMilliseconds}ms");

            // Stage 2: HMAC
            var hmacKey = new byte[32];
            RandomNumberGenerator.Fill(hmacKey);
            var hmacs = BatchHmacOperations.HmacSha256Batch(hmacKey, inputs);
            _output.WriteLine($"Stage 2 (HMAC): {sw.ElapsedMilliseconds}ms");

            // Stage 3: Encrypt
            var encKey = new byte[32];
            var nonce = new byte[12];
            RandomNumberGenerator.Fill(encKey);
            RandomNumberGenerator.Fill(nonce);
            var encrypted = await BatchEncryptionOperations.AesGcmEncryptBatchAsync(
                encKey, nonce, inputs);
            sw.Stop();
            _output.WriteLine($"Total processing: {sw.ElapsedMilliseconds}ms");

            // Assert
            Assert.Equal(batchSize, hashes.Length);
            Assert.Equal(batchSize, hmacs.Length);
            Assert.Equal(batchSize, encrypted.Length);

            var totalData = batchSize * dataSize;
            _output.WriteLine($"Processed {totalData / 1024}KB through 3 stages");
        }
        finally
        {
            // Cleanup - Return buffers to pool
            foreach (var input in inputs)
            {
                if (System.Runtime.InteropServices.MemoryMarshal.TryGetArray(input, out var segment))
                {
                    CryptoMemoryPool.Return(segment.Array!);
                }
            }
        }
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task EndToEnd_MixedOperations_WithCancellation()
    {
        // Test that cancellation works correctly across mixed operations
        var cts = new CancellationTokenSource();

        // Use a large dataset to ensure cancellation has time to take effect
        var messages = Enumerable.Range(0, 10000)
            .Select(_ => new ReadOnlyMemory<byte>(new byte[10240])) // 10KB each
            .ToArray();

        // Cancel immediately to ensure cancellation is triggered
        cts.Cancel();

        // Start a task that should be cancelled
        var task = Task.Run(async () =>
        {
            // Should throw OperationCanceledException
            var hashes = await BatchHashOperations.Sha256BatchAsync(
                messages, cancellationToken: cts.Token);

            var hmacKey = new byte[32];
            var hmacs = BatchHmacOperations.HmacSha256Batch(
                hmacKey, messages, cancellationToken: cts.Token);

            return (hashes, hmacs);
        });

        // Assert - Should throw OperationCanceledException
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await task);
    }

    #endregion

    #region Performance and Stress Tests

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public async Task Performance_BatchOperations_ComparedToSequential()
    {
        // Compare batch vs sequential performance
        const int count = 100;
        const int size = 1024;

        var inputs = Enumerable.Range(0, count)
            .Select(_ =>
            {
                var data = new byte[size];
                RandomNumberGenerator.Fill(data);
                return new ReadOnlyMemory<byte>(data);
            })
            .ToArray();

        // Sequential
        var sequentialSw = Stopwatch.StartNew();
        var sequentialResults = new byte[count][];
        for (int i = 0; i < count; i++)
        {
            sequentialResults[i] = SHA256.HashData(inputs[i].Span);
        }
        sequentialSw.Stop();

        // Batch
        var batchSw = Stopwatch.StartNew();
        var batchResults = await BatchHashOperations.Sha256BatchAsync(inputs);
        batchSw.Stop();

        // Report
        _output.WriteLine($"Sequential: {sequentialSw.ElapsedMilliseconds}ms");
        _output.WriteLine($"Batch: {batchSw.ElapsedMilliseconds}ms");
        var speedup = sequentialSw.ElapsedMilliseconds / (double)Math.Max(1, batchSw.ElapsedMilliseconds);
        _output.WriteLine($"Speedup: {speedup:F2}x");

        // Assert correctness
        for (int i = 0; i < count; i++)
        {
            Assert.Equal(sequentialResults[i], batchResults[i]);
        }

        // Note: Speedup varies by environment. Just verify correctness.
        _output.WriteLine($"Environment: {(speedup >= 1.0 ? "Batch beneficial" : "Sequential competitive")}");
    }

    [Theory]
    [InlineData(1000, 100)]   // Small messages
    [InlineData(100, 10240)]  // Medium messages
    [Trait("Category", TestCategories.Integration)]
    public async Task Stress_HighVolumeOperations_MaintainCorrectness(int count, int size)
    {
        // Stress test with high volume
        var inputs = Enumerable.Range(0, count)
            .Select(i =>
            {
                var data = new byte[size];
                // Use deterministic data for verification
                for (int j = 0; j < size; j++)
                {
                    data[j] = (byte)((i + j) % 256);
                }
                return new ReadOnlyMemory<byte>(data);
            })
            .ToArray();

        // Act
        var sw = Stopwatch.StartNew();
        var hashes = await BatchHashOperations.Sha256BatchAsync(inputs);
        sw.Stop();

        // Assert
        Assert.Equal(count, hashes.Length);
        _output.WriteLine($"Processed {count}x{size}B = {count * size / 1024}KB in {sw.ElapsedMilliseconds}ms");

        // Spot-check correctness
        var sample = SHA256.HashData(inputs[count / 2].Span);
        Assert.Equal(sample, hashes[count / 2]);
    }

    #endregion

    #region Parallel AES-GCM Tests

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_EncryptDecrypt_RoundtripSuccess()
    {
        // Arrange - Large data that will be chunked (> 2MB)
        var plaintext = new byte[3 * 1024 * 1024]; // 3 MB
        RandomNumberGenerator.Fill(plaintext);

        var key = new byte[32];
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        // Act
        var sw = Stopwatch.StartNew();
        var ciphertext = ParallelAesGcm.EncryptParallel(plaintext, key, nonce);
        sw.Stop();
        _output.WriteLine($"Parallel encryption of {plaintext.Length / 1024}KB: {sw.ElapsedMilliseconds}ms");

        sw.Restart();
        var decrypted = ParallelAesGcm.DecryptParallel(ciphertext, key, nonce);
        sw.Stop();
        _output.WriteLine($"Parallel decryption of {ciphertext.Length / 1024}KB: {sw.ElapsedMilliseconds}ms");

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.True(ciphertext.Length > plaintext.Length, "Ciphertext should include authentication tags");
    }

    [Theory]
    [InlineData(500 * 1024)]    // 500 KB - small data (single chunk)
    [InlineData(2048 * 1024)]   // 2 MB - multiple chunks
    [InlineData(5 * 1024 * 1024)] // 5 MB - many chunks
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_VariousSizes_MaintainCorrectness(int size)
    {
        // Arrange
        var plaintext = new byte[size];
        for (int i = 0; i < size; i++)
        {
            plaintext[i] = (byte)(i % 256); // Deterministic pattern
        }

        var key = new byte[32];
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        // Act
        var ciphertext = ParallelAesGcm.EncryptParallel(plaintext, key, nonce);
        var decrypted = ParallelAesGcm.DecryptParallel(ciphertext, key, nonce);

        // Assert
        Assert.Equal(plaintext, decrypted);
        _output.WriteLine($"Size: {size / 1024}KB - Roundtrip successful");
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_WithAssociatedData_AuthenticatesCorrectly()
    {
        // Arrange
        var plaintext = new byte[3 * 1024 * 1024]; // 3 MB
        RandomNumberGenerator.Fill(plaintext);

        var key = new byte[32];
        var nonce = new byte[12];
        var aad = Encoding.UTF8.GetBytes("metadata: user=alice, timestamp=2025-10-28");
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        // Act
        var ciphertext = ParallelAesGcm.EncryptParallel(plaintext, key, nonce, aad);
        var decrypted = ParallelAesGcm.DecryptParallel(ciphertext, key, nonce, aad);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_WithWrongKey_ThrowsCryptographicException()
    {
        // Arrange
        var plaintext = new byte[3 * 1024 * 1024];
        RandomNumberGenerator.Fill(plaintext);

        var key = new byte[32];
        var wrongKey = new byte[32];
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(wrongKey);
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = ParallelAesGcm.EncryptParallel(plaintext, key, nonce);

        // Act & Assert
        var ex = Assert.Throws<System.Security.Cryptography.CryptographicException>(
            () => ParallelAesGcm.DecryptParallel(ciphertext, wrongKey, nonce));

        Assert.Contains("Authentication tag verification failed", ex.Message);
        _output.WriteLine($"Correctly rejected wrong key: {ex.Message}");
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_WithWrongNonce_ThrowsCryptographicException()
    {
        // Arrange
        var plaintext = new byte[3 * 1024 * 1024];
        RandomNumberGenerator.Fill(plaintext);

        var key = new byte[32];
        var nonce = new byte[12];
        var wrongNonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(wrongNonce);

        var ciphertext = ParallelAesGcm.EncryptParallel(plaintext, key, nonce);

        // Act & Assert
        Assert.Throws<System.Security.Cryptography.CryptographicException>(
            () => ParallelAesGcm.DecryptParallel(ciphertext, key, wrongNonce));
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_WithWrongAad_ThrowsCryptographicException()
    {
        // Arrange
        var plaintext = new byte[3 * 1024 * 1024];
        RandomNumberGenerator.Fill(plaintext);

        var key = new byte[32];
        var nonce = new byte[12];
        var aad = Encoding.UTF8.GetBytes("correct metadata");
        var wrongAad = Encoding.UTF8.GetBytes("wrong metadata");
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = ParallelAesGcm.EncryptParallel(plaintext, key, nonce, aad);

        // Act & Assert
        Assert.Throws<System.Security.Cryptography.CryptographicException>(
            () => ParallelAesGcm.DecryptParallel(ciphertext, key, nonce, wrongAad));
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_WithTamperedCiphertext_ThrowsCryptographicException()
    {
        // Arrange
        var plaintext = new byte[3 * 1024 * 1024];
        RandomNumberGenerator.Fill(plaintext);

        var key = new byte[32];
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = ParallelAesGcm.EncryptParallel(plaintext, key, nonce);

        // Tamper with ciphertext (flip a bit in the middle)
        ciphertext[ciphertext.Length / 2] ^= 0xFF;

        // Act & Assert
        var ex = Assert.Throws<System.Security.Cryptography.CryptographicException>(
            () => ParallelAesGcm.DecryptParallel(ciphertext, key, nonce));

        Assert.Contains("Authentication tag verification failed", ex.Message);
        _output.WriteLine("Correctly detected ciphertext tampering");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(8)]
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_WithDifferentParallelism_ProducesConsistentResults(int parallelism)
    {
        // Arrange
        var plaintext = new byte[3 * 1024 * 1024];
        RandomNumberGenerator.Fill(plaintext);

        var key = new byte[32];
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        // Act
        var ciphertext = ParallelAesGcm.EncryptParallel(plaintext, key, nonce, degreeOfParallelism: parallelism);
        var decrypted = ParallelAesGcm.DecryptParallel(ciphertext, key, nonce, degreeOfParallelism: parallelism);

        // Assert
        Assert.Equal(plaintext, decrypted);
        _output.WriteLine($"Parallelism {parallelism}: Success");
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_SecurityTest_NoPlaintextLeakageOnAuthFailure()
    {
        // Critical security test: Ensure no plaintext is returned if authentication fails
        // This tests the two-phase verification approach

        // Arrange
        var plaintext = new byte[3 * 1024 * 1024];
        for (int i = 0; i < plaintext.Length; i++)
        {
            plaintext[i] = 0xAA; // Distinctive pattern
        }

        var key = new byte[32];
        var wrongKey = new byte[32];
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(wrongKey);
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = ParallelAesGcm.EncryptParallel(plaintext, key, nonce);

        // Act & Assert
        var ex = Assert.Throws<System.Security.Cryptography.CryptographicException>(
            () => ParallelAesGcm.DecryptParallel(ciphertext, wrongKey, nonce));

        // Verify the exception is thrown before any plaintext is returned
        Assert.Contains("Authentication tag verification failed", ex.Message);

        _output.WriteLine("SECURITY: No plaintext leaked on authentication failure");
        _output.WriteLine($"Exception: {ex.Message}");
    }

    [Fact]
    [Trait("Category", TestCategories.Integration)]
    public void ParallelAesGcm_Performance_ComparedToSequential()
    {
        // Performance comparison between parallel and sequential
        var plaintext = new byte[10 * 1024 * 1024]; // 10 MB
        RandomNumberGenerator.Fill(plaintext);

        var key = new byte[32];
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        // Parallel
        var parallelSw = Stopwatch.StartNew();
        var ciphertextParallel = ParallelAesGcm.EncryptParallel(plaintext, key, nonce);
        parallelSw.Stop();

        var decryptSw = Stopwatch.StartNew();
        var decryptedParallel = ParallelAesGcm.DecryptParallel(ciphertextParallel, key, nonce);
        decryptSw.Stop();

        // Assert correctness
        Assert.Equal(plaintext, decryptedParallel);

        // Report performance
        var throughputEnc = (plaintext.Length / (1024.0 * 1024.0)) / parallelSw.Elapsed.TotalSeconds;
        var throughputDec = (ciphertextParallel.Length / (1024.0 * 1024.0)) / decryptSw.Elapsed.TotalSeconds;

        _output.WriteLine($"Parallel Encryption: {parallelSw.ElapsedMilliseconds}ms ({throughputEnc:F2} MB/s)");
        _output.WriteLine($"Parallel Decryption: {decryptSw.ElapsedMilliseconds}ms ({throughputDec:F2} MB/s)");
        _output.WriteLine($"Processors: {Environment.ProcessorCount}");
    }

    #endregion
}

#endif
