using HeroCrypt.Encryption;

namespace HeroCrypt.Tests;

public class AeadServiceTests
{
    private readonly AeadService aeadService;

    public AeadServiceTests()
    {
        aeadService = new AeadService();
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task EncryptDecrypt_ValidData_Succeeds(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);
        var associatedData = "metadata"u8.ToArray();

        // Act - Encrypt
        var ciphertext = await aeadService.EncryptAsync(plaintext, key, nonce, associatedData, algorithm, TestContext.Current.CancellationToken);

        // Act - Decrypt
        var decrypted = await aeadService.DecryptAsync(ciphertext, key, nonce, associatedData, algorithm, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.Equal(plaintext.Length + aeadService.GetTagSize(algorithm), ciphertext.Length);
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task EncryptDecrypt_EmptyPlaintext_Succeeds(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = Array.Empty<byte>();
        var key = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);

        // Act
        var ciphertext = await aeadService.EncryptAsync(plaintext, key, nonce, null, algorithm, TestContext.Current.CancellationToken);
        var decrypted = await aeadService.DecryptAsync(ciphertext, key, nonce, null, algorithm, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(plaintext, decrypted);
        Assert.Equal(aeadService.GetTagSize(algorithm), ciphertext.Length);
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task EncryptDecrypt_NoAssociatedData_Succeeds(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = "Hello without AAD!"u8.ToArray();
        var key = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);

        // Act
        var ciphertext = await aeadService.EncryptAsync(plaintext, key, nonce, null, algorithm, TestContext.Current.CancellationToken);
        var decrypted = await aeadService.DecryptAsync(ciphertext, key, nonce, null, algorithm, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task Decrypt_ModifiedCiphertext_ThrowsUnauthorizedAccessException(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);
        var ciphertext = await aeadService.EncryptAsync(plaintext, key, nonce, null, algorithm, TestContext.Current.CancellationToken);

        // Modify ciphertext
        ciphertext[0] ^= 1;

        // Act & Assert
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            aeadService.DecryptAsync(ciphertext, key, nonce, null, algorithm, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task Decrypt_WrongKey_ThrowsUnauthorizedAccessException(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = aeadService.GenerateKey(algorithm);
        var wrongKey = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);
        var ciphertext = await aeadService.EncryptAsync(plaintext, key, nonce, null, algorithm, TestContext.Current.CancellationToken);

        // Act & Assert
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            aeadService.DecryptAsync(ciphertext, wrongKey, nonce, null, algorithm, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task Decrypt_WrongNonce_ThrowsUnauthorizedAccessException(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);
        var wrongNonce = aeadService.GenerateNonce(algorithm);
        var ciphertext = await aeadService.EncryptAsync(plaintext, key, nonce, null, algorithm, TestContext.Current.CancellationToken);

        // Act & Assert
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            aeadService.DecryptAsync(ciphertext, key, wrongNonce, null, algorithm, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task Decrypt_WrongAssociatedData_ThrowsUnauthorizedAccessException(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = "Hello, AEAD World!"u8.ToArray();
        var key = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);
        var associatedData = "metadata"u8.ToArray();
        var wrongAssociatedData = "wrong-metadata"u8.ToArray();
        var ciphertext = await aeadService.EncryptAsync(plaintext, key, nonce, associatedData, algorithm, TestContext.Current.CancellationToken);

        // Act & Assert
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            aeadService.DecryptAsync(ciphertext, key, nonce, wrongAssociatedData, algorithm, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task EncryptDecrypt_LargeData_Succeeds(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = new byte[1024 * 1024]; // 1MB
        new Random(42).NextBytes(plaintext);
        var key = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);

        // Act
        var ciphertext = await aeadService.EncryptAsync(plaintext, key, nonce, null, algorithm, TestContext.Current.CancellationToken);
        var decrypted = await aeadService.DecryptAsync(ciphertext, key, nonce, null, algorithm, TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task StreamEncryptDecrypt_SmallData_Succeeds(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = "Hello, Stream AEAD!"u8.ToArray();
        var key = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);

        using var plaintextStream = new MemoryStream(plaintext);
        using var ciphertextStream = new MemoryStream();
        using var decryptedStream = new MemoryStream();

        // Act - Encrypt
        await aeadService.EncryptStreamAsync(plaintextStream, ciphertextStream, key, nonce, null, algorithm, cancellationToken: TestContext.Current.CancellationToken);

        // Act - Decrypt
        ciphertextStream.Position = 0;
        await aeadService.DecryptStreamAsync(ciphertextStream, decryptedStream, key, nonce, null, algorithm, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(plaintext, decryptedStream.ToArray());
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task StreamEncryptDecrypt_LargeData_Succeeds(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = new byte[256 * 1024]; // 256KB
        new Random(42).NextBytes(plaintext);
        var key = aeadService.GenerateKey(algorithm);
        var nonce = aeadService.GenerateNonce(algorithm);

        using var plaintextStream = new MemoryStream(plaintext);
        using var ciphertextStream = new MemoryStream();
        using var decryptedStream = new MemoryStream();

        // Act - Encrypt
        await aeadService.EncryptStreamAsync(plaintextStream, ciphertextStream, key, nonce, null, algorithm, chunkSize: 4096, cancellationToken: TestContext.Current.CancellationToken);

        // Act - Decrypt
        ciphertextStream.Position = 0;
        await aeadService.DecryptStreamAsync(ciphertextStream, decryptedStream, key, nonce, null, algorithm, chunkSize: 4096, cancellationToken: TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(plaintext, decryptedStream.ToArray());
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public void GenerateKey_ValidAlgorithm_ReturnsCorrectSize(AeadAlgorithm algorithm)
    {
        // Act
        var key = aeadService.GenerateKey(algorithm);

        // Assert
        Assert.Equal(aeadService.GetKeySize(algorithm), key.Length);
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public void GenerateNonce_ValidAlgorithm_ReturnsCorrectSize(AeadAlgorithm algorithm)
    {
        // Act
        var nonce = aeadService.GenerateNonce(algorithm);

        // Assert
        Assert.Equal(aeadService.GetNonceSize(algorithm), nonce.Length);
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public void GenerateKey_MultipleCalls_ProducesDifferentKeys(AeadAlgorithm algorithm)
    {
        // Act
        var key1 = aeadService.GenerateKey(algorithm);
        var key2 = aeadService.GenerateKey(algorithm);

        // Assert
        Assert.NotEqual(key1, key2);
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public void GenerateNonce_MultipleCalls_ProducesDifferentNonces(AeadAlgorithm algorithm)
    {
        // Act
        var nonce1 = aeadService.GenerateNonce(algorithm);
        var nonce2 = aeadService.GenerateNonce(algorithm);

        // Assert
        Assert.NotEqual(nonce1, nonce2);
    }

    [Fact]
    public void GetKeySize_ChaCha20Poly1305_Returns32()
    {
        Assert.Equal(32, aeadService.GetKeySize(AeadAlgorithm.ChaCha20Poly1305));
    }

    [Fact]
    public void GetKeySize_XChaCha20Poly1305_Returns32()
    {
        Assert.Equal(32, aeadService.GetKeySize(AeadAlgorithm.XChaCha20Poly1305));
    }

    [Fact]
    public void GetKeySize_Aes128Gcm_Returns16()
    {
        Assert.Equal(16, aeadService.GetKeySize(AeadAlgorithm.Aes128Gcm));
    }

    [Fact]
    public void GetKeySize_Aes256Gcm_Returns32()
    {
        Assert.Equal(32, aeadService.GetKeySize(AeadAlgorithm.Aes256Gcm));
    }

    [Fact]
    public void GetNonceSize_ChaCha20Poly1305_Returns12()
    {
        Assert.Equal(12, aeadService.GetNonceSize(AeadAlgorithm.ChaCha20Poly1305));
    }

    [Fact]
    public void GetNonceSize_XChaCha20Poly1305_Returns24()
    {
        Assert.Equal(24, aeadService.GetNonceSize(AeadAlgorithm.XChaCha20Poly1305));
    }

    [Fact]
    public void GetNonceSize_AesGcm_Returns12()
    {
        Assert.Equal(12, aeadService.GetNonceSize(AeadAlgorithm.Aes128Gcm));
        Assert.Equal(12, aeadService.GetNonceSize(AeadAlgorithm.Aes256Gcm));
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public void GetTagSize_AllAlgorithms_Returns16(AeadAlgorithm algorithm)
    {
        Assert.Equal(16, aeadService.GetTagSize(algorithm));
    }

    [Fact]
    public async Task EncryptAsync_NullPlaintext_ThrowsArgumentNullException()
    {
        var key = aeadService.GenerateKey();
        var nonce = aeadService.GenerateNonce();

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            aeadService.EncryptAsync(null!, key, nonce, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task EncryptAsync_NullKey_ThrowsArgumentNullException()
    {
        var plaintext = "test"u8.ToArray();
        var nonce = aeadService.GenerateNonce();

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            aeadService.EncryptAsync(plaintext, null!, nonce, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task EncryptAsync_NullNonce_ThrowsArgumentNullException()
    {
        var plaintext = "test"u8.ToArray();
        var key = aeadService.GenerateKey();

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            aeadService.EncryptAsync(plaintext, key, null!, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task EncryptAsync_WrongKeySize_ThrowsArgumentException()
    {
        var plaintext = "test"u8.ToArray();
        var wrongKey = new byte[16]; // Wrong size for ChaCha20-Poly1305
        var nonce = aeadService.GenerateNonce();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            aeadService.EncryptAsync(plaintext, wrongKey, nonce, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task EncryptAsync_WrongNonceSize_ThrowsArgumentException()
    {
        var plaintext = "test"u8.ToArray();
        var key = aeadService.GenerateKey();
        var wrongNonce = new byte[16]; // Wrong size for ChaCha20-Poly1305

        await Assert.ThrowsAsync<ArgumentException>(() =>
            aeadService.EncryptAsync(plaintext, key, wrongNonce, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DecryptAsync_CiphertextTooShort_ThrowsArgumentException()
    {
        var key = aeadService.GenerateKey();
        var nonce = aeadService.GenerateNonce();
        var shortCiphertext = new byte[8]; // Too short to contain tag

        await Assert.ThrowsAsync<ArgumentException>(() =>
            aeadService.DecryptAsync(shortCiphertext, key, nonce, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    public async Task EncryptDecrypt_DifferentAlgorithms_ProduceDifferentCiphertext(AeadAlgorithm algorithm1)
    {
        // Arrange
        var algorithm2 = algorithm1 == AeadAlgorithm.ChaCha20Poly1305
            ? AeadAlgorithm.XChaCha20Poly1305
            : AeadAlgorithm.ChaCha20Poly1305;

        var plaintext = "Same plaintext for both algorithms"u8.ToArray();
        var key1 = aeadService.GenerateKey(algorithm1);
        var key2 = aeadService.GenerateKey(algorithm2);
        var nonce1 = aeadService.GenerateNonce(algorithm1);
        var nonce2 = aeadService.GenerateNonce(algorithm2);

        // Act
        var ciphertext1 = await aeadService.EncryptAsync(plaintext, key1, nonce1, null, algorithm1, TestContext.Current.CancellationToken);
        var ciphertext2 = await aeadService.EncryptAsync(plaintext, key2, nonce2, null, algorithm2, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Theory]
    [InlineData(AeadAlgorithm.ChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.XChaCha20Poly1305)]
    [InlineData(AeadAlgorithm.Aes128Gcm)]
    [InlineData(AeadAlgorithm.Aes256Gcm)]
    public async Task EncryptDecrypt_SamePlaintextDifferentNonce_ProduceDifferentCiphertext(AeadAlgorithm algorithm)
    {
        // Arrange
        var plaintext = "Same plaintext, different nonce"u8.ToArray();
        var key = aeadService.GenerateKey(algorithm);
        var nonce1 = aeadService.GenerateNonce(algorithm);
        var nonce2 = aeadService.GenerateNonce(algorithm);

        // Act
        var ciphertext1 = await aeadService.EncryptAsync(plaintext, key, nonce1, null, algorithm, TestContext.Current.CancellationToken);
        var ciphertext2 = await aeadService.EncryptAsync(plaintext, key, nonce2, null, algorithm, TestContext.Current.CancellationToken);

        // Assert
        Assert.NotEqual(ciphertext1, ciphertext2);

        // Verify both can be decrypted correctly
        var decrypted1 = await aeadService.DecryptAsync(ciphertext1, key, nonce1, null, algorithm, TestContext.Current.CancellationToken);
        var decrypted2 = await aeadService.DecryptAsync(ciphertext2, key, nonce2, null, algorithm, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, decrypted1);
        Assert.Equal(plaintext, decrypted2);
    }
}



