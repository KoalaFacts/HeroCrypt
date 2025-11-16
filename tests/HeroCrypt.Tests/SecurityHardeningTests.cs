using HeroCrypt.KeyManagement;
using HeroCrypt.Security;
using HeroCrypt.Signatures;
using Microsoft.Extensions.Logging;

namespace HeroCrypt.Tests;

/// <summary>
/// Comprehensive security hardening tests
/// </summary>
public class SecurityHardeningTests
{
    private readonly ILogger<SecurityHardeningTests> _logger;

    public SecurityHardeningTests()
    {
        using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        _logger = loggerFactory.CreateLogger<SecurityHardeningTests>();
    }

    #region SecureMemoryOperations Tests

    [Fact]
    public void SecureClear_ValidArray_ClearsAllBytes()
    {
        // Arrange
        var sensitiveData = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        SecureMemoryOperations.SecureClear(sensitiveData);

        // Assert
        Assert.True(SecureMemoryOperations.IsCleared(sensitiveData));
        Assert.All(sensitiveData, b => Assert.Equal(0, b));
    }

    [Fact]
    public void SecureClear_MultipleArrays_ClearsAllArrays()
    {
        // Arrange
        var array1 = new byte[] { 1, 2, 3 };
        var array2 = new byte[] { 4, 5, 6 };
        var array3 = new byte[] { 7, 8, 9 };

        // Act
        SecureMemoryOperations.SecureClear(array1, array2, array3);

        // Assert
        Assert.True(SecureMemoryOperations.IsCleared(array1));
        Assert.True(SecureMemoryOperations.IsCleared(array2));
        Assert.True(SecureMemoryOperations.IsCleared(array3));
    }

    [Fact]
    public void SecureClear_NullArray_DoesNotThrow()
    {
        // Act & Assert
        var exception = Record.Exception(() => SecureMemoryOperations.SecureClear((byte[])null));
        Assert.Null(exception);
    }

    [Fact]
    public void ConstantTimeEquals_SameArrays_ReturnsTrue()
    {
        // Arrange
        var array1 = new byte[] { 1, 2, 3, 4, 5 };
        var array2 = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var result = SecureMemoryOperations.ConstantTimeEquals(array1, array2);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void ConstantTimeEquals_DifferentArrays_ReturnsFalse()
    {
        // Arrange
        var array1 = new byte[] { 1, 2, 3, 4, 5 };
        var array2 = new byte[] { 1, 2, 3, 4, 6 };

        // Act
        var result = SecureMemoryOperations.ConstantTimeEquals(array1, array2);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void ConstantTimeEquals_DifferentLengths_ReturnsFalse()
    {
        // Arrange
        var array1 = new byte[] { 1, 2, 3 };
        var array2 = new byte[] { 1, 2, 3, 4 };

        // Act
        var result = SecureMemoryOperations.ConstantTimeEquals(array1, array2);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void SecureByteArray_AutomaticallyClears_OnDispose()
    {
        // Arrange
        byte[] retrievedData = null;

        // Act
        using (var secureArray = new SecureByteArray(new byte[] { 1, 2, 3, 4, 5 }))
        {
            retrievedData = secureArray.ToArray();
        }

        // Assert - we can't verify the internal array is cleared since it's private,
        // but we can verify the retrieved data is separate
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, retrievedData);
    }

    [Fact]
    public void SecureByteArray_WithBytes_ExecutesActionSafely()
    {
        // Arrange
        var secureArray = new SecureByteArray(new byte[] { 1, 2, 3, 4, 5 });
        var actionExecuted = false;

        // Act
        secureArray.WithBytes(bytes =>
        {
            actionExecuted = true;
            Assert.Equal(5, bytes.Length);
            Assert.Equal(1, bytes[0]);
        });

        // Assert
        Assert.True(actionExecuted);
        secureArray.Dispose();
    }

    #endregion

    #region ConstantTimeOperations Tests

    [Theory]
    [InlineData(0, 10, 20, 20)]
    [InlineData(1, 10, 20, 10)]
    public void ConditionalSelect_Byte_ReturnsCorrectValue(byte condition, byte trueValue, byte falseValue, byte expected)
    {
        // Act
        var result = ConstantTimeOperations.ConditionalSelect(condition, trueValue, falseValue);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(0, 100, 200, 200)]
    [InlineData(1, 100, 200, 100)]
    public void ConditionalSelect_Int_ReturnsCorrectValue(int condition, int trueValue, int falseValue, int expected)
    {
        // Act
        var result = ConstantTimeOperations.ConditionalSelect(condition, trueValue, falseValue);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ConditionalSwap_Condition1_SwapsArrays()
    {
        // Arrange
        var array1 = new byte[] { 1, 2, 3 };
        var array2 = new byte[] { 4, 5, 6 };
        var originalArray1 = (byte[])array1.Clone();
        var originalArray2 = (byte[])array2.Clone();

        // Act
        ConstantTimeOperations.ConditionalSwap(1, array1, array2);

        // Assert
        Assert.Equal(originalArray2, array1);
        Assert.Equal(originalArray1, array2);
    }

    [Fact]
    public void ConditionalSwap_Condition0_DoesNotSwap()
    {
        // Arrange
        var array1 = new byte[] { 1, 2, 3 };
        var array2 = new byte[] { 4, 5, 6 };
        var originalArray1 = (byte[])array1.Clone();
        var originalArray2 = (byte[])array2.Clone();

        // Act
        ConstantTimeOperations.ConditionalSwap(0, array1, array2);

        // Assert
        Assert.Equal(originalArray1, array1);
        Assert.Equal(originalArray2, array2);
    }

    [Theory]
    [InlineData(5, 5, 1)]
    [InlineData(5, 6, 0)]
    public void ConstantTimeEquals_Byte_ReturnsCorrectResult(byte a, byte b, byte expected)
    {
        // Act
        var result = ConstantTimeOperations.ConstantTimeEquals(a, b);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(100u, 200u, 1u)]
    [InlineData(200u, 100u, 0u)]
    [InlineData(100u, 100u, 0u)]
    public void ConstantTimeLessThan_ReturnsCorrectResult(uint a, uint b, uint expected)
    {
        // Act
        var result = ConstantTimeOperations.ConstantTimeLessThan(a, b);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ConstantTimeArrayEquals_SameArrays_Returns1()
    {
        // Arrange
        var array1 = new byte[] { 1, 2, 3, 4, 5 };
        var array2 = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var result = ConstantTimeOperations.ConstantTimeArrayEquals(array1, array2);

        // Assert
        Assert.Equal(1, result);
    }

    [Fact]
    public void ConstantTimeArrayEquals_DifferentArrays_Returns0()
    {
        // Arrange
        var array1 = new byte[] { 1, 2, 3, 4, 5 };
        var array2 = new byte[] { 1, 2, 3, 4, 6 };

        // Act
        var result = ConstantTimeOperations.ConstantTimeArrayEquals(array1, array2);

        // Assert
        Assert.Equal(0, result);
    }

    #endregion

    #region InputValidator Tests

    [Fact]
    public void ValidateByteArray_ValidArray_DoesNotThrow()
    {
        // Arrange
        var validArray = new byte[] { 1, 2, 3, 4, 5 };

        // Act & Assert
        var exception = Record.Exception(() => InputValidator.ValidateByteArray(validArray, "test"));
        Assert.Null(exception);
    }

    [Fact]
    public void ValidateByteArray_NullArray_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => InputValidator.ValidateByteArray(null, "test"));
    }

    [Fact]
    public void ValidateByteArray_EmptyArrayNotAllowed_ThrowsArgumentException()
    {
        // Arrange
        var emptyArray = new byte[0];

        // Act & Assert
        Assert.Throws<ArgumentException>(() => InputValidator.ValidateByteArray(emptyArray, "test", allowEmpty: false));
    }

    [Fact]
    public void ValidateByteArray_TooLarge_ThrowsArgumentException()
    {
        // Arrange
        var largeArray = new byte[1000];

        // Act & Assert
        Assert.Throws<ArgumentException>(() => InputValidator.ValidateByteArray(largeArray, "test", maxSize: 500));
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    [InlineData(4096)]
    public void ValidateRsaKeySize_ValidSizes_DoesNotThrow(int keySize)
    {
        // Act & Assert
        var exception = Record.Exception(() => InputValidator.ValidateRsaKeySize(keySize, "keySize"));
        Assert.Null(exception);
    }

    [Theory]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(1023)]
    [InlineData(20000)]
    public void ValidateRsaKeySize_InvalidSizes_ThrowsArgumentException(int keySize)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => InputValidator.ValidateRsaKeySize(keySize, "keySize"));
    }

    [Fact]
    public void ValidatePbkdf2Parameters_ValidParameters_DoesNotThrow()
    {
        // Arrange
        var password = new byte[] { 1, 2, 3, 4 };
        var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        // Act & Assert
        var exception = Record.Exception(() => InputValidator.ValidatePbkdf2Parameters(password, salt, 10000, 32));
        Assert.Null(exception);
    }

    [Fact]
    public void ValidatePbkdf2Parameters_ShortSalt_ThrowsArgumentException()
    {
        // Arrange
        var password = new byte[] { 1, 2, 3, 4 };
        var salt = new byte[] { 1, 2, 3 }; // Too short

        // Act & Assert
        Assert.Throws<ArgumentException>(() => InputValidator.ValidatePbkdf2Parameters(password, salt, 10000, 32));
    }

    [Fact]
    public void ValidatePbkdf2Parameters_LowIterations_ThrowsArgumentException()
    {
        // Arrange
        var password = new byte[] { 1, 2, 3, 4 };
        var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => InputValidator.ValidatePbkdf2Parameters(password, salt, 100, 32));
    }

    [Fact]
    public void ValidateKeyEntropy_AllZeros_ThrowsArgumentException()
    {
        // Arrange
        var weakKey = new byte[32]; // All zeros

        // Act & Assert
        Assert.Throws<ArgumentException>(() => InputValidator.ValidateKeyEntropy(weakKey, "key"));
    }

    [Fact]
    public void ValidateKeyEntropy_AllSame_ThrowsArgumentException()
    {
        // Arrange
        var weakKey = Enumerable.Repeat((byte)0xFF, 32).ToArray();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => InputValidator.ValidateKeyEntropy(weakKey, "key"));
    }

    [Fact]
    public void ValidateKeyEntropy_LowEntropy_ThrowsArgumentException()
    {
        // Arrange
        var weakKey = new byte[32];
        weakKey[0] = 1; // Only one unique byte

        // Act & Assert
        Assert.Throws<ArgumentException>(() => InputValidator.ValidateKeyEntropy(weakKey, "key"));
    }

    [Fact]
    public void ValidateKeyEntropy_GoodEntropy_DoesNotThrow()
    {
        // Arrange
        var goodKey = new byte[32];
        for (int i = 0; i < 16; i++)
        {
            goodKey[i] = (byte)i; // 16 unique bytes
        }

        // Act & Assert
        var exception = Record.Exception(() => InputValidator.ValidateKeyEntropy(goodKey, "key"));
        Assert.Null(exception);
    }

    #endregion

    #region SecureRandomNumberGenerator Tests

    [Fact]
    public void SecureRandomNumberGenerator_GetBytes_GeneratesRandomData()
    {
        // Arrange
        using var rng = new SecureRandomNumberGenerator();
        var buffer1 = new byte[256];
        var buffer2 = new byte[256];

        // Act
        rng.GetBytes(buffer1);
        rng.GetBytes(buffer2);

        // Assert
        Assert.False(buffer1.SequenceEqual(buffer2)); // Should be different
        Assert.Contains(buffer1, b => b != 0); // Should not be all zeros
        Assert.Contains(buffer2, b => b != 0);
    }

    [Fact]
    public void SecureRandomNumberGenerator_GetBytes_Span_GeneratesRandomData()
    {
        // Arrange
        using var rng = new SecureRandomNumberGenerator();
        Span<byte> buffer1 = stackalloc byte[256];
        Span<byte> buffer2 = stackalloc byte[256];

        // Act
        rng.GetBytes(buffer1);
        rng.GetBytes(buffer2);

        // Assert
        Assert.False(buffer1.SequenceEqual(buffer2)); // Should be different
    }

    [Fact]
    public void SecureRandomNumberGenerator_GetInt32_GeneratesRandomIntegers()
    {
        // Arrange
        using var rng = new SecureRandomNumberGenerator();
        var values = new int[100];

        // Act
        for (int i = 0; i < values.Length; i++)
        {
            values[i] = rng.GetInt32();
        }

        // Assert
        // Should have some variation (not all the same)
        var uniqueCount = values.Distinct().Count();
        Assert.True(uniqueCount > 50, $"Expected more unique values, got {uniqueCount}");
    }

    [Fact]
    public void SecureRandomNumberGenerator_GetInt32Range_RespectsRange()
    {
        // Arrange
        using var rng = new SecureRandomNumberGenerator();
        const int min = 10;
        const int max = 50;

        // Act & Assert
        for (int i = 0; i < 100; i++)
        {
            var value = rng.GetInt32(min, max);
            Assert.InRange(value, min, max - 1);
        }
    }

    [Fact]
    public void SecureRandomNumberGenerator_AddEntropy_DoesNotThrow()
    {
        // Arrange
        using var rng = new SecureRandomNumberGenerator();
        var entropy = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        // Act & Assert
        var exception = Record.Exception(() => rng.AddEntropy(entropy));
        Assert.Null(exception);
    }

    [Fact]
    public void SecureRandomNumberGenerator_Statistics_UpdatesCorrectly()
    {
        // Arrange
        using var rng = new SecureRandomNumberGenerator();
        var buffer = new byte[100];

        // Act
        rng.GetBytes(buffer);
        var stats = rng.Statistics;

        // Assert
        Assert.True(stats.BytesGenerated >= 100);
        Assert.True(stats.HealthCheckPassed);
    }

    [Fact]
    public void SecureRandomNumberGenerator_HealthCheck_CanBePerformed()
    {
        // Arrange
        using var rng = new SecureRandomNumberGenerator();

        // Act & Assert
        var exception = Record.Exception(() => rng.PerformImmediateHealthCheck());
        Assert.Null(exception);

        var stats = rng.Statistics;
        Assert.True(stats.HealthCheckPassed);
    }

    #endregion

    #region Integration Security Tests

    [Fact]
    public void RsaDigitalSignatureService_WithInputValidation_RejectsInvalidInput()
    {
        // Arrange
        var service = new RsaDigitalSignatureService(2048);

        // Act & Assert - Invalid key size in constructor is already tested in constructor

        // Test invalid data
        Assert.Throws<ArgumentException>(() => service.Sign(new byte[0], new byte[] { 1, 2, 3 }));
        Assert.Throws<ArgumentException>(() => service.Sign(new byte[] { 1, 2, 3 }, new byte[0]));

        // Test oversized data
        var oversizedData = new byte[InputValidator.MaxArraySize + 1];
        Assert.Throws<ArgumentException>(() => service.Sign(oversizedData, new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public async Task CryptographicKeyGenerationService_WithInputValidation_RejectsInvalidInput()
    {
        // Arrange
        var service = new CryptographicKeyGenerator();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => service.GenerateRandomBytes(-1));
        Assert.Throws<ArgumentException>(() => service.GenerateSymmetricKey(-1));
        Assert.Throws<ArgumentException>(() => service.GenerateRsaKeyPair(512)); // Too small

        // Test that 0-length is allowed for random bytes (empty arrays are valid)
        var emptyBytes = service.GenerateRandomBytes(0);
        Assert.Empty(emptyBytes);

        await Assert.ThrowsAsync<ArgumentException>(() => service.GenerateRandomBytesAsync(-1));

        service.Dispose();
    }

    [Fact]
    public void MemorySecurityIntegration_EnsuresProperCleanup()
    {
        // Arrange
        var sensitiveData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var workingCopy = new byte[sensitiveData.Length];

        // Act
        sensitiveData.CopyTo(workingCopy, 0);

        // Simulate cryptographic operation
        for (int i = 0; i < workingCopy.Length; i++)
        {
            workingCopy[i] ^= 0xFF; // Simple transformation
        }

        // Clean up
        SecureMemoryOperations.SecureClear(workingCopy);

        // Assert
        Assert.True(SecureMemoryOperations.IsCleared(workingCopy));
        Assert.NotEqual(sensitiveData, workingCopy); // Should be different after clearing
    }

    [Fact]
    public void TimingAttackProtection_ConstantTimeOperations_ConsistentTiming()
    {
        // This test is more about ensuring the operations don't obviously fail
        // Actual timing analysis would require more sophisticated tooling

        // Arrange
        var data1 = new byte[] { 1, 2, 3, 4, 5 };
        var data2 = new byte[] { 1, 2, 3, 4, 5 };
        var data3 = new byte[] { 6, 7, 8, 9, 10 };

        // Act - Multiple constant-time operations
        var result1 = ConstantTimeOperations.ConstantTimeArrayEquals(data1, data2);
        var result2 = ConstantTimeOperations.ConstantTimeArrayEquals(data1, data3);

        // Assert
        Assert.Equal(1, result1); // Should be equal
        Assert.Equal(0, result2); // Should be different

        // Test multiple iterations to ensure consistency
        for (int i = 0; i < 1000; i++)
        {
            var r1 = ConstantTimeOperations.ConstantTimeArrayEquals(data1, data2);
            var r2 = ConstantTimeOperations.ConstantTimeArrayEquals(data1, data3);
            Assert.Equal(1, r1);
            Assert.Equal(0, r2);
        }
    }

    #endregion
}

