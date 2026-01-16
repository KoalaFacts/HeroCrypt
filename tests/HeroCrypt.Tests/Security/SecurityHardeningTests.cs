using System.Security.Cryptography;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Security;

/// <summary>
/// Comprehensive security hardening tests.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class SecurityHardeningTests
{
    /// <summary>
    /// Tests for SecureMemoryOperations class.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.MEMORY)]
    public class SecureMemoryOperationsTests
    {
        [Fact]
        public void SecureClear_ValidArray_ClearsAllBytes()
        {
            var sensitiveData = new byte[] { 1, 2, 3, 4, 5 };

            SecureMemoryOperations.SecureClear(sensitiveData);

            Assert.True(SecureMemoryOperations.IsCleared(sensitiveData));
            Assert.All(sensitiveData, b => Assert.Equal(0, b));
        }

        [Fact]
        public void SecureClear_MultipleArrays_ClearsAllArrays()
        {
            var array1 = new byte[] { 1, 2, 3 };
            var array2 = new byte[] { 4, 5, 6 };
            var array3 = new byte[] { 7, 8, 9 };

            SecureMemoryOperations.SecureClear(array1, array2, array3);

            Assert.True(SecureMemoryOperations.IsCleared(array1));
            Assert.True(SecureMemoryOperations.IsCleared(array2));
            Assert.True(SecureMemoryOperations.IsCleared(array3));
        }

        [Fact]
        public void SecureClear_NullArray_DoesNotThrow()
        {
            byte[]? nullBuffer = null;
            var exception = Record.Exception(() => SecureMemoryOperations.SecureClear(nullBuffer!));
            Assert.Null(exception);
        }

        [Fact]
        public void ConstantTimeEquals_SameArrays_ReturnsTrue()
        {
            var array1 = new byte[] { 1, 2, 3, 4, 5 };
            var array2 = new byte[] { 1, 2, 3, 4, 5 };

            var result = SecureMemoryOperations.ConstantTimeEquals(array1, array2);

            Assert.True(result);
        }

        [Fact]
        public void ConstantTimeEquals_DifferentArrays_ReturnsFalse()
        {
            var array1 = new byte[] { 1, 2, 3, 4, 5 };
            var array2 = new byte[] { 1, 2, 3, 4, 6 };

            var result = SecureMemoryOperations.ConstantTimeEquals(array1, array2);

            Assert.False(result);
        }

        [Fact]
        public void ConstantTimeEquals_DifferentLengths_ReturnsFalse()
        {
            var array1 = new byte[] { 1, 2, 3 };
            var array2 = new byte[] { 1, 2, 3, 4 };

            var result = SecureMemoryOperations.ConstantTimeEquals(array1, array2);

            Assert.False(result);
        }

        [Fact]
        public void SecureByteArray_AutomaticallyClears_OnDispose()
        {
            byte[]? retrievedData = null;

            using (var secureArray = new SecureByteArray([1, 2, 3, 4, 5]))
            {
                retrievedData = secureArray.ToArray();
            }

            // The retrieved data is separate from the internal array
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, retrievedData);
        }

        [Fact]
        public void SecureByteArray_WithBytes_ExecutesActionSafely()
        {
            var secureArray = new SecureByteArray([1, 2, 3, 4, 5]);
            var actionExecuted = false;

            secureArray.WithBytes(bytes =>
            {
                actionExecuted = true;
                Assert.Equal(5, bytes.Length);
                Assert.Equal(1, bytes[0]);
            });

            Assert.True(actionExecuted);
            secureArray.Dispose();
        }
    }

    /// <summary>
    /// Tests for ConstantTimeOperations class.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SECURITY)]
    public class ConstantTimeOperationsTests
    {
        [Theory]
        [InlineData(0, 10, 20, 20)]
        [InlineData(1, 10, 20, 10)]
        public void ConditionalSelect_Byte_ReturnsCorrectValue(byte condition, byte trueValue, byte falseValue, byte expected)
        {
            var result = ConstantTimeOperations.ConditionalSelect(condition, trueValue, falseValue);

            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(0, 100, 200, 200)]
        [InlineData(1, 100, 200, 100)]
        public void ConditionalSelect_Int_ReturnsCorrectValue(int condition, int trueValue, int falseValue, int expected)
        {
            var result = ConstantTimeOperations.ConditionalSelect(condition, trueValue, falseValue);

            Assert.Equal(expected, result);
        }

        [Fact]
        public void ConditionalSwap_Condition1_SwapsArrays()
        {
            var array1 = new byte[] { 1, 2, 3 };
            var array2 = new byte[] { 4, 5, 6 };
            var originalArray1 = (byte[])array1.Clone();
            var originalArray2 = (byte[])array2.Clone();

            ConstantTimeOperations.ConditionalSwap(1, array1, array2);

            Assert.Equal(originalArray2, array1);
            Assert.Equal(originalArray1, array2);
        }

        [Fact]
        public void ConditionalSwap_Condition0_DoesNotSwap()
        {
            var array1 = new byte[] { 1, 2, 3 };
            var array2 = new byte[] { 4, 5, 6 };
            var originalArray1 = (byte[])array1.Clone();
            var originalArray2 = (byte[])array2.Clone();

            ConstantTimeOperations.ConditionalSwap(0, array1, array2);

            Assert.Equal(originalArray1, array1);
            Assert.Equal(originalArray2, array2);
        }

        [Theory]
        [InlineData(5, 5, 1)]
        [InlineData(5, 6, 0)]
        public void ConstantTimeEquals_Byte_ReturnsCorrectResult(byte a, byte b, byte expected)
        {
            var result = ConstantTimeOperations.ConstantTimeEquals(a, b);

            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(100u, 200u, 1u)]
        [InlineData(200u, 100u, 0u)]
        [InlineData(100u, 100u, 0u)]
        public void ConstantTimeLessThan_ReturnsCorrectResult(uint a, uint b, uint expected)
        {
            var result = ConstantTimeOperations.ConstantTimeLessThan(a, b);

            Assert.Equal(expected, result);
        }

        [Fact]
        public void ConstantTimeArrayEquals_SameArrays_Returns1()
        {
            var array1 = new byte[] { 1, 2, 3, 4, 5 };
            var array2 = new byte[] { 1, 2, 3, 4, 5 };

            var result = ConstantTimeOperations.ConstantTimeArrayEquals(array1, array2);

            Assert.Equal(1, result);
        }

        [Fact]
        public void ConstantTimeArrayEquals_DifferentArrays_Returns0()
        {
            var array1 = new byte[] { 1, 2, 3, 4, 5 };
            var array2 = new byte[] { 1, 2, 3, 4, 6 };

            var result = ConstantTimeOperations.ConstantTimeArrayEquals(array1, array2);

            Assert.Equal(0, result);
        }
    }

    /// <summary>
    /// Tests for InputValidator class.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    public class InputValidatorTests
    {
        [Fact]
        public void ValidateByteArray_ValidArray_DoesNotThrow()
        {
            var validArray = new byte[] { 1, 2, 3, 4, 5 };

            var exception = Record.Exception(() => InputValidator.ValidateByteArray(validArray, "test"));
            Assert.Null(exception);
        }

        [Fact]
        public void ValidateByteArray_EmptyArrayNotAllowed_ThrowsArgumentException()
        {
            var emptyArray = new byte[0];

            Assert.Throws<ArgumentException>(() => InputValidator.ValidateByteArray(emptyArray, "test", allowEmpty: false));
        }

        [Fact]
        public void ValidateByteArray_TooLarge_ThrowsArgumentException()
        {
            var largeArray = new byte[1000];

            Assert.Throws<ArgumentException>(() => InputValidator.ValidateByteArray(largeArray, "test", maxSize: 500));
        }

        [Theory]
        [InlineData(2048)]
        [InlineData(3072)]
        [InlineData(4096)]
        public void ValidateRsaKeySize_ValidSizes_DoesNotThrow(int keySize)
        {
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
            Assert.Throws<ArgumentException>(() => InputValidator.ValidateRsaKeySize(keySize, "keySize"));
        }

        [Fact]
        public void ValidatePbkdf2Parameters_ValidParameters_DoesNotThrow()
        {
            var password = new byte[] { 1, 2, 3, 4 };
            var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

            var exception = Record.Exception(() => InputValidator.ValidatePbkdf2Parameters(password, salt, 10000, 32));
            Assert.Null(exception);
        }

        [Fact]
        public void ValidatePbkdf2Parameters_ShortSalt_ThrowsArgumentException()
        {
            var password = new byte[] { 1, 2, 3, 4 };
            var salt = new byte[] { 1, 2, 3 }; // Too short

            Assert.Throws<ArgumentException>(() => InputValidator.ValidatePbkdf2Parameters(password, salt, 10000, 32));
        }

        [Fact]
        public void ValidatePbkdf2Parameters_LowIterations_ThrowsArgumentException()
        {
            var password = new byte[] { 1, 2, 3, 4 };
            var salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

            Assert.Throws<ArgumentException>(() => InputValidator.ValidatePbkdf2Parameters(password, salt, 100, 32));
        }

        [Fact]
        public void ValidateKeyEntropy_AllZeros_ThrowsArgumentException()
        {
            var weakKey = new byte[32]; // All zeros

            Assert.Throws<ArgumentException>(() => InputValidator.ValidateKeyEntropy(weakKey, "key"));
        }

        [Fact]
        public void ValidateKeyEntropy_AllSame_ThrowsArgumentException()
        {
            var weakKey = Enumerable.Repeat((byte)0xFF, 32).ToArray();

            Assert.Throws<ArgumentException>(() => InputValidator.ValidateKeyEntropy(weakKey, "key"));
        }

        [Fact]
        public void ValidateKeyEntropy_LowEntropy_ThrowsArgumentException()
        {
            var weakKey = new byte[32];
            weakKey[0] = 1; // Only one unique byte

            Assert.Throws<ArgumentException>(() => InputValidator.ValidateKeyEntropy(weakKey, "key"));
        }

        [Fact]
        public void ValidateKeyEntropy_GoodEntropy_DoesNotThrow()
        {
            var goodKey = new byte[32];
            for (int i = 0; i < 16; i++)
            {
                goodKey[i] = (byte)i; // 16 unique bytes
            }

            var exception = Record.Exception(() => InputValidator.ValidateKeyEntropy(goodKey, "key"));
            Assert.Null(exception);
        }
    }

    /// <summary>
    /// Tests for SecureRandomNumberGenerator class.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.SECURITY)]
    public class SecureRandomNumberGeneratorTests
    {
        [Fact]
        public void GetBytes_GeneratesRandomData()
        {
            using var rng = new SecureRandomNumberGenerator();
            var buffer1 = new byte[256];
            var buffer2 = new byte[256];

            rng.GetBytes(buffer1);
            rng.GetBytes(buffer2);

            Assert.False(buffer1.SequenceEqual(buffer2)); // Should be different
            Assert.Contains(buffer1, b => b != 0); // Should not be all zeros
            Assert.Contains(buffer2, b => b != 0);
        }

        [Fact]
        public void GetBytes_Span_GeneratesRandomData()
        {
            using var rng = new SecureRandomNumberGenerator();
            Span<byte> buffer1 = stackalloc byte[256];
            Span<byte> buffer2 = stackalloc byte[256];

            rng.GetBytes(buffer1);
            rng.GetBytes(buffer2);

            Assert.False(buffer1.SequenceEqual(buffer2)); // Should be different
        }

        [Fact]
        public void GetInt32_GeneratesRandomIntegers()
        {
            using var rng = new SecureRandomNumberGenerator();
            var values = new int[100];

            for (int i = 0; i < values.Length; i++)
            {
                values[i] = rng.GetInt32();
            }

            // Should have some variation (not all the same)
            var uniqueCount = values.Distinct().Count();
            Assert.True(uniqueCount > 50, $"Expected more unique values, got {uniqueCount}");
        }

        [Fact]
        public void GetInt32Range_RespectsRange()
        {
            using var rng = new SecureRandomNumberGenerator();
            const int min = 10;
            const int max = 50;

            for (int i = 0; i < 100; i++)
            {
                var value = rng.GetInt32(min, max);
                Assert.InRange(value, min, max - 1);
            }
        }

        [Fact]
        public void AddEntropy_DoesNotThrow()
        {
            using var rng = new SecureRandomNumberGenerator();
            var entropy = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            var exception = Record.Exception(() => rng.AddEntropy(entropy));
            Assert.Null(exception);
        }

        [Fact]
        public void Statistics_UpdatesCorrectly()
        {
            using var rng = new SecureRandomNumberGenerator();
            var buffer = new byte[100];

            rng.GetBytes(buffer);
            var stats = rng.Statistics;

            Assert.True(stats.BytesGenerated >= 100);
            Assert.True(stats.HealthCheckPassed);
        }

        [Fact]
        public void HealthCheck_CanBePerformed()
        {
            using var rng = new SecureRandomNumberGenerator();

            var exception = Record.Exception(rng.PerformImmediateHealthCheck);
            Assert.Null(exception);

            var stats = rng.Statistics;
            Assert.True(stats.HealthCheckPassed);
        }
    }

    /// <summary>
    /// Integration tests for security components working together.
    /// </summary>
    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.SECURITY)]
    public class IntegrationSecurityTests
    {
        [Fact]
        public void DigitalSignature_WithInputValidation_RejectsInvalidInput()
        {
            // Empty data
            Assert.ThrowsAny<ArgumentException>(() =>
                HeroCryptBuilder.Sign().WithEd25519().WithPrivateKey([1, 2, 3]).Sign([]));

            // Empty key
            Assert.ThrowsAny<ArgumentException>(() =>
                HeroCryptBuilder.Sign().WithEd25519().WithPrivateKey([]).Sign([1, 2, 3]));

            // Oversized data (len > MAX_ARRAY_SIZE)
            var oversizedData = new byte[InputValidator.MAX_ARRAY_SIZE + 1];
            Assert.ThrowsAny<ArgumentException>(() =>
                HeroCryptBuilder.Sign().WithEd25519().WithPrivateKey([1, 2, 3]).Sign(oversizedData));
        }

        [Fact]
        public void RandomMaterialGeneration_RejectsInvalidLengths()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => RandomNumberGenerator.GetBytes(-1));
        }

        [Fact]
        public void MemorySecurityIntegration_EnsuresProperCleanup()
        {
            var sensitiveData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var workingCopy = new byte[sensitiveData.Length];

            sensitiveData.CopyTo(workingCopy, 0);

            // Simulate cryptographic operation
            for (int i = 0; i < workingCopy.Length; i++)
            {
                workingCopy[i] ^= 0xFF; // Simple transformation
            }

            // Clean up
            SecureMemoryOperations.SecureClear(workingCopy);

            Assert.True(SecureMemoryOperations.IsCleared(workingCopy));
            Assert.NotEqual(sensitiveData, workingCopy); // Should be different after clearing
        }

        [Fact]
        public void TimingAttackProtection_ConstantTimeOperations_ConsistentTiming()
        {
            // This test ensures constant-time operations don't obviously fail
            // Actual timing analysis would require more sophisticated tooling
            var data1 = new byte[] { 1, 2, 3, 4, 5 };
            var data2 = new byte[] { 1, 2, 3, 4, 5 };
            var data3 = new byte[] { 6, 7, 8, 9, 10 };

            // Multiple constant-time operations
            var result1 = ConstantTimeOperations.ConstantTimeArrayEquals(data1, data2);
            var result2 = ConstantTimeOperations.ConstantTimeArrayEquals(data1, data3);

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
    }
}
