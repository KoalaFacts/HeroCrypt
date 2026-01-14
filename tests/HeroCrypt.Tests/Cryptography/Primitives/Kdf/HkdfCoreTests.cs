using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.Primitives.Kdf;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Cryptography.Primitives.Kdf;

/// <summary>
/// Comprehensive tests for HKDF (HMAC-based Key Derivation Function) implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class HkdfCoreTests
{
    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Fact]
        public void DeriveKey_WithValidParameters_ReturnsCorrectLength()
        {
            // Arrange
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            var info = Encoding.UTF8.GetBytes("info");
            var length = 32;

            // Act
            var key = HkdfCore.DeriveKey(ikm, salt, info, length, HashAlgorithmName.SHA256);

            // Assert
            Assert.Equal(length, key.Length);
        }

        [Fact]
        public void DeriveKey_IsDeterministic()
        {
            // Arrange
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            var info = Encoding.UTF8.GetBytes("info");
            var length = 32;

            // Act
            var key1 = HkdfCore.DeriveKey(ikm, salt, info, length, HashAlgorithmName.SHA256);
            var key2 = HkdfCore.DeriveKey(ikm, salt, info, length, HashAlgorithmName.SHA256);

            // Assert
            CryptoAssertions.AssertBytesEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_DifferentContexts_ProduceDifferentKeys()
        {
            // Arrange
            var ikm = Encoding.UTF8.GetBytes("master_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            var length = 32;

            // Act
            var key1 = HkdfCore.DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("context1"), length, HashAlgorithmName.SHA256);
            var key2 = HkdfCore.DeriveKey(ikm, salt, Encoding.UTF8.GetBytes("context2"), length, HashAlgorithmName.SHA256);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void Extract_WithEmptySalt_ProducesCorrectPRK()
        {
            // Test that Extract works correctly when salt is empty
            // This exercises the code path where a zero-filled salt is created
            var ikm = Encoding.UTF8.GetBytes("input_key_material");

            var prk = HkdfCore.Extract(ikm, [], HashAlgorithmName.SHA256);

            // PRK should be hash length (32 bytes for SHA-256)
            Assert.Equal(32, prk.Length);

            // PRK should be deterministic
            var prk2 = HkdfCore.Extract(ikm, [], HashAlgorithmName.SHA256);
            Assert.Equal(prk, prk2);
        }

        [Fact]
        public void Extract_WithNonEmptySalt_ProducesCorrectPRK()
        {
            // Test that Extract works correctly with provided salt
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("some_salt_value");

            var prk = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);

            // PRK should be hash length (32 bytes for SHA-256)
            Assert.Equal(32, prk.Length);

            // PRK should be deterministic
            var prk2 = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);
            Assert.Equal(prk, prk2);
        }

        [Fact]
        public void Extract_EmptyVsNonEmptySalt_ProduceDifferentPRKs()
        {
            // Verify that empty salt and non-empty salt produce different PRKs
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("some_salt_value");

            var prkWithEmptySalt = HkdfCore.Extract(ikm, [], HashAlgorithmName.SHA256);
            var prkWithSalt = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);

            // PRKs should be different
            Assert.False(prkWithEmptySalt.AsSpan().SequenceEqual(prkWithSalt));
        }

        [Fact]
        public void Extract_MultipleHashAlgorithms_Work()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");

            // Test SHA-256
            var prkSha256 = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA256);
            Assert.Equal(32, prkSha256.Length);

            // Test SHA-384
            var prkSha384 = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA384);
            Assert.Equal(48, prkSha384.Length);

            // Test SHA-512
            var prkSha512 = HkdfCore.Extract(ikm, salt, HashAlgorithmName.SHA512);
            Assert.Equal(64, prkSha512.Length);
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        [Fact]
        public void DeriveKey_EmptyInfo_Success()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var salt = Encoding.UTF8.GetBytes("salt");
            
            var key = HkdfCore.DeriveKey(ikm, salt, [], 32, HashAlgorithmName.SHA256);
            
            Assert.Equal(32, key.Length);
        }
        
        [Fact]
        public void DeriveKey_EmptySalt_Success()
        {
            var ikm = Encoding.UTF8.GetBytes("input_key_material");
            var info = Encoding.UTF8.GetBytes("info");
            
            var key = HkdfCore.DeriveKey(ikm, [], info, 32, HashAlgorithmName.SHA256);
            
            Assert.Equal(32, key.Length);
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        [Fact]
        public void DeriveKey_InvalidLength_ThrowsArgumentException()
        {
            var ikm = Encoding.UTF8.GetBytes("ikm");
            var salt = Encoding.UTF8.GetBytes("salt");
            
            Assert.Throws<ArgumentException>(() => 
                HkdfCore.DeriveKey(ikm, salt, [], 0, HashAlgorithmName.SHA256));
                
            Assert.Throws<ArgumentException>(() => 
                HkdfCore.DeriveKey(ikm, salt, [], -1, HashAlgorithmName.SHA256));
        }

        [Fact]
        public void Extract_EmptyIkm_ThrowsArgumentException()
        {
             Assert.Throws<ArgumentException>(() => 
                HkdfCore.Extract([], [], HashAlgorithmName.SHA256));
        }
    }
}
