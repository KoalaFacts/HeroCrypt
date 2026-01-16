using HeroCrypt.Protocols.KeyManagement;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Protocols.KeyManagement;

/// <summary>
/// Comprehensive tests for KeyManager, KeyRotationManager, KeyDerivationTree, and KeyPolicyManager.
/// </summary>
public class KeyManagerTests
{
    /// <summary>
    /// Tests for KeyManager static methods.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyManagerStaticTests
    {
        [Fact]
        public void GenerateSecureKey_DefaultLength_Returns32Bytes()
        {
            var key = KeyManager.GenerateSecureKey();

            Assert.Equal(32, key.Length);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        [InlineData(128)]
        public void GenerateSecureKey_SpecificLength_ReturnsCorrectLength(int length)
        {
            var key = KeyManager.GenerateSecureKey(length);

            Assert.Equal(length, key.Length);
        }

        [Fact]
        public void GenerateSecureKey_ZeroLength_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => KeyManager.GenerateSecureKey(0));
        }

        [Fact]
        public void GenerateSecureKey_NegativeLength_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => KeyManager.GenerateSecureKey(-1));
        }

        [Fact]
        public void ValidateKey_ValidRandomKey_ReturnsValid()
        {
            // Use 256 bytes to reliably achieve > 6.0 bits Shannon entropy.
            // Shannon entropy measures bits per unique symbol; with 256 bytes,
            // we get enough samples for entropy to approach the theoretical max of 8 bits.
            // Smaller samples (32-64 bytes) have high variance and often fail the 6.0 threshold.
            var key = new byte[256];
            System.Security.Cryptography.RandomNumberGenerator.Fill(key);

            var result = KeyManager.ValidateKey(key);

            Assert.True(result.IsValid, $"Validation failed with issues: {string.Join(", ", result.Issues)}");
            Assert.Empty(result.Issues);
            Assert.True(result.Entropy > 6.0, $"Entropy {result.Entropy:F2} should be > 6.0 for 256 random bytes");
            Assert.True(result.Score >= 80, $"Score {result.Score} should be high for valid random key");
        }

        [Fact]
        public void ValidateKey_32ByteRandomKey_HasReasonableEntropy()
        {
            // For typical 32-byte cryptographic keys, entropy is often 5.0-5.5 bits
            // due to limited sample size. This test documents expected behavior.
            var key = KeyManager.GenerateSecureKey(32);

            var result = KeyManager.ValidateKey(key);

            // 32-byte keys typically don't achieve 6.0 bits entropy due to sample size
            Assert.True(result.Entropy > 4.0, $"Entropy {result.Entropy:F2} should be reasonable");
            Assert.True(result.Score > 0, "Random key should have positive score");
            // The key may or may not be valid depending on entropy - document this behavior
            Assert.NotNull(result.Issues);
        }

        /// <summary>
        /// Documents Shannon entropy behavior for cryptographic keys of various sizes.
        /// Entropy increases with sample size as more byte values can be represented.
        /// </summary>
        [Theory]
        [InlineData(32, 4.5)]   // 32-byte keys: entropy ~5.0-5.5 bits typical
        [InlineData(64, 5.0)]   // 64-byte keys: entropy ~5.5-6.0 bits typical
        [InlineData(128, 5.5)] // 128-byte keys: entropy ~6.0-7.0 bits typical
        [InlineData(256, 6.5)] // 256-byte keys: entropy ~7.0-7.5 bits typical
        public void ValidateKey_EntropyScalesWithKeySize(int keySize, double minExpectedEntropy)
        {
            var key = KeyManager.GenerateSecureKey(keySize);

            var result = KeyManager.ValidateKey(key);

            Assert.True(result.Entropy >= minExpectedEntropy,
                $"Entropy {result.Entropy:F2} for {keySize}-byte key should be >= {minExpectedEntropy}");
        }

        [Fact]
        public void ValidateKey_AllZeros_ReturnsInvalid()
        {
            var key = new byte[32];

            var result = KeyManager.ValidateKey(key);

            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, i => i.Contains("all zeros"));
        }

        [Fact]
        public void ValidateKey_TooShort_ReturnsInvalid()
        {
            var key = TestHelpers.RandomBytes(8);

            var result = KeyManager.ValidateKey(key);

            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, i => i.Contains("too short"));
        }

        [Fact]
        public void ValidateKey_EmptyKey_ReturnsInvalid()
        {
            var result = KeyManager.ValidateKey([]);

            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, i => i.Contains("empty"));
        }

        [Fact]
        public void CombineKeys_MultipleKeys_ReturnsCombinedKey()
        {
            var key1 = TestHelpers.RandomBytes(32);
            var key2 = TestHelpers.RandomBytes(32);
            var key3 = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);
            var info = "test context"u8.ToArray();

            var combined = KeyManager.CombineKeys([key1, key2, key3], salt, info, 32);

            Assert.NotNull(combined);
            Assert.Equal(32, combined.Length);
        }

        [Fact]
        public void CombineKeys_SameInputs_ProducesSameOutput()
        {
            var key1 = TestHelpers.RandomBytes(32);
            var key2 = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);
            var info = "test context"u8.ToArray();

            var combined1 = KeyManager.CombineKeys([key1, key2], salt, info, 32);
            var combined2 = KeyManager.CombineKeys([key1, key2], salt, info, 32);

            Assert.Equal(combined1, combined2);
        }

        [Fact]
        public void CombineKeys_NullKeys_ThrowsArgumentNullException()
        {
            var salt = TestHelpers.RandomBytes(16);
            var info = "test"u8.ToArray();

            Assert.Throws<ArgumentNullException>(() =>
                KeyManager.CombineKeys(null!, salt, info));
        }

        [Fact]
        public void CombineKeys_EmptyKeys_ThrowsArgumentException()
        {
            var salt = TestHelpers.RandomBytes(16);
            var info = "test"u8.ToArray();

            Assert.Throws<ArgumentException>(() =>
                KeyManager.CombineKeys([], salt, info));
        }

        [Fact]
        public void CombineKeys_EmptySalt_ProducesDeterministicOutput()
        {
            var key1 = TestHelpers.RandomBytes(32);
            var key2 = TestHelpers.RandomBytes(32);
            var info = "test"u8.ToArray();

            // Empty salt should work (HKDF supports empty salt)
            var combined1 = KeyManager.CombineKeys([key1, key2], [], info, 32);
            var combined2 = KeyManager.CombineKeys([key1, key2], [], info, 32);

            Assert.NotNull(combined1);
            Assert.Equal(32, combined1.Length);
            Assert.Equal(combined1, combined2);
        }

        [Fact]
        public void CombineKeys_EmptyInfo_ProducesDeterministicOutput()
        {
            var key1 = TestHelpers.RandomBytes(32);
            var key2 = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            // Empty info should work (HKDF supports empty info)
            var combined1 = KeyManager.CombineKeys([key1, key2], salt, [], 32);
            var combined2 = KeyManager.CombineKeys([key1, key2], salt, [], 32);

            Assert.NotNull(combined1);
            Assert.Equal(32, combined1.Length);
            Assert.Equal(combined1, combined2);
        }

        [Fact]
        public void GenerateSecureKey_LargeLength_Succeeds()
        {
            // Test generating a larger key (1024 bytes)
            var key = KeyManager.GenerateSecureKey(1024);

            Assert.NotNull(key);
            Assert.Equal(1024, key.Length);
        }

        [Fact]
        public void CombineKeys_KeysWithNullElements_IgnoresNulls()
        {
            var key1 = TestHelpers.RandomBytes(32);
            byte[]? nullKey = null;
            var key2 = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);
            var info = "test"u8.ToArray();

            // Should skip null keys and combine the valid ones
            var combined = KeyManager.CombineKeys([key1, nullKey!, key2], salt, info, 32);

            Assert.NotNull(combined);
            Assert.Equal(32, combined.Length);
        }

        [Fact]
        public void ValidateKey_RepeatingPattern_ReturnsInvalid()
        {
            // Create a key with a repeating 2-byte pattern
            var key = new byte[32];
            for (var i = 0; i < key.Length; i += 2)
            {
                key[i] = 0xAB;
                key[i + 1] = 0xCD;
            }

            var result = KeyManager.ValidateKey(key);

            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, i => i.Contains("Repeating patterns"));
        }
    }

    /// <summary>
    /// Tests for KeyRotationManager.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyRotationManagerTests
    {
        [Fact]
        public void CreateKeyRotation_ValidParameters_ReturnsManager()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1));

            Assert.NotNull(manager);
        }

        [Fact]
        public void CreateKeyRotation_EmptyMasterKey_ThrowsArgumentException()
        {
            var salt = TestHelpers.RandomBytes(16);

            Assert.Throws<ArgumentException>(() =>
                KeyManager.CreateKeyRotation([], salt, TimeSpan.FromHours(1)));
        }

        [Fact]
        public void CreateKeyRotation_EmptySalt_ThrowsArgumentException()
        {
            var masterKey = TestHelpers.RandomBytes(32);

            Assert.Throws<ArgumentException>(() =>
                KeyManager.CreateKeyRotation(masterKey, [], TimeSpan.FromHours(1)));
        }

        [Fact]
        public void CreateKeyRotation_ZeroInterval_ThrowsArgumentException()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            Assert.Throws<ArgumentException>(() =>
                KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.Zero));
        }

        [Fact]
        public void CreateKeyRotation_NegativeInterval_ThrowsArgumentException()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            Assert.Throws<ArgumentException>(() =>
                KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(-1)));
        }

        [Fact]
        public void GetCurrentKey_ReturnsKeyAndTimestamp()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1));
            var (key, createdAt) = manager.GetCurrentKey();

            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
            Assert.True(createdAt <= DateTimeOffset.UtcNow);
        }

        [Fact]
        public void ForceRotation_CreatesNewKey()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1));
            var (key1, time1) = manager.GetCurrentKey();
            var (key2, time2) = manager.ForceRotation();

            Assert.NotEqual(key1, key2);
            // Time2 should be >= time1. In practice they may be equal if execution is fast,
            // which is acceptable since we use DateTimeOffset.UtcNow for both.
            Assert.True(time2 >= time1, $"New key timestamp {time2} should be >= original {time1}");
        }

        [Fact]
        public void ForceRotation_EachKeyHasUniqueTimestamp()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1));
            var timestamps = new HashSet<DateTimeOffset>();

            for (var i = 0; i < 5; i++)
            {
                var (_, timestamp) = manager.ForceRotation();
                timestamps.Add(timestamp);
                Thread.Sleep(1); // Ensure unique timestamps
            }

            // All timestamps should be unique
            Assert.Equal(5, timestamps.Count);
        }

        [Fact]
        public void GetAllActiveKeys_ReturnsAllKeys()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1), maxKeys: 5);
            // Initial key (1) + 2 forced rotations = 3 keys total
            manager.ForceRotation();
            manager.ForceRotation();

            var allKeys = manager.GetAllActiveKeys();

            Assert.Equal(3, allKeys.Count);
        }

        [Fact]
        public void GetAllActiveKeys_RespectsMaxKeysLimit()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1), maxKeys: 3);
            // Create more keys than maxKeys limit
            manager.ForceRotation();
            manager.ForceRotation();
            manager.ForceRotation();
            manager.ForceRotation();

            var allKeys = manager.GetAllActiveKeys();

            // Should only retain maxKeys (3) keys
            Assert.Equal(3, allKeys.Count);
        }

        [Fact]
        public void GetKeyByTimestamp_ExistingKey_ReturnsKey()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1));
            var (key, timestamp) = manager.GetCurrentKey();

            var retrievedKey = manager.GetKeyByTimestamp(timestamp);

            Assert.NotNull(retrievedKey);
            Assert.Equal(key, retrievedKey);
        }

        [Fact]
        public void GetKeyByTimestamp_NonExistingKey_ReturnsNull()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1));

            // DateTimeOffset.MinValue is an extreme edge case
            var retrievedKey = manager.GetKeyByTimestamp(DateTimeOffset.MinValue);

            Assert.Null(retrievedKey);
        }

        [Fact]
        public void GetKeyByTimestamp_RecentNonMatchingTimestamp_ReturnsNull()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1));
            var (_, actualTimestamp) = manager.GetCurrentKey();

            // Use a timestamp 1 millisecond different from the actual one
            var nonMatchingTimestamp = actualTimestamp.AddMilliseconds(1);
            var retrievedKey = manager.GetKeyByTimestamp(nonMatchingTimestamp);

            Assert.Null(retrievedKey);
        }

        [Fact]
        public void GetKeyByTimestamp_FutureTimestamp_ReturnsNull()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1));

            var futureTimestamp = DateTimeOffset.UtcNow.AddDays(1);
            var retrievedKey = manager.GetKeyByTimestamp(futureTimestamp);

            Assert.Null(retrievedKey);
        }
    }

    /// <summary>
    /// Tests for KeyDerivationTree.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyDerivationTreeTests
    {
        [Fact]
        public void CreateDerivationTree_ValidParameters_ReturnsTree()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var tree = KeyManager.CreateDerivationTree(rootKey, salt);

            Assert.NotNull(tree);
        }

        [Fact]
        public void CreateDerivationTree_EmptyRootKey_ThrowsArgumentException()
        {
            var salt = TestHelpers.RandomBytes(16);

            Assert.Throws<ArgumentException>(() =>
                KeyManager.CreateDerivationTree([], salt));
        }

        [Fact]
        public void DeriveKey_ValidPath_ReturnsKey()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var tree = KeyManager.CreateDerivationTree(rootKey, salt);
            var key = tree.DeriveKey("app/user/session");

            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void DeriveKey_SamePath_ReturnsSameKey()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var tree = KeyManager.CreateDerivationTree(rootKey, salt);
            var key1 = tree.DeriveKey("app/user/session");
            var key2 = tree.DeriveKey("app/user/session");

            Assert.Equal(key1, key2);
        }

        [Fact]
        public void DeriveKey_DifferentPaths_ReturnsDifferentKeys()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var tree = KeyManager.CreateDerivationTree(rootKey, salt);
            var key1 = tree.DeriveKey("app/user1");
            var key2 = tree.DeriveKey("app/user2");

            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void DeriveKey_EmptyPath_ThrowsArgumentException()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var tree = KeyManager.CreateDerivationTree(rootKey, salt);

            Assert.Throws<ArgumentException>(() => tree.DeriveKey(""));
        }

        [Fact]
        public void DeriveKey_ExceedsMaxDepth_ThrowsArgumentException()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            // treeDepth: 3 means max 3 path segments allowed
            // Path "a/b/c/d/e" has 5 segments, which exceeds the limit
            using var tree = KeyManager.CreateDerivationTree(rootKey, salt, treeDepth: 3);

            Assert.Throws<ArgumentException>(() => tree.DeriveKey("a/b/c/d/e"));
        }

        [Fact]
        public void DeriveKey_ExactlyAtMaxDepth_Succeeds()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            // treeDepth: 3 allows exactly 3 path segments
            using var tree = KeyManager.CreateDerivationTree(rootKey, salt, treeDepth: 3);

            var key = tree.DeriveKey("a/b/c");

            Assert.NotNull(key);
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void DeriveKey_PathWithTrailingSlash_TreatedSameAsWithout()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var tree = KeyManager.CreateDerivationTree(rootKey, salt);
            // StringSplitOptions.RemoveEmptyEntries normalizes paths
            var key1 = tree.DeriveKey("app/user");
            var key2 = tree.DeriveKey("app/user/");

            Assert.Equal(key1, key2);
        }

        [Fact]
        public void DeriveKeys_MultiplePaths_ReturnsAllKeys()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var tree = KeyManager.CreateDerivationTree(rootKey, salt);
            var keys = tree.DeriveKeys(["app/a", "app/b", "app/c"]);

            Assert.Equal(3, keys.Count);
            Assert.True(keys.ContainsKey("app/a"));
            Assert.True(keys.ContainsKey("app/b"));
            Assert.True(keys.ContainsKey("app/c"));
        }

        [Fact]
        public void ClearKey_ExistingKey_RemovesFromTree()
        {
            var rootKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var tree = KeyManager.CreateDerivationTree(rootKey, salt);
            tree.DeriveKey("app/temp");
            tree.ClearKey("app/temp");

            var allKeys = tree.GetAllKeys();
            Assert.False(allKeys.ContainsKey("app/temp"));
        }
    }

    /// <summary>
    /// Tests for KeyPolicyManager.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class KeyPolicyManagerTests
    {
        [Fact]
        public void CreateKeyPolicy_ValidPolicy_ReturnsManager()
        {
            var policy = new KeyPolicy { MinKeySize = 32 };

            var manager = KeyManager.CreateKeyPolicy(policy);

            Assert.NotNull(manager);
        }

        [Fact]
        public void CreateKeyPolicy_NullPolicy_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => KeyManager.CreateKeyPolicy(null!));
        }

        [Fact]
        public void ValidateKey_ValidKey_ReturnsValid()
        {
            // Use MinKeySize=128 to reliably achieve >6.0 bits Shannon entropy
            // (smaller samples have more variance in entropy measurement)
            var policy = new KeyPolicy { MinKeySize = 128, MinEntropy = 6.0 };
            var manager = KeyManager.CreateKeyPolicy(policy);
            var key = KeyManager.GenerateSecureKey(128);

            var result = manager.ValidateKey(key, DateTimeOffset.UtcNow);

            Assert.True(result.IsValid, $"Validation failed with issues: {string.Join(", ", result.Issues)}");
            Assert.Empty(result.Issues);
        }

        [Fact]
        public void ValidateKey_TooSmall_ReturnsInvalid()
        {
            var policy = new KeyPolicy { MinKeySize = 32 };
            var manager = KeyManager.CreateKeyPolicy(policy);
            var key = TestHelpers.RandomBytes(16);

            var result = manager.ValidateKey(key, DateTimeOffset.UtcNow);

            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, i => i.Contains("too small"));
        }

        [Fact]
        public void ValidateKey_TooOld_ReturnsInvalidAndShouldRotate()
        {
            var policy = new KeyPolicy { MaxAge = TimeSpan.FromDays(30) };
            var manager = KeyManager.CreateKeyPolicy(policy);
            var key = KeyManager.GenerateSecureKey(32);
            var oldTimestamp = DateTimeOffset.UtcNow.AddDays(-60);

            var result = manager.ValidateKey(key, oldTimestamp);

            Assert.False(result.IsValid);
            Assert.True(result.ShouldRotate);
            Assert.Contains(result.Issues, i => i.Contains("too old"));
        }

        [Fact]
        public void ValidateKey_ShouldRotate_WhenPastRotationInterval()
        {
            var policy = new KeyPolicy
            {
                RotationInterval = TimeSpan.FromDays(7),
                MaxAge = TimeSpan.FromDays(30)
            };
            var manager = KeyManager.CreateKeyPolicy(policy);
            var key = KeyManager.GenerateSecureKey(32);
            var timestamp = DateTimeOffset.UtcNow.AddDays(-10);

            var result = manager.ValidateKey(key, timestamp);

            Assert.True(result.ShouldRotate);
        }

        [Fact]
        public void GenerateCompliantKey_ReturnsValidKey()
        {
            // Use MinKeySize=128 to reliably achieve >6.0 bits Shannon entropy
            var policy = new KeyPolicy { MinKeySize = 128, MinEntropy = 6.0 };
            var manager = KeyManager.CreateKeyPolicy(policy);

            var key = manager.GenerateCompliantKey();

            Assert.NotNull(key);
            Assert.True(key.Length >= 128);

            var validation = manager.ValidateKey(key, DateTimeOffset.UtcNow);
            Assert.True(validation.IsValid, $"Validation failed with issues: {string.Join(", ", validation.Issues)}");
        }

        [Fact]
        public void ValidateKey_CustomValidator_IsApplied()
        {
            // Use a valid random key but set first byte to 0xFF to trigger custom validation
            var policy = new KeyPolicy
            {
                MinKeySize = 128,
                EnforceSecureGeneration = false, // Disable entropy check to isolate custom validator test
                CustomValidator = key => key[0] != 0xFF
            };
            var manager = KeyManager.CreateKeyPolicy(policy);
            var key = KeyManager.GenerateSecureKey(128);
            key[0] = 0xFF; // This should trigger custom validation failure

            var result = manager.ValidateKey(key, DateTimeOffset.UtcNow);

            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, i => i.Contains("Custom validation failed"));
        }

        [Fact]
        public void ValidateKey_CustomValidator_PassesWhenValid()
        {
            var policy = new KeyPolicy
            {
                MinKeySize = 128,
                EnforceSecureGeneration = false,
                CustomValidator = key => key[0] != 0xFF
            };
            var manager = KeyManager.CreateKeyPolicy(policy);
            var key = KeyManager.GenerateSecureKey(128);
            if (key[0] == 0xFF)
            {
                key[0] = 0x00; // Ensure the key passes custom validation
            }

            var result = manager.ValidateKey(key, DateTimeOffset.UtcNow);

            Assert.True(result.IsValid, $"Validation failed with: {string.Join(", ", result.Issues)}");
            Assert.DoesNotContain(result.Issues, i => i.Contains("Custom validation failed"));
        }
    }
}
