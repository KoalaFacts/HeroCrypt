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
            var key = KeyManager.GenerateSecureKey(32);

            var result = KeyManager.ValidateKey(key);

            Assert.True(result.IsValid);
            Assert.Empty(result.Issues);
            Assert.True(result.Score > 0);
            Assert.True(result.Entropy > 6.0);
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
            var result = KeyManager.ValidateKey(ReadOnlySpan<byte>.Empty);

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
                KeyManager.CreateKeyRotation(ReadOnlySpan<byte>.Empty, salt, TimeSpan.FromHours(1)));
        }

        [Fact]
        public void CreateKeyRotation_EmptySalt_ThrowsArgumentException()
        {
            var masterKey = TestHelpers.RandomBytes(32);

            Assert.Throws<ArgumentException>(() =>
                KeyManager.CreateKeyRotation(masterKey, ReadOnlySpan<byte>.Empty, TimeSpan.FromHours(1)));
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
            Assert.True(time2 >= time1);
        }

        [Fact]
        public void GetAllActiveKeys_ReturnsAllKeys()
        {
            var masterKey = TestHelpers.RandomBytes(32);
            var salt = TestHelpers.RandomBytes(16);

            using var manager = KeyManager.CreateKeyRotation(masterKey, salt, TimeSpan.FromHours(1), maxKeys: 5);
            manager.ForceRotation();
            manager.ForceRotation();

            var allKeys = manager.GetAllActiveKeys();

            Assert.True(allKeys.Count >= 2);
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

            var retrievedKey = manager.GetKeyByTimestamp(DateTimeOffset.MinValue);

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
                KeyManager.CreateDerivationTree(ReadOnlySpan<byte>.Empty, salt));
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

            using var tree = KeyManager.CreateDerivationTree(rootKey, salt, treeDepth: 3);

            Assert.Throws<ArgumentException>(() => tree.DeriveKey("a/b/c/d/e"));
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
            var policy = new KeyPolicy { MinKeySize = 32, MinEntropy = 6.0 };
            var manager = KeyManager.CreateKeyPolicy(policy);
            var key = KeyManager.GenerateSecureKey(32);

            var result = manager.ValidateKey(key, DateTimeOffset.UtcNow);

            Assert.True(result.IsValid);
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
            var policy = new KeyPolicy { MinKeySize = 32, MinEntropy = 6.0 };
            var manager = KeyManager.CreateKeyPolicy(policy);

            var key = manager.GenerateCompliantKey();

            Assert.NotNull(key);
            Assert.True(key.Length >= 32);

            var validation = manager.ValidateKey(key, DateTimeOffset.UtcNow);
            Assert.True(validation.IsValid);
        }

        [Fact]
        public void ValidateKey_CustomValidator_IsApplied()
        {
            var policy = new KeyPolicy
            {
                CustomValidator = key => key[0] != 0xFF
            };
            var manager = KeyManager.CreateKeyPolicy(policy);
            var key = new byte[32];
            key[0] = 0xFF;

            var result = manager.ValidateKey(key, DateTimeOffset.UtcNow);

            Assert.Contains(result.Issues, i => i.Contains("Custom validation failed"));
        }
    }
}
