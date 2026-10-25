using System.Security.Cryptography;
using HeroCrypt.Tests.Infrastructure;
using static HeroCrypt.Primitives.ChaCha20.ChaChaVariants;

namespace HeroCrypt.Tests.Primitives.ChaCha20;

/// <summary>
/// Comprehensive tests for ChaCha20 variants (ChaCha8, ChaCha12, ChaCha20).
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class ChaChaVariantsCoreTests
{
    private const int KEY_SIZE = 32;
    private const int NONCE_SIZE = 12;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        [Theory]
        [InlineData(ChaChaVariant.ChaCha8)]
        [InlineData(ChaChaVariant.ChaCha12)]
        [InlineData(ChaChaVariant.ChaCha20)]
        public void Transform_RoundTrip_Success(ChaChaVariant variant)
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            // Act
            Transform(ciphertext, plaintext, key, nonce, 0, variant);
            Transform(decrypted, ciphertext, key, nonce, 0, variant);

            // Assert
            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
            Assert.NotEqual(plaintext, ciphertext);
        }

        [Fact]
        public void Transform_DifferentVariants_ProduceDifferentCiphertexts()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var ct8 = new byte[plaintext.Length];
            var ct12 = new byte[plaintext.Length];
            var ct20 = new byte[plaintext.Length];

            // Act
            Transform(ct8, plaintext, key, nonce, 0, ChaChaVariant.ChaCha8);
            Transform(ct12, plaintext, key, nonce, 0, ChaChaVariant.ChaCha12);
            Transform(ct20, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);

            // Assert
            Assert.NotEqual(ct8, ct12);
            Assert.NotEqual(ct8, ct20);
            Assert.NotEqual(ct12, ct20);
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
        public void Transform_EmptyInput_Succeeds()
        {
            // Arrange
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = Array.Empty<byte>();
            var ciphertext = Array.Empty<byte>();

            // Act & Assert
            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
        }

        [Fact]
        public void Transform_SingleByte_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = new byte[] { 0x42 };
            var ciphertext = new byte[1];
            var decrypted = new byte[1];

            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(decrypted, ciphertext, key, nonce, 0, ChaChaVariant.ChaCha20);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        public void Transform_ExactBlockSize_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64); // ChaCha20 block size
            var ciphertext = new byte[64];
            var decrypted = new byte[64];

            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(decrypted, ciphertext, key, nonce, 0, ChaChaVariant.ChaCha20);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void Transform_LargeData_Success()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);
            var ciphertext = new byte[plaintext.Length];
            var decrypted = new byte[plaintext.Length];

            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(decrypted, ciphertext, key, nonce, 0, ChaChaVariant.ChaCha20);

            CryptoAssertions.AssertBytesEqual(plaintext, decrypted);
        }
    }

    /// <summary>
    /// Security-focused tests for cryptographic properties.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class Security
    {
        [Theory]
        [InlineData(ChaChaVariant.ChaCha8)]
        [InlineData(ChaChaVariant.ChaCha12)]
        [InlineData(ChaChaVariant.ChaCha20)]
        public void Transform_KeyNonceReuse_ProducesSameKeystream(ChaChaVariant variant)
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext1 = TestHelpers.RandomBytes(64);
            var plaintext2 = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext1, key, nonce, 0, variant);
            Transform(ciphertext2, plaintext2, key, nonce, 0, variant);

            // Same key/nonce should produce same keystream
            var keystream1 = new byte[64];
            var keystream2 = new byte[64];
            for (int i = 0; i < 64; i++)
            {
                keystream1[i] = (byte)(ciphertext1[i] ^ plaintext1[i]);
                keystream2[i] = (byte)(ciphertext2[i] ^ plaintext2[i]);
            }

            CryptoAssertions.AssertBytesEqual(keystream1, keystream2);
        }

        [Fact]
        public void Transform_DifferentKey_ProducesDifferentCiphertext()
        {
            var key1 = TestHelpers.RandomBytes(KEY_SIZE);
            var key2 = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key1, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(ciphertext2, plaintext, key2, nonce, 0, ChaChaVariant.ChaCha20);

            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Transform_DifferentNonce_ProducesDifferentCiphertext()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce1 = TestHelpers.RandomBytes(NONCE_SIZE);
            var nonce2 = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key, nonce1, 0, ChaChaVariant.ChaCha20);
            Transform(ciphertext2, plaintext, key, nonce2, 0, ChaChaVariant.ChaCha20);

            Assert.NotEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void Transform_OutputAppearsRandom()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = new byte[64]; // All zeros
            var ciphertext = new byte[64];

            Transform(ciphertext, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);

            CryptoAssertions.AssertAppearsRandom(ciphertext);
        }

        [Fact]
        public void Transform_SingleBitChange_CompletelyDifferentOutput()
        {
            var key1 = TestHelpers.RandomBytes(KEY_SIZE);
            var key2 = (byte[])key1.Clone();
            key2[0] ^= 0x01; // Flip one bit

            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = new byte[64];
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key1, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(ciphertext2, plaintext, key2, nonce, 0, ChaChaVariant.ChaCha20);

            Assert.NotEqual(ciphertext1, ciphertext2);

            // Count differing bits - should be roughly half
            int diffBits = 0;
            for (int i = 0; i < ciphertext1.Length; i++)
            {
                diffBits += System.Numerics.BitOperations.PopCount((uint)(ciphertext1[i] ^ ciphertext2[i]));
            }
            int totalBits = ciphertext1.Length * 8;
            Assert.InRange(diffBits, totalBits / 4, totalBits * 3 / 4);
        }
    }

    /// <summary>
    /// Prevents IETF 32-bit counter reuse in every ChaCha round-count variant.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class CounterBoundaryTests
    {
        private static readonly byte[] ReferenceKey = Enumerable.Range(0, KEY_SIZE).Select(i => (byte)i).ToArray();
        private static readonly byte[] ReferenceNonce = Convert.FromHexString("000000090000004A00000000");

        // Independent ChaCha quarter-round construction at counter 0xFFFFFFFF,
        // cross-checked against the RFC 8439 ChaCha20 counter-1 block.
        private static byte[] LastCounterReference(ChaChaVariant variant) => Convert.FromHexString(variant switch
        {
            ChaChaVariant.ChaCha8 =>
                "D9DA6C0CC37F522435D4B712355BC1C4C4824F4A3920796202C79ACC350F2E35" +
                "A1708EC0F333CA5347FFC08A285FD30051F4FC0146451675B0151E52948F82EE",
            ChaChaVariant.ChaCha12 =>
                "A58058D90377803BEC0B01D822566D6B961C75D350FF87375C482E405E9EEFB2D" +
                "D4C80C61BCF5E50A2926662E79E83A8948CDAE0E3073C4DAD877248DE4BFF2A",
            ChaChaVariant.ChaCha20 =>
                "FF2941B8D740F6CBB50936BF997EBD5218CB108DC53F41C64841D0218167430CA" +
                "03B770CA74CCB642A28194D1DEDD2ED13151E25EC5D7FAEB6D060BFB7E6B146",
            _ => throw new ArgumentOutOfRangeException(nameof(variant))
        });

        [Theory]
        [InlineData(ChaChaVariant.ChaCha8)]
        [InlineData(ChaChaVariant.ChaCha12)]
        [InlineData(ChaChaVariant.ChaCha20)]
        public void Transform_LastLegalCounter_ProducesIndependentReferenceForPartialAndFullBlocks(ChaChaVariant variant)
        {
            var expected = LastCounterReference(variant);
            foreach (int length in new[] { 1, 63, 64 })
            {
                var output = new byte[length];
                Transform(output, new byte[length], ReferenceKey, ReferenceNonce, uint.MaxValue, variant);
                Assert.Equal(expected.AsSpan(0, length).ToArray(), output);
            }

            var finalTwoBlocks = new byte[2 * BLOCK_SIZE];
            Transform(finalTwoBlocks, new byte[finalTwoBlocks.Length],
                ReferenceKey, ReferenceNonce, uint.MaxValue - 1u, variant);
            Assert.Equal(expected, finalTwoBlocks.AsSpan(BLOCK_SIZE, BLOCK_SIZE).ToArray());
        }

        [Theory]
        [InlineData(ChaChaVariant.ChaCha8)]
        [InlineData(ChaChaVariant.ChaCha12)]
        [InlineData(ChaChaVariant.ChaCha20)]
        public void GenerateKeystream_LastLegalCounter_MatchesIndependentReference(ChaChaVariant variant)
        {
            var output = new byte[BLOCK_SIZE];
            GenerateKeystream(output, ReferenceKey, ReferenceNonce, uint.MaxValue, variant);
            Assert.Equal(LastCounterReference(variant), output);

            var finalTwoBlocks = new byte[2 * BLOCK_SIZE];
            GenerateKeystream(finalTwoBlocks, ReferenceKey, ReferenceNonce, uint.MaxValue - 1u, variant);
            Assert.Equal(LastCounterReference(variant), finalTwoBlocks.AsSpan(BLOCK_SIZE).ToArray());
        }

        [Theory]
        [InlineData(ChaChaVariant.ChaCha8, uint.MaxValue, 65)]
        [InlineData(ChaChaVariant.ChaCha12, uint.MaxValue, 65)]
        [InlineData(ChaChaVariant.ChaCha20, uint.MaxValue, 65)]
        [InlineData(ChaChaVariant.ChaCha8, uint.MaxValue - 1u, 129)]
        [InlineData(ChaChaVariant.ChaCha12, uint.MaxValue - 1u, 129)]
        [InlineData(ChaChaVariant.ChaCha20, uint.MaxValue - 1u, 129)]
        public void Transform_OverflowRejectsBeforeMutatingAnyCallerOutput(
            ChaChaVariant variant, uint counter, int length)
        {
            var output = Enumerable.Repeat((byte)0xA5, length).ToArray();
            Assert.Throws<CryptographicException>(() =>
                Transform(output, new byte[length], ReferenceKey, ReferenceNonce, counter, variant));
            Assert.All(output, b => Assert.Equal((byte)0xA5, b));
        }

        [Theory]
        [InlineData(ChaChaVariant.ChaCha8, uint.MaxValue, 128)]
        [InlineData(ChaChaVariant.ChaCha12, uint.MaxValue, 128)]
        [InlineData(ChaChaVariant.ChaCha20, uint.MaxValue, 128)]
        [InlineData(ChaChaVariant.ChaCha8, uint.MaxValue - 1u, 192)]
        [InlineData(ChaChaVariant.ChaCha12, uint.MaxValue - 1u, 192)]
        [InlineData(ChaChaVariant.ChaCha20, uint.MaxValue - 1u, 192)]
        public void GenerateKeystream_OverflowRejectsBeforeMutatingAnyCallerOutput(
            ChaChaVariant variant, uint counter, int length)
        {
            var output = Enumerable.Repeat((byte)0xA5, length).ToArray();
            Assert.Throws<CryptographicException>(() =>
                GenerateKeystream(output, ReferenceKey, ReferenceNonce, counter, variant));
            Assert.All(output, b => Assert.Equal((byte)0xA5, b));
        }

        [Theory]
        [InlineData(ChaChaVariant.ChaCha8)]
        [InlineData(ChaChaVariant.ChaCha12)]
        [InlineData(ChaChaVariant.ChaCha20)]
        public void EmptyRequestsAtLastCounterAreAllowed(ChaChaVariant variant)
        {
            Transform([], [],
                ReferenceKey, ReferenceNonce, uint.MaxValue, variant);
            GenerateKeystream([], ReferenceKey, ReferenceNonce, uint.MaxValue, variant);
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
        public void Transform_InvalidKeySize_ThrowsArgumentException()
        {
            var invalidKey = new byte[16];
            var nonce = new byte[NONCE_SIZE];
            var plaintext = new byte[10];
            var ciphertext = new byte[10];

            CryptoAssertions.AssertExceptionContains<ArgumentException>(
                () => Transform(ciphertext, plaintext, invalidKey, nonce, 0, ChaChaVariant.ChaCha20),
                "32 bytes");
        }
    }

    /// <summary>
    /// Public operations must not accept arbitrary enum values as ChaCha round counts.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class InvalidVariantTests
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(7)]
        [InlineData(9)]
        [InlineData(21)]
        [InlineData(-1)]
        public void Transform_RejectsUndefinedVariantWithoutChangingOutput(int invalidRoundCount)
        {
            var variant = (ChaChaVariant)invalidRoundCount;
            byte[] key = new byte[KEY_SIZE];
            byte[] nonce = new byte[NONCE_SIZE];
            int[] lengths = [0, 1, 63, 64, 65];

            foreach (int length in lengths)
            {
                var output = Enumerable.Repeat((byte)0xA5, length).ToArray();
                var exception = Assert.Throws<ArgumentException>(() =>
                    Transform(output, new byte[length], key, nonce, 0, variant));
                Assert.Equal("variant", exception.ParamName);
                Assert.All(output, b => Assert.Equal((byte)0xA5, b));
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(7)]
        [InlineData(9)]
        [InlineData(21)]
        [InlineData(-1)]
        public void GenerateKeystream_RejectsUndefinedVariantWithoutChangingOutput(int invalidRoundCount)
        {
            var variant = (ChaChaVariant)invalidRoundCount;
            byte[] key = new byte[KEY_SIZE];
            byte[] nonce = new byte[NONCE_SIZE];
            int[] lengths = [0, 64, 128];

            foreach (int length in lengths)
            {
                var output = Enumerable.Repeat((byte)0xA5, length).ToArray();
                var exception = Assert.Throws<ArgumentException>(() =>
                    GenerateKeystream(output, key, nonce, 0, variant));
                Assert.Equal("variant", exception.ParamName);
                Assert.All(output, b => Assert.Equal((byte)0xA5, b));
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(7)]
        [InlineData(9)]
        [InlineData(21)]
        [InlineData(-1)]
        public void ValidateParameters_RejectsUndefinedVariant(int invalidRoundCount)
        {
            var exception = Assert.Throws<ArgumentException>(() =>
                ValidateParameters(new byte[KEY_SIZE], new byte[NONCE_SIZE],
                    (ChaChaVariant)invalidRoundCount));
            Assert.Equal("variant", exception.ParamName);
        }
    }

    /// <summary>
    /// Known Answer Tests using RFC 8439 vectors.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        [Fact]
        public void ChaCha20_RFC8439_Section232_ProducesSameBlockForBothEntryPoints()
        {
            // RFC 8439 section 2.3.2: key 00..1F, counter 1,
            // nonce 000000090000004A00000000.
            byte[] key = Convert.FromHexString(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
            byte[] nonce = Convert.FromHexString("000000090000004A00000000");
            byte[] expected = Convert.FromHexString(
                "10F1E7E4D13B5915500FDD1FA32071C4C7D1F4C733C068030422AA9AC3D46C4E" +
                "D2826446079FAA0914C2D705D98B02A2B5129CD1DE164EB9CBD083E8A2503C4E");
            byte[] keystream = new byte[BLOCK_SIZE];
            byte[] transformed = new byte[BLOCK_SIZE];

            GenerateKeystream(keystream, key, nonce, 1, ChaChaVariant.ChaCha20);
            Transform(transformed, new byte[BLOCK_SIZE], key, nonce, 1, ChaChaVariant.ChaCha20);

            Assert.Equal(expected, keystream);
            Assert.Equal(expected, transformed);
        }

        [Fact]
        public void ChaCha20_IsDeterministic()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);
            Transform(ciphertext2, plaintext, key, nonce, 0, ChaChaVariant.ChaCha20);

            CryptoAssertions.AssertBytesEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void ChaCha8_IsDeterministic()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key, nonce, 0, ChaChaVariant.ChaCha8);
            Transform(ciphertext2, plaintext, key, nonce, 0, ChaChaVariant.ChaCha8);

            CryptoAssertions.AssertBytesEqual(ciphertext1, ciphertext2);
        }

        [Fact]
        public void ChaCha12_IsDeterministic()
        {
            var key = TestHelpers.RandomBytes(KEY_SIZE);
            var nonce = TestHelpers.RandomBytes(NONCE_SIZE);
            var plaintext = TestHelpers.RandomBytes(64);
            var ciphertext1 = new byte[64];
            var ciphertext2 = new byte[64];

            Transform(ciphertext1, plaintext, key, nonce, 0, ChaChaVariant.ChaCha12);
            Transform(ciphertext2, plaintext, key, nonce, 0, ChaChaVariant.ChaCha12);

            CryptoAssertions.AssertBytesEqual(ciphertext1, ciphertext2);
        }
    }
}
