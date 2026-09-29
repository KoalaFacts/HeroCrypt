using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Secp256k1;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Secp256k1;

/// <summary>
/// Comprehensive tests for Secp256k1 implementation.
/// Follows HeroCrypt testing conventions - see TESTING_CONVENTIONS.md
/// </summary>
public class Secp256k1CoreTests
{
    private const int PRIVATE_KEY_SIZE = 32;
    private const int UNCOMPRESSED_PUB_SIZE = 65;
    private const int COMPRESSED_PUB_SIZE = 33;
    private const int SIGNATURE_SIZE = 64;

    /// <summary>
    /// Basic functionality tests for normal operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BasicFunctionality
    {
        private readonly Secp256k1Core core = new();

        [Fact]
        public void GenerateKeyPair_ReturnsValidKeys()
        {
            var (privateKey, publicKey) = core.GenerateKeyPair();

            Assert.Equal(PRIVATE_KEY_SIZE, privateKey.Length);
            Assert.Equal(UNCOMPRESSED_PUB_SIZE, publicKey.Length); // Default is uncompressed
            Assert.Equal(0x04, publicKey[0]); // Uncompressed prefix
        }

        [Fact]
        public void DerivePublicKey_Uncompressed_Success()
        {
            var (privateKey, _) = core.GenerateKeyPair();

            var publicKey = core.DerivePublicKey(privateKey, compressed: false);

            Assert.Equal(UNCOMPRESSED_PUB_SIZE, publicKey.Length);
            Assert.Equal(0x04, publicKey[0]);
        }

        [Fact]
        public void DerivePublicKey_Compressed_Success()
        {
            var (privateKey, _) = core.GenerateKeyPair();

            var publicKey = core.DerivePublicKey(privateKey, compressed: true);

            Assert.Equal(COMPRESSED_PUB_SIZE, publicKey.Length);
            // Prefix 0x02 or 0x03
            Assert.True(publicKey[0] is 0x02 or 0x03);
        }

        [Fact]
        public void Sign_And_Verify_Success()
        {
            // Arrange
            var (privateKey, publicKey) = core.GenerateKeyPair();
            var message = Encoding.UTF8.GetBytes("Hello Secp256k1");
            var messageHash = SHA256.Create().ComputeHash(message);

            // Act
            var signature = core.Sign(messageHash, privateKey);
            var isValid = core.Verify(messageHash, signature, publicKey);

            // Assert
            Assert.Equal(SIGNATURE_SIZE, signature.Length);
            Assert.True(isValid);
        }

        [Fact]
        public void Sign_And_Verify_CompressedKey_Success()
        {
            // Arrange
            var (privateKey, _) = core.GenerateKeyPair();
            var compressedPublicKey = core.DerivePublicKey(privateKey, compressed: true);
            var messageHash = new byte[32]; // Zero hash is valid for test

            // Act
            var signature = core.Sign(messageHash, privateKey);
            var isValid = core.Verify(messageHash, signature, compressedPublicKey);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void Verify_WrongMessage_ReturnsFalse()
        {
            // Arrange
            var (privateKey, publicKey) = core.GenerateKeyPair();
            var messageHash1 = new byte[32]; messageHash1[0] = 1;
            var messageHash2 = new byte[32]; messageHash2[0] = 2;

            // Act
            var signature = core.Sign(messageHash1, privateKey);
            var isValid = core.Verify(messageHash2, signature, publicKey);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void Verify_WrongKey_ReturnsFalse()
        {
            // Arrange
            var (privateKey1, _) = core.GenerateKeyPair();
            var (_, publicKey2) = core.GenerateKeyPair();
            var messageHash = new byte[32];

            // Act
            var signature = core.Sign(messageHash, privateKey1);
            var isValid = core.Verify(messageHash, signature, publicKey2);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void Verify_RejectsSignatureComputedFromPublicKey()
        {
            var (_, publicKey) = core.GenerateKeyPair();
            var messageHash = SHA256.HashData(Encoding.UTF8.GetBytes("public-key forgery"));
            var salt = Encoding.ASCII.GetBytes("HeroCrypt.Secp256k1.Signature");
            var material = new byte[publicKey.Length + salt.Length];
            publicKey.CopyTo(material, 0);
            salt.CopyTo(material, publicKey.Length);
            var forgedKey = SHA512.HashData(material);
            using var hmac = new HMACSHA512(forgedKey);
            var forgedSignature = hmac.ComputeHash(messageHash);

            Assert.False(core.Verify(messageHash, forgedSignature, publicKey));
        }

        [Fact]
        public void Compress_And_Decompress_Roundtrip()
        {
            var (_, uncompressed) = core.GenerateKeyPair();

            var compressed = core.CompressPublicKey(uncompressed);
            var decompressed = core.DecompressPublicKey(compressed);

            CryptoAssertions.AssertBytesEqual(uncompressed, decompressed);
        }
    }

    /// <summary>
    /// Edge case tests for boundary conditions.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCases
    {
        private readonly Secp256k1Core core = new();

        [Fact]
        public void Sign_ZeroHash_Success()
        {
            var (privateKey, publicKey) = core.GenerateKeyPair();
            var zeroHash = new byte[32];

            var signature = core.Sign(zeroHash, privateKey);
            var isValid = core.Verify(zeroHash, signature, publicKey);

            Assert.Equal(SIGNATURE_SIZE, signature.Length);
            Assert.True(isValid);
        }

        [Fact]
        public void Sign_MaxHash_Success()
        {
            var (privateKey, publicKey) = core.GenerateKeyPair();
            var maxHash = new byte[32];
            Array.Fill(maxHash, (byte)0xFF);

            var signature = core.Sign(maxHash, privateKey);
            var isValid = core.Verify(maxHash, signature, publicKey);

            Assert.Equal(SIGNATURE_SIZE, signature.Length);
            Assert.True(isValid);
        }

        [Fact]
        public void Sign_MultipleMessages_AllVerify()
        {
            var (privateKey, publicKey) = core.GenerateKeyPair();

            for (int i = 0; i < 10; i++)
            {
                var messageHash = TestHelpers.RandomBytes(32);
                var signature = core.Sign(messageHash, privateKey);
                Assert.True(core.Verify(messageHash, signature, publicKey));
            }
        }
    }

    /// <summary>
    /// Security-focused tests for cryptographic properties.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class Security
    {
        private readonly Secp256k1Core core = new();

        [Fact]
        public void PublicKey_AppearsRandom()
        {
            var (_, publicKey) = core.GenerateKeyPair();

            // Skip the 0x04 prefix, check that X and Y coordinates appear random
            var xCoord = publicKey.AsSpan(1, 32).ToArray();
            var yCoord = publicKey.AsSpan(33, 32).ToArray();

            CryptoAssertions.AssertAppearsRandom(xCoord);
            CryptoAssertions.AssertAppearsRandom(yCoord);
        }

        [Fact]
        public void Signature_AppearsRandom()
        {
            var (privateKey, _) = core.GenerateKeyPair();
            var messageHash = TestHelpers.RandomBytes(32);

            var signature = core.Sign(messageHash, privateKey);

            // r and s components should appear random
            var r = signature.AsSpan(0, 32).ToArray();
            var s = signature.AsSpan(32, 32).ToArray();

            CryptoAssertions.AssertAppearsRandom(r);
            CryptoAssertions.AssertAppearsRandom(s);
        }

        [Fact]
        public void Verify_TamperedMessage_ReturnsFalse()
        {
            var (privateKey, publicKey) = core.GenerateKeyPair();
            var messageHash = TestHelpers.RandomBytes(32);

            var signature = core.Sign(messageHash, privateKey);

            // Tamper with message
            var tamperedHash = TestHelpers.TamperFirst(messageHash);

            Assert.False(core.Verify(tamperedHash, signature, publicKey));
        }

        [Fact]
        public void Verify_TamperedSignature_ReturnsFalse()
        {
            var (privateKey, publicKey) = core.GenerateKeyPair();
            var messageHash = TestHelpers.RandomBytes(32);

            var signature = core.Sign(messageHash, privateKey);

            // Tamper with signature
            var tamperedSig = (byte[])signature.Clone();
            tamperedSig[0] ^= 0xFF;

            Assert.False(core.Verify(messageHash, tamperedSig, publicKey));
        }

        [Fact]
        public void DifferentKeys_ProduceDifferentSignatures()
        {
            var (privateKey1, _) = core.GenerateKeyPair();
            var (privateKey2, _) = core.GenerateKeyPair();
            var messageHash = TestHelpers.RandomBytes(32);

            var signature1 = core.Sign(messageHash, privateKey1);
            var signature2 = core.Sign(messageHash, privateKey2);

            Assert.NotEqual(signature1, signature2);
        }
    }

    /// <summary>
    /// Parameter validation tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParameterValidation
    {
        private readonly Secp256k1Core core = new();

        [Fact]
        public void Sign_InvalidHashLength_ThrowsArgumentException()
        {
            var (privateKey, _) = core.GenerateKeyPair();
            Assert.Throws<ArgumentException>(() => core.Sign(new byte[31], privateKey));
        }

        [Fact]
        public void Sign_InvalidKeyLength_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => core.Sign(new byte[32], new byte[31]));
        }

        [Fact]
        public void Verify_InvalidSignatureLength_ThrowsArgumentException()
        {
            var (_, publicKey) = core.GenerateKeyPair();
            Assert.Throws<ArgumentException>(() => core.Verify(new byte[32], new byte[63], publicKey));
        }
    }

    /// <summary>
    /// Known Answer Tests for Secp256k1 ECDSA.
    /// </summary>
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        private readonly Secp256k1Core core = new();

        [Fact]
        public void Secp256k1_PublicKeyDerivation_IsDeterministic()
        {
            var (privateKey, _) = core.GenerateKeyPair();

            var publicKey1 = core.DerivePublicKey(privateKey, compressed: false);
            var publicKey2 = core.DerivePublicKey(privateKey, compressed: false);

            // Uncompressed format: 04 || X || Y
            Assert.Equal(0x04, publicKey1[0]);
            Assert.Equal(UNCOMPRESSED_PUB_SIZE, publicKey1.Length);
            CryptoAssertions.AssertBytesEqual(publicKey1, publicKey2);
        }

        [Fact]
        public void Secp256k1_SignatureVerification_RoundTrip()
        {
            var (privateKey, publicKey) = core.GenerateKeyPair();

            // Hash of message "test"
            var messageHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("test"));

            // Sign and verify
            var signature = core.Sign(messageHash, privateKey);
            var isValid = core.Verify(messageHash, signature, publicKey);

            Assert.True(isValid);
            Assert.Equal(SIGNATURE_SIZE, signature.Length);
        }

        [Fact]
        public void Secp256k1_Signature_UsesStandardEcdsaFormat()
        {
            var (privateKey, publicKey) = core.GenerateKeyPair();
            var messageHash = TestHelpers.RandomBytes(32);
            var signature = core.Sign(messageHash, privateKey);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportParameters(new ECParameters
            {
                Curve = ECCurve.CreateFromFriendlyName("secP256k1"),
                Q = new ECPoint
                {
                    X = publicKey.AsSpan(1, 32).ToArray(),
                    Y = publicKey.AsSpan(33, 32).ToArray()
                }
            });

            Assert.True(ecdsa.VerifyHash(messageHash, signature));
        }

        [Fact]
        public void Secp256k1_CompressedPublicKey_CorrectFormat()
        {
            var (privateKey, _) = core.GenerateKeyPair();

            var compressedPublicKey = core.DerivePublicKey(privateKey, compressed: true);

            // Compressed format: 02 or 03 || X
            Assert.Equal(COMPRESSED_PUB_SIZE, compressedPublicKey.Length);
            Assert.True(compressedPublicKey[0] is 0x02 or 0x03);
        }
    }
}
