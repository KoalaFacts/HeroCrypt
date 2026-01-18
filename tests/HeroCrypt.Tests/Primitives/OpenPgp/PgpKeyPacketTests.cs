using System.Numerics;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Primitives.S2K;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP Key Packets per RFC 4880 Section 5.5 and RFC 9580.
/// </summary>
public class PgpKeyPacketTests
{
    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyAlgorithm Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PublicKeyAlgorithmTests
    {
        [Theory]
        [InlineData(PgpPublicKeyAlgorithm.RsaEncryptOrSign, true, true)]
        [InlineData(PgpPublicKeyAlgorithm.ElgamalEncryptOnly, true, false)]
        [InlineData(PgpPublicKeyAlgorithm.Dsa, false, true)]
        [InlineData(PgpPublicKeyAlgorithm.Ecdh, true, false)]
        [InlineData(PgpPublicKeyAlgorithm.Ecdsa, false, true)]
        [InlineData(PgpPublicKeyAlgorithm.Ed25519, false, true)]
        [InlineData(PgpPublicKeyAlgorithm.X25519, true, false)]
        public void CanEncryptAndSign_ReturnsCorrectCapabilities(PgpPublicKeyAlgorithm alg, bool canEncrypt, bool canSign)
        {
            Assert.Equal(canEncrypt, alg.CanEncrypt());
            Assert.Equal(canSign, alg.CanSign());
        }

        [Theory]
        [InlineData(PgpPublicKeyAlgorithm.Ecdsa, true)]
        [InlineData(PgpPublicKeyAlgorithm.Ecdh, true)]
        [InlineData(PgpPublicKeyAlgorithm.RsaEncryptOrSign, false)]
        [InlineData(PgpPublicKeyAlgorithm.Ed25519, false)]
        public void UsesOidEncoding_ReturnsCorrectValue(PgpPublicKeyAlgorithm alg, bool usesOid)
        {
            Assert.Equal(usesOid, alg.UsesOidEncoding());
        }

        [Theory]
        [InlineData(PgpPublicKeyAlgorithm.Ed25519, true, 32, 32)]
        [InlineData(PgpPublicKeyAlgorithm.X25519, true, 32, 32)]
        [InlineData(PgpPublicKeyAlgorithm.Ed448, true, 57, 57)]
        [InlineData(PgpPublicKeyAlgorithm.X448, true, 56, 56)]
        [InlineData(PgpPublicKeyAlgorithm.RsaEncryptOrSign, false, 0, 0)]
        public void NativeFormat_ReturnsCorrectSizes(PgpPublicKeyAlgorithm alg, bool isNative, int pubSize, int secSize)
        {
            Assert.Equal(isNative, alg.UsesNativeFormat());
            Assert.Equal(pubSize, alg.GetNativePublicKeySize());
            Assert.Equal(secSize, alg.GetNativeSecretKeySize());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyPacket Factory Method Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PublicKeyFactoryTests
    {
        [Fact]
        public void CreateV4_SetsCorrectVersion()
        {
            var creationTime = DateTimeOffset.UtcNow;
            var keyMaterial = TestHelpers.RandomBytes(100);

            var packet = PgpPublicKeyPacket.CreateV4(
                creationTime,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                keyMaterial);

            Assert.Equal(4, packet.Version);
            Assert.Equal(PgpPublicKeyAlgorithm.RsaEncryptOrSign, packet.Algorithm);
            Assert.False(packet.IsSubkey);
        }

        [Fact]
        public void CreateV6_SetsCorrectVersion()
        {
            var creationTime = DateTimeOffset.UtcNow;
            var keyMaterial = TestHelpers.RandomBytes(100);

            var packet = PgpPublicKeyPacket.CreateV6(
                creationTime,
                PgpPublicKeyAlgorithm.Ed25519,
                keyMaterial);

            Assert.Equal(6, packet.Version);
            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, packet.Algorithm);
        }

        [Fact]
        public void CreateV4_Subkey_SetsIsSubkeyTrue()
        {
            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ecdh,
                TestHelpers.RandomBytes(50),
                isSubkey: true);

            Assert.True(packet.IsSubkey);
        }

        [Fact]
        public void CreateRsa_EncodesKeyMaterialCorrectly()
        {
            var n = BigInteger.Parse("123456789012345678901234567890");
            var e = new BigInteger(65537);

            var packet = PgpPublicKeyPacket.CreateRsa(4, DateTimeOffset.UtcNow, n, e);

            var (readN, readE) = packet.ReadRsaKey();
            Assert.Equal(n, readN);
            Assert.Equal(e, readE);
        }

        [Fact]
        public void CreateEd25519_SetsCorrectAlgorithm()
        {
            var publicKey = TestHelpers.RandomBytes(32);

            var packet = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, publicKey);

            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, packet.Algorithm);
            Assert.Equal(6, packet.Version);
            Assert.Equal(publicKey, packet.ReadNativePublicKey());
        }

        [Fact]
        public void CreateEd25519_InvalidSize_ThrowsException()
        {
            var publicKey = TestHelpers.RandomBytes(33);

            Assert.Throws<ArgumentException>(() =>
                PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, publicKey));
        }

        [Fact]
        public void CreateX25519_SetsCorrectAlgorithm()
        {
            var publicKey = TestHelpers.RandomBytes(32);

            var packet = PgpPublicKeyPacket.CreateX25519(DateTimeOffset.UtcNow, publicKey);

            Assert.Equal(PgpPublicKeyAlgorithm.X25519, packet.Algorithm);
            Assert.Equal(publicKey, packet.ReadNativePublicKey());
        }

        [Fact]
        public void CreateEcdsa_EncodesOidCorrectly()
        {
            var publicPoint = TestHelpers.RandomBytes(65); // Uncompressed P-256 point

            var packet = PgpPublicKeyPacket.CreateEcdsa(
                4,
                DateTimeOffset.UtcNow,
                PgpCurveOid.NistP256,
                publicPoint);

            var (oid, point) = packet.ReadEcKeyWithOid();
            Assert.Equal(PgpCurveOid.NistP256.GetOidBytes(), oid);
            Assert.Equal(publicPoint, point);
        }

        [Fact]
        public void Constructor_InvalidVersion_ThrowsException()
        {
            Assert.Throws<ArgumentException>(() =>
                new PgpPublicKeyPacket(5, DateTimeOffset.UtcNow, PgpPublicKeyAlgorithm.RsaEncryptOrSign, Array.Empty<byte>()));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyPacket Round-Trip Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PublicKeyRoundTripTests
    {
        [Fact]
        public void RoundTrip_V4RsaKey_PreservesAllFields()
        {
            var n = BigInteger.Parse("123456789012345678901234567890123456789");
            var e = new BigInteger(65537);
            var creationTime = new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

            var original = PgpPublicKeyPacket.CreateRsa(4, creationTime, n, e);
            var encoded = original.ToArray();
            var decoded = PgpPublicKeyPacket.Read(encoded);

            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.Algorithm, decoded.Algorithm);
            Assert.Equal(original.CreationTime.ToUnixTimeSeconds(), decoded.CreationTime.ToUnixTimeSeconds());
            Assert.Equal(original.KeyMaterial.ToArray(), decoded.KeyMaterial.ToArray());
        }

        [Fact]
        public void RoundTrip_V6Ed25519Key_PreservesAllFields()
        {
            var publicKey = TestHelpers.RandomBytes(32);
            var creationTime = new DateTimeOffset(2024, 6, 1, 0, 0, 0, TimeSpan.Zero);

            var original = PgpPublicKeyPacket.CreateEd25519(creationTime, publicKey);
            var encoded = original.ToArray();
            var decoded = PgpPublicKeyPacket.Read(encoded);

            Assert.Equal(6, decoded.Version);
            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, decoded.Algorithm);
            Assert.Equal(publicKey, decoded.KeyMaterial.ToArray());
        }

        [Fact]
        public void RoundTrip_Subkey_PreservesIsSubkeyFlag()
        {
            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100),
                isSubkey: true);

            var encoded = packet.ToArray();
            var decoded = PgpPublicKeyPacket.Read(encoded, isSubkey: true);

            Assert.True(decoded.IsSubkey);
        }

        [Theory]
        [InlineData(4)]
        [InlineData(6)]
        public void RoundTrip_EmptyKeyMaterial_Works(byte version)
        {
            var original = version == 4
                ? PgpPublicKeyPacket.CreateV4(DateTimeOffset.UtcNow, PgpPublicKeyAlgorithm.RsaEncryptOrSign, Array.Empty<byte>())
                : PgpPublicKeyPacket.CreateV6(DateTimeOffset.UtcNow, PgpPublicKeyAlgorithm.Ed25519, Array.Empty<byte>());

            var encoded = original.ToArray();
            var decoded = PgpPublicKeyPacket.Read(encoded);

            Assert.Equal(version, decoded.Version);
            Assert.Empty(decoded.KeyMaterial.ToArray());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyPacket Fingerprint Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FingerprintTests
    {
        [Fact]
        public void ComputeFingerprint_V4_ReturnsSha1Hash()
        {
            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            var fingerprint = packet.ComputeFingerprint();

            Assert.Equal(20, fingerprint.Length); // SHA-1 = 20 bytes
        }

        [Fact]
        public void ComputeFingerprint_V6_ReturnsSha256Hash()
        {
            var packet = PgpPublicKeyPacket.CreateV6(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32));

            var fingerprint = packet.ComputeFingerprint();

            Assert.Equal(32, fingerprint.Length); // SHA-256 = 32 bytes
        }

        [Fact]
        public void GetKeyId_V4_ReturnsLast8BytesOfFingerprint()
        {
            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            var fingerprint = packet.ComputeFingerprint();
            var keyId = packet.GetKeyId();

            Assert.Equal(8, keyId.Length);
            Assert.Equal(fingerprint[^8..], keyId);
        }

        [Fact]
        public void GetKeyId_V6_ReturnsFirst8BytesOfFingerprint()
        {
            var packet = PgpPublicKeyPacket.CreateV6(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32));

            var fingerprint = packet.ComputeFingerprint();
            var keyId = packet.GetKeyId();

            Assert.Equal(8, keyId.Length);
            Assert.Equal(fingerprint[..8], keyId);
        }

        [Fact]
        public void ComputeFingerprint_Deterministic_SameInputSameOutput()
        {
            var keyMaterial = TestHelpers.RandomBytes(100);
            var creationTime = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

            var packet1 = PgpPublicKeyPacket.CreateV4(creationTime, PgpPublicKeyAlgorithm.RsaEncryptOrSign, keyMaterial);
            var packet2 = PgpPublicKeyPacket.CreateV4(creationTime, PgpPublicKeyAlgorithm.RsaEncryptOrSign, keyMaterial);

            Assert.Equal(packet1.ComputeFingerprint(), packet2.ComputeFingerprint());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpPublicKeyPacket Error Handling Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PublicKeyErrorHandlingTests
    {
        [Fact]
        public void TryRead_EmptySource_ReturnsFalse()
        {
            var success = PgpPublicKeyPacket.TryRead([], false, out _, out var error);

            Assert.False(success);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_UnsupportedVersion_ReturnsFalse()
        {
            byte[] source = [5, 0, 0, 0, 0, 1]; // Version 5

            var success = PgpPublicKeyPacket.TryRead(source, false, out _, out var error);

            Assert.False(success);
            Assert.Contains("Unsupported", error);
        }

        [Fact]
        public void TryRead_V4TruncatedHeader_ReturnsFalse()
        {
            byte[] source = [4, 0, 0]; // Only 3 bytes of header

            var success = PgpPublicKeyPacket.TryRead(source, false, out _, out var error);

            Assert.False(success);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_V6TruncatedHeader_ReturnsFalse()
        {
            byte[] source = [6, 0, 0, 0, 0, 27]; // Missing key length

            var success = PgpPublicKeyPacket.TryRead(source, false, out _, out var error);

            Assert.False(success);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_V6KeyLengthMismatch_ReturnsFalse()
        {
            // Version 6, creation time, algorithm, key length = 100, but only 10 bytes of key
            byte[] source = [6, 0, 0, 0, 1, 27, 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

            var success = PgpPublicKeyPacket.TryRead(source, false, out _, out var error);

            Assert.False(success);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void Read_InvalidSource_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpPublicKeyPacket.Read([]));
        }

        [Fact]
        public void ReadRsaKey_NonRsaAlgorithm_ThrowsInvalidOperationException()
        {
            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Dsa,
                TestHelpers.RandomBytes(100));

            Assert.Throws<InvalidOperationException>(() => packet.ReadRsaKey());
        }

        [Fact]
        public void ReadNativePublicKey_NonNativeAlgorithm_ThrowsInvalidOperationException()
        {
            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            Assert.Throws<InvalidOperationException>(packet.ReadNativePublicKey);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpS2KSpecifier Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class S2KSpecifierTests
    {
        [Fact]
        public void CreateSimple_SetsCorrectType()
        {
            var spec = PgpS2KSpecifier.CreateSimple(8); // SHA-256

            Assert.Equal(S2KType.Simple, spec.Type);
            Assert.Equal(8, spec.HashAlgorithm);
            Assert.Equal(2, spec.GetEncodedLength());
        }

        [Fact]
        public void CreateSalted_SetsCorrectFields()
        {
            var salt = TestHelpers.RandomBytes(8);

            var spec = PgpS2KSpecifier.CreateSalted(8, salt);

            Assert.Equal(S2KType.Salted, spec.Type);
            Assert.Equal(8, spec.HashAlgorithm);
            Assert.Equal(salt, spec.Salt.ToArray());
            Assert.Equal(10, spec.GetEncodedLength());
        }

        [Fact]
        public void CreateSalted_InvalidSaltLength_ThrowsException()
        {
            Assert.Throws<ArgumentException>(() =>
                PgpS2KSpecifier.CreateSalted(8, TestHelpers.RandomBytes(7)));
        }

        [Fact]
        public void CreateIterated_SetsCorrectFields()
        {
            var salt = TestHelpers.RandomBytes(8);

            var spec = PgpS2KSpecifier.CreateIterated(8, salt, 224);

            Assert.Equal(S2KType.IteratedAndSalted, spec.Type);
            Assert.Equal(224, spec.EncodedCount);
            Assert.Equal(11, spec.GetEncodedLength());
        }

        [Fact]
        public void RoundTrip_SimpleS2K_PreservesFields()
        {
            var original = PgpS2KSpecifier.CreateSimple(10);

            var buffer = new byte[original.GetEncodedLength()];
            original.Write(buffer);

            var success = PgpS2KSpecifier.TryRead(buffer, out var decoded, out _, out _);

            Assert.True(success);
            Assert.Equal(original.Type, decoded.Type);
            Assert.Equal(original.HashAlgorithm, decoded.HashAlgorithm);
        }

        [Fact]
        public void RoundTrip_IteratedS2K_PreservesFields()
        {
            var salt = TestHelpers.RandomBytes(8);
            var original = PgpS2KSpecifier.CreateIterated(8, salt, 200);

            var buffer = new byte[original.GetEncodedLength()];
            original.Write(buffer);

            var success = PgpS2KSpecifier.TryRead(buffer, out var decoded, out _, out _);

            Assert.True(success);
            Assert.Equal(original.Type, decoded.Type);
            Assert.Equal(original.HashAlgorithm, decoded.HashAlgorithm);
            Assert.Equal(original.Salt.ToArray(), decoded.Salt.ToArray());
            Assert.Equal(original.EncodedCount, decoded.EncodedCount);
        }

        [Fact]
        public void GetIterationCount_ReturnsDecodedValue()
        {
            var salt = TestHelpers.RandomBytes(8);
            var spec = PgpS2KSpecifier.CreateIterated(8, salt, 224);

            var count = spec.GetIterationCount();

            Assert.True(count > 0);
            Assert.Equal(S2KCore.DecodeIterationCount(224), count);
        }

        [Fact]
        public void TryRead_TruncatedSource_ReturnsFalse()
        {
            var success = PgpS2KSpecifier.TryRead([0x03], out _, out _, out var error);

            Assert.False(success);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void CreateArgon2_ValidParameters_Succeeds()
        {
            var salt = TestHelpers.RandomBytes(16);

            var spec = PgpS2KSpecifier.CreateArgon2(8, salt, passes: 3, parallelism: 4, memoryExponent: 16);

            Assert.Equal(S2KType.Argon2, spec.Type);
            Assert.Equal(8, spec.HashAlgorithm);
            Assert.Equal(salt, spec.Salt.ToArray());
            Assert.NotNull(spec.Argon2Params);
            Assert.Equal(3, spec.Argon2Params.Value.Passes);
            Assert.Equal(4, spec.Argon2Params.Value.Parallelism);
            Assert.Equal(16, spec.Argon2Params.Value.MemoryExponent);
        }

        [Fact]
        public void CreateArgon2_InvalidSaltLength_ThrowsArgumentException()
        {
            var salt = TestHelpers.RandomBytes(8); // Should be 16

            Assert.Throws<ArgumentException>(() =>
                PgpS2KSpecifier.CreateArgon2(8, salt, passes: 3, parallelism: 4, memoryExponent: 16));
        }

        [Fact]
        public void CreateArgon2_MemoryExponentTooLow_ThrowsArgumentOutOfRangeException()
        {
            var salt = TestHelpers.RandomBytes(16);

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpS2KSpecifier.CreateArgon2(8, salt, passes: 3, parallelism: 4, memoryExponent: 2));
        }

        [Fact]
        public void CreateArgon2_MemoryExponentTooHigh_ThrowsArgumentOutOfRangeException()
        {
            var salt = TestHelpers.RandomBytes(16);

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpS2KSpecifier.CreateArgon2(8, salt, passes: 3, parallelism: 4, memoryExponent: 32));
        }

        [Fact]
        public void CreateArgon2_PassesZero_ThrowsArgumentOutOfRangeException()
        {
            var salt = TestHelpers.RandomBytes(16);

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpS2KSpecifier.CreateArgon2(8, salt, passes: 0, parallelism: 4, memoryExponent: 16));
        }

        [Fact]
        public void CreateArgon2_ParallelismZero_ThrowsArgumentOutOfRangeException()
        {
            var salt = TestHelpers.RandomBytes(16);

            Assert.Throws<ArgumentOutOfRangeException>(() =>
                PgpS2KSpecifier.CreateArgon2(8, salt, passes: 3, parallelism: 0, memoryExponent: 16));
        }

        [Fact]
        public void TryRead_Argon2_InvalidMemoryExponent_ReturnsFalse()
        {
            // Argon2 S2K: type(1) + hash(1) + salt(16) + memoryExponent(1) + passes(1) + parallelism(1) = 21 bytes
            // Type 4 = Argon2
            var data = new byte[21];
            data[0] = 4; // Argon2 type
            data[1] = 8; // Hash algorithm
            // salt is 16 bytes at indices 2-17
            data[18] = 2; // Invalid memory exponent (< 3)
            data[19] = 3; // Passes
            data[20] = 4; // Parallelism

            var success = PgpS2KSpecifier.TryRead(data, out _, out _, out var error);

            Assert.False(success);
            Assert.Contains("memory", error.ToLower());
        }

        [Fact]
        public void TryRead_Argon2_InvalidPasses_ReturnsFalse()
        {
            var data = new byte[21];
            data[0] = 4; // Argon2 type
            data[1] = 8; // Hash algorithm
            data[18] = 16; // Memory exponent
            data[19] = 0; // Invalid passes (< 1)
            data[20] = 4; // Parallelism

            var success = PgpS2KSpecifier.TryRead(data, out _, out _, out var error);

            Assert.False(success);
            Assert.Contains("passes", error.ToLower());
        }

        [Fact]
        public void TryRead_Argon2_InvalidParallelism_ReturnsFalse()
        {
            var data = new byte[21];
            data[0] = 4; // Argon2 type
            data[1] = 8; // Hash algorithm
            data[18] = 16; // Memory exponent
            data[19] = 3; // Passes
            data[20] = 0; // Invalid parallelism (< 1)

            var success = PgpS2KSpecifier.TryRead(data, out _, out _, out var error);

            Assert.False(success);
            Assert.Contains("parallelism", error.ToLower());
        }

        [Fact]
        public void RoundTrip_Argon2S2K_PreservesFields()
        {
            var salt = TestHelpers.RandomBytes(16);
            var original = PgpS2KSpecifier.CreateArgon2(10, salt, passes: 5, parallelism: 8, memoryExponent: 20);

            var buffer = new byte[original.GetEncodedLength()];
            original.Write(buffer);

            var success = PgpS2KSpecifier.TryRead(buffer, out var decoded, out _, out _);

            Assert.True(success);
            Assert.Equal(S2KType.Argon2, decoded.Type);
            Assert.Equal(10, decoded.HashAlgorithm);
            Assert.Equal(salt, decoded.Salt.ToArray());
            Assert.NotNull(decoded.Argon2Params);
            Assert.Equal(5, decoded.Argon2Params.Value.Passes);
            Assert.Equal(8, decoded.Argon2Params.Value.Parallelism);
            Assert.Equal(20, decoded.Argon2Params.Value.MemoryExponent);
        }

        [Fact]
        public void ValidateArgon2Parameters_AllValid_NoException()
        {
            // Should not throw
            PgpS2KSpecifier.ValidateArgon2Parameters(passes: 1, parallelism: 1, memoryExponent: 3);
            PgpS2KSpecifier.ValidateArgon2Parameters(passes: 255, parallelism: 255, memoryExponent: 31);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpSecretKeyPacket Factory Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SecretKeyFactoryTests
    {
        [Fact]
        public void CreateUnencrypted_SetsCorrectUsage()
        {
            var publicKey = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));
            var secretMaterial = TestHelpers.RandomBytes(200);

            var packet = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretMaterial);

            Assert.Equal(PgpS2KUsage.None, packet.S2KUsage);
            Assert.False(packet.IsEncrypted);
            // SecretKeyMaterial includes the original data + 2-byte checksum
            Assert.Equal(secretMaterial.Length + 2, packet.SecretKeyMaterial.Length);
            Assert.Equal(secretMaterial, packet.SecretKeyMaterial.Slice(0, secretMaterial.Length).ToArray());
        }

        [Fact]
        public void CreateEncrypted_SetsCorrectFields()
        {
            var publicKey = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));
            var salt = TestHelpers.RandomBytes(8);
            var s2k = PgpS2KSpecifier.CreateIterated(8, salt, 224);
            var iv = TestHelpers.RandomBytes(16);
            var encryptedMaterial = TestHelpers.RandomBytes(200);

            var packet = PgpSecretKeyPacket.CreateEncrypted(
                publicKey,
                PgpS2KUsage.Sha1Hash,
                9, // AES-256
                s2k,
                iv,
                encryptedMaterial);

            Assert.Equal(PgpS2KUsage.Sha1Hash, packet.S2KUsage);
            Assert.True(packet.IsEncrypted);
            Assert.Equal(9, packet.CipherAlgorithm);
            Assert.Equal(iv, packet.IV.ToArray());
        }

        [Fact]
        public void CreateEncrypted_WithNoneUsage_ThrowsException()
        {
            var publicKey = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            Assert.Throws<ArgumentException>(() =>
                PgpSecretKeyPacket.CreateEncrypted(
                    publicKey,
                    PgpS2KUsage.None,
                    9,
                    PgpS2KSpecifier.CreateSimple(8),
                    Array.Empty<byte>(),
                    Array.Empty<byte>()));
        }

        [Fact]
        public void PublicKeyProperties_DelegateToPublicKey()
        {
            var creationTime = new DateTimeOffset(2024, 3, 15, 0, 0, 0, TimeSpan.Zero);
            var publicKey = PgpPublicKeyPacket.CreateV4(
                creationTime,
                PgpPublicKeyAlgorithm.Ed25519,
                TestHelpers.RandomBytes(32),
                isSubkey: true);

            var secretKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, TestHelpers.RandomBytes(32));

            Assert.Equal(4, secretKey.Version);
            Assert.Equal(creationTime, secretKey.CreationTime);
            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, secretKey.Algorithm);
            Assert.True(secretKey.IsSubkey);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpSecretKeyPacket Round-Trip Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SecretKeyRoundTripTests
    {
        [Fact]
        public void RoundTrip_UnencryptedV4RsaKey_PreservesAllFields()
        {
            // Create a proper RSA key material (n + e MPIs)
            var n = BigInteger.Parse("123456789012345678901234567890123456789");
            var e = new BigInteger(65537);
            int nLen = Mpi.GetEncodedLength(n);
            int eLen = Mpi.GetEncodedLength(e);
            var keyMaterial = new byte[nLen + eLen];
            int offset = Mpi.Write(n, keyMaterial);
            Mpi.Write(e, keyMaterial.AsSpan(offset));

            var creationTime = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);
            var publicKey = new PgpPublicKeyPacket(4, creationTime, PgpPublicKeyAlgorithm.RsaEncryptOrSign, keyMaterial);
            var secretMaterial = TestHelpers.RandomBytes(200);

            var original = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretMaterial);
            var encoded = original.ToArray();
            var decoded = PgpSecretKeyPacket.Read(encoded);

            Assert.Equal(original.Version, decoded.Version);
            Assert.Equal(original.Algorithm, decoded.Algorithm);
            Assert.Equal(original.S2KUsage, decoded.S2KUsage);
            Assert.False(decoded.IsEncrypted);
            Assert.Equal(original.SecretKeyMaterial.ToArray(), decoded.SecretKeyMaterial.ToArray());
        }

        [Fact]
        public void RoundTrip_EncryptedV4Key_PreservesAllFields()
        {
            // Create proper RSA key material
            var n = BigInteger.Parse("99999999999999999999999999999999999999999");
            var e = new BigInteger(65537);
            int nLen = Mpi.GetEncodedLength(n);
            int eLen = Mpi.GetEncodedLength(e);
            var keyMaterial = new byte[nLen + eLen];
            int offset = Mpi.Write(n, keyMaterial);
            Mpi.Write(e, keyMaterial.AsSpan(offset));

            var publicKey = new PgpPublicKeyPacket(4, DateTimeOffset.UtcNow, PgpPublicKeyAlgorithm.RsaEncryptOrSign, keyMaterial);
            var salt = TestHelpers.RandomBytes(8);
            var s2k = PgpS2KSpecifier.CreateIterated(8, salt, 224);
            var iv = TestHelpers.RandomBytes(16); // AES block size
            var encryptedMaterial = TestHelpers.RandomBytes(200);

            var original = PgpSecretKeyPacket.CreateEncrypted(
                publicKey,
                PgpS2KUsage.Sha1Hash,
                9, // AES-256
                s2k,
                iv,
                encryptedMaterial);

            var encoded = original.ToArray();
            var decoded = PgpSecretKeyPacket.Read(encoded);

            Assert.Equal(original.S2KUsage, decoded.S2KUsage);
            Assert.Equal(original.CipherAlgorithm, decoded.CipherAlgorithm);
            Assert.True(decoded.IsEncrypted);
            Assert.NotNull(decoded.S2KSpecifier);
            Assert.Equal(original.S2KSpecifier!.Value.Type, decoded.S2KSpecifier!.Value.Type);
            Assert.Equal(original.IV.ToArray(), decoded.IV.ToArray());
            Assert.Equal(original.SecretKeyMaterial.ToArray(), decoded.SecretKeyMaterial.ToArray());
        }

        [Fact]
        public void RoundTrip_V6NativeKey_PreservesAllFields()
        {
            var publicKey = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, TestHelpers.RandomBytes(32));
            var secretMaterial = TestHelpers.RandomBytes(32);

            var original = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretMaterial);
            var encoded = original.ToArray();
            var decoded = PgpSecretKeyPacket.Read(encoded);

            Assert.Equal(6, decoded.Version);
            Assert.Equal(PgpPublicKeyAlgorithm.Ed25519, decoded.Algorithm);
            // SecretKeyMaterial includes the original data + 2-byte checksum
            Assert.Equal(secretMaterial.Length + 2, decoded.SecretKeyMaterial.Length);
            Assert.Equal(secretMaterial, decoded.SecretKeyMaterial.Slice(0, secretMaterial.Length).ToArray());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // PgpSecretKeyPacket Error Handling Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SecretKeyErrorHandlingTests
    {
        [Fact]
        public void TryRead_EmptySource_ReturnsFalse()
        {
            var success = PgpSecretKeyPacket.TryRead([], false, out _, out var error);

            Assert.False(success);
            Assert.Contains("too short", error);
        }

        [Fact]
        public void TryRead_UnsupportedVersion_ReturnsFalse()
        {
            byte[] source = [5, 0, 0, 0, 0, 1];

            var success = PgpSecretKeyPacket.TryRead(source, false, out _, out var error);

            Assert.False(success);
            Assert.Contains("Unsupported", error);
        }

        [Fact]
        public void TryRead_InvalidChecksum_ReturnsFalse()
        {
            // Create a valid unencrypted secret key packet using Ed25519 (fixed-size key material)
            var publicKey = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, TestHelpers.RandomBytes(32));
            var secretKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, TestHelpers.RandomBytes(32));
            var encoded = secretKey.ToArray();

            // Corrupt the checksum (last 2 bytes)
            encoded[^1] = (byte)(encoded[^1] ^ 0xFF);
            encoded[^2] = (byte)(encoded[^2] ^ 0xFF);

            var success = PgpSecretKeyPacket.TryRead(encoded, false, out _, out var error);

            Assert.False(success);
            Assert.Contains("checksum mismatch", error);
        }

        [Fact]
        public void ReadRsaSecretKey_WhenEncrypted_ThrowsInvalidOperationException()
        {
            var n = BigInteger.Parse("123456789012345678901234567890123456789");
            var e = new BigInteger(65537);
            int nLen = Mpi.GetEncodedLength(n);
            int eLen = Mpi.GetEncodedLength(e);
            var keyMaterial = new byte[nLen + eLen];
            int offset = Mpi.Write(n, keyMaterial);
            Mpi.Write(e, keyMaterial.AsSpan(offset));

            var publicKey = new PgpPublicKeyPacket(4, DateTimeOffset.UtcNow, PgpPublicKeyAlgorithm.RsaEncryptOrSign, keyMaterial);
            var s2k = PgpS2KSpecifier.CreateSimple(8);

            var packet = PgpSecretKeyPacket.CreateEncrypted(
                publicKey,
                PgpS2KUsage.Sha1Hash,
                9,
                s2k,
                TestHelpers.RandomBytes(16),
                TestHelpers.RandomBytes(100));

            Assert.Throws<InvalidOperationException>(() => packet.ReadRsaSecretKey());
        }

        [Fact]
        public void ReadEcSecretKey_WhenEncrypted_ThrowsInvalidOperationException()
        {
            var publicKey = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, TestHelpers.RandomBytes(32));
            var s2k = PgpS2KSpecifier.CreateSimple(8);

            var packet = PgpSecretKeyPacket.CreateEncrypted(
                publicKey,
                PgpS2KUsage.Sha1Hash,
                9,
                s2k,
                TestHelpers.RandomBytes(16),
                TestHelpers.RandomBytes(100));

            Assert.Throws<InvalidOperationException>(packet.ReadEcSecretKey);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Integration Tests with PgpPacketWriter
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class PacketWriterIntegrationTests
    {
        [Fact]
        public void WriteTo_PublicKey_WritesCorrectTag()
        {
            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            packet.WriteTo(writer);
            writer.Dispose();

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream);
            Assert.True(reader.ReadNextPacket(out var tag, out _));
            Assert.Equal(PgpPacketTag.PublicKey, tag);
        }

        [Fact]
        public void WriteTo_PublicSubkey_WritesCorrectTag()
        {
            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ecdh,
                TestHelpers.RandomBytes(50),
                isSubkey: true);

            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            packet.WriteTo(writer);
            writer.Dispose();

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream);
            Assert.True(reader.ReadNextPacket(out var tag, out _));
            Assert.Equal(PgpPacketTag.PublicSubkey, tag);
        }

        [Fact]
        public void WriteTo_SecretKey_WritesCorrectTag()
        {
            var publicKey = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, TestHelpers.RandomBytes(32));
            var secretKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, TestHelpers.RandomBytes(32));

            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            secretKey.WriteTo(writer);
            writer.Dispose();

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream);
            Assert.True(reader.ReadNextPacket(out var tag, out _));
            Assert.Equal(PgpPacketTag.SecretKey, tag);
        }

        [Fact]
        public void WriteTo_SecretSubkey_WritesCorrectTag()
        {
            var publicKey = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ecdh,
                TestHelpers.RandomBytes(50),
                isSubkey: true);
            var secretKey = PgpSecretKeyPacket.CreateUnencrypted(publicKey, TestHelpers.RandomBytes(32));

            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            secretKey.WriteTo(writer);
            writer.Dispose();

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream);
            Assert.True(reader.ReadNextPacket(out var tag, out _));
            Assert.Equal(PgpPacketTag.SecretSubkey, tag);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ToString Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ToStringTests
    {
        [Fact]
        public void PublicKey_ToString_ContainsRelevantInfo()
        {
            var packet = PgpPublicKeyPacket.CreateV4(
                new DateTimeOffset(2024, 6, 15, 0, 0, 0, TimeSpan.Zero),
                PgpPublicKeyAlgorithm.RsaEncryptOrSign,
                TestHelpers.RandomBytes(100));

            var str = packet.ToString();

            Assert.Contains("v4", str);
            Assert.Contains("Rsa", str);
            Assert.Contains("2024-06-15", str);
            Assert.Contains("ID:", str);
        }

        [Fact]
        public void SecretKey_ToString_ContainsEncryptionStatus()
        {
            var publicKey = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, TestHelpers.RandomBytes(32));

            var unencrypted = PgpSecretKeyPacket.CreateUnencrypted(publicKey, TestHelpers.RandomBytes(32));
            var encrypted = PgpSecretKeyPacket.CreateEncrypted(
                publicKey,
                PgpS2KUsage.Sha1Hash,
                9,
                PgpS2KSpecifier.CreateSimple(8),
                TestHelpers.RandomBytes(16),
                TestHelpers.RandomBytes(100));

            Assert.Contains("unencrypted", unencrypted.ToString());
            Assert.Contains("encrypted", encrypted.ToString());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Algorithm-Specific Key Reading Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class AlgorithmSpecificReadTests
    {
        [Fact]
        public void ReadDsaKey_ReturnsCorrectParameters()
        {
            // Build DSA key material: p, q, g, y
            var p = BigInteger.Parse("123456789012345678901234567890");
            var q = BigInteger.Parse("98765432109876543210");
            var g = BigInteger.Parse("11111111111111111111");
            var y = BigInteger.Parse("22222222222222222222");

            int totalLen = Mpi.GetEncodedLength(p) + Mpi.GetEncodedLength(q) +
                          Mpi.GetEncodedLength(g) + Mpi.GetEncodedLength(y);
            var keyMaterial = new byte[totalLen];
            int offset = 0;
            offset += Mpi.Write(p, keyMaterial.AsSpan(offset));
            offset += Mpi.Write(q, keyMaterial.AsSpan(offset));
            offset += Mpi.Write(g, keyMaterial.AsSpan(offset));
            Mpi.Write(y, keyMaterial.AsSpan(offset));

            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Dsa,
                keyMaterial);

            var (readP, readQ, readG, readY) = packet.ReadDsaKey();

            Assert.Equal(p, readP);
            Assert.Equal(q, readQ);
            Assert.Equal(g, readG);
            Assert.Equal(y, readY);
        }

        [Fact]
        public void ReadElgamalKey_ReturnsCorrectParameters()
        {
            var p = BigInteger.Parse("123456789012345678901234567890");
            var g = BigInteger.Parse("11111111111111111111");
            var y = BigInteger.Parse("22222222222222222222");

            int totalLen = Mpi.GetEncodedLength(p) + Mpi.GetEncodedLength(g) + Mpi.GetEncodedLength(y);
            var keyMaterial = new byte[totalLen];
            int offset = 0;
            offset += Mpi.Write(p, keyMaterial.AsSpan(offset));
            offset += Mpi.Write(g, keyMaterial.AsSpan(offset));
            Mpi.Write(y, keyMaterial.AsSpan(offset));

            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.ElgamalEncryptOnly,
                keyMaterial);

            var (readP, readG, readY) = packet.ReadElgamalKey();

            Assert.Equal(p, readP);
            Assert.Equal(g, readG);
            Assert.Equal(y, readY);
        }

        [Fact]
        public void ReadEcdhKey_ReturnsCorrectParametersWithKdf()
        {
            var oid = PgpCurveOid.NistP256.GetOidBytes();
            var publicPoint = TestHelpers.RandomBytes(65);
            byte hashAlgo = 8; // SHA-256
            byte cipherAlgo = 9; // AES-256

            // Build ECDH key material: OID length + OID + Q (MPI) + KDF params
            int qMpiLen = Mpi.GetEncodedLength(publicPoint);
            var keyMaterial = new byte[1 + oid.Length + qMpiLen + 4];
            int offset = 0;
            keyMaterial[offset++] = (byte)oid.Length;
            oid.CopyTo(keyMaterial.AsSpan(offset));
            offset += oid.Length;
            offset += Mpi.Write(publicPoint, keyMaterial.AsSpan(offset));
            // KDF params: 03 01 hash cipher
            keyMaterial[offset++] = 0x03;
            keyMaterial[offset++] = 0x01;
            keyMaterial[offset++] = hashAlgo;
            keyMaterial[offset] = cipherAlgo;

            var packet = PgpPublicKeyPacket.CreateV4(
                DateTimeOffset.UtcNow,
                PgpPublicKeyAlgorithm.Ecdh,
                keyMaterial);

            var (readOid, readPoint, readHash, readCipher) = packet.ReadEcdhKey();

            Assert.Equal(oid, readOid);
            Assert.Equal(publicPoint, readPoint);
            Assert.Equal(hashAlgo, readHash);
            Assert.Equal(cipherAlgo, readCipher);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Secure Memory Clearing Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class SecureMemoryClearingTests
    {
        [Fact]
        public void ClearSensitiveData_UnencryptedKey_ClearsSecretMaterial()
        {
            var publicKey = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, TestHelpers.RandomBytes(32));
            var secretMaterial = TestHelpers.RandomBytes(32);
            var packet = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretMaterial);

            // Verify data exists before clearing
            Assert.False(packet.SecretKeyMaterial.Span.ToArray().All(b => b == 0));

            // Clear sensitive data
            packet.ClearSensitiveData();

            // Verify all bytes are zeroed
            Assert.True(packet.SecretKeyMaterial.Span.ToArray().All(b => b == 0));
        }

        [Fact]
        public void ClearSensitiveData_EncryptedKey_ClearsMaterialAndIv()
        {
            var publicKey = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, TestHelpers.RandomBytes(32));
            var iv = TestHelpers.RandomBytes(16);
            var encryptedMaterial = TestHelpers.RandomBytes(100);

            var packet = PgpSecretKeyPacket.CreateEncrypted(
                publicKey,
                PgpS2KUsage.Sha1Hash,
                9,
                PgpS2KSpecifier.CreateSimple(8),
                iv,
                encryptedMaterial);

            // Verify data exists before clearing
            Assert.False(packet.SecretKeyMaterial.Span.ToArray().All(b => b == 0));
            Assert.False(packet.IV.Span.ToArray().All(b => b == 0));

            // Clear sensitive data
            packet.ClearSensitiveData();

            // Verify all bytes are zeroed
            Assert.True(packet.SecretKeyMaterial.Span.ToArray().All(b => b == 0));
            Assert.True(packet.IV.Span.ToArray().All(b => b == 0));
        }

        [Fact]
        public void ClearSensitiveData_WithS2KSalt_ClearsSalt()
        {
            var publicKey = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, TestHelpers.RandomBytes(32));
            var salt = TestHelpers.RandomBytes(8);
            var s2k = PgpS2KSpecifier.CreateSalted(8, salt);
            var iv = TestHelpers.RandomBytes(16);
            var encryptedMaterial = TestHelpers.RandomBytes(100);

            var packet = PgpSecretKeyPacket.CreateEncrypted(
                publicKey,
                PgpS2KUsage.Sha1Hash,
                9,
                s2k,
                iv,
                encryptedMaterial);

            // Verify salt exists before clearing
            Assert.True(packet.S2KSpecifier.HasValue);
            Assert.False(packet.S2KSpecifier.Value.Salt.Span.ToArray().All(b => b == 0));

            // Clear sensitive data
            packet.ClearSensitiveData();

            // Verify salt is zeroed
            Assert.True(packet.S2KSpecifier.Value.Salt.Span.ToArray().All(b => b == 0));
        }

        [Fact]
        public void ClearSensitiveData_EmptyIv_DoesNotThrow()
        {
            var publicKey = PgpPublicKeyPacket.CreateEd25519(DateTimeOffset.UtcNow, TestHelpers.RandomBytes(32));
            var secretMaterial = TestHelpers.RandomBytes(32);
            var packet = PgpSecretKeyPacket.CreateUnencrypted(publicKey, secretMaterial);

            // Should not throw for empty IV
            var exception = Record.Exception(packet.ClearSensitiveData);
            Assert.Null(exception);
        }

        [Fact]
        public void PgpS2KSpecifier_ClearSensitiveData_ClearsSalt()
        {
            var salt = TestHelpers.RandomBytes(8);
            var s2k = PgpS2KSpecifier.CreateSalted(8, salt);

            // Verify salt exists before clearing
            Assert.False(s2k.Salt.Span.ToArray().All(b => b == 0));

            // Clear sensitive data
            s2k.ClearSensitiveData();

            // Verify salt is zeroed
            Assert.True(s2k.Salt.Span.ToArray().All(b => b == 0));
        }

        [Fact]
        public void PgpS2KSpecifier_ClearSensitiveData_EmptySalt_DoesNotThrow()
        {
            var s2k = PgpS2KSpecifier.CreateSimple(8);

            // Should not throw for empty salt
            var exception = Record.Exception(s2k.ClearSensitiveData);
            Assert.Null(exception);
        }

        [Theory]
        [InlineData((ushort)0, (ushort)0, true)]
        [InlineData((ushort)0xFFFF, (ushort)0xFFFF, true)]
        [InlineData((ushort)0x1234, (ushort)0x1234, true)]
        [InlineData((ushort)0, (ushort)1, false)]
        [InlineData((ushort)0xFFFF, (ushort)0xFFFE, false)]
        [InlineData((ushort)0x1234, (ushort)0x4321, false)]
        public void ConstantTimeEquals_UInt16_ReturnsCorrectResult(ushort a, ushort b, bool expected)
        {
            Assert.Equal(expected, SecureMemoryClear.ConstantTimeEquals(a, b));
        }

        [Fact]
        public void ConstantTimeEquals_ByteSpan_EqualSpans_ReturnsTrue()
        {
            byte[] a = [1, 2, 3, 4, 5];
            byte[] b = [1, 2, 3, 4, 5];

            Assert.True(SecureMemoryClear.ConstantTimeEquals(a, b));
        }

        [Fact]
        public void ConstantTimeEquals_ByteSpan_DifferentSpans_ReturnsFalse()
        {
            byte[] a = [1, 2, 3, 4, 5];
            byte[] b = [1, 2, 3, 4, 6];

            Assert.False(SecureMemoryClear.ConstantTimeEquals(a, b));
        }

        [Fact]
        public void ConstantTimeEquals_ByteSpan_DifferentLengths_ReturnsFalse()
        {
            byte[] a = [1, 2, 3];
            byte[] b = [1, 2, 3, 4];

            Assert.False(SecureMemoryClear.ConstantTimeEquals(a, b));
        }

        [Fact]
        public void ConstantTimeEquals_ByteSpan_EmptySpans_ReturnsTrue()
        {
            Assert.True(SecureMemoryClear.ConstantTimeEquals([], []));
        }
    }
}
