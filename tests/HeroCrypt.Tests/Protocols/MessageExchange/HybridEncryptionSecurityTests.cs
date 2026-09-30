using System.Security.Cryptography;
using HeroCrypt.Operations;
using HeroCrypt.Primitives.Curve25519;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Protocols.MessageExchange;
using HeroCrypt.Security;
#if NET10_0_OR_GREATER
using HeroCrypt.Primitives.MLKem;
#endif

namespace HeroCrypt.Tests.Protocols.MessageExchange;

[Trait("Category", TestCategories.UNIT)]
[Trait("Category", TestCategories.FAST)]
public class HybridEncryptionSecurityTests(HybridEncryptionKeyFixture fixture) : IClassFixture<HybridEncryptionKeyFixture>
{
    private static readonly byte[] PrivateKey = Convert.FromHexString("77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A");

    [Theory]
    [InlineData("unknown")]
    [InlineData("")]
    [InlineData("0")]
    [InlineData(" AesGcm ")]
    [InlineData("AesGcm, AesGcm")]
    public void RsaEnvelope_RejectsNoncanonicalAlgorithm(string algorithm)
    {
        var envelope = fixture.Builder.Encrypt("payload", fixture.KeyPair.PublicKey);
        Assert.Throws<ArgumentException>(() => HybridEncryptionBuilder.DecryptToBytes(Copy(envelope, algorithm), fixture.KeyPair.PrivateKey));
    }

    [Theory]
    [InlineData(EncryptionAlgorithm.AesCcm)]
    [InlineData(EncryptionAlgorithm.X25519AesGcm)]
    [InlineData((EncryptionAlgorithm)int.MaxValue)]
    public void RsaBuilder_RejectsUnsupportedCipher(EncryptionAlgorithm algorithm)
    {
        Assert.Throws<ArgumentException>(() => new HybridEncryptionBuilder().WithEncryptionAlgorithm(algorithm));
    }

    [Fact]
    public void RsaEnvelope_RejectsImported1024BitPublicKey()
    {
        using var rsa = RSA.Create(1024);
        Assert.Throws<CryptographicException>(() => fixture.Builder.Encrypt("payload", rsa.ExportSubjectPublicKeyInfoPem()));
    }

    [Theory]
    [InlineData(1024, 32)]
    [InlineData(2048, 16)]
    [InlineData(2048, 24)]
    public void RsaEnvelope_RejectsWeakImportedPrivateKeyOrShortPayloadKey(int rsaBits, int keyBytes)
    {
        using var rsa = RSA.Create(rsaBits);
        var key = Enumerable.Range(1, keyBytes).Select(i => (byte)i).ToArray();
        using var cipher = HeroCryptBuilder.Encrypt().WithAesGcm().WithKey(key);
        var encrypted = cipher.Encrypt("payload"u8.ToArray());
        var envelope = new HybridEncryptionEnvelope
        {
            Ciphertext = encrypted.CiphertextAsBase64,
            Nonce = encrypted.NonceAsBase64,
            EncryptedKey = Convert.ToBase64String(rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256)),
            Algorithm = nameof(EncryptionAlgorithm.AesGcm)
        };
        Assert.Throws<CryptographicException>(() => HybridEncryptionBuilder.DecryptToBytes(envelope, rsa.ExportPkcs8PrivateKeyPem()));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RsaEnvelope_RejectsWrongPemLabel(bool privateKey)
    {
        var envelope = fixture.Builder.Encrypt("payload", fixture.KeyPair.PublicKey);
        if (privateKey)
        {
            var pem = fixture.KeyPair.PrivateKey.Replace("PRIVATE KEY", "CERTIFICATE", StringComparison.Ordinal);
            Assert.Throws<ArgumentException>(() => HybridEncryptionBuilder.DecryptToBytes(envelope, pem));
        }
        else
        {
            var pem = fixture.KeyPair.PublicKey.Replace("PUBLIC KEY", "CERTIFICATE", StringComparison.Ordinal);
            Assert.Throws<ArgumentException>(() => fixture.Builder.Encrypt("payload", pem));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RsaEnvelope_RejectsTrailingDer(bool privateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKey ? fixture.KeyPair.PrivateKey : fixture.KeyPair.PublicKey);
        var der = privateKey ? rsa.ExportPkcs8PrivateKey() : rsa.ExportSubjectPublicKeyInfo();
        var pem = PemEncoding.WriteString(privateKey ? "PRIVATE KEY" : "PUBLIC KEY", [.. der, 0]);
        if (privateKey)
        {
            var envelope = fixture.Builder.Encrypt("payload", fixture.KeyPair.PublicKey);
            Assert.Throws<CryptographicException>(() => HybridEncryptionBuilder.DecryptToBytes(envelope, pem));
        }
        else
            Assert.Throws<CryptographicException>(() => fixture.Builder.Encrypt("payload", pem));
    }

    [Fact]
    public void RsaEnvelope_IsTextIsOnlyAnUnauthenticatedHint()
    {
        var envelope = fixture.Builder.Encrypt("payload", fixture.KeyPair.PublicKey);
        envelope.IsText = false;
        Assert.Equal("payload", HybridEncryptionBuilder.DecryptToString(envelope, fixture.KeyPair.PrivateKey));
    }

    [Fact]
    public void RsaEnvelope_RejectsMissingAlgorithmAndAmbiguousPem()
    {
        var envelope = fixture.Builder.Encrypt("payload", fixture.KeyPair.PublicKey);
        var missing = new HybridEncryptionEnvelope { Ciphertext = envelope.Ciphertext, Nonce = envelope.Nonce, EncryptedKey = envelope.EncryptedKey };
        Assert.Throws<ArgumentException>(() => HybridEncryptionBuilder.DecryptToBytes(missing, fixture.KeyPair.PrivateKey));
        Assert.Throws<ArgumentException>(() => fixture.Builder.Encrypt("payload", fixture.KeyPair.PublicKey + fixture.KeyPair.PublicKey));
        Assert.Throws<ArgumentException>(() => HybridEncryptionBuilder.DecryptToBytes(envelope, fixture.KeyPair.PrivateKey + fixture.KeyPair.PrivateKey));
        Assert.Throws<ArgumentNullException>(() => fixture.Builder.Encrypt("payload", null!));
        Assert.Throws<ArgumentNullException>(() => HybridEncryptionBuilder.DecryptToBytes(envelope, null!));
    }

    [Theory]
    [InlineData(EncryptionAlgorithm.AesGcm)]
    [InlineData(EncryptionAlgorithm.ChaCha20Poly1305)]
    [InlineData(EncryptionAlgorithm.XChaCha20Poly1305)]
    public void RsaEnvelope_AuthenticatesCiphertextNonceWrappedKeyAndAad(EncryptionAlgorithm algorithm)
    {
        var data = "payload"u8.ToArray();
        var aad = "expected context"u8.ToArray();
        var envelope = new HybridEncryptionBuilder().WithEncryptionAlgorithm(algorithm).Encrypt(data, fixture.KeyPair.PublicKey, aad);
        Assert.Equal(data, HybridEncryptionBuilder.DecryptToBytes(envelope, fixture.KeyPair.PrivateKey));
        Assert.Equal("payload"u8.ToArray(), data);
        Assert.Equal("expected context"u8.ToArray(), aad);
        foreach (var field in new[] { "ciphertext", "nonce", "key", "aad" })
        {
            var tampered = new HybridEncryptionEnvelope
            {
                Algorithm = envelope.Algorithm,
                Ciphertext = field == "ciphertext" ? Flip(envelope.Ciphertext) : envelope.Ciphertext,
                Nonce = field == "nonce" ? Flip(envelope.Nonce) : envelope.Nonce,
                EncryptedKey = field == "key" ? Flip(envelope.EncryptedKey) : envelope.EncryptedKey,
                AssociatedData = field == "aad" ? Flip(envelope.AssociatedData!) : envelope.AssociatedData
            };
            Assert.ThrowsAny<CryptographicException>(() => HybridEncryptionBuilder.DecryptToBytes(tampered, fixture.KeyPair.PrivateKey));
        }
    }

    [Fact]
    public void RsaEnvelope_RespectsCompliancePolicy()
    {
        var builder = new HybridEncryptionBuilder().WithEncryptionAlgorithm(EncryptionAlgorithm.ChaCha20Poly1305);
        var envelope = builder.Encrypt("payload", fixture.KeyPair.PublicKey);
        using var scope = SecurityPolicy.ComplianceScope();
        Assert.Throws<SecurityPolicyException>(() => builder.Encrypt("payload", fixture.KeyPair.PublicKey));
        Assert.Throws<SecurityPolicyException>(() => HybridEncryptionBuilder.DecryptToBytes(envelope, fixture.KeyPair.PrivateKey));
        var aes = new HybridEncryptionBuilder().Encrypt("payload", fixture.KeyPair.PublicKey);
        Assert.Equal("payload", HybridEncryptionBuilder.DecryptToString(aes, fixture.KeyPair.PrivateKey));
    }

    public static IEnumerable<object[]> LowOrderPoints()
    {
        yield return [new byte[32]];
        yield return [new byte[] { 1 }.Concat(new byte[31]).ToArray()];
        foreach (var first in new byte[] { 0xec, 0xed, 0xee })
        {
            var point = Enumerable.Repeat((byte)0xff, 32).ToArray();
            point[0] = first;
            point[31] = 0x7f;
            yield return [point];
        }
        var highBitZero = new byte[32];
        highBitZero[31] = 0x80;
        yield return [highBitZero];
    }

    [Theory]
    [MemberData(nameof(LowOrderPoints))]
    public void X25519KeyAgreement_RejectsAllZeroSharedSecret(byte[] point)
    {
        Assert.Throws<CryptographicException>(() => new Curve25519Core(SecurityPolicyOptions.Testing).ComputeSharedSecret(PrivateKey, point));
    }

    [Theory]
    [InlineData(EncryptionAlgorithm.X25519AesGcm, EncryptionAlgorithm.AesGcm)]
    [InlineData(EncryptionAlgorithm.X25519ChaCha20Poly1305, EncryptionAlgorithm.ChaCha20Poly1305)]
    [InlineData(EncryptionAlgorithm.X25519XChaCha20Poly1305, EncryptionAlgorithm.XChaCha20Poly1305)]
    public void X25519Hybrid_RejectsKnownKeyCiphertextAndInvalidRecipient(EncryptionAlgorithm hybrid, EncryptionAlgorithm cipher)
    {
        var knownKey = new HkdfCore().DeriveKey(new byte[32], [], "X25519-Hybrid-Encryption"u8.ToArray(), 32, HashAlgorithmName.SHA256);
        using var encrypt = HeroCryptBuilder.Encrypt().WithAlgorithm(cipher).WithKey(knownKey);
        var result = encrypt.Encrypt("attacker chosen payload"u8.ToArray());
        using var decrypt = HeroCryptBuilder.Decrypt().WithAlgorithm(hybrid).WithKey(PrivateKey).WithNonce(result.Nonce).WithEncapsulatedKey(new byte[32]);
        Assert.Throws<CryptographicException>(() => decrypt.Decrypt(result.Ciphertext));
        using var invalidRecipient = HeroCryptBuilder.Encrypt().WithAlgorithm(hybrid).WithKey(new byte[32]);
        Assert.Throws<CryptographicException>(() => invalidRecipient.Encrypt("payload"u8.ToArray()));
    }

    [Theory]
    [InlineData(EncryptionAlgorithm.X25519AesGcm)]
    [InlineData(EncryptionAlgorithm.X25519ChaCha20Poly1305)]
    [InlineData(EncryptionAlgorithm.X25519XChaCha20Poly1305)]
    public void X25519Hybrid_RejectsInvalidRecipient(EncryptionAlgorithm algorithm)
    {
        using var encrypt = HeroCryptBuilder.Encrypt().WithAlgorithm(algorithm).WithKey(new byte[32]);
        Assert.Throws<CryptographicException>(() => encrypt.Encrypt("payload"u8.ToArray()));
    }

    [Theory]
    [InlineData(EncryptionAlgorithm.X25519AesGcm, 12)]
    [InlineData(EncryptionAlgorithm.X25519ChaCha20Poly1305, 12)]
    [InlineData(EncryptionAlgorithm.X25519XChaCha20Poly1305, 24)]
    public void X25519Hybrid_HonorsExplicitNonceAndRejectsDeterministicMode(EncryptionAlgorithm algorithm, int nonceSize)
    {
        var nonce = Enumerable.Repeat((byte)0x42, nonceSize).ToArray();
        var publicKey = new Curve25519Core().DerivePublicKey(PrivateKey);
        using var encrypt = HeroCryptBuilder.Encrypt().WithAlgorithm(algorithm).WithKey(publicKey).WithNonce(nonce);
        var result = encrypt.Encrypt("payload"u8.ToArray());
        Assert.Equal(nonce, result.Nonce);
        using var decrypt = HeroCryptBuilder.Decrypt().WithAlgorithm(algorithm).WithKey(PrivateKey).FromEncryptionResult(result);
        Assert.Equal("payload"u8.ToArray(), decrypt.Decrypt(result.Ciphertext));
        encrypt.WithNonce(new byte[1]);
        Assert.Throws<ArgumentException>(() => encrypt.Encrypt("payload"u8.ToArray()));
        encrypt.WithSecurityPolicy(SecurityPolicyOptions.Testing);
#pragma warning disable CS0618
        encrypt.WithDeterministicMode();
#pragma warning restore CS0618
        Assert.Throws<InvalidOperationException>(() => encrypt.Encrypt("payload"u8.ToArray()));
    }

    [Theory]
    [InlineData(EncryptionAlgorithm.X25519AesGcm)]
    [InlineData(EncryptionAlgorithm.X25519ChaCha20Poly1305)]
    [InlineData(EncryptionAlgorithm.X25519XChaCha20Poly1305)]
    public void X25519Hybrid_RejectsDeterministicModeEvenWithTestingPolicy(EncryptionAlgorithm algorithm)
    {
        using var encrypt = HeroCryptBuilder.Encrypt().WithAlgorithm(algorithm)
            .WithKey(new Curve25519Core().DerivePublicKey(PrivateKey)).WithSecurityPolicy(SecurityPolicyOptions.Testing);
#pragma warning disable CS0618
        encrypt.WithDeterministicMode();
#pragma warning restore CS0618
        Assert.Throws<InvalidOperationException>(() => encrypt.Encrypt("payload"u8.ToArray()));
    }

    [Fact]
    public void X25519KeyAgreement_Rfc7748VectorStillMatches()
    {
        var bob = Convert.FromHexString("DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F");
        Assert.Equal(Convert.FromHexString("4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742"), new Curve25519Core().ComputeSharedSecret(PrivateKey, bob));
        bob[31] |= 0x80;
        var encoded = bob.ToArray();
        Assert.Equal(Convert.FromHexString("4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742"), new Curve25519Core().ComputeSharedSecret(PrivateKey, bob));
        Assert.Equal(encoded, bob);
    }

    [Fact]
    public void X25519KeyAgreement_MatchesIndependentImplementation()
    {
        var core = new Curve25519Core();
        for (var i = 0; i < 16; i++)
        {
            var scalar = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"scalar-{i}"));
            var point = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"point-{i}"));
            var expected = new byte[32];
            Assert.True(Org.BouncyCastle.Math.EC.Rfc7748.X25519.CalculateAgreement(scalar, 0, point, 0, expected, 0));
            Assert.Equal(expected, core.ComputeSharedSecret(scalar, point));
            Assert.Equal(expected, core.ComputeSharedSecret(scalar, point.Select((b, index) => index == 31 ? (byte)(b ^ 0x80) : b).ToArray()));
        }
    }

    [Fact]
    public void ExistingAlgorithmNumbers_RemainStableAcrossFrameworks()
    {
        Assert.Equal(21, (int)EncryptionAlgorithm.AesCbcHmacSha256);
        Assert.Equal(22, (int)EncryptionAlgorithm.RsaPkcs1v15);
    }

#if NET10_0_OR_GREATER
    [Theory]
    [InlineData("MLKem768AesGcm")]
    [InlineData("MLKem1024AesGcm")]
    [InlineData("MLKem768ChaCha20Poly1305")]
    [InlineData("MLKem1024ChaCha20Poly1305")]
    public void MLKemHybrid_SelectedSuiteIsAvailableOnNet10(string suite)
    {
        Assert.True(Enum.TryParse<EncryptionAlgorithm>(suite, out _), $"Missing .NET 10 suite: {suite}");
    }

    [Theory]
    [InlineData(MLKemCore.SecurityLevel.MLKem512)]
    [InlineData(MLKemCore.SecurityLevel.MLKem768)]
    public void MLKemPublicKey_RejectsMismatchedDeclaredLevel(MLKemCore.SecurityLevel actual)
    {
        var core = new MLKemCore();
        Assert.SkipUnless(core.IsSupported(), "Native ML-KEM is unavailable on this platform.");
        using var keys = core.GenerateKeyPair(actual);
        Assert.Throws<CryptographicException>(() => core.ImportPublicKey(keys.PublicKeyPem, MLKemCore.SecurityLevel.MLKem1024));
    }

    [Theory]
    [InlineData("MLKem768AesGcm", MLKemCore.SecurityLevel.MLKem768)]
    [InlineData("MLKem1024AesGcm", MLKemCore.SecurityLevel.MLKem1024)]
    [InlineData("MLKem768ChaCha20Poly1305", MLKemCore.SecurityLevel.MLKem768)]
    [InlineData("MLKem1024ChaCha20Poly1305", MLKemCore.SecurityLevel.MLKem1024)]
    public void MLKemHybrid_EnforcesParameterSetAndAuthenticatesPayload(string suite, MLKemCore.SecurityLevel expected)
    {
        var core = new MLKemCore();
        Assert.SkipUnless(core.IsSupported(), "Native ML-KEM is unavailable on this platform.");
        var algorithm = Enum.Parse<EncryptionAlgorithm>(suite);
        using var matching = core.GenerateKeyPair(expected);
        var publicKey = System.Text.Encoding.UTF8.GetBytes(matching.PublicKeyPem);
        var privateKey = System.Text.Encoding.UTF8.GetBytes(matching.SecretKeyPem);
        var aad = "expected context"u8.ToArray();
        var nonce = Enumerable.Repeat((byte)0x42, 12).ToArray();
        using var encrypt = HeroCryptBuilder.Encrypt().WithAlgorithm(algorithm).WithKey(publicKey).WithAssociatedData(aad).WithNonce(nonce);
        var result = encrypt.Encrypt("payload"u8.ToArray());
        Assert.Equal(nonce, result.Nonce);
        using var decrypt = HeroCryptBuilder.Decrypt().WithAlgorithm(algorithm).WithKey(privateKey).FromEncryptionResult(result).WithAssociatedData(aad);
        Assert.Equal("payload"u8.ToArray(), decrypt.Decrypt(result.Ciphertext));
        using (var wrongRecipient = core.GenerateKeyPair(expected))
        {
            using var wrongDecrypt = HeroCryptBuilder.Decrypt().WithAlgorithm(algorithm).WithKey(System.Text.Encoding.UTF8.GetBytes(wrongRecipient.SecretKeyPem)).FromEncryptionResult(result).WithAssociatedData(aad);
            Assert.ThrowsAny<CryptographicException>(() => wrongDecrypt.Decrypt(result.Ciphertext));
        }
        result.Ciphertext[0] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => decrypt.Decrypt(result.Ciphertext));
        result.Ciphertext[0] ^= 1;
        decrypt.WithAssociatedData("wrong context"u8.ToArray());
        Assert.ThrowsAny<CryptographicException>(() => decrypt.Decrypt(result.Ciphertext));
        decrypt.WithAssociatedData(aad);
        var wrongNonce = result.Nonce.ToArray();
        wrongNonce[0] ^= 1;
        decrypt.WithNonce(wrongNonce);
        Assert.ThrowsAny<CryptographicException>(() => decrypt.Decrypt(result.Ciphertext));
        decrypt.WithNonce(result.Nonce);
        result.EncapsulatedKey![0] ^= 1;
        decrypt.WithEncapsulatedKey(result.EncapsulatedKey);
        Assert.ThrowsAny<CryptographicException>(() => decrypt.Decrypt(result.Ciphertext));

        foreach (var actual in Enum.GetValues<MLKemCore.SecurityLevel>().Where(level => level != expected))
        {
            using var mismatched = core.GenerateKeyPair(actual);
            encrypt.WithKey(System.Text.Encoding.UTF8.GetBytes(mismatched.PublicKeyPem));
            Assert.Throws<CryptographicException>(() => encrypt.Encrypt("payload"u8.ToArray()));
            // Construct a valid ciphertext for the actual key, then request the wrong suite at the recipient.
            var actualSuite = suite.EndsWith("AesGcm", StringComparison.Ordinal) ? EncryptionAlgorithm.AesGcm : EncryptionAlgorithm.ChaCha20Poly1305;
            using var encapsulated = core.Encapsulate(mismatched.PublicKeyPem);
            using var symmetric = HeroCryptBuilder.Encrypt().WithAlgorithm(actualSuite).WithKey(encapsulated.SharedSecret).WithAssociatedData(aad);
            var payload = symmetric.Encrypt("payload"u8.ToArray());
            decrypt.WithKey(System.Text.Encoding.UTF8.GetBytes(mismatched.SecretKeyPem)).WithNonce(payload.Nonce).WithEncapsulatedKey(encapsulated.Ciphertext);
            Assert.Throws<CryptographicException>(() => decrypt.Decrypt(payload.Ciphertext));
        }
        encrypt.WithKey(publicKey).WithNonce(new byte[1]);
        Assert.Throws<ArgumentException>(() => encrypt.Encrypt("payload"u8.ToArray()));
        encrypt.WithSecurityPolicy(SecurityPolicyOptions.Testing);
#pragma warning disable CS0618
        encrypt.WithDeterministicMode();
#pragma warning restore CS0618
        Assert.Throws<InvalidOperationException>(() => encrypt.Encrypt("payload"u8.ToArray()));
        CryptographicOperations.ZeroMemory(privateKey);
    }
#endif

    private static string Flip(string encoded)
    {
        var bytes = Convert.FromBase64String(encoded);
        bytes[0] ^= 1;
        return Convert.ToBase64String(bytes);
    }

    private static HybridEncryptionEnvelope Copy(HybridEncryptionEnvelope source, string algorithm) => new()
    {
        Algorithm = algorithm,
        Ciphertext = source.Ciphertext,
        Nonce = source.Nonce,
        EncryptedKey = source.EncryptedKey,
        AssociatedData = source.AssociatedData
    };
}
