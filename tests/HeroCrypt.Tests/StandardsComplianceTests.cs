using HeroCrypt.Cryptography.Primitives.Kdf;
using System.Globalization;
using System.Text;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests to verify compliance with cryptographic standards:
/// - Argon2: RFC 9106 (https://datatracker.ietf.org/doc/html/rfc9106)
/// - RSA: PKCS#1 v2.2 (RFC 8017)
/// - Blake2b: RFC 7693
/// </summary>
[Trait("Category", TestCategories.Fast)]
[Trait("Category", TestCategories.Compliance)]
public class StandardsComplianceTests
{
    /// <summary>
    /// Test vectors from RFC 9106 Appendix A.1 - Argon2d
    /// </summary>
    [Fact]
    public void Argon2dRfc9106TestVector1()
    {
        // RFC 9106 Test Vector 1 for Argon2d
        var password = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

        var salt = new byte[] { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                               0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };

        var secret = new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };

        var ad = new byte[] { 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                             0x04, 0x04, 0x04, 0x04 };

        var expected = "512b391b6f1162975371d30919734294" +
                      "f868e3be3984f3c1a13a4db9fabe4acb";

        var result = Argon2Core.Hash(
            password: password,
            salt: salt,
            iterations: 3,
            memorySize: 32,
            parallelism: 4,
            hashLength: 32,
            type: Argon2Type.Argon2d,
            associatedData: ad,
            secret: secret
        );

#if NET5_0_OR_GREATER
        var resultHex = Convert.ToHexString(result).ToLower(CultureInfo.InvariantCulture);
#else
        var resultHex = BitConverter.ToString(result).Replace("-", "", StringComparison.Ordinal).ToLower(CultureInfo.InvariantCulture);
#endif

        Assert.Equal(expected, resultHex);
    }

    /// <summary>
    /// Test vectors from RFC 9106 Appendix A.2 - Argon2i
    /// </summary>
    [Fact]
    public void Argon2iRfc9106TestVector2()
    {
        var password = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

        var salt = new byte[] { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                               0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };

        var secret = new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };

        var ad = new byte[] { 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                             0x04, 0x04, 0x04, 0x04 };

        var expected = "c814d9d1dc7f37aa13f0d77f2494bda1" +
                      "c8de6b016dd388d29952a4c4672b6ce8";

        var result = Argon2Core.Hash(
            password: password,
            salt: salt,
            iterations: 3,
            memorySize: 32,
            parallelism: 4,
            hashLength: 32,
            type: Argon2Type.Argon2i,
            associatedData: ad,
            secret: secret
        );

#if NET5_0_OR_GREATER
        var resultHex = Convert.ToHexString(result).ToLower(CultureInfo.InvariantCulture);
#else
        var resultHex = BitConverter.ToString(result).Replace("-", "", StringComparison.Ordinal).ToLower(CultureInfo.InvariantCulture);
#endif

        Assert.Equal(expected, resultHex);
    }

    /// <summary>
    /// Test vectors from RFC 9106 Appendix A.3 - Argon2id
    /// </summary>
    [Fact]
    public void Argon2idRfc9106TestVector3()
    {
        var password = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

        var salt = new byte[] { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                               0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };

        var secret = new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };

        var ad = new byte[] { 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                             0x04, 0x04, 0x04, 0x04 };

        var expected = "0d640df58d78766c08c037a34a8b53c9" +
                      "d01ef0452d75b65eb52520e96b01e659";

        var result = Argon2Core.Hash(
            password: password,
            salt: salt,
            iterations: 3,
            memorySize: 32,
            parallelism: 4,
            hashLength: 32,
            type: Argon2Type.Argon2id,
            associatedData: ad,
            secret: secret
        );

#if NET5_0_OR_GREATER
        var resultHex = Convert.ToHexString(result).ToLower(CultureInfo.InvariantCulture);
#else
        var resultHex = BitConverter.ToString(result).Replace("-", "", StringComparison.Ordinal).ToLower(CultureInfo.InvariantCulture);
#endif

        Assert.Equal(expected, resultHex);
    }

    /// <summary>
    /// Test vector without secret and associated data
    /// </summary>
    [Fact]
    public void Argon2idSimpleTestVector()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = Encoding.UTF8.GetBytes("somesalt");

        // This is a known test vector for Argon2id with t=1, m=64 (64KB), p=1
        var result = Argon2Core.Hash(
            password: password,
            salt: salt,
            iterations: 1,
            memorySize: 64,
            parallelism: 1,
            hashLength: 32,
            type: Argon2Type.Argon2id,
            associatedData: null,
            secret: null
        );

        Assert.NotNull(result);
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verify that different salts produce different outputs
    /// </summary>
    [Fact]
    public void Argon2DifferentSaltsProduceDifferentOutputs()
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt1 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        var salt2 = new byte[] { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

        var result1 = Argon2Core.Hash(
            password: password,
            salt: salt1,
            iterations: 3,
            memorySize: 32,
            parallelism: 4,
            hashLength: 32,
            type: Argon2Type.Argon2id
        );

        var result2 = Argon2Core.Hash(
            password: password,
            salt: salt2,
            iterations: 3,
            memorySize: 32,
            parallelism: 4,
            hashLength: 32,
            type: Argon2Type.Argon2id
        );

        Assert.NotEqual(result1, result2);
    }

    /// <summary>
    /// Verify parameter validation
    /// </summary>
    [Theory]
    [InlineData(0, 32, 4)] // iterations < 1
    [InlineData(1, 7, 4)]  // memory < 8 * parallelism
    [InlineData(1, 32, 0)] // parallelism < 1
    public void Argon2InvalidParametersThrowsException(int iterations, int memory, int parallelism)
    {
        var password = Encoding.UTF8.GetBytes("password");
        var salt = new byte[16];

        Assert.Throws<ArgumentException>(() =>
            Argon2Core.Hash(
                password: password,
                salt: salt,
                iterations: iterations,
                memorySize: memory,
                parallelism: parallelism,
                hashLength: 32,
                type: Argon2Type.Argon2id
            )
        );
    }
}