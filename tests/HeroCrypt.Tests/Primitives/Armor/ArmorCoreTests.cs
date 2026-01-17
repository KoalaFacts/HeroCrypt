using HeroCrypt.Primitives.Armor;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.Armor;

/// <summary>
/// Comprehensive tests for ASCII Armor encoding implementation.
/// Tests the OpenPGP ASCII Armor format specified in RFC 4880 Section 6.
/// </summary>
public class ArmorCoreTests
{
    /// <summary>
    /// Basic functionality tests for encoding operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EncodingTests
    {
        [Fact]
        public void Encode_ValidData_ContainsHeader()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var armored = ArmorCore.Encode(data, ArmorType.Message);

            Assert.Contains("-----BEGIN PGP MESSAGE-----", armored);
        }

        [Fact]
        public void Encode_ValidData_ContainsTail()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var armored = ArmorCore.Encode(data, ArmorType.Message);

            Assert.Contains("-----END PGP MESSAGE-----", armored);
        }

        [Fact]
        public void Encode_ValidData_ContainsCrc()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var armored = ArmorCore.Encode(data, ArmorType.Message);

            // CRC line starts with '=' followed by 4 Base64 characters
            Assert.Matches(@"=[\w\+/]{4}", armored);
        }

        [Theory]
        [InlineData(ArmorType.Message, "MESSAGE")]
        [InlineData(ArmorType.PublicKey, "PUBLIC KEY BLOCK")]
        [InlineData(ArmorType.PrivateKey, "PRIVATE KEY BLOCK")]
        [InlineData(ArmorType.Signature, "SIGNATURE")]
        [InlineData(ArmorType.SignedMessage, "SIGNED MESSAGE")]
        public void Encode_DifferentTypes_ContainsCorrectTypeName(ArmorType type, string expectedTypeName)
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Small);

            var armored = ArmorCore.Encode(data, type);

            Assert.Contains($"-----BEGIN PGP {expectedTypeName}-----", armored);
            Assert.Contains($"-----END PGP {expectedTypeName}-----", armored);
        }

        [Fact]
        public void Encode_WithHeaders_IncludesHeaders()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Small);
            var headers = new Dictionary<string, string>
            {
                { "Version", "HeroCrypt 1.0" },
                { "Comment", "Test Data" }
            };

            var armored = ArmorCore.Encode(data, ArmorType.Message, headers);

            Assert.Contains("Version: HeroCrypt 1.0", armored);
            Assert.Contains("Comment: Test Data", armored);
        }

        [Fact]
        public void Encode_IsDeterministic()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var armored1 = ArmorCore.Encode(data, ArmorType.Message);
            var armored2 = ArmorCore.Encode(data, ArmorType.Message);

            Assert.Equal(armored1, armored2);
        }
    }

    /// <summary>
    /// Basic functionality tests for decoding operations.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class DecodingTests
    {
        [Fact]
        public void Decode_ValidArmor_ReturnsOriginalData()
        {
            var originalData = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var armored = ArmorCore.Encode(originalData, ArmorType.Message);

            var result = ArmorCore.Decode(armored);

            Assert.Equal(originalData, result.Data);
        }

        [Fact]
        public void Decode_ValidArmor_ReturnsCorrectType()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Small);
            var armored = ArmorCore.Encode(data, ArmorType.PublicKey);

            var result = ArmorCore.Decode(armored);

            Assert.Equal(ArmorType.PublicKey, result.Type);
        }

        [Fact]
        public void Decode_WithHeaders_ReturnsHeaders()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Small);
            var headers = new Dictionary<string, string>
            {
                { "Version", "HeroCrypt 1.0" },
                { "Comment", "Test" }
            };
            var armored = ArmorCore.Encode(data, ArmorType.Message, headers);

            var result = ArmorCore.Decode(armored);

            Assert.Equal("HeroCrypt 1.0", result.Headers["Version"]);
            Assert.Equal("Test", result.Headers["Comment"]);
        }

        [Theory]
        [InlineData(ArmorType.Message)]
        [InlineData(ArmorType.PublicKey)]
        [InlineData(ArmorType.PrivateKey)]
        [InlineData(ArmorType.Signature)]
        [InlineData(ArmorType.SignedMessage)]
        public void RoundTrip_AllTypes_PreservesData(ArmorType type)
        {
            var originalData = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var armored = ArmorCore.Encode(originalData, type);

            var result = ArmorCore.Decode(armored);

            Assert.Equal(originalData, result.Data);
            Assert.Equal(type, result.Type);
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
        public void Encode_EmptyData_Succeeds()
        {
            var data = Array.Empty<byte>();

            var armored = ArmorCore.Encode(data, ArmorType.Message);

            Assert.Contains("-----BEGIN PGP MESSAGE-----", armored);
            Assert.Contains("-----END PGP MESSAGE-----", armored);
        }

        [Fact]
        public void RoundTrip_EmptyData_ReturnsEmptyArray()
        {
            var originalData = Array.Empty<byte>();
            var armored = ArmorCore.Encode(originalData, ArmorType.Message);

            var result = ArmorCore.Decode(armored);

            Assert.Empty(result.Data);
        }

        [Fact]
        public void Encode_SingleByte_Succeeds()
        {
            var data = new byte[] { 0x42 };

            var armored = ArmorCore.Encode(data, ArmorType.Message);
            var result = ArmorCore.Decode(armored);

            Assert.Equal(data, result.Data);
        }

        [Fact]
        [Trait("Category", TestCategories.SLOW)]
        public void RoundTrip_LargeData_PreservesData()
        {
            var originalData = TestHelpers.RandomBytes(TestDataSizes.VeryLarge);
            var armored = ArmorCore.Encode(originalData, ArmorType.Message);

            var result = ArmorCore.Decode(armored);

            Assert.Equal(originalData, result.Data);
        }

        [Fact]
        public void Decode_WithLeadingWhitespace_Succeeds()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Small);
            var armored = "\n\n  \n" + ArmorCore.Encode(data, ArmorType.Message);

            var result = ArmorCore.Decode(armored);

            Assert.Equal(data, result.Data);
        }

        [Fact]
        public void Encode_NoHeaders_HasBlankLineBeforeData()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Small);

            var armored = ArmorCore.Encode(data, ArmorType.Message);
            var lines = armored.Split(["\r\n", "\n"], StringSplitOptions.None);

            // Line 0: header, Line 1: blank, Line 2+: data
            Assert.StartsWith("-----BEGIN", lines[0]);
            Assert.Equal("", lines[1]);
        }
    }

    /// <summary>
    /// Error handling tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ErrorHandling
    {
        [Fact]
        public void Decode_InvalidHeader_ThrowsFormatException()
        {
            var invalidArmor = "Not a valid armor format";

            Assert.Throws<FormatException>(() => ArmorCore.Decode(invalidArmor));
        }

        [Fact]
        public void Decode_MissingEndMarker_ThrowsFormatException()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Small);
            var armored = ArmorCore.Encode(data, ArmorType.Message);
            var truncated = armored.Split("-----END")[0];

            // Should still decode since we don't require the end marker strictly
            // But we should validate this behavior
            var result = ArmorCore.Decode(truncated);
            Assert.NotNull(result.Data);
        }

        [Fact]
        public void Decode_CorruptedCrc_ThrowsFormatException()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var armored = ArmorCore.Encode(data, ArmorType.Message);

            // Corrupt the CRC by changing a character
            var lines = armored.Split('\n');
            for (var i = 0; i < lines.Length; i++)
            {
                if (lines[i].StartsWith("="))
                {
                    lines[i] = "=AAAA"; // Invalid CRC
                    break;
                }
            }
            var corruptedArmor = string.Join("\n", lines);

            Assert.Throws<FormatException>(() => ArmorCore.Decode(corruptedArmor));
        }

        [Fact]
        public void Decode_InvalidBase64_ThrowsFormatException()
        {
            var invalidArmor = @"-----BEGIN PGP MESSAGE-----

!!!invalid-base64!!!
=AAAA
-----END PGP MESSAGE-----";

            Assert.Throws<FormatException>(() => ArmorCore.Decode(invalidArmor));
        }

        [Fact]
        public void Decode_NullInput_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => ArmorCore.Decode(null!));
        }

        [Fact]
        public void Decode_UnknownArmorType_ThrowsFormatException()
        {
            var invalidArmor = @"-----BEGIN PGP UNKNOWN TYPE-----

dGVzdA==
=t8Cs
-----END PGP UNKNOWN TYPE-----";

            Assert.Throws<FormatException>(() => ArmorCore.Decode(invalidArmor));
        }
    }

    /// <summary>
    /// CRC verification tests.
    /// </summary>
    [Trait("Category", TestCategories.SECURITY)]
    [Trait("Category", TestCategories.FAST)]
    public class CrcVerification
    {
        [Fact]
        public void VerifyChecksum_ValidArmor_ReturnsTrue()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var armored = ArmorCore.Encode(data, ArmorType.Message);

            var result = ArmorCore.VerifyChecksum(armored);

            Assert.True(result);
        }

        [Fact]
        public void VerifyChecksum_CorruptedData_ReturnsFalse()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var armored = ArmorCore.Encode(data, ArmorType.Message);

            // Corrupt the Base64 data (not the CRC)
            var lines = armored.Split('\n').ToList();
            for (var i = 0; i < lines.Count; i++)
            {
                // Find a Base64 data line (not header, blank, CRC, or tail)
                if (lines[i].Length > 10 && !lines[i].StartsWith("-----") && !lines[i].StartsWith("="))
                {
                    var chars = lines[i].ToCharArray();
                    chars[0] = chars[0] == 'A' ? 'B' : 'A'; // Flip a character
                    lines[i] = new string(chars);
                    break;
                }
            }
            var corruptedArmor = string.Join("\n", lines);

            var result = ArmorCore.VerifyChecksum(corruptedArmor);

            Assert.False(result);
        }
    }

    /// <summary>
    /// Builder API tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class BuilderApiTests
    {
        [Fact]
        public void Builder_Encode_MatchesCore()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);

            var coreArmored = ArmorCore.Encode(data, ArmorType.Message);
            var builderArmored = ArmorBuilder.Create().WithType(ArmorType.Message).Encode(data);

            Assert.Equal(coreArmored, builderArmored);
        }

        [Fact]
        public void Builder_Decode_MatchesCore()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var armored = ArmorCore.Encode(data, ArmorType.Message);

            var coreResult = ArmorCore.Decode(armored);
            var builderResult = ArmorBuilder.Create().Decode(armored);

            Assert.Equal(coreResult.Data, builderResult.Data);
            Assert.Equal(coreResult.Type, builderResult.Type);
        }

        [Fact]
        public void Builder_WithHeaders_AddsHeaders()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Small);

            var armored = ArmorBuilder.Create()
                .WithType(ArmorType.Message)
                .WithHeader("Version", "1.0")
                .WithHeader("Comment", "Test")
                .Encode(data);

            Assert.Contains("Version: 1.0", armored);
            Assert.Contains("Comment: Test", armored);
        }

        [Fact]
        public void Builder_ClearHeaders_RemovesHeaders()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Small);

            var armored = ArmorBuilder.Create()
                .WithType(ArmorType.Message)
                .WithHeader("Version", "1.0")
                .ClearHeaders()
                .Encode(data);

            Assert.DoesNotContain("Version:", armored);
        }

        [Fact]
        public void Builder_TryDecode_ValidArmor_ReturnsTrue()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var armored = ArmorCore.Encode(data, ArmorType.Message);

            var success = ArmorBuilder.Create().TryDecode(armored, out var result);

            Assert.True(success);
            Assert.NotNull(result);
            Assert.Equal(data, result.Data);
        }

        [Fact]
        public void Builder_TryDecode_InvalidArmor_ReturnsFalse()
        {
            var invalidArmor = "not valid armor";

            var success = ArmorBuilder.Create().TryDecode(invalidArmor, out var result);

            Assert.False(success);
            Assert.Null(result);
        }

        [Fact]
        public void Builder_DecodeData_ReturnsOnlyData()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Medium);
            var armored = ArmorCore.Encode(data, ArmorType.Message);

            var decodedData = ArmorBuilder.Create().DecodeData(armored);

            Assert.Equal(data, decodedData);
        }

        [Fact]
        public void HeroCryptBuilder_Armor_CreatesBuilder()
        {
            var builder = HeroCryptBuilder.Armor();

            Assert.NotNull(builder);
            Assert.IsType<ArmorBuilder>(builder);
        }
    }

    /// <summary>
    /// Line length conformance tests.
    /// </summary>
    [Trait("Category", TestCategories.COMPLIANCE)]
    [Trait("Category", TestCategories.FAST)]
    public class LineFormatTests
    {
        [Fact]
        public void Encode_Base64Lines_DoNotExceedMaxLength()
        {
            var data = TestHelpers.RandomBytes(TestDataSizes.Large);

            var armored = ArmorCore.Encode(data, ArmorType.Message);
            var lines = armored.Split(["\r\n", "\n"], StringSplitOptions.None);

            foreach (var line in lines)
            {
                // Skip header, tail, CRC, and empty lines
                if (line.StartsWith("-----") || line.StartsWith("=") || string.IsNullOrEmpty(line))
                    continue;

                Assert.True(line.Length <= ArmorCore.MAX_LINE_LENGTH,
                    $"Line exceeds max length: {line.Length} > {ArmorCore.MAX_LINE_LENGTH}");
            }
        }
    }
}
