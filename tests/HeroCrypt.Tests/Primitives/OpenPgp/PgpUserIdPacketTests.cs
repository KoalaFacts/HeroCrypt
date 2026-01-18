using System.Text;
using HeroCrypt.Primitives.OpenPgp;
using HeroCrypt.Tests.Infrastructure;

namespace HeroCrypt.Tests.Primitives.OpenPgp;

/// <summary>
/// Comprehensive tests for PGP User ID Packet per RFC 4880 Section 5.11.
/// </summary>
public class PgpUserIdPacketTests
{
    /// <summary>
    /// Constructor and basic property tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ConstructorTests
    {
        [Fact]
        public void Constructor_WithUserId_SetsProperty()
        {
            var userId = "Alice <alice@example.com>";

            var packet = new PgpUserIdPacket(userId);

            Assert.Equal(userId, packet.UserId);
        }

        [Fact]
        public void Constructor_WithNull_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => new PgpUserIdPacket(null!));
        }

        [Fact]
        public void Constructor_WithEmptyString_Succeeds()
        {
            var packet = new PgpUserIdPacket(string.Empty);

            Assert.Equal(string.Empty, packet.UserId);
        }
    }

    /// <summary>
    /// Factory method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class FactoryMethodTests
    {
        [Fact]
        public void Create_WithNameAndEmail_FormatsCorrectly()
        {
            var packet = PgpUserIdPacket.Create("Alice", "alice@example.com");

            Assert.Equal("Alice <alice@example.com>", packet.UserId);
        }

        [Fact]
        public void Create_WithNameCommentAndEmail_FormatsCorrectly()
        {
            var packet = PgpUserIdPacket.Create("Alice", "Work Key", "alice@example.com");

            Assert.Equal("Alice (Work Key) <alice@example.com>", packet.UserId);
        }

        [Fact]
        public void Create_WithOnlyName_FormatsCorrectly()
        {
            var packet = PgpUserIdPacket.Create("Alice", null, null);

            Assert.Equal("Alice", packet.UserId);
        }

        [Fact]
        public void Create_WithOnlyEmail_FormatsCorrectly()
        {
            var packet = PgpUserIdPacket.Create(null, null, "alice@example.com");

            Assert.Equal("<alice@example.com>", packet.UserId);
        }

        [Fact]
        public void Create_WithOnlyComment_FormatsCorrectly()
        {
            var packet = PgpUserIdPacket.Create(null, "Some Comment", null);

            Assert.Equal("(Some Comment)", packet.UserId);
        }

        [Fact]
        public void Create_WithEmptyStrings_ReturnsEmpty()
        {
            var packet = PgpUserIdPacket.Create("", "", "");

            Assert.Equal(string.Empty, packet.UserId);
        }

        [Fact]
        public void Create_TrimsWhitespace()
        {
            var packet = PgpUserIdPacket.Create("  Alice  ", "  Comment  ", "  alice@example.com  ");

            Assert.Equal("Alice (Comment) <alice@example.com>", packet.UserId);
        }

        [Fact]
        public void Create_NameWithAngleBracket_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpUserIdPacket.Create("Alice <fake>", "alice@example.com"));
        }

        [Fact]
        public void Create_NameWithParenthesis_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpUserIdPacket.Create("Alice (fake)", null, "alice@example.com"));
        }

        [Fact]
        public void Create_CommentWithClosingParen_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpUserIdPacket.Create("Alice", "Comment) injection", "alice@example.com"));
        }

        [Fact]
        public void Create_EmailWithClosingAngle_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => PgpUserIdPacket.Create("Alice", null, "alice@example.com> injection"));
        }
    }

    /// <summary>
    /// GetComponents method tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class GetComponentsTests
    {
        [Fact]
        public void GetComponents_FullFormat_ReturnsAllComponents()
        {
            var packet = new PgpUserIdPacket("Alice (Work Key) <alice@example.com>");

            var (name, comment, email) = packet.GetComponents();

            Assert.Equal("Alice", name);
            Assert.Equal("Work Key", comment);
            Assert.Equal("alice@example.com", email);
        }

        [Fact]
        public void GetComponents_NameAndEmail_ReturnsNameAndEmail()
        {
            var packet = new PgpUserIdPacket("Alice <alice@example.com>");

            var (name, comment, email) = packet.GetComponents();

            Assert.Equal("Alice", name);
            Assert.Null(comment);
            Assert.Equal("alice@example.com", email);
        }

        [Fact]
        public void GetComponents_OnlyName_ReturnsOnlyName()
        {
            var packet = new PgpUserIdPacket("Alice");

            var (name, comment, email) = packet.GetComponents();

            Assert.Equal("Alice", name);
            Assert.Null(comment);
            Assert.Null(email);
        }

        [Fact]
        public void GetComponents_OnlyEmail_ReturnsOnlyEmail()
        {
            var packet = new PgpUserIdPacket("<alice@example.com>");

            var (name, comment, email) = packet.GetComponents();

            Assert.Equal(string.Empty, name);
            Assert.Null(comment);
            Assert.Equal("alice@example.com", email);
        }

        [Fact]
        public void GetComponents_UnconventionalFormat_ReturnsFullStringAsName()
        {
            var packet = new PgpUserIdPacket("just some random text");

            var (name, comment, email) = packet.GetComponents();

            Assert.Equal("just some random text", name);
            Assert.Null(comment);
            Assert.Null(email);
        }
    }

    /// <summary>
    /// Component parsing tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ParsingTests
    {
        [Fact]
        public void GetName_FullFormat_ExtractsName()
        {
            var packet = new PgpUserIdPacket("Alice (Work) <alice@example.com>");

            Assert.Equal("Alice", packet.GetName());
        }

        [Fact]
        public void GetName_NameAndEmail_ExtractsName()
        {
            var packet = new PgpUserIdPacket("Alice <alice@example.com>");

            Assert.Equal("Alice", packet.GetName());
        }

        [Fact]
        public void GetName_OnlyName_ReturnsName()
        {
            var packet = new PgpUserIdPacket("Alice");

            Assert.Equal("Alice", packet.GetName());
        }

        [Fact]
        public void GetName_OnlyEmail_ReturnsEmpty()
        {
            var packet = new PgpUserIdPacket("<alice@example.com>");

            Assert.Equal(string.Empty, packet.GetName());
        }

        [Fact]
        public void GetComment_FullFormat_ExtractsComment()
        {
            var packet = new PgpUserIdPacket("Alice (Work Key) <alice@example.com>");

            Assert.Equal("Work Key", packet.GetComment());
        }

        [Fact]
        public void GetComment_NoComment_ReturnsNull()
        {
            var packet = new PgpUserIdPacket("Alice <alice@example.com>");

            Assert.Null(packet.GetComment());
        }

        [Fact]
        public void GetEmail_FullFormat_ExtractsEmail()
        {
            var packet = new PgpUserIdPacket("Alice (Work) <alice@example.com>");

            Assert.Equal("alice@example.com", packet.GetEmail());
        }

        [Fact]
        public void GetEmail_NameAndEmail_ExtractsEmail()
        {
            var packet = new PgpUserIdPacket("Alice <alice@example.com>");

            Assert.Equal("alice@example.com", packet.GetEmail());
        }

        [Fact]
        public void GetEmail_OnlyEmail_ExtractsEmail()
        {
            var packet = new PgpUserIdPacket("<alice@example.com>");

            Assert.Equal("alice@example.com", packet.GetEmail());
        }

        [Fact]
        public void GetEmail_NoEmail_ReturnsNull()
        {
            var packet = new PgpUserIdPacket("Alice");

            Assert.Null(packet.GetEmail());
        }

        [Fact]
        public void GetName_MultiWordName_ExtractsFullName()
        {
            var packet = new PgpUserIdPacket("Alice Marie Smith <alice@example.com>");

            Assert.Equal("Alice Marie Smith", packet.GetName());
        }
    }

    /// <summary>
    /// Round-trip serialization tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class RoundTripTests
    {
        [Fact]
        public void RoundTrip_FullFormat_PreservesContent()
        {
            var original = new PgpUserIdPacket("Alice (Work Key) <alice@example.com>");

            var encoded = original.ToArray();
            var decoded = PgpUserIdPacket.Read(encoded);

            Assert.Equal(original.UserId, decoded.UserId);
        }

        [Fact]
        public void RoundTrip_UnicodeCharacters_PreservesContent()
        {
            var original = new PgpUserIdPacket("爱丽丝 <alice@例え.jp>");

            var encoded = original.ToArray();
            var decoded = PgpUserIdPacket.Read(encoded);

            Assert.Equal(original.UserId, decoded.UserId);
        }

        [Fact]
        public void RoundTrip_EmptyUserId_PreservesContent()
        {
            var original = new PgpUserIdPacket(string.Empty);

            var encoded = original.ToArray();
            var decoded = PgpUserIdPacket.Read(encoded);

            Assert.Equal(string.Empty, decoded.UserId);
        }

        [Fact]
        public void RoundTrip_LongUserId_PreservesContent()
        {
            var longName = new string('A', 1000);
            var original = new PgpUserIdPacket($"{longName} <alice@example.com>");

            var encoded = original.ToArray();
            var decoded = PgpUserIdPacket.Read(encoded);

            Assert.Equal(original.UserId, decoded.UserId);
        }

        [Fact]
        public void RoundTrip_SpecialCharacters_PreservesContent()
        {
            var original = new PgpUserIdPacket("Alice \"The Coder\" O'Brien <alice+pgp@example.com>");

            var encoded = original.ToArray();
            var decoded = PgpUserIdPacket.Read(encoded);

            Assert.Equal(original.UserId, decoded.UserId);
        }
    }

    /// <summary>
    /// Integration tests with PgpPacketWriter/Reader.
    /// </summary>
    [Trait("Category", TestCategories.INTEGRATION)]
    [Trait("Category", TestCategories.FAST)]
    public class PacketWriterReaderIntegrationTests
    {
        [Fact]
        public void WriteTo_AndReadBack_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = new PgpUserIdPacket("Alice <alice@example.com>");
            original.WriteTo(writer);

            stream.Position = 0;
            using var reader = new PgpPacketReader(stream, leaveOpen: true);

            Assert.True(reader.ReadNextPacket(out var tag, out var body));
            Assert.Equal(PgpPacketTag.UserId, tag);

            var decoded = PgpUserIdPacket.Read(body.Span);
            Assert.Equal(original.UserId, decoded.UserId);
        }

        [Fact]
        public void WriteTo_OldFormat_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = new PgpUserIdPacket("Alice <alice@example.com>");
            original.WriteTo(writer, PgpPacketFormat.Old);

            stream.Position = 0;
            var firstByte = stream.ReadByte();
            Assert.True((firstByte & 0x40) == 0); // Old format
        }

        [Fact]
        public void WriteTo_NewFormat_Succeeds()
        {
            using var stream = new MemoryStream();
            using var writer = new PgpPacketWriter(stream, leaveOpen: true);

            var original = new PgpUserIdPacket("Alice <alice@example.com>");
            original.WriteTo(writer, PgpPacketFormat.New);

            stream.Position = 0;
            var firstByte = stream.ReadByte();
            Assert.True((firstByte & 0x40) != 0); // New format
        }
    }

    /// <summary>
    /// Encoding tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EncodingTests
    {
        [Fact]
        public void ToArray_ReturnsUtf8Bytes()
        {
            var userId = "Alice <alice@example.com>";
            var packet = new PgpUserIdPacket(userId);

            var encoded = packet.ToArray();

            Assert.Equal(Encoding.UTF8.GetBytes(userId), encoded);
        }

        [Fact]
        public void GetEncodedLength_ReturnsCorrectLength()
        {
            var userId = "Alice <alice@example.com>";
            var packet = new PgpUserIdPacket(userId);

            var length = packet.GetEncodedLength();

            Assert.Equal(Encoding.UTF8.GetByteCount(userId), length);
        }

        [Fact]
        public void GetEncodedLength_UnicodeCharacters_ReturnsCorrectLength()
        {
            var userId = "爱丽丝 <alice@example.com>";
            var packet = new PgpUserIdPacket(userId);

            var length = packet.GetEncodedLength();

            Assert.Equal(Encoding.UTF8.GetByteCount(userId), length);
        }

        [Fact]
        public void Write_WritesToSpan()
        {
            var userId = "Alice";
            var packet = new PgpUserIdPacket(userId);
            var buffer = new byte[100];

            var bytesWritten = packet.Write(buffer);

            Assert.Equal(5, bytesWritten);
            Assert.Equal(Encoding.UTF8.GetBytes(userId), buffer.AsSpan(0, bytesWritten).ToArray());
        }

        [Fact]
        public void Write_DestinationTooSmall_ThrowsArgumentException()
        {
            var packet = new PgpUserIdPacket("Alice <alice@example.com>");
            var smallBuffer = new byte[5];

            Assert.Throws<ArgumentException>(() => packet.Write(smallBuffer));
        }

        [Fact]
        public void TryWrite_SufficientSpace_ReturnsTrue()
        {
            var packet = new PgpUserIdPacket("Alice");
            var buffer = new byte[100];

            var result = packet.TryWrite(buffer, out var bytesWritten);

            Assert.True(result);
            Assert.Equal(5, bytesWritten);
            Assert.Equal(Encoding.UTF8.GetBytes("Alice"), buffer.AsSpan(0, bytesWritten).ToArray());
        }

        [Fact]
        public void TryWrite_InsufficientSpace_ReturnsFalse()
        {
            var packet = new PgpUserIdPacket("Alice <alice@example.com>");
            var smallBuffer = new byte[5];

            var result = packet.TryWrite(smallBuffer, out var bytesWritten);

            Assert.False(result);
            Assert.Equal(0, bytesWritten);
        }

        [Fact]
        public void TryWrite_ExactSpace_ReturnsTrue()
        {
            var userId = "Alice";
            var packet = new PgpUserIdPacket(userId);
            var exactBuffer = new byte[5];

            var result = packet.TryWrite(exactBuffer, out var bytesWritten);

            Assert.True(result);
            Assert.Equal(5, bytesWritten);
        }
    }

    /// <summary>
    /// Read error handling tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ReadErrorHandlingTests
    {
        [Fact]
        public void TryRead_EmptySource_Succeeds()
        {
            var result = PgpUserIdPacket.TryRead([], out var packet, out _);

            Assert.True(result);
            Assert.Equal(string.Empty, packet.UserId);
        }

        [Fact]
        public void TryRead_InvalidUtf8_HandlesWithReplacement()
        {
            // Invalid UTF-8 sequences are handled with replacement characters by .NET's decoder
            // This is acceptable per RFC - we accept the data rather than rejecting the whole key
            var invalidUtf8 = new byte[] { 0xFF, 0xFE, 0x00 };

            var result = PgpUserIdPacket.TryRead(invalidUtf8, out var packet, out _);

            // Should succeed - .NET replaces invalid bytes with replacement character
            Assert.True(result);
            Assert.Contains('\uFFFD', packet.UserId); // Unicode replacement character
        }

        [Fact]
        public void Read_InvalidUtf8_HandlesWithReplacement()
        {
            var invalidUtf8 = new byte[] { 0xFF, 0xFE };

            // Should not throw - invalid sequences are replaced
            var packet = PgpUserIdPacket.Read(invalidUtf8);
            Assert.Contains('\uFFFD', packet.UserId);
        }

        [Fact]
        public void TryRead_ExceedsMaxLength_ReturnsFalse()
        {
            var oversizedData = new byte[PgpUserIdPacket.MaxUserIdLength + 1];

            var result = PgpUserIdPacket.TryRead(oversizedData, out _, out var error);

            Assert.False(result);
            Assert.Contains("exceeds maximum", error);
        }

        [Fact]
        public void Read_ExceedsMaxLength_ThrowsArgumentException()
        {
            var oversizedData = new byte[PgpUserIdPacket.MaxUserIdLength + 1];

            Assert.Throws<ArgumentException>(() => PgpUserIdPacket.Read(oversizedData));
        }

        [Fact]
        public void TryRead_AtMaxLength_Succeeds()
        {
            var maxData = new byte[PgpUserIdPacket.MaxUserIdLength];
            Array.Fill(maxData, (byte)'A');

            var result = PgpUserIdPacket.TryRead(maxData, out var packet, out _);

            Assert.True(result);
            Assert.Equal(PgpUserIdPacket.MaxUserIdLength, packet.UserId.Length);
        }
    }

    /// <summary>
    /// Equality tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class EqualityTests
    {
        [Fact]
        public void Equals_SameUserId_ReturnsTrue()
        {
            var packet1 = new PgpUserIdPacket("Alice <alice@example.com>");
            var packet2 = new PgpUserIdPacket("Alice <alice@example.com>");

            Assert.True(packet1.Equals(packet2));
            Assert.True(packet1 == packet2);
        }

        [Fact]
        public void Equals_DifferentUserId_ReturnsFalse()
        {
            var packet1 = new PgpUserIdPacket("Alice <alice@example.com>");
            var packet2 = new PgpUserIdPacket("Bob <bob@example.com>");

            Assert.False(packet1.Equals(packet2));
            Assert.True(packet1 != packet2);
        }

        [Fact]
        public void Equals_Object_ReturnsTrue()
        {
            var packet1 = new PgpUserIdPacket("Alice <alice@example.com>");
            object packet2 = new PgpUserIdPacket("Alice <alice@example.com>");

            Assert.True(packet1.Equals(packet2));
        }

        [Fact]
        public void Equals_NullObject_ReturnsFalse()
        {
            var packet = new PgpUserIdPacket("Alice <alice@example.com>");

            Assert.False(packet.Equals(null));
        }

        [Fact]
        public void GetHashCode_SameUserId_ReturnsSameHash()
        {
            var packet1 = new PgpUserIdPacket("Alice <alice@example.com>");
            var packet2 = new PgpUserIdPacket("Alice <alice@example.com>");

            Assert.Equal(packet1.GetHashCode(), packet2.GetHashCode());
        }
    }

    /// <summary>
    /// ToString tests.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class ToStringTests
    {
        [Fact]
        public void ToString_ReturnsUserId()
        {
            var userId = "Alice <alice@example.com>";
            var packet = new PgpUserIdPacket(userId);

            Assert.Equal(userId, packet.ToString());
        }
    }

    /// <summary>
    /// Edge case tests.
    /// </summary>
    [Trait("Category", TestCategories.EDGE_CASE)]
    [Trait("Category", TestCategories.FAST)]
    public class EdgeCaseTests
    {
        [Fact]
        public void GetName_NestedParentheses_HandlesGracefully()
        {
            var packet = new PgpUserIdPacket("Alice (Comment (nested)) <alice@example.com>");

            // The regex will only capture "Comment (nested" due to the first closing paren
            var name = packet.GetName();
            Assert.NotNull(name);
        }

        [Fact]
        public void GetEmail_MultipleAngleBrackets_ReturnsNull()
        {
            // Non-standard format with multiple angle brackets doesn't match the conventional pattern
            var packet = new PgpUserIdPacket("Alice <alice@example.com> <extra>");

            // The pattern requires the email to be at the end, so this doesn't match
            var email = packet.GetEmail();
            Assert.Null(email);

            // But GetName still returns the full string as fallback
            Assert.Equal("Alice <alice@example.com> <extra>", packet.GetName());
        }

        [Fact]
        public void RoundTrip_OnlyWhitespace_PreservesContent()
        {
            var original = new PgpUserIdPacket("   ");

            var encoded = original.ToArray();
            var decoded = PgpUserIdPacket.Read(encoded);

            Assert.Equal("   ", decoded.UserId);
        }

        [Fact]
        public void RoundTrip_NewlinesInUserId_PreservesContent()
        {
            var original = new PgpUserIdPacket("Alice\n<alice@example.com>");

            var encoded = original.ToArray();
            var decoded = PgpUserIdPacket.Read(encoded);

            Assert.Equal(original.UserId, decoded.UserId);
        }

        [Fact]
        public void Create_AllNulls_ReturnsEmptyUserId()
        {
            var packet = PgpUserIdPacket.Create(null, null, null);

            Assert.Equal(string.Empty, packet.UserId);
        }

        [Fact]
        public void GetComponents_UnconventionalFormat_HandlesGracefully()
        {
            var packet = new PgpUserIdPacket("just some random text without email or comment");

            var name = packet.GetName();
            var comment = packet.GetComment();
            var email = packet.GetEmail();

            Assert.Equal("just some random text without email or comment", name);
            Assert.Null(comment);
            Assert.Null(email);
        }
    }

    /// <summary>
    /// Real-world User ID examples.
    /// </summary>
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.FAST)]
    public class RealWorldExamplesTests
    {
        [Theory]
        [InlineData("Werner Koch <wk@gnupg.org>", "Werner Koch", null, "wk@gnupg.org")]
        [InlineData("Linus Torvalds <torvalds@linux-foundation.org>", "Linus Torvalds", null, "torvalds@linux-foundation.org")]
        [InlineData("GitHub (web-flow commit signing) <noreply@github.com>", "GitHub", "web-flow commit signing", "noreply@github.com")]
        [InlineData("<anonymous@example.com>", "", null, "anonymous@example.com")]
        [InlineData("John Doe", "John Doe", null, null)]
        public void Parse_RealWorldUserIds_ExtractsCorrectComponents(
            string userId, string expectedName, string? expectedComment, string? expectedEmail)
        {
            var packet = new PgpUserIdPacket(userId);

            Assert.Equal(expectedName, packet.GetName());
            Assert.Equal(expectedComment, packet.GetComment());
            Assert.Equal(expectedEmail, packet.GetEmail());
        }

        [Fact]
        public void RoundTrip_GpgGeneratedUserId_Succeeds()
        {
            // Typical GPG-generated User ID
            var original = new PgpUserIdPacket("Test User (Test Key) <test@example.com>");

            var encoded = original.ToArray();
            var decoded = PgpUserIdPacket.Read(encoded);

            Assert.Equal(original.UserId, decoded.UserId);
            Assert.Equal("Test User", decoded.GetName());
            Assert.Equal("Test Key", decoded.GetComment());
            Assert.Equal("test@example.com", decoded.GetEmail());
        }
    }
}
