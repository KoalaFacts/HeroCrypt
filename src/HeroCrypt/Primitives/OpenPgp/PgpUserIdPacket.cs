using System.Text;
using System.Text.RegularExpressions;

namespace HeroCrypt.Primitives.OpenPgp;

/// <summary>
/// Represents a User ID Packet (Tag 13) as defined in RFC 4880 Section 5.11.
/// </summary>
/// <remarks>
/// <para>
/// A User ID packet consists of UTF-8 text that is intended to represent
/// the name and email address of the key holder. By convention, it includes
/// an RFC 2822 mail name-addr, but there are no restrictions on its content.
/// </para>
/// <para>
/// <b>Common formats:</b>
/// <list type="bullet">
///   <item><c>Name (Comment) &lt;email@example.com&gt;</c></item>
///   <item><c>Name &lt;email@example.com&gt;</c></item>
///   <item><c>&lt;email@example.com&gt;</c></item>
///   <item><c>Name</c></item>
/// </list>
/// </para>
/// <para>
/// <b>Wire format:</b> The packet body is simply a UTF-8 encoded string.
/// The packet length in the header specifies the length of the User ID.
/// </para>
/// </remarks>
public readonly struct PgpUserIdPacket : IEquatable<PgpUserIdPacket>
{
    /// <summary>
    /// Maximum allowed User ID length in bytes (64 KB).
    /// </summary>
    public const int MaxUserIdLength = 65536;

    // Pattern to parse conventional user ID format: Name (Comment) <email>
    // The pattern matches:
    //   - name: any characters except ( and < at the start (lazy match)
    //   - comment: text within parentheses (optional)
    //   - email: text within angle brackets (optional)
    // Limitations:
    //   - Nested parentheses in comments are not fully supported
    //   - Multiple angle bracket pairs will not match (returns full string as name fallback)
    // Timeout protects against ReDoS attacks with pathological input.
    private static readonly Regex UserIdPattern = new(
        @"^(?<name>[^(<]*?)\s*(?:\((?<comment>[^)]*)\)\s*)?(?:<(?<email>[^>]+)>)?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    /// <summary>
    /// Gets the raw User ID string.
    /// </summary>
    public string UserId { get; }

    /// <summary>
    /// Initializes a new User ID packet with the specified ID string.
    /// </summary>
    /// <param name="userId">The user ID string.</param>
    /// <exception cref="ArgumentNullException">If userId is null.</exception>
    public PgpUserIdPacket(string userId)
    {
        UserId = userId ?? throw new ArgumentNullException(nameof(userId));
    }

    /// <summary>
    /// Creates a User ID packet from name and email components.
    /// </summary>
    /// <param name="name">The user's name.</param>
    /// <param name="email">The user's email address.</param>
    /// <returns>A new User ID packet.</returns>
    /// <exception cref="ArgumentException">If name or email contains reserved characters.</exception>
    public static PgpUserIdPacket Create(string name, string email)
    {
        return Create(name, null, email);
    }

    /// <summary>
    /// Creates a User ID packet from name, comment, and email components.
    /// </summary>
    /// <param name="name">The user's name (can be empty).</param>
    /// <param name="comment">Optional comment (can be null or empty).</param>
    /// <param name="email">The user's email address (can be empty).</param>
    /// <returns>A new User ID packet.</returns>
    /// <exception cref="ArgumentException">If any component contains reserved characters that would create ambiguous User IDs.</exception>
    public static PgpUserIdPacket Create(string? name, string? comment, string? email)
    {
        // Validate inputs to prevent ambiguous User ID construction
        if (name != null && ContainsAny(name, '<', '>', '(', ')'))
        {
            throw new ArgumentException("Name cannot contain <, >, (, or ) characters.", nameof(name));
        }

        if (comment != null && comment.Contains(')'))
        {
            throw new ArgumentException("Comment cannot contain ) character.", nameof(comment));
        }

        if (email != null && email.Contains('>'))
        {
            throw new ArgumentException("Email cannot contain > character.", nameof(email));
        }

        var parts = new List<string>();

        if (!string.IsNullOrWhiteSpace(name))
        {
            parts.Add(name!.Trim());
        }

        if (!string.IsNullOrWhiteSpace(comment))
        {
            parts.Add($"({comment!.Trim()})");
        }

        if (!string.IsNullOrWhiteSpace(email))
        {
            parts.Add($"<{email!.Trim()}>");
        }

        var userId = string.Join(" ", parts);
        return new PgpUserIdPacket(userId);
    }

    /// <summary>
    /// Extracts all components (name, comment, email) from the User ID in a single operation.
    /// </summary>
    /// <returns>A tuple containing the name, comment (null if not present), and email (null if not present).</returns>
    /// <remarks>
    /// This method is more efficient than calling <see cref="GetName"/>, <see cref="GetComment"/>,
    /// and <see cref="GetEmail"/> separately when you need all components.
    /// </remarks>
    public (string Name, string? Comment, string? Email) GetComponents()
    {
        try
        {
            var match = UserIdPattern.Match(UserId);
            if (!match.Success)
            {
                return (UserId.Trim(), null, null);
            }

            var name = match.Groups["name"].Value.Trim();

            string? comment = null;
            if (match.Groups["comment"].Success)
            {
                var commentValue = match.Groups["comment"].Value.Trim();
                if (!string.IsNullOrEmpty(commentValue))
                {
                    comment = commentValue;
                }
            }

            string? email = null;
            if (match.Groups["email"].Success)
            {
                var emailValue = match.Groups["email"].Value.Trim();
                if (!string.IsNullOrEmpty(emailValue))
                {
                    email = emailValue;
                }
            }

            return (name, comment, email);
        }
        catch (RegexMatchTimeoutException)
        {
            // Pathological input - return full string as name
            return (UserId.Trim(), null, null);
        }
    }

    /// <summary>
    /// Attempts to parse the name from the User ID string.
    /// </summary>
    /// <returns>The name portion, or the full User ID if parsing fails.</returns>
    public string GetName()
    {
        var (name, _, _) = GetComponents();
        return name;
    }

    /// <summary>
    /// Attempts to parse the comment from the User ID string.
    /// </summary>
    /// <returns>The comment portion (without parentheses), or null if not found.</returns>
    public string? GetComment()
    {
        var (_, comment, _) = GetComponents();
        return comment;
    }

    /// <summary>
    /// Attempts to parse the email address from the User ID string.
    /// </summary>
    /// <returns>The email address (without angle brackets), or null if not found.</returns>
    public string? GetEmail()
    {
        var (_, _, email) = GetComponents();
        return email;
    }

    /// <summary>
    /// Reads a User ID packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <returns>The parsed User ID packet.</returns>
    /// <exception cref="ArgumentException">If the source exceeds the maximum length.</exception>
    public static PgpUserIdPacket Read(ReadOnlySpan<byte> source)
    {
        if (!TryRead(source, out var packet, out var error))
        {
            throw new ArgumentException(error, nameof(source));
        }

        return packet;
    }

    /// <summary>
    /// Tries to read a User ID packet from a span.
    /// </summary>
    /// <param name="source">The source span containing packet body data.</param>
    /// <param name="packet">The parsed packet if successful.</param>
    /// <param name="error">Error message if parsing failed.</param>
    /// <returns>True if the packet was parsed successfully.</returns>
    public static bool TryRead(ReadOnlySpan<byte> source, out PgpUserIdPacket packet, out string error)
    {
        packet = default;
        error = string.Empty;

        if (source.Length > MaxUserIdLength)
        {
            error = $"User ID length {source.Length} exceeds maximum allowed size of {MaxUserIdLength} bytes.";
            return false;
        }

        if (source.IsEmpty)
        {
            // Empty User ID is technically valid per RFC
            packet = new PgpUserIdPacket(string.Empty);
            return true;
        }

        // Note: Encoding.UTF8 uses replacement fallback by default, replacing invalid
        // sequences with U+FFFD. This is intentional - we accept malformed data rather
        // than rejecting entire keys due to encoding issues.
        var userId = Encoding.UTF8.GetString(source);
        packet = new PgpUserIdPacket(userId);
        return true;
    }

    /// <summary>
    /// Gets the encoded length of this packet's body.
    /// </summary>
    /// <returns>The number of bytes needed to encode the packet body.</returns>
    public int GetEncodedLength()
    {
        return Encoding.UTF8.GetByteCount(UserId);
    }

    /// <summary>
    /// Writes the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <returns>The number of bytes written.</returns>
    /// <exception cref="ArgumentException">If the destination is too small.</exception>
    public int Write(Span<byte> destination)
    {
        int encodedLength = GetEncodedLength();
        if (destination.Length < encodedLength)
        {
            throw new ArgumentException($"Destination too small. Need {encodedLength} bytes.", nameof(destination));
        }

        return Encoding.UTF8.GetBytes(UserId, destination);
    }

    /// <summary>
    /// Tries to write the packet body to a span.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    /// <param name="bytesWritten">The number of bytes written if successful.</param>
    /// <returns>True if the write was successful; false if the destination is too small.</returns>
    public bool TryWrite(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        int encodedLength = GetEncodedLength();
        if (destination.Length < encodedLength)
        {
            return false;
        }

        bytesWritten = Encoding.UTF8.GetBytes(UserId, destination);
        return true;
    }

    /// <summary>
    /// Writes the packet body to a byte array.
    /// </summary>
    /// <returns>The encoded packet body.</returns>
    public byte[] ToArray()
    {
        return Encoding.UTF8.GetBytes(UserId);
    }

    /// <summary>
    /// Writes the complete packet (including header) using the specified writer.
    /// </summary>
    /// <param name="writer">The packet writer.</param>
    /// <param name="format">The packet format to use (default: New).</param>
    public void WriteTo(PgpPacketWriter writer, PgpPacketFormat format = PgpPacketFormat.New)
    {
        byte[] body = ToArray();
        writer.WritePacket(PgpPacketTag.UserId, body, format);
    }

    /// <summary>
    /// Returns the User ID string.
    /// </summary>
    public override string ToString() => UserId;

    /// <inheritdoc />
    public bool Equals(PgpUserIdPacket other) => UserId == other.UserId;

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is PgpUserIdPacket other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => UserId.GetHashCode();

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(PgpUserIdPacket left, PgpUserIdPacket right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(PgpUserIdPacket left, PgpUserIdPacket right) => !left.Equals(right);

    private static bool ContainsAny(string value, params char[] chars)
    {
        foreach (var c in chars)
        {
            if (value.Contains(c))
            {
                return true;
            }
        }

        return false;
    }
}
