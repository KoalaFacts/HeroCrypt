using HeroCrypt.Polyfills;

namespace HeroCrypt.Primitives.Crc24;

/// <summary>
/// Fluent builder for CRC24 checksum operations.
/// Implements the OpenPGP CRC24 algorithm specified in RFC 4880 Section 6.1.
/// </summary>
/// <remarks>
/// CRC24 is used in OpenPGP ASCII Armor to detect transmission errors.
/// It is NOT a cryptographic checksum and should not be used for security purposes.
/// </remarks>
/// <example>
/// <code>
/// // Compute CRC24
/// var crc = Crc24Builder.Create()
///     .Compute(data);
///
/// // Compute and get as bytes
/// var crcBytes = Crc24Builder.Create()
///     .ComputeToBytes(data);
///
/// // Verify CRC24
/// var isValid = Crc24Builder.Create()
///     .Verify(expectedCrc, data);
/// </code>
/// </example>
public sealed class Crc24Builder
{
    private Crc24Builder() { }

    /// <summary>
    /// Creates a new CRC24 builder instance.
    /// </summary>
    /// <returns>A new builder instance.</returns>
    public static Crc24Builder Create() => new();

    /// <summary>
    /// Computes the CRC24 checksum for the given data.
    /// </summary>
    /// <param name="data">The data to compute the checksum for.</param>
    /// <returns>The 24-bit CRC value as a 32-bit unsigned integer (upper 8 bits are zero).</returns>
    /// <exception cref="ArgumentNullException">If data is null.</exception>
    public uint Compute(byte[] data)
    {
        ArgumentHelper.ThrowIfNull(data);
        return Crc24Core.Compute(data);
    }

    /// <summary>
    /// Computes the CRC24 checksum for the given data.
    /// </summary>
    /// <param name="data">The data to compute the checksum for.</param>
    /// <returns>The 24-bit CRC value as a 32-bit unsigned integer (upper 8 bits are zero).</returns>
    public uint Compute(ReadOnlySpan<byte> data)
    {
        return Crc24Core.Compute(data);
    }

    /// <summary>
    /// Computes the CRC24 checksum and writes it to the output buffer.
    /// </summary>
    /// <param name="output">The output buffer (must be at least 3 bytes).</param>
    /// <param name="data">The data to compute the checksum for.</param>
    /// <exception cref="ArgumentException">If output buffer is too small.</exception>
    public void Compute(Span<byte> output, ReadOnlySpan<byte> data)
    {
        Crc24Core.Compute(output, data);
    }

    /// <summary>
    /// Computes the CRC24 checksum and returns it as a byte array.
    /// </summary>
    /// <param name="data">The data to compute the checksum for.</param>
    /// <returns>A 3-byte array containing the CRC24 in big-endian format.</returns>
    /// <exception cref="ArgumentNullException">If data is null.</exception>
    public byte[] ComputeToBytes(byte[] data)
    {
        ArgumentHelper.ThrowIfNull(data);
        return Crc24Core.ComputeToBytes(data);
    }

    /// <summary>
    /// Computes the CRC24 checksum and returns it as a byte array.
    /// </summary>
    /// <param name="data">The data to compute the checksum for.</param>
    /// <returns>A 3-byte array containing the CRC24 in big-endian format.</returns>
    public byte[] ComputeToBytes(ReadOnlySpan<byte> data)
    {
        return Crc24Core.ComputeToBytes(data);
    }

    /// <summary>
    /// Verifies that the CRC24 checksum matches the expected value.
    /// </summary>
    /// <param name="expectedCrc">The expected CRC value as a 32-bit integer.</param>
    /// <param name="data">The data to verify.</param>
    /// <returns>True if the checksum matches, false otherwise.</returns>
    /// <exception cref="ArgumentNullException">If data is null.</exception>
    public bool Verify(uint expectedCrc, byte[] data)
    {
        ArgumentHelper.ThrowIfNull(data);
        return Crc24Core.Verify(expectedCrc, data);
    }

    /// <summary>
    /// Verifies that the CRC24 checksum matches the expected value.
    /// </summary>
    /// <param name="expectedCrc">The expected CRC value as a 32-bit integer.</param>
    /// <param name="data">The data to verify.</param>
    /// <returns>True if the checksum matches, false otherwise.</returns>
    public bool Verify(uint expectedCrc, ReadOnlySpan<byte> data)
    {
        return Crc24Core.Verify(expectedCrc, data);
    }

    /// <summary>
    /// Verifies that the CRC24 checksum matches the expected bytes.
    /// </summary>
    /// <param name="expectedCrc">The expected CRC as a 3-byte array in big-endian format.</param>
    /// <param name="data">The data to verify.</param>
    /// <returns>True if the checksum matches, false otherwise.</returns>
    /// <exception cref="ArgumentNullException">If expectedCrc or data is null.</exception>
    public bool Verify(byte[] expectedCrc, byte[] data)
    {
        ArgumentHelper.ThrowIfNull(expectedCrc);
        ArgumentHelper.ThrowIfNull(data);
        return Crc24Core.Verify(expectedCrc, data);
    }

    /// <summary>
    /// Verifies that the CRC24 checksum matches the expected bytes.
    /// </summary>
    /// <param name="expectedCrc">The expected CRC as a 3-byte array in big-endian format.</param>
    /// <param name="data">The data to verify.</param>
    /// <returns>True if the checksum matches, false otherwise.</returns>
    public bool Verify(ReadOnlySpan<byte> expectedCrc, ReadOnlySpan<byte> data)
    {
        return Crc24Core.Verify(expectedCrc, data);
    }
}
