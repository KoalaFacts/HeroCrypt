using System.Runtime.CompilerServices;

namespace HeroCrypt.Primitives.Crc24;

/// <summary>
/// High-performance CRC24 implementation for OpenPGP ASCII Armor.
/// Implements the CRC24 algorithm specified in RFC 4880 Section 6.1.
/// </summary>
/// <remarks>
/// The CRC24 is computed using:
/// - Polynomial: 0x864CFB
/// - Initial value: 0xB704CE
/// - Final XOR: None (direct output)
/// </remarks>
internal static class Crc24Core
{
    /// <summary>
    /// CRC24 output size in bytes.
    /// </summary>
    public const int CRC_SIZE = 3;

    /// <summary>
    /// OpenPGP CRC24 polynomial: x^24 + x^23 + x^18 + x^17 + x^14 + x^11 + x^10 + x^7 + x^6 + x^5 + x^4 + x^3 + x + 1.
    /// </summary>
    private const uint POLYNOMIAL = 0x864CFB;

    /// <summary>
    /// Initial CRC24 value as specified in RFC 4880.
    /// </summary>
    private const uint INIT_VALUE = 0xB704CE;

    /// <summary>
    /// Precomputed lookup table for fast CRC24 computation.
    /// </summary>
    private static readonly uint[] CrcTable = GenerateCrcTable();

    /// <summary>
    /// Computes the CRC24 checksum for the given data.
    /// </summary>
    /// <param name="data">The data to compute the checksum for.</param>
    /// <returns>The 24-bit CRC value as a 32-bit unsigned integer (upper 8 bits are zero).</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Compute(ReadOnlySpan<byte> data)
    {
        var crc = INIT_VALUE;

        foreach (var b in data)
        {
            var index = ((crc >> 16) ^ b) & 0xFF;
            crc = (CrcTable[index] ^ (crc << 8)) & 0xFFFFFF;
        }

        return crc;
    }

    /// <summary>
    /// Computes the CRC24 checksum and writes it to the output buffer.
    /// </summary>
    /// <param name="output">The output buffer (must be at least 3 bytes).</param>
    /// <param name="data">The data to compute the checksum for.</param>
    /// <exception cref="ArgumentException">If output buffer is too small.</exception>
    public static void Compute(Span<byte> output, ReadOnlySpan<byte> data)
    {
        if (output.Length < CRC_SIZE)
        {
            throw new ArgumentException($"Output buffer must be at least {CRC_SIZE} bytes.", nameof(output));
        }

        var crc = Compute(data);

        // Write CRC in big-endian format (most significant byte first)
        output[0] = (byte)((crc >> 16) & 0xFF);
        output[1] = (byte)((crc >> 8) & 0xFF);
        output[2] = (byte)(crc & 0xFF);
    }

    /// <summary>
    /// Computes the CRC24 checksum and returns it as a byte array.
    /// </summary>
    /// <param name="data">The data to compute the checksum for.</param>
    /// <returns>A 3-byte array containing the CRC24 in big-endian format.</returns>
    public static byte[] ComputeToBytes(ReadOnlySpan<byte> data)
    {
        var result = new byte[CRC_SIZE];
        Compute(result, data);
        return result;
    }

    /// <summary>
    /// Verifies that the CRC24 checksum matches the expected value.
    /// </summary>
    /// <param name="expectedCrc">The expected CRC value as a 32-bit integer.</param>
    /// <param name="data">The data to verify.</param>
    /// <returns>True if the checksum matches, false otherwise.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Verify(uint expectedCrc, ReadOnlySpan<byte> data)
    {
        return Compute(data) == (expectedCrc & 0xFFFFFF);
    }

    /// <summary>
    /// Verifies that the CRC24 checksum matches the expected bytes.
    /// </summary>
    /// <param name="expectedCrc">The expected CRC as a 3-byte array in big-endian format.</param>
    /// <param name="data">The data to verify.</param>
    /// <returns>True if the checksum matches, false otherwise.</returns>
    public static bool Verify(ReadOnlySpan<byte> expectedCrc, ReadOnlySpan<byte> data)
    {
        if (expectedCrc.Length < CRC_SIZE)
        {
            return false;
        }

        var expected = ((uint)expectedCrc[0] << 16) | ((uint)expectedCrc[1] << 8) | expectedCrc[2];
        return Verify(expected, data);
    }

    /// <summary>
    /// Generates the CRC24 lookup table for fast computation.
    /// </summary>
    private static uint[] GenerateCrcTable()
    {
        var table = new uint[256];

        for (var i = 0; i < 256; i++)
        {
            var crc = (uint)i << 16;

            for (var j = 0; j < 8; j++)
            {
                if ((crc & 0x800000) != 0)
                {
                    crc = (crc << 1) ^ POLYNOMIAL;
                }
                else
                {
                    crc <<= 1;
                }
            }

            table[i] = crc & 0xFFFFFF;
        }

        return table;
    }
}
