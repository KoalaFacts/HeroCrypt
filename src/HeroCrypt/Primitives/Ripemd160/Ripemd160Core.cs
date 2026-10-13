using System.Buffers.Binary;

namespace HeroCrypt.Primitives.Ripemd160;

/// <summary>RIPEMD-160 for BIP32 HASH160 fingerprints.</summary>
internal static class Ripemd160Core
{
    // RIPEMD-160 specification: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
    private static readonly byte[] LeftWord =
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
    ];
    private static readonly byte[] RightWord =
    [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
    ];
    private static readonly byte[] LeftRotation =
    [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
    ];
    private static readonly byte[] RightRotation =
    [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
    ];
    private static readonly uint[] LeftConstant = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
    private static readonly uint[] RightConstant = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0];

    /// <summary>Computes the 20-byte RIPEMD-160 digest of a message.</summary>
    public static byte[] Hash(ReadOnlySpan<byte> message)
    {
        Span<uint> state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        var fullBlocks = message.Length / 64;
        for (var block = 0; block < fullBlocks; block++)
        {
            Compress(message.Slice(block * 64, 64), state);
        }

        Span<byte> tail = stackalloc byte[128];
        tail.Clear();
        var remaining = message.Slice(fullBlocks * 64);
        remaining.CopyTo(tail);
        tail[remaining.Length] = 0x80;
        var paddedLength = remaining.Length < 56 ? 64 : 128;
        BinaryPrimitives.WriteUInt64LittleEndian(tail.Slice(paddedLength - 8, 8), (ulong)message.Length * 8);
        Compress(tail.Slice(0, 64), state);
        if (paddedLength == 128) Compress(tail.Slice(64, 64), state);

        var digest = new byte[20];
        for (var i = 0; i < state.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(digest.AsSpan(i * 4, 4), state[i]);
        }
        tail.Clear();
        state.Clear();
        return digest;
    }

    private static void Compress(ReadOnlySpan<byte> block, Span<uint> state)
    {
        Span<uint> words = stackalloc uint[16];
        for (var i = 0; i < words.Length; i++)
            words[i] = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(i * 4, 4));

        var a = state[0]; var b = state[1]; var c = state[2]; var d = state[3]; var e = state[4];
        var aa = a; var bb = b; var cc = c; var dd = d; var ee = e;
        unchecked
        {
            for (var i = 0; i < 80; i++)
            {
                var round = i / 16;
                var next = Rotate(a + Function(round, b, c, d) + words[LeftWord[i]] + LeftConstant[round], LeftRotation[i]) + e;
                a = e; e = d; d = Rotate(c, 10); c = b; b = next;
                next = Rotate(aa + Function(4 - round, bb, cc, dd) + words[RightWord[i]] + RightConstant[round], RightRotation[i]) + ee;
                aa = ee; ee = dd; dd = Rotate(cc, 10); cc = bb; bb = next;
            }
            var combined = state[1] + c + dd;
            state[1] = state[2] + d + ee;
            state[2] = state[3] + e + aa;
            state[3] = state[4] + a + bb;
            state[4] = state[0] + b + cc;
            state[0] = combined;
        }
        words.Clear();
    }

    private static uint Function(int round, uint x, uint y, uint z) => round switch
    {
        0 => x ^ y ^ z,
        1 => (x & y) | (~x & z),
        2 => (x | ~y) ^ z,
        3 => (x & z) | (y & ~z),
        _ => x ^ (y | ~z)
    };

    private static uint Rotate(uint value, int count) => (value << count) | (value >> (32 - count));
}
