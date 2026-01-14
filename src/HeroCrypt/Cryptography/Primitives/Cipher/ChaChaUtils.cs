using System.Runtime.CompilerServices;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.Primitives.Cipher;

/// <summary>
/// Shared utilities for ChaCha-based cipher implementations.
/// Contains common operations used by ChaCha20, XChaCha20, and related constructions.
/// </summary>
internal static class ChaChaUtils
{
    /// <summary>
    /// ChaCha quarter round function.
    /// This is the core primitive shared by ChaCha20, XChaCha20, and HChaCha20.
    /// </summary>
    /// <param name="state">The cipher state</param>
    /// <param name="a">Index of first word</param>
    /// <param name="b">Index of second word</param>
    /// <param name="c">Index of third word</param>
    /// <param name="d">Index of fourth word</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void QuarterRound(Span<uint> state, int a, int b, int c, int d)
    {
        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = BitOperations.RotateLeft(state[d], 16);

        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = BitOperations.RotateLeft(state[b], 12);

        state[a] += state[b];
        state[d] ^= state[a];
        state[d] = BitOperations.RotateLeft(state[d], 8);

        state[c] += state[d];
        state[b] ^= state[c];
        state[b] = BitOperations.RotateLeft(state[b], 7);
    }

    /// <summary>
    /// Performs the full ChaCha double round (column rounds followed by diagonal rounds).
    /// Executes 10 iterations for a total of 20 rounds as per the ChaCha20 specification.
    /// </summary>
    /// <param name="state">The cipher state</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DoubleRound(Span<uint> state)
    {
        for (int i = 0; i < 10; i++)
        {
            // Odd round - column rounds
            QuarterRound(state, 0, 4, 8, 12);
            QuarterRound(state, 1, 5, 9, 13);
            QuarterRound(state, 2, 6, 10, 14);
            QuarterRound(state, 3, 7, 11, 15);

            // Even round - diagonal rounds
            QuarterRound(state, 0, 5, 10, 15);
            QuarterRound(state, 1, 6, 11, 12);
            QuarterRound(state, 2, 7, 8, 13);
            QuarterRound(state, 3, 4, 9, 14);
        }
    }
}
