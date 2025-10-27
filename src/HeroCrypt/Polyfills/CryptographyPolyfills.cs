using System;
using System.Security.Cryptography;

#if NETSTANDARD2_0
// Polyfills for .NET Standard 2.0
// These provide APIs that are available in .NET Core 3.0+ but not in .NET Standard 2.0

namespace System.Security.Cryptography
{
    /// <summary>
    /// Polyfills for SHA256.HashData (not available in .NET Standard 2.0)
    /// </summary>
    internal static class Sha256Extensions
    {
        public static byte[] HashData(byte[] source)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(source);
        }

        public static byte[] HashData(ReadOnlySpan<byte> source)
        {
            using var sha256 = SHA256.Create();
            return sha256.ComputeHash(source.ToArray());
        }
    }

    /// <summary>
    /// Polyfills for SHA512.HashData (not available in .NET Standard 2.0)
    /// </summary>
    internal static class Sha512Extensions
    {
        public static byte[] HashData(byte[] source)
        {
            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(source);
        }

        public static byte[] HashData(ReadOnlySpan<byte> source)
        {
            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(source.ToArray());
        }
    }

    /// <summary>
    /// Polyfill for CryptographicOperations class (not available in .NET Standard 2.0)
    /// </summary>
    internal static class CryptographicOperations
    {
        /// <summary>
        /// Constant-time equality comparison
        /// </summary>
        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            if (left.Length != right.Length)
                return false;

            int result = 0;
            for (int i = 0; i < left.Length; i++)
            {
                result |= left[i] ^ right[i];
            }
            return result == 0;
        }
    }

    /// <summary>
    /// Extension methods for RandomNumberGenerator to provide .NET Core 3.0+ APIs
    /// </summary>
    internal static class RandomNumberGeneratorExtensions
    {
        private static readonly RandomNumberGenerator _globalRng = RandomNumberGenerator.Create();

        /// <summary>
        /// Static Fill method like .NET Core 3.0+
        /// </summary>
        public static void Fill(Span<byte> data)
        {
            var array = new byte[data.Length];
            _globalRng.GetBytes(array);
            array.AsSpan().CopyTo(data);
        }

        /// <summary>
        /// Extension method for RandomNumberGenerator instances
        /// </summary>
        public static void Fill(this RandomNumberGenerator rng, Span<byte> data)
        {
            var array = new byte[data.Length];
            rng.GetBytes(array);
            array.AsSpan().CopyTo(data);
        }

        /// <summary>
        /// Extension TryComputeHash for HMACSHA512
        /// </summary>
        public static bool TryComputeHash(this HMACSHA512 hmac, ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten)
        {
            var hash = hmac.ComputeHash(source.ToArray());
            if (hash.Length <= destination.Length)
            {
                hash.AsSpan().CopyTo(destination);
                bytesWritten = hash.Length;
                return true;
            }
            bytesWritten = 0;
            return false;
        }

        /// <summary>
        /// Extension TryComputeHash for SHA256
        /// </summary>
        public static bool TryComputeHash(this SHA256 sha256, ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten)
        {
            var hash = sha256.ComputeHash(source.ToArray());
            if (hash.Length <= destination.Length)
            {
                hash.AsSpan().CopyTo(destination);
                bytesWritten = hash.Length;
                return true;
            }
            bytesWritten = 0;
            return false;
        }

        /// <summary>
        /// Extension TryComputeHash for SHA512
        /// </summary>
        public static bool TryComputeHash(this SHA512 sha512, ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten)
        {
            var hash = sha512.ComputeHash(source.ToArray());
            if (hash.Length <= destination.Length)
            {
                hash.AsSpan().CopyTo(destination);
                bytesWritten = hash.Length;
                return true;
            }
            bytesWritten = 0;
            return false;
        }
    }
}

namespace System
{
    /// <summary>
    /// Polyfills for BitConverter extensions not available in .NET Standard 2.0
    /// </summary>
    internal static class BitConverterExtensions
    {
        public static bool TryWriteBytes(Span<byte> destination, ulong value)
        {
            if (destination.Length < sizeof(ulong))
                return false;

            var bytes = BitConverter.GetBytes(value);
            bytes.AsSpan().CopyTo(destination);
            return true;
        }

        public static bool TryWriteBytes(Span<byte> destination, uint value)
        {
            if (destination.Length < sizeof(uint))
                return false;

            var bytes = BitConverter.GetBytes(value);
            bytes.AsSpan().CopyTo(destination);
            return true;
        }
    }
}
#endif
