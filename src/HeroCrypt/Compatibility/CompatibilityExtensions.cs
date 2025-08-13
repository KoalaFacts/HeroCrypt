#if NETSTANDARD2_0 || NET6_0 || NET7_0
using System.Runtime.CompilerServices;

namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit { }
}

namespace System
{
    internal static class ArgumentExceptionExtensions
    {
        public static void ThrowIfNullOrWhiteSpace(string? argument, string? paramName = null)
        {
            if (string.IsNullOrWhiteSpace(argument))
            {
                throw new ArgumentException("Value cannot be null or whitespace.", paramName ?? "value");
            }
        }
    }
    
    internal static class ArgumentNullExceptionExtensions
    {
        public static void ThrowIfNull(object? argument, string? paramName = null)
        {
            if (argument == null)
            {
                throw new ArgumentNullException(paramName ?? "value");
            }
        }
    }
}
#endif

#if NETSTANDARD2_0
namespace HeroCrypt.Compatibility
{
    internal static class BinaryPrimitivesCompat
    {
        public static void WriteInt32LittleEndian(Span<byte> destination, int value)
        {
            if (destination.Length < 4)
                throw new ArgumentException("Destination too small");
            
            destination[0] = (byte)value;
            destination[1] = (byte)(value >> 8);
            destination[2] = (byte)(value >> 16);
            destination[3] = (byte)(value >> 24);
        }
        
        public static void WriteUInt64LittleEndian(Span<byte> destination, ulong value)
        {
            if (destination.Length < 8)
                throw new ArgumentException("Destination too small");
            
            destination[0] = (byte)value;
            destination[1] = (byte)(value >> 8);
            destination[2] = (byte)(value >> 16);
            destination[3] = (byte)(value >> 24);
            destination[4] = (byte)(value >> 32);
            destination[5] = (byte)(value >> 40);
            destination[6] = (byte)(value >> 48);
            destination[7] = (byte)(value >> 56);
        }
        
        public static int ReadInt32LittleEndian(ReadOnlySpan<byte> source)
        {
            if (source.Length < 4)
                throw new ArgumentException("Source too small");
            
            return source[0] | (source[1] << 8) | (source[2] << 16) | (source[3] << 24);
        }
        
        public static ulong ReadUInt64LittleEndian(ReadOnlySpan<byte> source)
        {
            if (source.Length < 8)
                throw new ArgumentException("Source too small");
            
            return (ulong)source[0] |
                   ((ulong)source[1] << 8) |
                   ((ulong)source[2] << 16) |
                   ((ulong)source[3] << 24) |
                   ((ulong)source[4] << 32) |
                   ((ulong)source[5] << 40) |
                   ((ulong)source[6] << 48) |
                   ((ulong)source[7] << 56);
        }
    }
}

namespace System.Security.Cryptography
{
    internal static class CryptographicOperations
    {
        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            if (left.Length != right.Length)
                return false;
            
            var result = 0;
            for (var i = 0; i < left.Length; i++)
            {
                result |= left[i] ^ right[i];
            }
            
            return result == 0;
        }
    }
}
#endif