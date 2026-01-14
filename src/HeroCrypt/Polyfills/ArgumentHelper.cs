using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace HeroCrypt.Polyfills;

/// <summary>
/// Provides argument validation helper methods that work across all target frameworks.
/// </summary>
internal static class ArgumentHelper
{
    /// <summary>
    /// Throws an <see cref="ArgumentNullException"/> if the argument is null.
    /// </summary>
    /// <param name="argument">The reference type argument to validate as non-null.</param>
    /// <param name="paramName">The name of the parameter being validated.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="argument"/> is null.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ThrowIfNull(
#if !NETSTANDARD2_0
        [NotNull]
#endif
        object? argument,
        [CallerArgumentExpression(nameof(argument))] string? paramName = null)
    {
#if NETSTANDARD2_0
        if (argument == null)
        {
            throw new ArgumentNullException(paramName);
        }
#else
        ArgumentNullException.ThrowIfNull(argument, paramName);
#endif
    }

    /// <summary>
    /// Throws an <see cref="ArgumentException"/> if the string is null or empty.
    /// </summary>
    /// <param name="argument">The string argument to validate.</param>
    /// <param name="paramName">The name of the parameter being validated.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="argument"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="argument"/> is empty.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ThrowIfNullOrEmpty(
#if !NETSTANDARD2_0
        [NotNull]
#endif
        string? argument,
        [CallerArgumentExpression(nameof(argument))] string? paramName = null)
    {
#if NETSTANDARD2_0
        if (argument == null)
        {
            throw new ArgumentNullException(paramName);
        }
        if (argument.Length == 0)
        {
            throw new ArgumentException("Value cannot be empty.", paramName);
        }
#else
        ArgumentException.ThrowIfNullOrEmpty(argument, paramName);
#endif
    }

    /// <summary>
    /// Throws an <see cref="ArgumentOutOfRangeException"/> if the value is negative.
    /// </summary>
    /// <param name="value">The argument to validate as non-negative.</param>
    /// <param name="paramName">The name of the parameter being validated.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="value"/> is negative.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ThrowIfNegative(int value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
#if NETSTANDARD2_0 || NET8_0
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(paramName, value, "Value cannot be negative.");
        }
#else
        ArgumentOutOfRangeException.ThrowIfNegative(value, paramName);
#endif
    }

    /// <summary>
    /// Throws an <see cref="ArgumentOutOfRangeException"/> if the value is less than or equal to zero.
    /// </summary>
    /// <param name="value">The argument to validate as positive.</param>
    /// <param name="paramName">The name of the parameter being validated.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="value"/> is zero or negative.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ThrowIfNegativeOrZero(int value, [CallerArgumentExpression(nameof(value))] string? paramName = null)
    {
#if NETSTANDARD2_0 || NET8_0
        if (value <= 0)
        {
            throw new ArgumentOutOfRangeException(paramName, value, "Value must be positive.");
        }
#else
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(value, paramName);
#endif
    }
}
