#if NETSTANDARD2_0 || NETSTANDARD2_1 || NETCOREAPP2_0 || NETCOREAPP2_1 || NETCOREAPP2_2 || NETCOREAPP3_0 || NETCOREAPP3_1 || NET45 || NET451 || NET452 || NET46 || NET461 || NET462 || NET47 || NET471 || NET472 || NET48

// ReSharper disable once CheckNamespace
namespace System.Runtime.CompilerServices
{
    /// <summary>
    /// Reserved for compiler use to enable init-only setters in C# 9.0 and later.
    /// This polyfill enables the use of init accessors in older target frameworks.
    /// </summary>
    internal static class IsExternalInit
    {
    }
}

#endif
