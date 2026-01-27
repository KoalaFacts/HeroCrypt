namespace HeroCrypt.Primitives.Argon2;

/// <summary>
/// Argon2 algorithm variants as defined in RFC 9106.
/// </summary>
/// <remarks>
/// <para>
/// Argon2 is the winner of the Password Hashing Competition (2015) and is the
/// recommended algorithm for password hashing and key derivation from passwords.
/// </para>
/// <para>
/// <b>Variant selection guide:</b>
/// </para>
/// <list type="table">
///   <listheader>
///     <term>Variant</term>
///     <description>Use When</description>
///   </listheader>
///   <item>
///     <term>Argon2id</term>
///     <description><b>Default choice</b> - balanced protection against all attack types</description>
///   </item>
///   <item>
///     <term>Argon2d</term>
///     <description>Backend servers where side-channel attacks are not a concern</description>
///   </item>
///   <item>
///     <term>Argon2i</term>
///     <description>Shared/untrusted environments where side-channel resistance is critical</description>
///   </item>
/// </list>
/// <para>
/// <b>Standard:</b> RFC 9106 - Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
/// </para>
/// </remarks>
public enum Argon2Type
{
    /// <summary>
    /// Argon2d - Data-dependent version.
    /// </summary>
    /// <remarks>
    /// Maximizes resistance to GPU cracking attacks through data-dependent memory access patterns.
    /// <b>Warning:</b> Vulnerable to side-channel attacks (cache-timing). Only use in trusted
    /// execution environments where attackers cannot measure memory access patterns.
    /// </remarks>
    Argon2d = 0,

    /// <summary>
    /// Argon2i - Data-independent version.
    /// </summary>
    /// <remarks>
    /// Uses data-independent memory access patterns, providing resistance to side-channel attacks.
    /// Trade-off: Allows more efficient GPU attacks compared to Argon2d.
    /// Best for environments where side-channel attacks are a primary concern.
    /// </remarks>
    Argon2i = 1,

    /// <summary>
    /// Argon2id - Hybrid version (recommended).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Combines the benefits of both variants: uses Argon2i for the first half of the first pass
    /// (side-channel resistant), then switches to Argon2d for subsequent operations (GPU resistant).
    /// </para>
    /// <para>
    /// <b>This is the recommended variant for most applications</b>, including password hashing
    /// and key derivation. It is also the only variant required by OWASP password storage guidelines.
    /// </para>
    /// </remarks>
    Argon2id = 2
}
