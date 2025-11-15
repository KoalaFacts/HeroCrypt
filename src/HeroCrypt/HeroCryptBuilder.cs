using HeroCrypt.Abstractions;
using System.Diagnostics.CodeAnalysis;

namespace HeroCrypt
{

/// <summary>
/// Unified fluent builder providing a single entry point for all HeroCrypt cryptographic operations
/// </summary>
/// <example>
/// <code>
/// // Argon2 password hashing
/// var hash = HeroCryptBuilder.Create()
///     .Argon2()
///     .WithPassword("myPassword")
///     .WithSecurityLevel(SecurityLevel.High)
///     .HashAsync();
///
/// // Post-Quantum Cryptography (.NET 10+)
/// var keyPair = HeroCryptBuilder.Create()
///     .PostQuantum()
///     .MLKem()
///     .WithSecurityBits(192)
///     .GenerateKeyPair();
///
/// var signature = HeroCryptBuilder.Create()
///     .PostQuantum()
///     .MLDsa()
///     .WithData("message")
///     .WithKeyPair(signingKey)
///     .Sign();
/// </code>
/// </example>
public sealed class HeroCryptFluentBuilder
{
    /// <summary>
    /// Creates a new HeroCrypt builder instance
    /// </summary>
    /// <returns>A new builder instance</returns>
    public static HeroCryptFluentBuilder Create() => new();

    private HeroCryptFluentBuilder() { }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Starts building Post-Quantum Cryptography operations (.NET 10+ only)
    /// </summary>
    /// <returns>Post-Quantum builder context</returns>
    public PostQuantumBuilderContext PostQuantum() => new();
#endif

#if NET10_0_OR_GREATER
    /// <summary>
    /// Context for building Post-Quantum Cryptography operations
    /// </summary>
    public class PostQuantumBuilderContext
    {
        /// <summary>
        /// Starts building ML-KEM (key encapsulation) operations
        /// </summary>
        /// <returns>ML-KEM builder</returns>
#pragma warning disable SYSLIB5006 // Experimental feature warnings
        public Cryptography.PostQuantum.Kyber.MLKemBuilder MLKem() =>
            Cryptography.PostQuantum.Kyber.MLKemBuilder.Create();
#pragma warning restore SYSLIB5006

        /// <summary>
        /// Starts building ML-DSA (digital signature) operations
        /// </summary>
        /// <returns>ML-DSA builder</returns>
#pragma warning disable SYSLIB5006 // Experimental feature warnings
        public Cryptography.PostQuantum.Dilithium.MLDsaBuilder MLDsa() =>
            Cryptography.PostQuantum.Dilithium.MLDsaBuilder.Create();
#pragma warning restore SYSLIB5006

        /// <summary>
        /// Starts building SLH-DSA (hash-based signature) operations
        /// </summary>
        /// <returns>SLH-DSA builder</returns>
        [Experimental("SYSLIB5006")]
        public Cryptography.PostQuantum.Sphincs.SlhDsaBuilder SlhDsa() =>
            Cryptography.PostQuantum.Sphincs.SlhDsaBuilder.Create();
    }
#endif
}

/// <summary>
/// Static entry point for HeroCrypt fluent builder API
/// </summary>
public static class HeroCryptBuilder
{
    /// <summary>
    /// Creates a new unified HeroCrypt builder
    /// </summary>
    /// <returns>A new builder instance</returns>
    public static HeroCryptFluentBuilder Create() => HeroCryptFluentBuilder.Create();

#if NET10_0_OR_GREATER
    /// <summary>
    /// Quick access to Post-Quantum Cryptography operations
    /// </summary>
    public static class PostQuantum
    {
        /// <summary>
        /// Quick access to ML-KEM operations
        /// </summary>
        [Experimental("SYSLIB5006")]
        public static class MLKem
        {
            /// <summary>
            /// Creates a new ML-KEM builder
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.PostQuantum.Kyber.MLKemBuilder Create() =>
                Cryptography.PostQuantum.Kyber.MLKemBuilder.Create();

            /// <summary>
            /// Generates a key pair with default security (ML-KEM-768)
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.PostQuantum.Kyber.MLKemWrapper.MLKemKeyPair GenerateKeyPair() =>
                Cryptography.PostQuantum.Kyber.MLKem.GenerateKeyPair();

            /// <summary>
            /// Generates a key pair with specified security level
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.PostQuantum.Kyber.MLKemWrapper.MLKemKeyPair GenerateKeyPair(
                Cryptography.PostQuantum.Kyber.MLKemWrapper.SecurityLevel level) =>
                Cryptography.PostQuantum.Kyber.MLKem.GenerateKeyPair(level);
        }

        /// <summary>
        /// Quick access to ML-DSA operations
        /// </summary>
        [Experimental("SYSLIB5006")]
        public static class MLDsa
        {
            /// <summary>
            /// Creates a new ML-DSA builder
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.PostQuantum.Dilithium.MLDsaBuilder Create() =>
                Cryptography.PostQuantum.Dilithium.MLDsaBuilder.Create();

            /// <summary>
            /// Generates a key pair with default security (ML-DSA-65)
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.PostQuantum.Dilithium.MLDsaWrapper.MLDsaKeyPair GenerateKeyPair() =>
                Cryptography.PostQuantum.Dilithium.MLDsa.GenerateKeyPair();

            /// <summary>
            /// Verifies a signature
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static bool Verify(string publicKeyPem, byte[] data, byte[] signature) =>
                Cryptography.PostQuantum.Dilithium.MLDsa.Verify(publicKeyPem, data, signature);
        }

        /// <summary>
        /// Quick access to SLH-DSA operations
        /// </summary>
        [Experimental("SYSLIB5006")]
        public static class SlhDsa
        {
            /// <summary>
            /// Creates a new SLH-DSA builder
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.PostQuantum.Sphincs.SlhDsaBuilder Create() =>
                Cryptography.PostQuantum.Sphincs.SlhDsaBuilder.Create();

            /// <summary>
            /// Generates a key pair with default security (SLH-DSA-128s)
            /// </summary>
            [Experimental("SYSLIB5006")]
            public static Cryptography.PostQuantum.Sphincs.SlhDsaWrapper.SlhDsaKeyPair GenerateKeyPair() =>
                Cryptography.PostQuantum.Sphincs.SlhDsa.GenerateKeyPair();
        }
    }
#endif
}
} // End namespace HeroCrypt
