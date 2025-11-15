namespace HeroCrypt.Fluent;

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
public class HeroCryptBuilder
{
    /// <summary>
    /// Creates a new HeroCrypt builder instance
    /// </summary>
    /// <returns>A new builder instance</returns>
    public static HeroCryptBuilder Create() => new HeroCryptBuilder();

    private HeroCryptBuilder() { }

    /// <summary>
    /// Starts building an Argon2 hashing operation
    /// </summary>
    /// <returns>Argon2 fluent builder</returns>
    public Argon2BuilderContext Argon2() => new Argon2BuilderContext();

    /// <summary>
    /// Starts building PGP encryption/decryption operations
    /// </summary>
    /// <returns>PGP fluent builder</returns>
    public PgpBuilderContext Pgp() => new PgpBuilderContext();

#if NET10_0_OR_GREATER
    /// <summary>
    /// Starts building Post-Quantum Cryptography operations (.NET 10+ only)
    /// </summary>
    /// <returns>Post-Quantum builder context</returns>
    public PostQuantumBuilderContext PostQuantum() => new PostQuantumBuilderContext();
#endif

    /// <summary>
    /// Context for building Argon2 operations
    /// </summary>
    public class Argon2BuilderContext
    {
        /// <summary>
        /// Returns an Argon2 fluent builder instance
        /// Note: Requires dependency injection setup for full functionality
        /// </summary>
        public IArgon2FluentBuilder WithDependencyInjection(IServiceProvider serviceProvider)
        {
            return serviceProvider.GetService(typeof(IArgon2FluentBuilder)) as IArgon2FluentBuilder
                ?? throw new InvalidOperationException("IArgon2FluentBuilder not registered in DI container");
        }
    }

    /// <summary>
    /// Context for building PGP operations
    /// </summary>
    public class PgpBuilderContext
    {
        /// <summary>
        /// Returns a PGP fluent builder instance
        /// Note: Requires dependency injection setup for full functionality
        /// </summary>
        public IPgpFluentBuilder WithDependencyInjection(IServiceProvider serviceProvider)
        {
            return serviceProvider.GetService(typeof(IPgpFluentBuilder)) as IPgpFluentBuilder
                ?? throw new InvalidOperationException("IPgpFluentBuilder not registered in DI container");
        }
    }

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
        public Cryptography.PostQuantum.Kyber.MLKemBuilder MLKem() =>
            Cryptography.PostQuantum.Kyber.MLKemBuilder.Create();

        /// <summary>
        /// Starts building ML-DSA (digital signature) operations
        /// </summary>
        /// <returns>ML-DSA builder</returns>
        public Cryptography.PostQuantum.Dilithium.MLDsaBuilder MLDsa() =>
            Cryptography.PostQuantum.Dilithium.MLDsaBuilder.Create();

        /// <summary>
        /// Starts building SLH-DSA (hash-based signature) operations
        /// </summary>
        /// <returns>SLH-DSA builder</returns>
        public Cryptography.PostQuantum.Sphincs.SlhDsaBuilder SlhDsa() =>
            Cryptography.PostQuantum.Sphincs.SlhDsaBuilder.Create();
    }
#endif
}

/// <summary>
/// Static entry point for HeroCrypt fluent builder API
/// </summary>
public static class HeroCrypt
{
    /// <summary>
    /// Creates a new unified HeroCrypt builder
    /// </summary>
    /// <returns>A new builder instance</returns>
    public static HeroCryptBuilder Create() => HeroCryptBuilder.Create();

#if NET10_0_OR_GREATER
    /// <summary>
    /// Quick access to Post-Quantum Cryptography operations
    /// </summary>
    public static class PostQuantum
    {
        /// <summary>
        /// Quick access to ML-KEM operations
        /// </summary>
        public static class MLKem
        {
            /// <summary>
            /// Creates a new ML-KEM builder
            /// </summary>
            public static Cryptography.PostQuantum.Kyber.MLKemBuilder Create() =>
                Cryptography.PostQuantum.Kyber.MLKemBuilder.Create();

            /// <summary>
            /// Generates a key pair with default security (ML-KEM-768)
            /// </summary>
            public static Cryptography.PostQuantum.Kyber.MLKemWrapper.MLKemKeyPair GenerateKeyPair() =>
                Cryptography.PostQuantum.Kyber.MLKem.GenerateKeyPair();

            /// <summary>
            /// Generates a key pair with specified security level
            /// </summary>
            public static Cryptography.PostQuantum.Kyber.MLKemWrapper.MLKemKeyPair GenerateKeyPair(
                Cryptography.PostQuantum.Kyber.MLKemWrapper.SecurityLevel level) =>
                Cryptography.PostQuantum.Kyber.MLKem.GenerateKeyPair(level);
        }

        /// <summary>
        /// Quick access to ML-DSA operations
        /// </summary>
        public static class MLDsa
        {
            /// <summary>
            /// Creates a new ML-DSA builder
            /// </summary>
            public static Cryptography.PostQuantum.Dilithium.MLDsaBuilder Create() =>
                Cryptography.PostQuantum.Dilithium.MLDsaBuilder.Create();

            /// <summary>
            /// Generates a key pair with default security (ML-DSA-65)
            /// </summary>
            public static Cryptography.PostQuantum.Dilithium.MLDsaWrapper.MLDsaKeyPair GenerateKeyPair() =>
                Cryptography.PostQuantum.Dilithium.MLDsa.GenerateKeyPair();

            /// <summary>
            /// Verifies a signature
            /// </summary>
            public static bool Verify(string publicKeyPem, byte[] data, byte[] signature) =>
                Cryptography.PostQuantum.Dilithium.MLDsa.Verify(publicKeyPem, data, signature);
        }

        /// <summary>
        /// Quick access to SLH-DSA operations
        /// </summary>
        public static class SlhDsa
        {
            /// <summary>
            /// Creates a new SLH-DSA builder
            /// </summary>
            public static Cryptography.PostQuantum.Sphincs.SlhDsaBuilder Create() =>
                Cryptography.PostQuantum.Sphincs.SlhDsaBuilder.Create();

            /// <summary>
            /// Generates a key pair with default security (SLH-DSA-128s)
            /// </summary>
            public static Cryptography.PostQuantum.Sphincs.SlhDsaWrapper.SlhDsaKeyPair GenerateKeyPair() =>
                Cryptography.PostQuantum.Sphincs.SlhDsa.GenerateKeyPair();
        }
    }
#endif
}
