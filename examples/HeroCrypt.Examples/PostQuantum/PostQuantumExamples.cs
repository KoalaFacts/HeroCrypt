#if NET10_0_OR_GREATER
using HeroCrypt.Cryptography.Primitives.PostQuantum.Kyber;
using HeroCrypt.Cryptography.Primitives.PostQuantum.Dilithium;
using HeroCrypt.Cryptography.Primitives.PostQuantum.Sphincs;

namespace HeroCrypt.Examples.PostQuantum;

/// <summary>
/// Main entry point for Post-Quantum Cryptography examples
/// Demonstrates .NET 10's native PQC support in HeroCrypt
/// </summary>
public static class PostQuantumExamples
{
    public static void RunAll()
    {
        Console.WriteLine("╔════════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║      HeroCrypt Post-Quantum Cryptography Examples              ║");
        Console.WriteLine("║      .NET 10+ Native PQC Support                               ║");
        Console.WriteLine("╚════════════════════════════════════════════════════════════════╝");
        Console.WriteLine();

        CheckPlatformSupport();
        Console.WriteLine();

        if (!MLKemWrapper.IsSupported() && !MLDsaWrapper.IsSupported() && !SlhDsaWrapper.IsSupported())
        {
            Console.WriteLine("❌ Post-Quantum Cryptography is not supported on this platform.");
            Console.WriteLine();
            Console.WriteLine("Requirements:");
            Console.WriteLine("  • .NET 10 or later");
            Console.WriteLine("  • Windows: CNG with PQC support");
            Console.WriteLine("  • Linux: OpenSSL 3.5 or newer");
            return;
        }

        Console.WriteLine("Select an example to run:");
        Console.WriteLine();
        Console.WriteLine("  [1] Hybrid Encryption (ML-KEM + AES-GCM)");
        Console.WriteLine("  [2] Multiple Message Encryption");
        Console.WriteLine("  [3] Digital Signatures (ML-DSA)");
        Console.WriteLine("  [4] Code Signing (SLH-DSA)");
        Console.WriteLine("  [5] Multi-Party Approval Chain");
        Console.WriteLine("  [6] Run All Examples");
        Console.WriteLine("  [0] Exit");
        Console.WriteLine();
        Console.Write("Enter choice: ");

        var choice = Console.ReadLine();
        Console.WriteLine();

        switch (choice)
        {
            case "1":
                HybridEncryptionExample.Run();
                break;
            case "2":
                HybridEncryptionExample.RunMultipleMessages();
                break;
            case "3":
                DigitalSignatureExample.Run();
                break;
            case "4":
                DigitalSignatureExample.RunCodeSigning();
                break;
            case "5":
                DigitalSignatureExample.RunMultipartyApproval();
                break;
            case "6":
                RunAllExamples();
                break;
            case "0":
                Console.WriteLine("Goodbye!");
                break;
            default:
                Console.WriteLine("Invalid choice. Please run again.");
                break;
        }

        Console.WriteLine();
        Console.WriteLine("Press any key to continue...");
        Console.ReadKey();
    }

    private static void RunAllExamples()
    {
        Console.WriteLine("Running all PQC examples...\n");
        Console.WriteLine(new string('═', 70));
        Console.WriteLine();

        try
        {
            HybridEncryptionExample.Run();
            Console.WriteLine(new string('═', 70));
            Console.WriteLine();

            HybridEncryptionExample.RunMultipleMessages();
            Console.WriteLine(new string('═', 70));
            Console.WriteLine();

            DigitalSignatureExample.Run();
            Console.WriteLine(new string('═', 70));
            Console.WriteLine();

            DigitalSignatureExample.RunCodeSigning();
            Console.WriteLine(new string('═', 70));
            Console.WriteLine();

            DigitalSignatureExample.RunMultipartyApproval();
            Console.WriteLine(new string('═', 70));
            Console.WriteLine();

            Console.WriteLine("✅ All examples completed successfully!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
        }
    }

    private static void CheckPlatformSupport()
    {
        Console.WriteLine("Platform Support Check:");
        Console.WriteLine();

        Console.WriteLine($"  .NET Version: {Environment.Version}");
        Console.WriteLine($"  OS: {Environment.OSVersion}");
        Console.WriteLine();

        Console.WriteLine("Algorithm Support:");

        // ML-KEM
        var mlKemSupported = MLKemWrapper.IsSupported();
        Console.Write($"  • ML-KEM (FIPS 203)  : ");
        Console.ForegroundColor = mlKemSupported ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(mlKemSupported ? "✓ Supported" : "✗ Not Supported");
        Console.ResetColor();

        if (mlKemSupported)
        {
            Console.WriteLine("    - ML-KEM-512  (~128-bit PQ security)");
            Console.WriteLine("    - ML-KEM-768  (~192-bit PQ security)");
            Console.WriteLine("    - ML-KEM-1024 (~256-bit PQ security)");
        }

        // ML-DSA
        var mlDsaSupported = MLDsaWrapper.IsSupported();
        Console.Write($"  • ML-DSA (FIPS 204)  : ");
        Console.ForegroundColor = mlDsaSupported ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(mlDsaSupported ? "✓ Supported" : "✗ Not Supported");
        Console.ResetColor();

        if (mlDsaSupported)
        {
            Console.WriteLine("    - ML-DSA-44 (~128-bit PQ security)");
            Console.WriteLine("    - ML-DSA-65 (~192-bit PQ security)");
            Console.WriteLine("    - ML-DSA-87 (~256-bit PQ security)");
        }

        // SLH-DSA
        var slhDsaSupported = SlhDsaWrapper.IsSupported();
        Console.Write($"  • SLH-DSA (FIPS 205) : ");
        Console.ForegroundColor = slhDsaSupported ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(slhDsaSupported ? "✓ Supported" : "✗ Not Supported");
        Console.ResetColor();

        if (slhDsaSupported)
        {
            Console.WriteLine("    - SLH-DSA-128s/f (128-bit, small/fast)");
            Console.WriteLine("    - SLH-DSA-192s/f (192-bit, small/fast)");
            Console.WriteLine("    - SLH-DSA-256s/f (256-bit, small/fast)");
        }
    }

    /// <summary>
    /// Quick demonstration showing all three PQC algorithms in action
    /// </summary>
    public static void QuickDemo()
    {
        Console.WriteLine("=== Quick PQC Demo ===\n");

        if (MLKemWrapper.IsSupported())
        {
            Console.WriteLine("1. ML-KEM (Key Encapsulation):");
            using var kemKey = MLKem.GenerateKeyPair();
            using var enc = MLKemBuilder.Create()
                .WithPublicKey(kemKey.PublicKeyPem).Encapsulate();
            var recovered = kemKey.Decapsulate(enc.Ciphertext);
            Console.WriteLine($"   ✓ Shared secret established ({enc.SharedSecret.Length} bytes)");
            Console.WriteLine($"   ✓ Decapsulation successful: {enc.SharedSecret.SequenceEqual(recovered)}");
            Console.WriteLine();
        }

        if (MLDsaWrapper.IsSupported())
        {
            Console.WriteLine("2. ML-DSA (Digital Signatures):");
            using var dsaKey = MLDsa.GenerateKeyPair();
            var data = System.Text.Encoding.UTF8.GetBytes("Test message");
            var sig = dsaKey.Sign(data);
            var valid = MLDsa.Verify(dsaKey.PublicKeyPem, data, sig);
            Console.WriteLine($"   ✓ Document signed ({sig.Length} bytes)");
            Console.WriteLine($"   ✓ Signature valid: {valid}");
            Console.WriteLine();
        }

        if (SlhDsaWrapper.IsSupported())
        {
            Console.WriteLine("3. SLH-DSA (Hash-Based Signatures):");
            using var slhKey = SlhDsa.GenerateKeyPair();
            var data = System.Text.Encoding.UTF8.GetBytes("Code release v1.0");
            var sig = slhKey.Sign(data);
            var valid = SlhDsaBuilder.Create()
                .WithPublicKey(slhKey.PublicKeyPem)
                .WithData(data)
                .Verify(sig);
            Console.WriteLine($"   ✓ Software signed ({sig.Length} bytes)");
            Console.WriteLine($"   ✓ Signature valid: {valid}");
            Console.WriteLine();
        }

        Console.WriteLine("✅ All PQC algorithms working correctly!");
    }
}
#endif
