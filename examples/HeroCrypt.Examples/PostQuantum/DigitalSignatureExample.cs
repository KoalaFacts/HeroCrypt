#if NET10_0_OR_GREATER
using System.Text;
using System.Text.Json;
using HeroCrypt.Cryptography.Primitives.PostQuantum.Signature;

namespace HeroCrypt.Examples.PostQuantum;

/// <summary>
/// Demonstrates ML-DSA and SLH-DSA builder usage with simple sign/verify flows.
/// </summary>
public static class DigitalSignatureExample
{
    public static void Run()
    {
        Console.WriteLine("=== ML-DSA Digital Signatures ===");

        if (!MLDsaWrapper.IsSupported())
        {
            Console.WriteLine("ML-DSA not supported on this platform.");
            return;
        }

        var document = new
        {
            DocumentId = "CONTRACT-2025-001",
            Title = "Software License Agreement",
            Content = "This agreement is made between...",
            Date = DateTime.UtcNow
        };

        var documentBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(document));

        using var signingKey = MLDsaBuilder.Create()
            .WithSecurityLevel(MLDsaWrapper.SecurityLevel.MLDsa65)
            .GenerateKeyPair();

        var signature = MLDsaBuilder.Create()
            .WithKeyPair(signingKey)
            .WithData(documentBytes)
            .WithContext($"legal:{document.DocumentId}")
            .Sign();

        var isValid = MLDsaBuilder.Create()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(documentBytes)
            .WithContext($"legal:{document.DocumentId}")
            .Verify(signature);

        Console.WriteLine($"Signature valid: {isValid}");
        Console.WriteLine();
    }

    public static void RunCodeSigning()
    {
        Console.WriteLine("=== SLH-DSA Code Signing ===");

        if (!SlhDsaWrapper.IsSupported())
        {
            Console.WriteLine("SLH-DSA not supported on this platform.");
            return;
        }

        var releaseInfo = new
        {
            Version = "v2.5.0",
            Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        };

        var releaseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(releaseInfo));

        using var signingKey = SlhDsaBuilder.Create()
            .WithSmallVariant(128)
            .GenerateKeyPair();

        var signature = SlhDsaBuilder.Create()
            .WithKeyPair(signingKey)
            .WithData(releaseBytes)
            .WithContext($"code:{releaseInfo.Version}")
            .Sign();

        var isAuthentic = SlhDsaBuilder.Create()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(releaseBytes)
            .WithContext($"code:{releaseInfo.Version}")
            .Verify(signature);

        Console.WriteLine($"Release signature valid: {isAuthentic}");
        Console.WriteLine();
    }

    public static void RunMultipartyApproval()
    {
        Console.WriteLine("=== ML-DSA Multi-Party Approval ===");

        if (!MLDsaWrapper.IsSupported())
        {
            Console.WriteLine("ML-DSA not supported on this platform.");
            return;
        }

        var proposalBytes = Encoding.UTF8.GetBytes("Budget proposal");

        using var managerKey = MLDsaBuilder.Create().GenerateKeyPair();
        using var directorKey = MLDsaBuilder.Create().GenerateKeyPair();
        using var cfoKey = MLDsaBuilder.Create().WithSecurityLevel(MLDsaWrapper.SecurityLevel.MLDsa87).GenerateKeyPair();

        byte[] managerSig = MLDsaBuilder.Create().WithKeyPair(managerKey).WithData(proposalBytes).Sign();
        bool managerApproved = MLDsaBuilder.Create().WithPublicKey(managerKey.PublicKeyPem).WithData(proposalBytes).Verify(managerSig);

        byte[] directorSig = MLDsaBuilder.Create().WithKeyPair(directorKey).WithData(proposalBytes).Sign();
        bool directorApproved = MLDsaBuilder.Create().WithPublicKey(directorKey.PublicKeyPem).WithData(proposalBytes).Verify(directorSig);

        byte[] cfoSig = MLDsaBuilder.Create().WithKeyPair(cfoKey).WithData(proposalBytes).Sign();
        bool cfoApproved = MLDsaBuilder.Create().WithPublicKey(cfoKey.PublicKeyPem).WithData(proposalBytes).Verify(cfoSig);

        Console.WriteLine($"Manager approved:  {managerApproved}");
        Console.WriteLine($"Director approved: {directorApproved}");
        Console.WriteLine($"CFO approved:      {cfoApproved}");
        Console.WriteLine();
    }
}
#endif
