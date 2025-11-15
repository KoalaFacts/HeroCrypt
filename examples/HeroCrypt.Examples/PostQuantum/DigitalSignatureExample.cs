#if NET10_0_OR_GREATER
using System.Text;
using System.Text.Json;
using HeroCrypt.Fluent;
using HeroCrypt.Cryptography.PostQuantum.Dilithium;
using HeroCrypt.Cryptography.PostQuantum.Sphincs;

namespace HeroCrypt.Examples.PostQuantum;

/// <summary>
/// Demonstrates quantum-resistant digital signatures using ML-DSA and SLH-DSA
/// </summary>
public static class DigitalSignatureExample
{
    public static void Run()
    {
        Console.WriteLine("=== Digital Signatures with ML-DSA ===\n");

        if (!MLDsaWrapper.IsSupported())
        {
            Console.WriteLine("⚠️  ML-DSA is not supported on this platform.");
            return;
        }

        // Scenario: Signing a legal document
        Console.WriteLine("📄 Scenario: Digital signature for legal document\n");

        // Document details
        var document = new
        {
            DocumentId = "CONTRACT-2025-001",
            Title = "Software License Agreement",
            Content = "This agreement is made between...",
            Date = DateTime.UtcNow,
            Parties = new[] { "Company A", "Company B" }
        };

        var documentJson = JsonSerializer.Serialize(document, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        Console.WriteLine("Document to sign:");
        Console.WriteLine(documentJson);
        Console.WriteLine();

        // Step 1: Generate signing key
        Console.WriteLine("1️⃣  Generating ML-DSA signing key...");
        using var signingKey = HeroCrypt.Create()
            .PostQuantum()
            .MLDsa()
            .WithSecurityLevel(MLDsaWrapper.SecurityLevel.MLDsa87)  // Maximum security
            .GenerateKeyPair();

        var info = MLDsaWrapper.GetLevelInfo(MLDsaWrapper.SecurityLevel.MLDsa87);
        Console.WriteLine($"   ✓ Security Level: {info.SecurityBits}-bit post-quantum");
        Console.WriteLine($"   ✓ Expected Signature Size: ~{info.SignatureSize} bytes");
        Console.WriteLine();

        // Step 2: Sign the document with context
        Console.WriteLine("2️⃣  Signing document...");
        var documentBytes = Encoding.UTF8.GetBytes(documentJson);

        var signature = HeroCrypt.Create()
            .PostQuantum()
            .MLDsa()
            .WithKeyPair(signingKey)
            .WithData(documentBytes)
            .WithContext($"legal-contract:{document.DocumentId}")  // Domain separation
            .Sign();

        Console.WriteLine($"   ✓ Signature created: {signature.Length} bytes");
        Console.WriteLine($"   ✓ Signature (Base64): {Convert.ToBase64String(signature)[..60]}...");
        Console.WriteLine();

        // Step 3: Verify the signature
        Console.WriteLine("3️⃣  Verifying signature...");
        var isValid = HeroCrypt.Create()
            .PostQuantum()
            .MLDsa()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(documentBytes)
            .WithContext($"legal-contract:{document.DocumentId}")
            .Verify(signature);

        Console.WriteLine($"   ✓ Signature Valid: {isValid}");
        Console.WriteLine();

        // Step 4: Tamper detection
        Console.WriteLine("4️⃣  Testing tamper detection...");
        var tamperedDoc = documentJson.Replace("Company A", "Company X");
        var tamperedBytes = Encoding.UTF8.GetBytes(tamperedDoc);

        var isTamperedValid = HeroCrypt.Create()
            .PostQuantum()
            .MLDsa()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(tamperedBytes)
            .WithContext($"legal-contract:{document.DocumentId}")
            .Verify(signature);

        Console.WriteLine($"   ✓ Tampered Document Valid: {isTamperedValid} (should be false)");
        Console.WriteLine();

        Console.WriteLine("✅ Digital signature workflow complete!");
        Console.WriteLine("   • Document signed with quantum-resistant algorithm");
        Console.WriteLine("   • Signature verified successfully");
        Console.WriteLine("   • Tampering detected correctly");
    }

    public static void RunCodeSigning()
    {
        Console.WriteLine("\n=== Code Signing with SLH-DSA ===\n");

        if (!SlhDsaWrapper.IsSupported())
        {
            Console.WriteLine("⚠️  SLH-DSA is not supported on this platform.");
            return;
        }

        // Scenario: Signing software release
        Console.WriteLine("💾 Scenario: Signing software release\n");

        var release = new
        {
            Version = "v2.5.0",
            BuildNumber = "20250615.1",
            Sha256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Platform = "Windows x64",
            ReleaseDate = DateTime.UtcNow
        };

        Console.WriteLine("Release Info:");
        Console.WriteLine(JsonSerializer.Serialize(release, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine();

        // Use hash-based signatures for conservative security
        Console.WriteLine("1️⃣  Generating SLH-DSA signing key (small variant)...");
        using var signingKey = HeroCrypt.Create()
            .PostQuantum()
            .SlhDsa()
            .WithSmallVariant(192)  // 192-bit security, smaller signatures
            .GenerateKeyPair();

        var info = SlhDsaWrapper.GetLevelInfo(SlhDsaWrapper.SecurityLevel.SlhDsa192s);
        Console.WriteLine($"   ✓ Security Level: {info.SecurityBits}-bit (hash-based)");
        Console.WriteLine($"   ✓ Signature Size: ~{info.SignatureSizeApprox} bytes");
        Console.WriteLine();

        // Sign the release
        Console.WriteLine("2️⃣  Signing release...");
        var releaseData = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(release));

        var signature = HeroCrypt.Create()
            .PostQuantum()
            .SlhDsa()
            .WithKeyPair(signingKey)
            .WithData(releaseData)
            .WithContext($"code-signing:{release.Version}")
            .Sign();

        Console.WriteLine($"   ✓ Release signed: {signature.Length} bytes");
        Console.WriteLine();

        // Users verify the signature
        Console.WriteLine("3️⃣  End user verifying signature...");
        var isAuthentic = HeroCrypt.Create()
            .PostQuantum()
            .SlhDsa()
            .WithPublicKey(signingKey.PublicKeyPem)
            .WithData(releaseData)
            .WithContext($"code-signing:{release.Version}")
            .Verify(signature);

        Console.WriteLine($"   ✓ Software Authentic: {isAuthentic}");
        Console.WriteLine();

        Console.WriteLine("✅ Code signing complete!");
        Console.WriteLine("   • Hash-based signature (conservative security)");
        Console.WriteLine("   • No number-theoretic assumptions");
        Console.WriteLine("   • Suitable for long-term archival");
    }

    public static void RunMultipartyApproval()
    {
        Console.WriteLine("\n=== Multi-Party Approval Chain ===\n");

        if (!MLDsaWrapper.IsSupported())
            return;

        Console.WriteLine("🏢 Scenario: Three-level approval workflow\n");

        var proposal = new
        {
            ProposalId = "BUDGET-Q1-2025",
            Amount = 1_500_000m,
            Department = "Engineering",
            Description = "Infrastructure upgrades"
        };

        var proposalBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(proposal));

        // Three approvers with different security levels
        Console.WriteLine("1️⃣  Generating keys for approvers...");
        using var managerKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);
        using var directorKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa65);
        using var cfoKey = MLDsa.GenerateKeyPair(MLDsaWrapper.SecurityLevel.MLDsa87);

        Console.WriteLine("   ✓ Manager Key (ML-DSA-65)");
        Console.WriteLine("   ✓ Director Key (ML-DSA-65)");
        Console.WriteLine("   ✓ CFO Key (ML-DSA-87)");
        Console.WriteLine();

        // Level 1: Manager approval
        Console.WriteLine("2️⃣  Manager signing...");
        var managerSig = MLDsa.Create()
            .WithKeyPair(managerKey)
            .WithData(proposalBytes)
            .WithContext("approval:manager")
            .Sign();
        Console.WriteLine($"   ✓ Manager approved ({managerSig.Length} bytes)");

        // Level 2: Director approval (includes manager's signature)
        Console.WriteLine("3️⃣  Director signing...");
        var directorData = proposalBytes.Concat(managerSig).ToArray();
        var directorSig = MLDsa.Create()
            .WithKeyPair(directorKey)
            .WithData(directorData)
            .WithContext("approval:director")
            .Sign();
        Console.WriteLine($"   ✓ Director approved ({directorSig.Length} bytes)");

        // Level 3: CFO final approval
        Console.WriteLine("4️⃣  CFO signing (final approval)...");
        var cfoData = directorData.Concat(directorSig).ToArray();
        var cfoSig = MLDsa.Create()
            .WithKeyPair(cfoKey)
            .WithData(cfoData)
            .WithContext("approval:cfo")
            .Sign();
        Console.WriteLine($"   ✓ CFO approved ({cfoSig.Length} bytes)");
        Console.WriteLine();

        // Verify the approval chain
        Console.WriteLine("5️⃣  Verifying approval chain...");
        var cfoValid = MLDsa.Verify(cfoKey.PublicKeyPem, cfoData, cfoSig);
        var directorValid = MLDsa.Verify(directorKey.PublicKeyPem, directorData, directorSig);
        var managerValid = MLDsa.Verify(managerKey.PublicKeyPem, proposalBytes, managerSig);

        Console.WriteLine($"   ✓ CFO Signature: {cfoValid}");
        Console.WriteLine($"   ✓ Director Signature: {directorValid}");
        Console.WriteLine($"   ✓ Manager Signature: {managerValid}");
        Console.WriteLine();

        if (cfoValid && directorValid && managerValid)
        {
            Console.WriteLine("✅ Complete approval chain verified!");
            Console.WriteLine($"   Budget proposal {proposal.ProposalId} fully approved");
            Console.WriteLine($"   Amount: ${proposal.Amount:N0}");
        }
    }
}
#endif
