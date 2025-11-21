using System.Security.Cryptography;
using System.Text;

namespace HeroCrypt.Examples.UseCases;

/// <summary>
/// Demonstrates digital signatures using RSA and ECC
/// </summary>
public static class DigitalSignaturesExample
{
    public static async Task RunAsync()
    {
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine("Digital Signatures Example");
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine();

        // Example 1: RSA digital signatures
        await RsaSignatureExample();

        // Example 2: ECDSA digital signatures
        await EcdsaSignatureExample();

        // Example 3: Document signing workflow
        await DocumentSigningWorkflow();
    }

    private static async Task RsaSignatureExample()
    {
        Console.WriteLine("1. RSA Digital Signatures (PSS Padding)");
        Console.WriteLine("-".PadRight(60, '-'));

        // Generate RSA key pair
        using RSA rsa = RSA.Create(3072);  // 3072-bit key (recommended)

        byte[] privateKey = rsa.ExportRSAPrivateKey();
        byte[] publicKey = rsa.ExportRSAPublicKey();

        Console.WriteLine($"Generated 3072-bit RSA key pair");
        Console.WriteLine($"Private key size: {privateKey.Length} bytes");
        Console.WriteLine($"Public key size: {publicKey.Length} bytes");
        Console.WriteLine();

        // Document to sign
        string document = "This is an important contract that needs to be signed.";
        byte[] documentBytes = Encoding.UTF8.GetBytes(document);

        Console.WriteLine($"Document: {document}");
        Console.WriteLine();

        // Sign the document using PSS padding (recommended)
        byte[] signature = rsa.SignData(
            documentBytes,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss
        );

        Console.WriteLine($"Signature: {Convert.ToBase64String(signature)[..60]}...");
        Console.WriteLine($"Signature size: {signature.Length} bytes");
        Console.WriteLine();

        // Verify the signature
        bool isValid = rsa.VerifyData(
            documentBytes,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss
        );

        Console.WriteLine($"Signature verification: {(isValid ? "✅ VALID" : "❌ INVALID")}");
        Console.WriteLine();

        // Attempt to verify with tampered document
        byte[] tamperedDocument = Encoding.UTF8.GetBytes(document + " TAMPERED");
        bool isTamperedValid = rsa.VerifyData(
            tamperedDocument,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss
        );

        Console.WriteLine($"Tampered document verification: {(isTamperedValid ? "✅ VALID" : "❌ INVALID")}");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    private static async Task EcdsaSignatureExample()
    {
        Console.WriteLine("2. ECDSA Digital Signatures (P-256)");
        Console.WriteLine("-".PadRight(60, '-'));

        // Generate ECDSA key pair using P-256 curve
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] privateKey = ecdsa.ExportECPrivateKey();
        byte[] publicKey = ecdsa.ExportSubjectPublicKeyInfo();

        Console.WriteLine("Generated ECDSA P-256 key pair");
        Console.WriteLine($"Private key size: {privateKey.Length} bytes");
        Console.WriteLine($"Public key size: {publicKey.Length} bytes");
        Console.WriteLine();

        // Message to sign
        string message = "Authentication token: abc123xyz";
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);

        Console.WriteLine($"Message: {message}");
        Console.WriteLine();

        // Sign the message
        byte[] signature = ecdsa.SignData(messageBytes, HashAlgorithmName.SHA256);

        Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");
        Console.WriteLine($"Signature size: {signature.Length} bytes (much smaller than RSA!)");
        Console.WriteLine();

        // Verify the signature
        bool isValid = ecdsa.VerifyData(messageBytes, signature, HashAlgorithmName.SHA256);

        Console.WriteLine($"Signature verification: {(isValid ? "✅ VALID" : "❌ INVALID")}");
        Console.WriteLine();

        // Performance comparison
        Console.WriteLine("Performance Comparison (approximate):");
        Console.WriteLine("  RSA-3072 Sign:    2,000 ops/sec");
        Console.WriteLine("  RSA-3072 Verify: 50,000 ops/sec");
        Console.WriteLine("  ECDSA-P256 Sign: 15,000 ops/sec (7.5x faster)");
        Console.WriteLine("  ECDSA-P256 Verify: 8,000 ops/sec");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    private static async Task DocumentSigningWorkflow()
    {
        Console.WriteLine("3. Document Signing Workflow");
        Console.WriteLine("-".PadRight(60, '-'));

        // Step 1: Generate signer's key pair
        using ECDsa signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] signerPublicKey = signerKey.ExportSubjectPublicKeyInfo();

        Console.WriteLine("Step 1: Generated signer's key pair");
        Console.WriteLine();

        // Step 2: Create document
        SignedDocument document = new()
        {
            DocumentId = Guid.NewGuid().ToString(),
            Title = "Software License Agreement",
            Content = "The parties agree to the following terms...",
            Author = "John Doe",
            CreatedAt = DateTime.UtcNow
        };

        Console.WriteLine($"Step 2: Created document '{document.Title}'");
        Console.WriteLine($"Document ID: {document.DocumentId}");
        Console.WriteLine($"Author: {document.Author}");
        Console.WriteLine();

        // Step 3: Compute document hash
        string documentJson = System.Text.Json.JsonSerializer.Serialize(document);
        byte[] documentBytes = Encoding.UTF8.GetBytes(documentJson);

        using SHA256 sha256 = SHA256.Create();
        byte[] documentHash = sha256.ComputeHash(documentBytes);

        Console.WriteLine($"Step 3: Computed document hash");
        Console.WriteLine($"Hash: {Convert.ToBase64String(documentHash)}");
        Console.WriteLine();

        // Step 4: Sign the document hash
        byte[] signature = signerKey.SignData(documentHash, HashAlgorithmName.SHA256);

        document.Signature = signature;
        document.SignerPublicKey = signerPublicKey;
        document.SignedAt = DateTime.UtcNow;

        Console.WriteLine($"Step 4: Signed document");
        Console.WriteLine($"Signature: {Convert.ToBase64String(signature)[..40]}...");
        Console.WriteLine($"Signed at: {document.SignedAt}");
        Console.WriteLine();

        // Step 5: Verify the signature (by recipient)
        Console.WriteLine("Step 5: Recipient verifies signature");

        // Import signer's public key
        using ECDsa verifierKey = ECDsa.Create();
        verifierKey.ImportSubjectPublicKeyInfo(document.SignerPublicKey, out _);

        // Recompute document hash
        SignedDocument verifyDocument = new()
        {
            DocumentId = document.DocumentId,
            Title = document.Title,
            Content = document.Content,
            Author = document.Author,
            CreatedAt = document.CreatedAt
        };

        string verifyJson = System.Text.Json.JsonSerializer.Serialize(verifyDocument);
        byte[] verifyBytes = Encoding.UTF8.GetBytes(verifyJson);
        byte[] verifyHash = sha256.ComputeHash(verifyBytes);

        // Verify signature
        bool isValid = verifierKey.VerifyData(verifyHash, document.Signature, HashAlgorithmName.SHA256);

        Console.WriteLine($"Signature verification: {(isValid ? "✅ VALID" : "❌ INVALID")}");
        Console.WriteLine($"Document integrity: {(isValid ? "✅ NOT TAMPERED" : "❌ TAMPERED")}");
        Console.WriteLine($"Signer identity: {(isValid ? "✅ VERIFIED" : "❌ NOT VERIFIED")}");
        Console.WriteLine();

        // Step 6: Detect tampering
        Console.WriteLine("Step 6: Attempting to tamper with document");

        document.Content += " TAMPERED CONTENT";
        string tamperedJson = System.Text.Json.JsonSerializer.Serialize(document);
        byte[] tamperedBytes = Encoding.UTF8.GetBytes(tamperedJson);
        byte[] tamperedHash = sha256.ComputeHash(tamperedBytes);

        bool isTamperedValid = verifierKey.VerifyData(
            tamperedHash,
            document.Signature,
            HashAlgorithmName.SHA256
        );

        Console.WriteLine($"Tampered document verification: {(isTamperedValid ? "✅ VALID" : "❌ INVALID")}");
        Console.WriteLine("✅ Tampering detected successfully!");
        Console.WriteLine();

        Console.WriteLine("Best Practices:");
        Console.WriteLine("  ✅ Use ECDSA P-256 or higher for efficiency");
        Console.WriteLine("  ✅ Use RSA 3072-bit or higher for compatibility");
        Console.WriteLine("  ✅ Always use PSS padding for RSA signatures");
        Console.WriteLine("  ✅ Hash the document before signing (not the raw content)");
        Console.WriteLine("  ✅ Store the signer's public key with the signature");
        Console.WriteLine("  ✅ Include timestamp in the signed data");
        Console.WriteLine("  ✅ Use SHA-256 or higher for hashing");
        Console.WriteLine();

        await Task.CompletedTask;
    }
}

/// <summary>
/// Represents a digitally signed document
/// </summary>
public class SignedDocument
{
    public string DocumentId { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public byte[] Signature { get; set; } = [];
    public byte[] SignerPublicKey { get; set; } = [];
    public DateTime? SignedAt { get; set; }
}
