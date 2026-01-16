using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroCrypt.Primitives.Hkdf;

namespace HeroCrypt.Examples.UseCases;

/// <summary>
/// Demonstrates secure data encryption using the public fluent API.
/// </summary>
public static class DataEncryptionExample
{
    public static async Task RunAsync()
    {
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine("Data Encryption Example - ChaCha20-Poly1305");
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine();

        // Example 1: Encrypting user data
        await EncryptUserDataAsync();

        // Example 2: Encrypting files
        await EncryptFileAsync();

        // Example 3: Key derivation for encryption
        await KeyDerivationExampleAsync();
    }

    private static async Task EncryptUserDataAsync()
    {
        Console.WriteLine("1. Encrypting User Data");
        Console.WriteLine("-".PadRight(60, '-'));

        // Simulated user data
        var userData = new UserData
        {
            UserId = "user123",
            Email = "user@example.com",
            CreditCard = "1234-5678-9012-3456",
            SSN = "123-45-6789"
        };

        var jsonData = JsonSerializer.Serialize(userData, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        Console.WriteLine("Original data:");
        Console.WriteLine(jsonData);
        Console.WriteLine();

        // Generate a data encryption key (DEK)
        var dek = new byte[32];  // 256-bit key
        RandomNumberGenerator.Fill(dek);
        Console.WriteLine($"Generated DEK: {Convert.ToBase64String(dek)[..40]}...");

        // Use user ID as associated data for context binding
        var associatedData = Encoding.UTF8.GetBytes(userData.UserId);

        // Encrypt the data using the fluent API
        var plaintext = Encoding.UTF8.GetBytes(jsonData);
        var encryptionResult = HeroCryptBuilder.Encrypt()
            .WithChaCha20Poly1305()
            .WithKey(dek)
            .WithAssociatedData(associatedData)
            .Encrypt(plaintext);

        Console.WriteLine($"Encrypted data: {Convert.ToBase64String(encryptionResult.Ciphertext)[..60]}...");
        Console.WriteLine($"Ciphertext size: {encryptionResult.Ciphertext.Length} bytes (original: {plaintext.Length} bytes)");
        Console.WriteLine();

        // Decrypt the data using the captured nonce
        var decrypted = HeroCryptBuilder.Decrypt()
            .WithChaCha20Poly1305()
            .WithKey(dek)
            .WithNonce(encryptionResult.Nonce)
            .WithAssociatedData(associatedData)
            .Decrypt(encryptionResult.Ciphertext);

        var decryptedJson = Encoding.UTF8.GetString(decrypted);
        var decryptedData = JsonSerializer.Deserialize<UserData>(decryptedJson);

        Console.WriteLine("Decrypted data:");
        Console.WriteLine($"UserId: {decryptedData?.UserId}");
        Console.WriteLine($"Email: {decryptedData?.Email}");
        Console.WriteLine($"Credit Card: {decryptedData?.CreditCard}");
        Console.WriteLine($"SSN: {decryptedData?.SSN}");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    private static async Task EncryptFileAsync()
    {
        Console.WriteLine("2. Encrypting Files");
        Console.WriteLine("-".PadRight(60, '-'));

        // Simulate file data
        var fileContent = "This is sensitive file content that needs to be encrypted.";
        var fileData = Encoding.UTF8.GetBytes(fileContent);

        Console.WriteLine($"Original file content: {fileContent}");
        Console.WriteLine($"File size: {fileData.Length} bytes");
        Console.WriteLine();

        // Generate encryption key
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        // Use filename as associated data
        var filename = "sensitive-document.txt";
        var associatedData = Encoding.UTF8.GetBytes(filename);

        // Encrypt the file using fluent API
        var encryptedFile = HeroCryptBuilder.Encrypt()
            .WithChaCha20Poly1305()
            .WithKey(key)
            .WithAssociatedData(associatedData)
            .Encrypt(fileData);

        Console.WriteLine($"Encrypted file size: {encryptedFile.Ciphertext.Length} bytes");
        Console.WriteLine();

        // Create encrypted file package
        var filePackage = new EncryptedFilePackage
        {
            Filename = filename,
            Nonce = encryptedFile.Nonce,
            Ciphertext = encryptedFile.Ciphertext,
            // In production, EncryptedKey would be the DEK encrypted with KEK
        };

        Console.WriteLine("File encrypted successfully!");
        Console.WriteLine($"Package: {filename}, Nonce: {Convert.ToBase64String(filePackage.Nonce)[..20]}...");
        Console.WriteLine();

        // Decrypt the file
        var decryptedFile = HeroCryptBuilder.Decrypt()
            .WithChaCha20Poly1305()
            .WithKey(key)
            .WithNonce(filePackage.Nonce)
            .WithAssociatedData(Encoding.UTF8.GetBytes(filePackage.Filename))
            .Decrypt(filePackage.Ciphertext);

        var decryptedContent = Encoding.UTF8.GetString(decryptedFile);
        Console.WriteLine($"Decrypted file content: {decryptedContent}");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    private static async Task KeyDerivationExampleAsync()
    {
        Console.WriteLine("3. Key Derivation for Encryption");
        Console.WriteLine("-".PadRight(60, '-'));

        // Master key (would be securely stored in KMS or HSM)
        var masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        Console.WriteLine($"Master key: {Convert.ToBase64String(masterKey)[..40]}...");

        // Derive separate keys for different purposes using HKDF via primitive builder
        using var encryptionKdf = HkdfBuilder.Create()
            .WithInputKeyMaterial(masterKey)
            .WithInfo("encryption-key-v1")
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .WithOutputLength(32);
        var encryptionKey = encryptionKdf.DeriveKey();

        using var authKdf = HkdfBuilder.Create()
            .WithInputKeyMaterial(masterKey)
            .WithInfo("authentication-key-v1")
            .WithHashAlgorithm(HashAlgorithmName.SHA256)
            .WithOutputLength(32);
        var authenticationKey = authKdf.DeriveKey();

        Console.WriteLine($"Derived encryption key: {Convert.ToBase64String(encryptionKey)[..40]}...");
        Console.WriteLine($"Derived authentication key: {Convert.ToBase64String(authenticationKey)[..40]}...");
        Console.WriteLine();

        Console.WriteLine("Best Practices:");
        Console.WriteLine("  - Use separate keys for encryption and authentication");
        Console.WriteLine("  - Derive keys from a master key using HKDF");
        Console.WriteLine("  - Include context-specific info in key derivation");
        Console.WriteLine("  - Store master key in secure storage (KMS, HSM)");
        Console.WriteLine("  - Rotate keys periodically");
        Console.WriteLine("  - Never reuse nonces with the same key");
        Console.WriteLine();

        await Task.CompletedTask;
    }
}

/// <summary>
/// Represents sensitive user data
/// </summary>
public class UserData
{
    public string UserId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string CreditCard { get; set; } = string.Empty;
    public string SSN { get; set; } = string.Empty;
}

/// <summary>
/// Represents an encrypted file package
/// </summary>
public class EncryptedFilePackage
{
    public string Filename { get; set; } = string.Empty;
    public byte[] Nonce { get; set; } = [];
    public byte[] Ciphertext { get; set; } = [];
    public byte[]? EncryptedKey { get; set; }  // DEK encrypted with KEK
}
