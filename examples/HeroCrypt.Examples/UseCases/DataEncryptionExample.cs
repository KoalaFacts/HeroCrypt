using HeroCrypt.Cryptography.Symmetric;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HeroCrypt.Examples.UseCases;

/// <summary>
/// Demonstrates secure data encryption using ChaCha20-Poly1305 AEAD
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
        await KeyDerivationExample();
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
        Console.WriteLine($"Generated DEK: {Convert.ToBase64String(dek)}");

        // Generate a unique nonce for this encryption
        var nonce = new byte[12];  // 96-bit nonce for ChaCha20-Poly1305
        RandomNumberGenerator.Fill(nonce);
        Console.WriteLine($"Generated nonce: {Convert.ToBase64String(nonce)}");

        // Use user ID as associated data for context binding
        var associatedData = Encoding.UTF8.GetBytes(userData.UserId);

        // Encrypt the data
        var plaintext = Encoding.UTF8.GetBytes(jsonData);
        var ciphertext = ChaCha20Poly1305Cipher.Encrypt(
            plaintext,
            dek,
            nonce,
            associatedData
        );

        Console.WriteLine($"Encrypted data: {Convert.ToBase64String(ciphertext)}");
        Console.WriteLine($"Ciphertext size: {ciphertext.Length} bytes (original: {plaintext.Length} bytes)");
        Console.WriteLine();

        // Decrypt the data
        var decrypted = ChaCha20Poly1305Cipher.Decrypt(
            ciphertext,
            dek,
            nonce,
            associatedData
        );

        var decryptedJson = Encoding.UTF8.GetString(decrypted);
        var decryptedData = JsonSerializer.Deserialize<UserData>(decryptedJson);

        Console.WriteLine("Decrypted data:");
        Console.WriteLine($"UserId: {decryptedData?.UserId}");
        Console.WriteLine($"Email: {decryptedData?.Email}");
        Console.WriteLine($"Credit Card: {decryptedData?.CreditCard}");
        Console.WriteLine($"SSN: {decryptedData?.SSN}");
        Console.WriteLine();

        // In production, you would:
        // 1. Encrypt the DEK with a master key (KEK - Key Encryption Key)
        // 2. Store the encrypted DEK with the ciphertext
        // 3. Store the nonce with the ciphertext
        // 4. Never reuse the same nonce with the same key

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

        // Generate nonce
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        // Use filename as associated data
        var filename = "sensitive-document.txt";
        var associatedData = Encoding.UTF8.GetBytes(filename);

        // Encrypt the file
        var encryptedFile = ChaCha20Poly1305Cipher.Encrypt(
            fileData,
            key,
            nonce,
            associatedData
        );

        Console.WriteLine($"Encrypted file size: {encryptedFile.Length} bytes");
        Console.WriteLine();

        // Create encrypted file package
        var filePackage = new EncryptedFilePackage
        {
            Filename = filename,
            Nonce = nonce,
            Ciphertext = encryptedFile,
            // In production, EncryptedKey would be the DEK encrypted with KEK
        };

        Console.WriteLine("File encrypted successfully!");
        Console.WriteLine($"Package: {filename}, Nonce: {Convert.ToBase64String(nonce)[..20]}...");
        Console.WriteLine();

        // Decrypt the file
        var decryptedFile = ChaCha20Poly1305Cipher.Decrypt(
            filePackage.Ciphertext,
            key,
            filePackage.Nonce,
            Encoding.UTF8.GetBytes(filePackage.Filename)
        );

        var decryptedContent = Encoding.UTF8.GetString(decryptedFile);
        Console.WriteLine($"Decrypted file content: {decryptedContent}");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    private static async Task KeyDerivationExample()
    {
        Console.WriteLine("3. Key Derivation for Encryption");
        Console.WriteLine("-".PadRight(60, '-'));

        // Master key (would be securely stored in KMS or HSM)
        var masterKey = new byte[32];
        RandomNumberGenerator.Fill(masterKey);
        Console.WriteLine($"Master key: {Convert.ToBase64String(masterKey)[..40]}...");

        // Derive separate keys for different purposes using HKDF
        using HeroCrypt.Cryptography.KeyDerivation;

        var encryptionKey = HkdfCore.DeriveKey(
            masterKey,
            keyLength: 32,
            info: Encoding.UTF8.GetBytes("encryption-key-v1"),
            salt: null
        );

        var authenticationKey = HkdfCore.DeriveKey(
            masterKey,
            keyLength: 32,
            info: Encoding.UTF8.GetBytes("authentication-key-v1"),
            salt: null
        );

        Console.WriteLine($"Derived encryption key: {Convert.ToBase64String(encryptionKey)[..40]}...");
        Console.WriteLine($"Derived authentication key: {Convert.ToBase64String(authenticationKey)[..40]}...");
        Console.WriteLine();

        Console.WriteLine("✅ Best Practices:");
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
    public byte[] Nonce { get; set; } = Array.Empty<byte>();
    public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
    public byte[]? EncryptedKey { get; set; }  // DEK encrypted with KEK
}
