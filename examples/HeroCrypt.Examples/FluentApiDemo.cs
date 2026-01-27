using System.Security.Cryptography;
using System.Text;

namespace HeroCrypt.Examples;

/// <summary>
/// Demonstrates HeroCrypt's fluent API with text encoding convenience methods.
/// Shows best practices for working with Hex, Base64, and Base64Url formats.
/// </summary>
public static class FluentApiDemo
{
    public static async Task RunAsync()
    {
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine("HeroCrypt Fluent API Demo - Text Encoding");
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine();

        // 1. Encryption with Text Output
        await EncryptionWithTextEncodingAsync();

        // 2. Decryption from Text Input
        await DecryptionFromTextAsync();

        // 3. Password Hashing for Database Storage
        await PasswordHashingWithTextStorageAsync();

        // 4. API Request Signing with Base64Url
        await ApiSigningWithBase64UrlAsync();

        // 5. Key Management with Text Formats
        await KeyManagementDemoAsync();

        // 6. Data Hashing with Text Output
        await DataHashingDemoAsync();

        // 7. Keyed Hashing (HMAC) for Message Authentication
        await KeyedHashingDemoAsync();
    }

    /// <summary>
    /// Shows how to encrypt data and get results in text formats.
    /// </summary>
    private static async Task EncryptionWithTextEncodingAsync()
    {
        Console.WriteLine("1. Encryption with Text Encoding");
        Console.WriteLine("-".PadRight(60, '-'));

        var secretMessage = "This is sensitive data that needs protection.";
        Console.WriteLine($"Original: {secretMessage}");
        Console.WriteLine();

        // Encrypt using fluent API with random key
        using var encryptor = HeroCryptBuilder.Encrypt()
            .WithChaCha20Poly1305()
            .WithRandomKey();

        var result = encryptor.Encrypt(secretMessage);

        // Get key for storage (choose format based on use case)
        Console.WriteLine("Encryption Key Formats:");
        Console.WriteLine($"  Hex:       {encryptor.GetKeyAsHex()}");
        Console.WriteLine($"  Base64:    {encryptor.GetKeyAsBase64()}");
        Console.WriteLine($"  Base64Url: {encryptor.GetKeyAsBase64Url()}");
        Console.WriteLine();

        // Get ciphertext in various formats
        Console.WriteLine("Ciphertext Formats:");
        Console.WriteLine($"  Hex:       {result.CiphertextAsHex[..60]}...");
        Console.WriteLine($"  Base64:    {result.CiphertextAsBase64}");
        Console.WriteLine($"  Base64Url: {result.CiphertextAsBase64Url}");
        Console.WriteLine();

        // Get nonce (needed for decryption)
        Console.WriteLine("Nonce Formats:");
        Console.WriteLine($"  Hex:       {result.NonceAsHex}");
        Console.WriteLine($"  Base64:    {result.NonceAsBase64}");
        Console.WriteLine($"  Base64Url: {result.NonceAsBase64Url}");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    /// <summary>
    /// Shows how to decrypt data from text-encoded input.
    /// </summary>
    private static async Task DecryptionFromTextAsync()
    {
        Console.WriteLine("2. Decryption from Text Input");
        Console.WriteLine("-".PadRight(60, '-'));

        // First, create some encrypted data
        var originalMessage = "Secret message for round-trip demo";

        using var encryptor = HeroCryptBuilder.Encrypt()
            .WithAesGcm()
            .WithRandomKey();

        var encrypted = encryptor.Encrypt(originalMessage);

        // Save as text (simulating database storage)
        var storedKey = encryptor.GetKeyAsBase64();
        var storedNonce = encrypted.NonceAsBase64;
        var storedCiphertext = encrypted.CiphertextAsBase64;

        Console.WriteLine("Stored Values (Base64):");
        Console.WriteLine($"  Key:        {storedKey}");
        Console.WriteLine($"  Nonce:      {storedNonce}");
        Console.WriteLine($"  Ciphertext: {storedCiphertext}");
        Console.WriteLine();

        // Later: Load from text and decrypt
        using var decryptor = HeroCryptBuilder.Decrypt()
            .WithAesGcm()
            .WithKeyFromBase64(storedKey)
            .WithNonceFromBase64(storedNonce);

        var decrypted = decryptor.DecryptFromBase64ToString(storedCiphertext);

        Console.WriteLine($"Decrypted: {decrypted}");
        Console.WriteLine($"Match: {originalMessage == decrypted}");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    /// <summary>
    /// Shows how to hash passwords and store them as text.
    /// </summary>
    private static async Task PasswordHashingWithTextStorageAsync()
    {
        Console.WriteLine("3. Password Hashing for Database Storage");
        Console.WriteLine("-".PadRight(60, '-'));

        var password = "MySecurePassword123!";
        Console.WriteLine($"Password: {password}");
        Console.WriteLine();

        // Hash password using KeyDerivationBuilder with Argon2id
        // Uses secure defaults: 3 iterations, 64MB memory, 4 parallelism
        using var kdf = HeroCryptBuilder.DeriveKey()
            .WithArgon2id()
            .WithPassword(password)
            .WithRandomSalt()
            .WithOutputLength(32);

        // Get salt and hash as text for database storage
        var saltHex = kdf.GetSaltAsHex();
        var hashHex = kdf.DeriveKeyToHex();

        Console.WriteLine("For Database Storage (Hex):");
        Console.WriteLine($"  Salt: {saltHex}");
        Console.WriteLine($"  Hash: {hashHex}");
        Console.WriteLine();

        // Verification: Load salt from hex, derive hash, compare
        Console.WriteLine("Verification:");
        using var verifier = HeroCryptBuilder.DeriveKey()
            .WithArgon2id()
            .WithPassword(password)
            .WithSaltFromHex(saltHex)
            .WithOutputLength(32);

        var verifyHash = verifier.DeriveKeyToHex();
        Console.WriteLine($"  Computed: {verifyHash}");
        Console.WriteLine($"  Match: {hashHex == verifyHash}");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    /// <summary>
    /// Shows how to sign API requests using Base64Url (URL-safe).
    /// </summary>
    private static async Task ApiSigningWithBase64UrlAsync()
    {
        Console.WriteLine("4. API Request Signing with Base64Url");
        Console.WriteLine("-".PadRight(60, '-'));

        // Simulate API request payload
        var apiRequest = new
        {
            endpoint = "/api/v1/transfer",
            timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            amount = 100.50,
            currency = "USD"
        };

        var payload = System.Text.Json.JsonSerializer.Serialize(apiRequest);
        Console.WriteLine($"API Request: {payload}");
        Console.WriteLine();

        // Generate a secure key for HMAC signing
        var secretKeyBytes = RandomNumberGenerator.GetBytes(32);
        var secretKeyBase64Url = Convert.ToBase64String(secretKeyBytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        // Create HMAC signature using Base64Url (safe for headers/URLs)
        using var signer = HeroCryptBuilder.Sign()
            .WithHmacSha256()
            .WithKey(secretKeyBytes);

        var signature = signer.SignToBase64Url(payload);

        Console.WriteLine("Request Signing (Base64Url - URL-safe):");
        Console.WriteLine($"  Secret Key:  {secretKeyBase64Url}");
        Console.WriteLine($"  Signature:   {signature}");
        Console.WriteLine();

        // Server-side verification
        using var verifier = HeroCryptBuilder.Verify()
            .WithHmacSha256()
            .WithKeyFromBase64Url(secretKeyBase64Url)
            .WithSignatureFromBase64Url(signature);

        var isValid = verifier.Verify(payload);
        Console.WriteLine($"Server Verification: {(isValid ? "VALID" : "INVALID")}");
        Console.WriteLine();

        // Show why Base64Url is preferred for URLs
        Console.WriteLine("Base64Url vs Base64 Comparison:");
        var base64Sig = signer.SignToBase64(payload);
        var base64UrlSig = signer.SignToBase64Url(payload);
        Console.WriteLine($"  Base64:    {base64Sig}");
        Console.WriteLine($"  Base64Url: {base64UrlSig}");
        Console.WriteLine("  Note: Base64Url uses '-' and '_' (URL-safe), no '=' padding");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    /// <summary>
    /// Shows key management patterns with text encoding.
    /// </summary>
    private static async Task KeyManagementDemoAsync()
    {
        Console.WriteLine("5. Key Management with Text Formats");
        Console.WriteLine("-".PadRight(60, '-'));

        // Generate a master key using HKDF from random input
        var masterSeed = RandomNumberGenerator.GetBytes(32);

        using var masterKdf = HeroCryptBuilder.DeriveKey()
            .WithHkdfSha256()
            .WithPassword(masterSeed)  // HKDF uses IKM (input key material)
            .WithSalt(Encoding.UTF8.GetBytes("my-application"))
            .WithInfo("master-key-v1")
            .WithOutputLength(32);

        var masterKeyHex = masterKdf.DeriveKeyToHex();
        Console.WriteLine($"Master Key (Hex): {masterKeyHex}");
        Console.WriteLine();

        // Derive purpose-specific keys from master
        var masterKeyBytes = Convert.FromHexString(masterKeyHex);

        using var encryptionKdf = HeroCryptBuilder.DeriveKey()
            .WithHkdfSha256()
            .WithPassword(masterKeyBytes)
            .WithInfo("encryption-key")
            .WithOutputLength(32);

        using var signingKdf = HeroCryptBuilder.DeriveKey()
            .WithHkdfSha256()
            .WithPassword(masterKeyBytes)
            .WithInfo("signing-key")
            .WithOutputLength(32);

        Console.WriteLine("Derived Keys:");
        Console.WriteLine($"  Encryption: {encryptionKdf.DeriveKeyToBase64()}");
        Console.WriteLine($"  Signing:    {signingKdf.DeriveKeyToBase64()}");
        Console.WriteLine();

        // Format Selection Guide
        Console.WriteLine("Format Selection Guide:");
        Console.WriteLine("  Hex       - Best for: Logs, debugging, config files");
        Console.WriteLine("              Size: +100% (32 bytes -> 64 chars)");
        Console.WriteLine("  Base64    - Best for: Database, JSON, file storage");
        Console.WriteLine("              Size: +33% (32 bytes -> 44 chars)");
        Console.WriteLine("  Base64Url - Best for: URLs, query strings, JWTs, APIs");
        Console.WriteLine("              Size: +33% (32 bytes -> 43 chars, no padding)");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    /// <summary>
    /// Shows how to compute data hashes in various text formats.
    /// </summary>
    private static async Task DataHashingDemoAsync()
    {
        Console.WriteLine("6. Data Hashing with Text Output");
        Console.WriteLine("-".PadRight(60, '-'));

        var document = "Important document content that needs integrity verification.";
        Console.WriteLine($"Document: {document}");
        Console.WriteLine();

        // Hash using SHA-256
        using var sha256Hasher = HeroCryptBuilder.Hash()
            .WithSha256();

        Console.WriteLine("SHA-256 Hash Formats:");
        Console.WriteLine($"  Hex:       {sha256Hasher.ComputeHashToHex(document)}");
        Console.WriteLine($"  Base64:    {sha256Hasher.ComputeHashToBase64(document)}");
        Console.WriteLine($"  Base64Url: {sha256Hasher.ComputeHashToBase64Url(document)}");
        Console.WriteLine();

        // Hash using Blake2b (faster alternative)
        using var blake2bHasher = HeroCryptBuilder.Hash()
            .WithBlake2b256();

        Console.WriteLine("Blake2b-256 Hash Formats:");
        Console.WriteLine($"  Hex:       {blake2bHasher.ComputeHashToHex(document)}");
        Console.WriteLine($"  Base64:    {blake2bHasher.ComputeHashToBase64(document)}");
        Console.WriteLine($"  Base64Url: {blake2bHasher.ComputeHashToBase64Url(document)}");
        Console.WriteLine();

        // File integrity verification example
        Console.WriteLine("File Integrity Verification:");
        var expectedHashHex = sha256Hasher.ComputeHashToHex(document);
        Console.WriteLine($"  Expected: {expectedHashHex}");

        // Simulate file verification
        var actualHashHex = sha256Hasher.ComputeHashToHex(document);
        var integrityValid = expectedHashHex == actualHashHex;
        Console.WriteLine($"  Actual:   {actualHashHex}");
        Console.WriteLine($"  Integrity: {(integrityValid ? "VALID" : "CORRUPTED")}");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    /// <summary>
    /// Shows keyed hashing (HMAC) for message authentication with text encoding.
    /// </summary>
    private static async Task KeyedHashingDemoAsync()
    {
        Console.WriteLine("7. Keyed Hashing (HMAC) for Message Authentication");
        Console.WriteLine("-".PadRight(60, '-'));

        var message = "Transfer $1000 to account 12345";
        Console.WriteLine($"Message: {message}");
        Console.WriteLine();

        // Generate a secret key for HMAC
        var secretKey = RandomNumberGenerator.GetBytes(32);
        var secretKeyHex = Convert.ToHexString(secretKey).ToLowerInvariant();
        Console.WriteLine($"Secret Key (Hex): {secretKeyHex}");
        Console.WriteLine();

        // HMAC-SHA256 using HashBuilder with key
        using var hmacHasher = HeroCryptBuilder.Hash()
            .WithSha256()
            .WithKey(secretKey);

        Console.WriteLine("HMAC-SHA256 (Message Authentication Code):");
        Console.WriteLine($"  Hex:       {hmacHasher.ComputeHashToHex(message)}");
        Console.WriteLine($"  Base64:    {hmacHasher.ComputeHashToBase64(message)}");
        Console.WriteLine($"  Base64Url: {hmacHasher.ComputeHashToBase64Url(message)}");
        Console.WriteLine();

        // Verification: Load key from hex and verify MAC
        Console.WriteLine("Verification (loading key from hex):");
        using var verifyHasher = HeroCryptBuilder.Hash()
            .WithSha256()
            .WithKeyFromHex(secretKeyHex);

        var expectedMac = hmacHasher.ComputeHashToHex(message);
        var actualMac = verifyHasher.ComputeHashToHex(message);
        Console.WriteLine($"  Expected MAC: {expectedMac}");
        Console.WriteLine($"  Computed MAC: {actualMac}");
        Console.WriteLine($"  Authentic: {(expectedMac == actualMac ? "YES" : "NO")}");
        Console.WriteLine();

        // Blake2b keyed mode (native, not HMAC)
        using var blake2KeyedHasher = HeroCryptBuilder.Hash()
            .WithBlake2b256()
            .WithKey(secretKey);

        Console.WriteLine("Blake2b-256 Keyed (native keyed mode, not HMAC):");
        Console.WriteLine($"  Hex:       {blake2KeyedHasher.ComputeHashToHex(message)}");
        Console.WriteLine($"  Base64:    {blake2KeyedHasher.ComputeHashToBase64(message)}");
        Console.WriteLine();

        Console.WriteLine("Note: Use keyed hashing for message authentication codes (MACs).");
        Console.WriteLine("      HMAC-SHA256 is widely compatible; Blake2b keyed mode is faster.");
        Console.WriteLine();

        await Task.CompletedTask;
    }
}
