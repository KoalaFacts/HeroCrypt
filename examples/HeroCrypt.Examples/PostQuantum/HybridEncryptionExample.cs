#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.Primitives.PostQuantum.Kyber;

namespace HeroCrypt.Examples.PostQuantum;

/// <summary>
/// Demonstrates hybrid encryption using ML-KEM for key exchange and AES-GCM for data encryption
/// This is the recommended approach for quantum-resistant data encryption
/// </summary>
public static class HybridEncryptionExample
{
    public static void Run()
    {
        Console.WriteLine("=== Hybrid Encryption with ML-KEM + AES-GCM ===\n");

        if (!MLKemWrapper.IsSupported())
        {
            Console.WriteLine("⚠️  ML-KEM is not supported on this platform.");
            Console.WriteLine("   Requires .NET 10+ with Windows CNG PQC support or OpenSSL 3.5+");
            return;
        }

        // Scenario: Alice wants to send encrypted data to Bob
        Console.WriteLine("📧 Scenario: Alice sends encrypted message to Bob\n");

        // Step 1: Bob generates a key pair and shares his public key
        Console.WriteLine("1️⃣  Bob generates ML-KEM key pair...");
        using var bobKeyPair = HeroCryptBuilder.PostQuantum.MLKem.Create()
            .WithSecurityBits(256)  // High security (ML-KEM-1024)
            .GenerateKeyPair();

        Console.WriteLine($"   ✓ Security Level: {bobKeyPair.Level}");
        Console.WriteLine($"   ✓ Public Key Length: {bobKeyPair.PublicKeyPem.Length} chars");
        Console.WriteLine();

        // Bob shares his public key with Alice
        string bobPublicKey = bobKeyPair.PublicKeyPem;

        // Step 2: Alice creates a message
        var secretMessage = "Top secret project details: Launch on 2025-12-01";
        Console.WriteLine($"2️⃣  Alice's message: \"{secretMessage}\"");
        Console.WriteLine();

        // Step 3: Alice encapsulates a shared secret using Bob's public key
        Console.WriteLine("3️⃣  Alice encapsulates shared secret using Bob's public key...");
        using var encapsulation = HeroCryptBuilder.PostQuantum.MLKem.Create()
            .WithPublicKey(bobPublicKey)
            .Encapsulate();

        Console.WriteLine($"   ✓ Shared Secret: {encapsulation.SharedSecret.Length} bytes");
        Console.WriteLine($"   ✓ Ciphertext: {encapsulation.Ciphertext.Length} bytes");
        Console.WriteLine();

        // Step 4: Alice encrypts the message using AES-GCM with the shared secret
        Console.WriteLine("4️⃣  Alice encrypts message with AES-256-GCM...");
        var messageBytes = Encoding.UTF8.GetBytes(secretMessage);

        byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);

        byte[] encryptedMessage = new byte[messageBytes.Length];
        byte[] authTag = new byte[AesGcm.TagByteSizes.MaxSize];

        using (var aes = new AesGcm(encapsulation.SharedSecret, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Encrypt(nonce, messageBytes, encryptedMessage, authTag);
        }

        Console.WriteLine($"   ✓ Encrypted: {Convert.ToBase64String(encryptedMessage)}");
        Console.WriteLine($"   ✓ Auth Tag: {Convert.ToBase64String(authTag)}");
        Console.WriteLine();

        // Step 5: Alice sends to Bob:
        // - ML-KEM ciphertext (encapsulation.Ciphertext)
        // - AES-GCM nonce
        // - Encrypted message
        // - Authentication tag
        Console.WriteLine("5️⃣  Alice sends to Bob:");
        Console.WriteLine($"   • ML-KEM Ciphertext: {encapsulation.Ciphertext.Length} bytes");
        Console.WriteLine($"   • Nonce: {nonce.Length} bytes");
        Console.WriteLine($"   • Encrypted Message: {encryptedMessage.Length} bytes");
        Console.WriteLine($"   • Auth Tag: {authTag.Length} bytes");
        Console.WriteLine($"   Total: {encapsulation.Ciphertext.Length + nonce.Length + encryptedMessage.Length + authTag.Length} bytes");
        Console.WriteLine();

        // Step 6: Bob decapsulates to recover the shared secret
        Console.WriteLine("6️⃣  Bob decapsulates to recover shared secret...");
        var recoveredSecret = bobKeyPair.Decapsulate(encapsulation.Ciphertext);

        Console.WriteLine($"   ✓ Recovered Secret: {recoveredSecret.Length} bytes");
        Console.WriteLine($"   ✓ Secrets Match: {encapsulation.SharedSecret.SequenceEqual(recoveredSecret)}");
        Console.WriteLine();

        // Step 7: Bob decrypts the message
        Console.WriteLine("7️⃣  Bob decrypts message with AES-256-GCM...");
        byte[] decryptedMessage = new byte[encryptedMessage.Length];

        using (var aes = new AesGcm(recoveredSecret, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Decrypt(nonce, encryptedMessage, authTag, decryptedMessage);
        }

        var recoveredMessage = Encoding.UTF8.GetString(decryptedMessage);
        Console.WriteLine($"   ✓ Decrypted: \"{recoveredMessage}\"");
        Console.WriteLine();

        // Verification
        Console.WriteLine("✅ Success! End-to-end encryption verified:");
        Console.WriteLine($"   Original:  \"{secretMessage}\"");
        Console.WriteLine($"   Recovered: \"{recoveredMessage}\"");
        Console.WriteLine($"   Match: {secretMessage == recoveredMessage}");
        Console.WriteLine();

        // Security notes
        Console.WriteLine("🔒 Security Notes:");
        Console.WriteLine("   • ML-KEM provides quantum-resistant key exchange");
        Console.WriteLine("   • AES-256-GCM provides authenticated encryption");
        Console.WriteLine("   • Combined: Hybrid post-quantum secure encryption");
        Console.WriteLine("   • Protects against 'harvest now, decrypt later' attacks");
    }

    /// <summary>
    /// Demonstrates encrypting multiple messages to the same recipient
    /// </summary>
    public static void RunMultipleMessages()
    {
        Console.WriteLine("\n=== Multiple Message Encryption ===\n");

        if (!MLKemWrapper.IsSupported())
            return;

        // Recipient generates key pair once
        using var recipientKey = HeroCryptBuilder.PostQuantum.MLKem.GenerateKeyPair();

        var messages = new[]
        {
            "Message 1: Status update",
            "Message 2: Financial data",
            "Message 3: Technical specs"
        };

        Console.WriteLine($"Encrypting {messages.Length} messages to same recipient:\n");

        var encryptedPackages = new List<(byte[] kemCiphertext, byte[] nonce, byte[] encrypted, byte[] tag)>();

        // Encrypt each message with a fresh shared secret
        foreach (var message in messages)
        {
            // New key exchange for each message
            using var enc = HeroCrypt.Cryptography.Primitives.PostQuantum.Kyber.MLKem.Create()
                .WithPublicKey(recipientKey.PublicKeyPem)
                .Encapsulate();

            var msgBytes = Encoding.UTF8.GetBytes(message);
            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);

            byte[] encrypted = new byte[msgBytes.Length];
            byte[] tag = new byte[16];

            using var aes = new AesGcm(enc.SharedSecret, 16);
            aes.Encrypt(nonce, msgBytes, encrypted, tag);

            encryptedPackages.Add((enc.Ciphertext, nonce, encrypted, tag));
            Console.WriteLine($"✓ Encrypted: \"{message}\"");
        }

        Console.WriteLine($"\nDecrypting all messages...\n");

        // Decrypt all messages
        for (int i = 0; i < encryptedPackages.Count; i++)
        {
            var package = encryptedPackages[i];
            var secret = recipientKey.Decapsulate(package.kemCiphertext);

            byte[] decrypted = new byte[package.encrypted.Length];
            using var aes = new AesGcm(secret, 16);
            aes.Decrypt(package.nonce, package.encrypted, package.tag, decrypted);

            var recovered = Encoding.UTF8.GetString(decrypted);
            Console.WriteLine($"✓ Decrypted: \"{recovered}\"");
            Console.WriteLine($"  Match: {recovered == messages[i]}");
        }
    }
}
#endif
