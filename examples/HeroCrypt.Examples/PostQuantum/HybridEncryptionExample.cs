#if NET10_0_OR_GREATER
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.Primitives.PostQuantum.Kem;

namespace HeroCrypt.Examples.PostQuantum;

/// <summary>
/// Demonstrates ML-KEM key encapsulation combined with AES-GCM data encryption.
/// </summary>
public static class HybridEncryptionExample
{
    public static void Run()
    {
        Console.WriteLine("=== Hybrid Encryption: ML-KEM + AES-GCM ===");

        if (!MLKemWrapper.IsSupported())
        {
            Console.WriteLine("ML-KEM not supported on this platform.");
            return;
        }

        // Key pair for recipient (Bob)
        using var bobKeyPair = MLKemBuilder.Create()
            .WithSecurityBits(256)
            .GenerateKeyPair();

        const string message = "Top secret project details: Launch on 2025-12-01";
        var messageBytes = Encoding.UTF8.GetBytes(message);

        // Sender (Alice) encapsulates a shared secret for Bob
        using var encapsulation = MLKemBuilder.Create()
            .WithPublicKey(bobKeyPair.PublicKeyPem)
            .Encapsulate();

        // Encrypt with AES-GCM using shared secret
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(nonce);

        var encrypted = new byte[messageBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];

        using (var aes = new AesGcm(encapsulation.SharedSecret, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Encrypt(nonce, messageBytes, encrypted, tag);
        }

        // Recipient decapsulates and decrypts
        var recoveredSecret = bobKeyPair.Decapsulate(encapsulation.Ciphertext);
        var decrypted = new byte[encrypted.Length];
        using (var aes = new AesGcm(recoveredSecret, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Decrypt(nonce, encrypted, tag, decrypted);
        }

        var recoveredMessage = Encoding.UTF8.GetString(decrypted);
        Console.WriteLine($"Original:  {message}");
        Console.WriteLine($"Recovered: {recoveredMessage}");
        Console.WriteLine($"Match: {message == recoveredMessage}");
        Console.WriteLine();
    }

    public static void RunMultipleMessages()
    {
        Console.WriteLine("=== Hybrid Encryption: Multiple messages ===");

        if (!MLKemWrapper.IsSupported())
        {
            Console.WriteLine("ML-KEM not supported on this platform.");
            return;
        }

        using var recipientKey = MLKemBuilder.Create().GenerateKeyPair();
        string[] messages =
        [
            "Message 1: Status update",
            "Message 2: Financial data",
            "Message 3: Technical specs"
        ];

        var encryptedPackages = new List<(byte[] kemCiphertext, byte[] nonce, byte[] encrypted, byte[] tag)>();

        foreach (var message in messages)
        {
            using var enc = MLKemBuilder.Create()
                .WithPublicKey(recipientKey.PublicKeyPem)
                .Encapsulate();

            var msgBytes = Encoding.UTF8.GetBytes(message);
            var nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);

            var encrypted = new byte[msgBytes.Length];
            var tag = new byte[16];

            using var aes = new AesGcm(enc.SharedSecret, 16);
            aes.Encrypt(nonce, msgBytes, encrypted, tag);

            encryptedPackages.Add((enc.Ciphertext, nonce, encrypted, tag));
        }

        for (var i = 0; i < encryptedPackages.Count; i++)
        {
            var (kemCiphertext, nonce, encrypted, tag) = encryptedPackages[i];
            var secret = recipientKey.Decapsulate(kemCiphertext);

            var decrypted = new byte[encrypted.Length];
            using var aes = new AesGcm(secret, 16);
            aes.Decrypt(nonce, encrypted, tag, decrypted);

            var recovered = Encoding.UTF8.GetString(decrypted);
            Console.WriteLine($"Message {i + 1} match: {recovered == messages[i]}");
        }

        Console.WriteLine();
    }
}
#endif
