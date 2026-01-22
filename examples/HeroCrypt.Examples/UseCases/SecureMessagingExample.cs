using System.Text;
using HeroCrypt;

namespace HeroCrypt.Examples.UseCases;

/// <summary>
/// Demonstrates an End-to-End Encrypted messaging flow between two parties.
/// </summary>
public static class SecureMessagingExample
{
    public static async Task RunAsync()
    {
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine("Secure Messaging Example - Hybrid Encryption");
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine();

        // 1. Setup Phase: Users generate their Key Pairs
        Console.WriteLine("1. Setup: Generating RSA Key Pairs for Alice and Bob...");
        
        // Alice generates her key pair
        var aliceBuilder = HeroCryptBuilder.HybridEncryption();
        var aliceKeys = aliceBuilder.GenerateRsaKeyPair();
        Console.WriteLine($"Alice's Public Key: {Convert.ToBase64String(aliceKeys.PublicKey.ExportSubjectPublicKeyInfo())[..30]}...");

        // Bob generates his key pair
        var bobBuilder = HeroCryptBuilder.HybridEncryption();
        var bobKeys = bobBuilder.GenerateRsaKeyPair();
        Console.WriteLine($"Bob's Public Key:   {Convert.ToBase64String(bobKeys.PublicKey.ExportSubjectPublicKeyInfo())[..30]}...");
        Console.WriteLine();

        // 2. Message Exchange: Alice sends a message to Bob
        Console.WriteLine("2. Alice sends a secure message to Bob");
        string originalMessage = "Hello Bob! This is a secret message that only you can read.";
        Console.WriteLine($"Original Message: \"{originalMessage}\"");

        // Alice encrypts the message using Bob's Public Key
        // Hybrid encryption generates a random symmetric key, encrypts the message with it,
        // and encrypts the symmetric key with the recipient's RSA public key.
        var encryptedPacket = aliceBuilder.Encrypt(
            Encoding.UTF8.GetBytes(originalMessage), 
            bobKeys.PublicKey // Alice uses Bob's public key
        );

        Console.WriteLine($"Encrypted Packet Size: {encryptedPacket.Length} bytes");
        Console.WriteLine($"Encrypted Data (Base64): {Convert.ToBase64String(encryptedPacket)[..50]}...");
        Console.WriteLine();

        // 3. Decryption: Bob receives and decrypts the message
        Console.WriteLine("3. Bob receives and decrypts the message");
        
        try
        {
            // Bob decrypts using his Private Key
            var decryptedBytes = bobBuilder.Decrypt(
                encryptedPacket, 
                bobKeys.PrivateKey // Bob uses his private key
            );
            
            string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine($"Decrypted Message: \"{decryptedMessage}\"");

            if (originalMessage == decryptedMessage)
            {
                Console.WriteLine("SUCCESS: Message integrity verified.");
            }
            else
            {
                Console.WriteLine("ERROR: Message content mismatch!");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Decryption Failed: {ex.Message}");
        }

        Console.WriteLine();

        // 4. Response: Bob replies to Alice
        Console.WriteLine("4. Bob replies to Alice");
        string replyMessage = "Hi Alice! message received loud and clear.";
        
        var replyPacket = bobBuilder.Encrypt(
            Encoding.UTF8.GetBytes(replyMessage),
            aliceKeys.PublicKey // Bob uses Alice's public key
        );

        var aliceDecryptedFromBob = aliceBuilder.Decrypt(
            replyPacket,
            aliceKeys.PrivateKey // Alice uses her private key
        );

        Console.WriteLine($"Alice Decrypted Reply: \"{Encoding.UTF8.GetString(aliceDecryptedFromBob)}\"");
        Console.WriteLine();

        await Task.CompletedTask;
    }
}
