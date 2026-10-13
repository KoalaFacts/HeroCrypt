using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Protocols.DoubleRatchet;

namespace HeroCrypt.Examples.UseCases;

/// <summary>Demonstrates two-party Double Ratchet messaging and out-of-order delivery.</summary>
public static class DoubleRatchetExample
{
    /// <summary>Runs an in-memory example with an in-process trusted bootstrap.</summary>
    public static Task RunAsync()
    {
        Console.WriteLine("Double Ratchet: HeroCrypt two-party in-memory profile");
        Console.WriteLine("Demo bootstrap is trusted in-process; authenticate shared secret, peer key and context in real applications.");
        using var keyGenerator = HeroCryptBuilder.Curve25519();
        var (bobPrivate, bobPublic) = keyGenerator.GenerateKeyPair();
        var sharedSecret = RandomNumberGenerator.GetBytes(32);
        var context = Encoding.UTF8.GetBytes($"demo|alice|bob|{Guid.NewGuid():N}");
        try
        {
            using var alice = DoubleRatchetSession.CreateInitiator(sharedSecret, bobPublic, context);
            using var bob = DoubleRatchetSession.CreateResponder(sharedSecret, bobPrivate, context);
            var first = alice.Encrypt("First message"u8, "demo metadata"u8);
            var second = alice.Encrypt("Second message"u8, "demo metadata"u8);
            Print("Bob received out of order", bob.Decrypt(DoubleRatchetMessage.FromBytes(second.ToBytes()), "demo metadata"u8));
            Print("Bob received delayed", bob.Decrypt(first, "demo metadata"u8));
            Print("Alice received reply", alice.Decrypt(bob.Encrypt("Reply with a new DH ratchet key"u8)));
            Print("Bob received next turn", bob.Decrypt(alice.Encrypt("New Alice DH ratchet turn"u8)));
            try
            {
                bob.Decrypt(first, "demo metadata"u8);
                throw new InvalidOperationException("The example accepted a replay.");
            }
            catch (CryptographicException)
            {
                Console.WriteLine("Replay rejected.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(bobPrivate);
        }
        Console.WriteLine("This profile is unaudited, has no X3DH or Signal wire compatibility, and requires a fresh session after restart.");
        return Task.CompletedTask;
    }

    private static void Print(string label, byte[] plaintext)
    {
        try
        {
            Console.WriteLine($"{label}: {Encoding.UTF8.GetString(plaintext)}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
