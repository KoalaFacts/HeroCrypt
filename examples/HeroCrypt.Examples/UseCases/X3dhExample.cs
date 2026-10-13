using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Protocols.X3dh;
using Spectre.Console;

namespace HeroCrypt.Examples.UseCases;

/// <summary>Offline identity/prekey publication, X3DH handshake and ratchet messaging.</summary>
public static class X3dhExample
{
    /// <summary>Runs a complete in-memory handshake and replay-rejection example.</summary>
    public static Task RunAsync()
    {
        using var alice = X3dhIdentityKey.Generate();
        using var bob = X3dhIdentityKey.Generate();
        using var store = X3dhPreKeyStore.Create(bob);
        // Local trust for this offline example. A real application independently
        // verifies and pins these identities before accepting directory bundles.
        var expectedBob = bob.PublicKey; var expectedAlice = alice.PublicKey;
        var context = "HeroCrypt offline example / Alice / Bob"u8.ToArray();
        var published = store.GetBundle(store.GenerateOneTimePreKey()).ToBytes();
        var bundle = X3dhPreKeyBundle.FromBytes(published);
        if (!bundle.OneTimePreKeyId.HasValue || bundle.OneTimePreKeyPublicKey == null)
            throw new CryptographicException("This example requires four-DH with an OPK.");
        using var outgoing = X3dhHandshake.Initiate(alice, bundle, expectedBob, context, "Hello from Alice"u8, "conversation 42"u8);
        var delivered = X3dhInitialMessage.FromBytes(outgoing.InitialMessage.ToBytes());
        using var incoming = store.Accept(delivered, expectedAlice, context, "conversation 42"u8);
        var plaintext = incoming.Plaintext;
        try { AnsiConsole.WriteLine($"X3DH initial authenticated: {Encoding.UTF8.GetString(plaintext)}"); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        var reply = incoming.Session.Encrypt("Hello from Bob"u8);
        var replyPlaintext = outgoing.Session.Decrypt(reply);
        try { AnsiConsole.WriteLine($"Double Ratchet reply authenticated: {Encoding.UTF8.GetString(replyPlaintext)}"); }
        finally { CryptographicOperations.ZeroMemory(replyPlaintext); }
        try
        {
            using var replay = store.Accept(delivered, expectedAlice, context, "conversation 42"u8);
            throw new InvalidOperationException("Replay was unexpectedly accepted.");
        }
        catch (CryptographicException) { AnsiConsole.WriteLine("Handshake replay rejected; OPK consumed once."); }
        AnsiConsole.WriteLine("Offline trust only: verify peer identities externally. Store is in memory; no professional audit is claimed.");
        return Task.CompletedTask;
    }
}
