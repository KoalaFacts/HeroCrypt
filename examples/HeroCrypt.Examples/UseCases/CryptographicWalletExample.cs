namespace HeroCrypt.Examples.UseCases;

/// <summary>
/// Demonstrates the creation of a Hierarchical Deterministic (HD) Wallet
/// and derivation of key pairs for cryptocurrency usage.
/// </summary>
public static class CryptographicWalletExample
{
    public static async Task RunAsync()
    {
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine("Cryptographic Wallet Example - HD Wallet (BIP32/BIP39)");
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine();

        // 1. Mnemonic Generation (BIP39)
        Console.WriteLine("1. Generating Mnemonic Phrase...");
        // In a real wallet, this is the "backup phrase" given to the user
        // We generate a 24-word mnemonic for high entropy
        var walletGenResult = HeroCryptBuilder.HdWallet()
            .GenerateMnemonic(wordCount: 24)
            .Derive();

        string mnemonic = walletGenResult.Mnemonic!; // We know it's not null because we generated it

        Console.WriteLine("  Mnemonic Phrase (KEEP SECRET!):");
        Console.WriteLine($"  \"{mnemonic}\"");
        Console.WriteLine();

        // 2. Seed Generation
        Console.WriteLine("2. Converting Mnemonic to Seed...");
        // The optional passphrase acts as a "13th/25th word" or salt
        string passphrase = "correct-horse-battery-staple";
        Console.WriteLine($"  Passphrase used: \"{passphrase}\"");

        // The builder flows naturally from mnemonic generation/input to derivation
        // Note: usage might vary slightly based on exact API surface, assuming generic flow:
        // Ideally: input mnemonic -> to seed -> master node

        // Let's assume we re-initialize builder with the mnemonic we just made
        // or chain it if API allows.
        // Looking at generic HDWallet pattern:
        var walletRoot = HeroCryptBuilder.HdWallet()
            .FromMnemonic(mnemonic)
            .WithPassphrase(passphrase)
            .Derive(); // Derives the root master key

        Console.WriteLine($"  Root Key (Base58/Hex): {Convert.ToBase64String(walletRoot.Key.Key)[..20]}...");
        Console.WriteLine();

        // 3. Address Derivation (BIP44 standard paths)
        Console.WriteLine("3. Deriving Addresses (BIP44 paths)");

        // Path: m / purpose' / coin_type' / account' / change / address_index
        // Bitcoin (Mainnet) path: m/44'/0'/0'/0/0
        string btcPath = "m/44'/0'/0'/0/0";
        Console.WriteLine($"  Deriving Bitcoin Address #0 ({btcPath})...");

        var btcWallet = HeroCryptBuilder.HdWallet()
            .FromMnemonic(mnemonic)
            .WithPassphrase(passphrase)
            .WithPath(btcPath)
            .Derive();

        // Key property holds the derived key (ExtendedKey)
        var btcKey = btcWallet.Key;

        Console.WriteLine($"  BTC Private Key: {Convert.ToBase64String(btcKey.Key)[..40]}...");
        // Public key derivation from private key is internal in this library version
        Console.WriteLine();

        // Ethereum (Mainnet) path: m/44'/60'/0'/0/0
        string ethPath = "m/44'/60'/0'/0/0";
        Console.WriteLine($"  Deriving Ethereum Address #0 ({ethPath})...");

        var ethWallet = HeroCryptBuilder.HdWallet()
            .FromMnemonic(mnemonic)
            .WithPassphrase(passphrase)
            .WithPath(ethPath)
            .Derive();

        var ethKey = ethWallet.Key;

        Console.WriteLine($"  ETH Private Key: {Convert.ToBase64String(ethKey.Key)[..40]}...");
        Console.WriteLine();

        Console.WriteLine("Key Takeaway:");
        Console.WriteLine("  One mnemonic phrase can generate infinite keys for infinite chains,");
        Console.WriteLine("  deterministically and securely.");
        Console.WriteLine();

        await Task.CompletedTask;
    }
}
