using HeroCrypt.Security;

namespace HeroCrypt.Protocols.HdWallet;

#if !NETSTANDARD2_0

/// <summary>
/// Result of HD wallet generation or derivation.
/// </summary>
public sealed class HdWalletResult
{
    /// <summary>
    /// The mnemonic phrase (if generated).
    /// </summary>
    public string? Mnemonic { get; }

    /// <summary>
    /// Owned seed bytes. Callers must clear this buffer when finished.
    /// </summary>
    public byte[] Seed { get; }

    /// <summary>
    /// The derived extended key.
    /// </summary>
    public Bip32HdWallet.ExtendedKey Key { get; }

    /// <summary>
    /// The derivation path used.
    /// </summary>
    public string? Path { get; }

    internal HdWalletResult(string? mnemonic, byte[] seed, Bip32HdWallet.ExtendedKey key, string? path)
    {
        Mnemonic = mnemonic;
        Seed = seed;
        Key = key;
        Path = path;
    }
}

/// <summary>
/// Fluent builder for BIP32/BIP39 HD wallet operations.
/// The last seed or mnemonic source selected replaces the previous source.
/// </summary>
public sealed class HdWalletBuilder
{
    private string? mnemonic;
    private int wordCount = 24;
    private string passphrase = "";
    private string? derivationPath;
    private byte[]? seed;

    /// <summary>
    /// Generates a new random mnemonic with the specified word count.
    /// </summary>
    /// <param name="wordCount">Number of words (12, 15, 18, 21, or 24). Default is 24.</param>
    /// <returns>This builder for chaining.</returns>
    public HdWalletBuilder GenerateMnemonic(int wordCount = 24)
    {
        this.wordCount = wordCount;
        mnemonic = null; // Will be generated during terminal operation
        seed = null;
        return this;
    }

    /// <summary>
    /// Uses an existing mnemonic phrase.
    /// </summary>
    /// <param name="mnemonic">The mnemonic phrase.</param>
    /// <returns>This builder for chaining.</returns>
    public HdWalletBuilder FromMnemonic(string mnemonic)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mnemonic);
        this.mnemonic = mnemonic;
        seed = null;
        return this;
    }

    /// <summary>
    /// Uses an existing seed directly (skips mnemonic).
    /// </summary>
    /// <param name="seed">The seed bytes.</param>
    /// <returns>This builder for chaining.</returns>
    public HdWalletBuilder FromSeed(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        this.seed = seed;
        mnemonic = null;
        return this;
    }

    /// <summary>
    /// Sets the optional passphrase for seed derivation.
    /// </summary>
    /// <param name="passphrase">The passphrase.</param>
    /// <returns>This builder for chaining.</returns>
    public HdWalletBuilder WithPassphrase(string passphrase)
    {
        this.passphrase = passphrase ?? "";
        return this;
    }

    /// <summary>
    /// Sets the derivation path.
    /// </summary>
    /// <param name="path">BIP32 derivation path (e.g., "m/44'/0'/0'/0/0").</param>
    /// <returns>This builder for chaining.</returns>
    public HdWalletBuilder WithPath(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        derivationPath = path;
        return this;
    }

    /// <summary>
    /// Generates the wallet and derives the key at the specified path.
    /// </summary>
    /// <returns>The HD wallet result containing mnemonic, seed, and derived key.</returns>
    public HdWalletResult Derive()
    {
        byte[]? derivedSeed = null;
        Bip32HdWallet.ExtendedKey? masterKey = null;
        Bip32HdWallet.ExtendedKey? finalKey = null;
        var succeeded = false;
        string? resultMnemonic = mnemonic;

        try
        {
            if (seed != null)
            {
                // Result ownership is independent of the caller's seed buffer.
                derivedSeed = seed.ToArray();
                resultMnemonic = null;
            }
            else
            {
                var bip39 = new Bip39Mnemonic();
                resultMnemonic ??= bip39.GenerateRandomMnemonic(wordCount);
                derivedSeed = bip39.MnemonicToSeed(resultMnemonic, passphrase);
            }

            var bip32 = new Bip32HdWallet();
            masterKey = bip32.GenerateMasterKey(derivedSeed);
            finalKey = string.IsNullOrEmpty(derivationPath)
                ? masterKey
                : bip32.DerivePath(masterKey, derivationPath);

            var result = new HdWalletResult(resultMnemonic, derivedSeed, finalKey, derivationPath);
            succeeded = true;
            return result;
        }
        finally
        {
            if (masterKey != null && (!succeeded || masterKey != finalKey)) masterKey.Clear();
            if (!succeeded)
            {
                if (finalKey != null && finalKey != masterKey) finalKey.Clear();
                if (derivedSeed != null) SecureMemoryOperations.SecureClear(derivedSeed);
            }
        }
    }

    /// <summary>
    /// Generates only the master key without path derivation.
    /// </summary>
    /// <returns>The HD wallet result with master key.</returns>
    public HdWalletResult GenerateMasterKey()
    {
        derivationPath = null;
        return Derive();
    }
}

#endif
