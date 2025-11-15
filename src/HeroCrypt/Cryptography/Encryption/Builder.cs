namespace HeroCrypt.Cryptography.Encryption;

/// <summary>
/// Fluent builder for encryption and decryption operations
/// </summary>
public class Builder
{
    private byte[]? _data;
    private byte[]? _key;
    private byte[]? _nonce;
    private byte[]? _keyCiphertext;
    private byte[]? _associatedData;
    private EncryptionAlgorithm? _algorithm;

    /// <summary>
    /// Creates a new encryption builder instance
    /// </summary>
    public static Builder Create() => new Builder();

    /// <summary>
    /// Sets the data to encrypt or the ciphertext to decrypt
    /// </summary>
    /// <param name="data">The data bytes</param>
    /// <returns>The builder instance</returns>
    public Builder WithData(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
        return this;
    }

    /// <summary>
    /// Sets the encryption or decryption key
    /// </summary>
    /// <param name="key">The key bytes (format and size depends on algorithm)</param>
    /// <returns>The builder instance</returns>
    public Builder WithKey(byte[] key)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
        return this;
    }

    /// <summary>
    /// Sets the nonce/IV (required for decryption)
    /// </summary>
    /// <param name="nonce">The nonce bytes</param>
    /// <returns>The builder instance</returns>
    public Builder WithNonce(byte[] nonce)
    {
        _nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        return this;
    }

    /// <summary>
    /// Sets the key ciphertext (required for hybrid encryption decryption)
    /// </summary>
    /// <param name="keyCiphertext">The encapsulated key ciphertext</param>
    /// <returns>The builder instance</returns>
    public Builder WithKeyCiphertext(byte[] keyCiphertext)
    {
        _keyCiphertext = keyCiphertext ?? throw new ArgumentNullException(nameof(keyCiphertext));
        return this;
    }

    /// <summary>
    /// Sets the authenticated associated data (for AEAD ciphers)
    /// </summary>
    /// <param name="associatedData">The associated data bytes</param>
    /// <returns>The builder instance</returns>
    public Builder WithAssociatedData(byte[] associatedData)
    {
        _associatedData = associatedData ?? throw new ArgumentNullException(nameof(associatedData));
        return this;
    }

    /// <summary>
    /// Sets the encryption algorithm to use
    /// </summary>
    /// <param name="algorithm">The encryption algorithm</param>
    /// <returns>The builder instance</returns>
    public Builder WithAlgorithm(EncryptionAlgorithm algorithm)
    {
        _algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Encrypts the data with the configured algorithm and key
    /// </summary>
    /// <returns>Encryption result containing ciphertext and nonce</returns>
    /// <exception cref="InvalidOperationException">Thrown when required parameters are not set</exception>
    public Encryption.EncryptionResult Encrypt()
    {
        if (_data == null)
            throw new InvalidOperationException("Data must be set before encrypting. Use WithData().");
        if (_key == null)
            throw new InvalidOperationException("Key must be set before encrypting. Use WithKey().");
        if (_algorithm == null)
            throw new InvalidOperationException("Algorithm must be set before encrypting. Use WithAlgorithm().");

        return Encryption.Encrypt(_data, _key, _algorithm.Value, _associatedData);
    }

    /// <summary>
    /// Decrypts the data with the configured algorithm and key
    /// </summary>
    /// <returns>The decrypted plaintext</returns>
    /// <exception cref="InvalidOperationException">Thrown when required parameters are not set</exception>
    public byte[] Decrypt()
    {
        if (_data == null)
            throw new InvalidOperationException("Data (ciphertext) must be set before decrypting. Use WithData().");
        if (_key == null)
            throw new InvalidOperationException("Key must be set before decrypting. Use WithKey().");
        if (_nonce == null)
            throw new InvalidOperationException("Nonce must be set before decrypting. Use WithNonce().");
        if (_algorithm == null)
            throw new InvalidOperationException("Algorithm must be set before decrypting. Use WithAlgorithm().");

        return Encryption.Decrypt(_data, _key, _nonce, _algorithm.Value, _associatedData, _keyCiphertext);
    }
}
