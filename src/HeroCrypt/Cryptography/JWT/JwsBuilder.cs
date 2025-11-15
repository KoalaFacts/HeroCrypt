namespace HeroCrypt.Cryptography.JWT;

/// <summary>
/// Fluent builder for JSON Web Signature (JWS) operations
/// </summary>
public class JwsBuilder
{
    private byte[]? _data;
    private byte[]? _key;
    private byte[]? _signature;
    private JwsAlgorithm? _algorithm;

    /// <summary>
    /// Creates a new JWS builder instance
    /// </summary>
    public static JwsBuilder Create() => new JwsBuilder();

    /// <summary>
    /// Sets the data to sign or verify
    /// </summary>
    /// <param name="data">The data bytes</param>
    /// <returns>The builder instance</returns>
    public JwsBuilder WithData(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
        return this;
    }

    /// <summary>
    /// Sets the data to sign or verify from a string (UTF-8 encoded)
    /// </summary>
    /// <param name="data">The data string</param>
    /// <returns>The builder instance</returns>
    public JwsBuilder WithData(string data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        _data = System.Text.Encoding.UTF8.GetBytes(data);
        return this;
    }

    /// <summary>
    /// Sets the signing or verification key
    /// </summary>
    /// <param name="key">The key bytes (format depends on algorithm)</param>
    /// <returns>The builder instance</returns>
    public JwsBuilder WithKey(byte[] key)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
        return this;
    }

    /// <summary>
    /// Sets the signature for verification
    /// </summary>
    /// <param name="signature">The signature bytes</param>
    /// <returns>The builder instance</returns>
    public JwsBuilder WithSignature(byte[] signature)
    {
        _signature = signature ?? throw new ArgumentNullException(nameof(signature));
        return this;
    }

    /// <summary>
    /// Sets the JWS algorithm to use
    /// </summary>
    /// <param name="algorithm">The JWS algorithm</param>
    /// <returns>The builder instance</returns>
    public JwsBuilder WithAlgorithm(JwsAlgorithm algorithm)
    {
        _algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Signs the data with the configured algorithm and key
    /// </summary>
    /// <returns>The signature bytes</returns>
    /// <exception cref="InvalidOperationException">Thrown when required parameters are not set</exception>
    public byte[] Sign()
    {
        if (_data == null)
            throw new InvalidOperationException("Data must be set before signing. Use WithData().");
        if (_key == null)
            throw new InvalidOperationException("Key must be set before signing. Use WithKey().");
        if (_algorithm == null)
            throw new InvalidOperationException("Algorithm must be set before signing. Use WithAlgorithm().");

        return JwsSigner.Sign(_data, _key, _algorithm.Value);
    }

    /// <summary>
    /// Verifies the signature with the configured algorithm and key
    /// </summary>
    /// <returns>True if the signature is valid; otherwise, false</returns>
    /// <exception cref="InvalidOperationException">Thrown when required parameters are not set</exception>
    public bool Verify()
    {
        if (_data == null)
            throw new InvalidOperationException("Data must be set before verifying. Use WithData().");
        if (_signature == null)
            throw new InvalidOperationException("Signature must be set before verifying. Use WithSignature().");
        if (_key == null)
            throw new InvalidOperationException("Key must be set before verifying. Use WithKey().");
        if (_algorithm == null)
            throw new InvalidOperationException("Algorithm must be set before verifying. Use WithAlgorithm().");

        return JwsSigner.Verify(_data, _signature, _key, _algorithm.Value);
    }
}
