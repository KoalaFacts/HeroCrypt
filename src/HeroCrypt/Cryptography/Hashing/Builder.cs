namespace HeroCrypt.Cryptography.Hashing;

/// <summary>
/// Fluent builder for hashing operations
/// </summary>
public class Builder
{
    private byte[]? _data;
    private byte[]? _key;
    private HashAlgorithm? _algorithm;

    /// <summary>
    /// Creates a new hash builder instance
    /// </summary>
    public static Builder Create() => new Builder();

    /// <summary>
    /// Sets the data to hash
    /// </summary>
    /// <param name="data">The data bytes</param>
    /// <returns>The builder instance</returns>
    public Builder WithData(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
        return this;
    }

    /// <summary>
    /// Sets the data to hash from a string (UTF-8 encoded)
    /// </summary>
    /// <param name="data">The data string</param>
    /// <returns>The builder instance</returns>
    public Builder WithData(string data)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        _data = System.Text.Encoding.UTF8.GetBytes(data);
        return this;
    }

    /// <summary>
    /// Sets the key for keyed hashing (MAC)
    /// </summary>
    /// <param name="key">The key bytes</param>
    /// <returns>The builder instance</returns>
    public Builder WithKey(byte[] key)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
        return this;
    }

    /// <summary>
    /// Sets the hash algorithm to use
    /// </summary>
    /// <param name="algorithm">The hash algorithm</param>
    /// <returns>The builder instance</returns>
    public Builder WithAlgorithm(HashAlgorithm algorithm)
    {
        _algorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Computes the hash of the data
    /// </summary>
    /// <returns>The computed hash</returns>
    /// <exception cref="InvalidOperationException">Thrown when required parameters are not set</exception>
    public byte[] Compute()
    {
        if (_data == null)
            throw new InvalidOperationException("Data must be set before hashing. Use WithData().");
        if (_algorithm == null)
            throw new InvalidOperationException("Algorithm must be set before hashing. Use WithAlgorithm().");

        if (_key != null)
        {
            return Hash.ComputeKeyed(_data, _key, _algorithm.Value);
        }
        else
        {
            return Hash.Compute(_data, _algorithm.Value);
        }
    }
}
