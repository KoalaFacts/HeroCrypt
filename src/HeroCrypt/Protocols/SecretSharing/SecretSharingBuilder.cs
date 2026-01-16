namespace HeroCrypt.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Fluent builder for Shamir's Secret Sharing operations.
/// </summary>
public sealed class SecretSharingBuilder
{
    private int threshold = 2;
    private int shareCount = 3;
    private ShamirSecretSharing.Share[]? shares;

    /// <summary>
    /// Sets the threshold (minimum shares needed to reconstruct).
    /// </summary>
    /// <param name="threshold">The threshold value (minimum 2).</param>
    /// <returns>This builder for chaining.</returns>
    public SecretSharingBuilder WithThreshold(int threshold)
    {
        this.threshold = threshold;
        return this;
    }

    /// <summary>
    /// Sets the total number of shares to generate.
    /// </summary>
    /// <param name="count">The share count (maximum 255).</param>
    /// <returns>This builder for chaining.</returns>
    public SecretSharingBuilder WithShareCount(int count)
    {
        shareCount = count;
        return this;
    }

    /// <summary>
    /// Provides shares for reconstruction.
    /// </summary>
    /// <param name="shares">The shares to use for reconstruction.</param>
    /// <returns>This builder for chaining.</returns>
    public SecretSharingBuilder WithShares(ShamirSecretSharing.Share[] shares)
    {
        this.shares = shares;
        return this;
    }

    /// <summary>
    /// Splits a secret into shares.
    /// </summary>
    /// <param name="secret">The secret to split.</param>
    /// <returns>Array of shares.</returns>
    public ShamirSecretSharing.Share[] Split(ReadOnlySpan<byte> secret)
    {
        return ShamirSecretSharing.Split(secret, threshold, shareCount);
    }

    /// <summary>
    /// Splits a secret into shares.
    /// </summary>
    /// <param name="secret">The secret to split.</param>
    /// <returns>Array of shares.</returns>
    public ShamirSecretSharing.Share[] Split(byte[] secret)
    {
        return ShamirSecretSharing.Split(secret, threshold, shareCount);
    }

    /// <summary>
    /// Reconstructs the secret from the provided shares.
    /// </summary>
    /// <returns>The reconstructed secret.</returns>
    public byte[] Reconstruct()
    {
        if (shares == null || shares.Length == 0)
        {
            throw new InvalidOperationException("No shares provided. Use WithShares() first.");
        }

        return ShamirSecretSharing.Reconstruct(shares);
    }

    /// <summary>
    /// Reconstructs the secret from the specified shares.
    /// </summary>
    /// <param name="shares">The shares to use for reconstruction.</param>
    /// <returns>The reconstructed secret.</returns>
    public byte[] Reconstruct(ShamirSecretSharing.Share[] shares)
    {
        return ShamirSecretSharing.Reconstruct(shares);
    }

    /// <summary>
    /// Verifies that the provided shares can reconstruct the expected secret.
    /// </summary>
    /// <param name="expectedSecret">The expected secret.</param>
    /// <returns>True if verification succeeds.</returns>
    public bool Verify(ReadOnlySpan<byte> expectedSecret)
    {
        if (shares == null || shares.Length == 0)
        {
            throw new InvalidOperationException("No shares provided. Use WithShares() first.");
        }

        return ShamirSecretSharing.Verify(shares, expectedSecret);
    }
}

#endif
