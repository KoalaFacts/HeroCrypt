namespace HeroCrypt.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Fluent builder for Shamir's Secret Sharing operations.
/// Reconstruction and verification enforce the configured threshold (default 2).
/// Shares and the threshold must come from a trusted source; no share authentication is provided.
/// </summary>
public sealed class SecretSharingBuilder
{
    private int threshold = 2;
    private int shareCount = 3;
    private ShamirSecretSharing.Share[]? shares;

    /// <summary>
    /// Sets the threshold (minimum shares needed to reconstruct).
    /// </summary>
    /// <param name="threshold">The trusted threshold value (between 2 and 255).</param>
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
        var shamir = new ShamirSecretSharing();
        return shamir.Split(secret, threshold, shareCount);
    }

    /// <summary>
    /// Splits a secret into shares.
    /// </summary>
    /// <param name="secret">The secret to split.</param>
    /// <returns>Array of shares.</returns>
    public ShamirSecretSharing.Share[] Split(byte[] secret)
    {
        var shamir = new ShamirSecretSharing();
        return shamir.Split(secret, threshold, shareCount);
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

        var shamir = new ShamirSecretSharing();
        return shamir.Reconstruct(shares, threshold);
    }

    /// <summary>
    /// Reconstructs the secret from the specified shares.
    /// </summary>
    /// <param name="shares">The shares to use for reconstruction.</param>
    /// <returns>The reconstructed secret.</returns>
    public byte[] Reconstruct(ShamirSecretSharing.Share[] shares)
    {
        var shamir = new ShamirSecretSharing();
        return shamir.Reconstruct(shares, threshold);
    }

    /// <summary>
    /// Enforces the configured threshold and compares the reconstructed value.
    /// A match does not authenticate shares or their sharing session.
    /// </summary>
    /// <param name="expectedSecret">The expected secret.</param>
    /// <returns>True if verification succeeds.</returns>
    public bool Verify(ReadOnlySpan<byte> expectedSecret)
    {
        if (shares == null || shares.Length == 0)
        {
            throw new InvalidOperationException("No shares provided. Use WithShares() first.");
        }

        var shamir = new ShamirSecretSharing();
        return shamir.Verify(shares, expectedSecret, threshold);
    }
}

#endif
