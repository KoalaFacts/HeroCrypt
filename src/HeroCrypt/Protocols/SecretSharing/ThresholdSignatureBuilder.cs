namespace HeroCrypt.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Fluent builder for threshold signature operations.
/// </summary>
public sealed class ThresholdSignatureBuilder
{
    private int numParties = 3;
    private int threshold = 2;
    private ThresholdSignatures.SignatureScheme scheme = ThresholdSignatures.SignatureScheme.Schnorr;
    private byte[]? message;
    private ThresholdSignatures.KeyShare? keyShare;
    private int[]? signers;
    private ThresholdSignatures.PartialSignature[]? partialSignatures;
    private byte[]? publicKey;

    /// <summary>
    /// Sets the total number of parties.
    /// </summary>
    /// <param name="count">Number of parties.</param>
    /// <returns>This builder for chaining.</returns>
    public ThresholdSignatureBuilder WithParties(int count)
    {
        numParties = count;
        return this;
    }

    /// <summary>
    /// Sets the threshold (t) - need t+1 parties to sign.
    /// </summary>
    /// <param name="threshold">The threshold value.</param>
    /// <returns>This builder for chaining.</returns>
    public ThresholdSignatureBuilder WithThreshold(int threshold)
    {
        this.threshold = threshold;
        return this;
    }

    /// <summary>
    /// Sets the signature scheme.
    /// </summary>
    /// <param name="scheme">The signature scheme to use.</param>
    /// <returns>This builder for chaining.</returns>
    public ThresholdSignatureBuilder WithScheme(ThresholdSignatures.SignatureScheme scheme)
    {
        this.scheme = scheme;
        return this;
    }

    /// <summary>
    /// Sets the message to sign.
    /// </summary>
    /// <param name="message">The message bytes.</param>
    /// <returns>This builder for chaining.</returns>
    public ThresholdSignatureBuilder WithMessage(byte[] message)
    {
        this.message = message;
        return this;
    }

    /// <summary>
    /// Sets the key share for signing.
    /// </summary>
    /// <param name="keyShare">The party's key share.</param>
    /// <returns>This builder for chaining.</returns>
    public ThresholdSignatureBuilder WithKeyShare(ThresholdSignatures.KeyShare keyShare)
    {
        this.keyShare = keyShare;
        return this;
    }

    /// <summary>
    /// Sets the list of participating signers.
    /// </summary>
    /// <param name="signers">Array of signer party IDs.</param>
    /// <returns>This builder for chaining.</returns>
    public ThresholdSignatureBuilder WithSigners(int[] signers)
    {
        this.signers = signers;
        return this;
    }

    /// <summary>
    /// Sets partial signatures for combination.
    /// </summary>
    /// <param name="partials">The partial signatures to combine.</param>
    /// <returns>This builder for chaining.</returns>
    public ThresholdSignatureBuilder WithPartialSignatures(ThresholdSignatures.PartialSignature[] partials)
    {
        partialSignatures = partials;
        return this;
    }

    /// <summary>
    /// Sets the public key for verification or combination.
    /// </summary>
    /// <param name="publicKey">The public key bytes.</param>
    /// <returns>This builder for chaining.</returns>
    public ThresholdSignatureBuilder WithPublicKey(byte[] publicKey)
    {
        this.publicKey = publicKey;
        return this;
    }

    /// <summary>
    /// Generates key shares for all parties.
    /// </summary>
    /// <returns>Key generation result with shares for each party.</returns>
    public ThresholdSignatures.KeyGenerationResult GenerateKeys()
    {
        return ThresholdSignatures.GenerateKeys(numParties, threshold, scheme);
    }

    /// <summary>
    /// Creates a partial signature using the configured key share.
    /// </summary>
    /// <returns>The partial signature from this party.</returns>
    public ThresholdSignatures.PartialSignature SignPartial()
    {
        if (message == null)
            throw new InvalidOperationException("Message not set. Use WithMessage() first.");
        if (keyShare == null)
            throw new InvalidOperationException("Key share not set. Use WithKeyShare() first.");
        if (signers == null)
            throw new InvalidOperationException("Signers not set. Use WithSigners() first.");

        return ThresholdSignatures.SignPartial(message, keyShare, signers);
    }

    /// <summary>
    /// Combines partial signatures into a complete threshold signature.
    /// </summary>
    /// <returns>The combined threshold signature.</returns>
    public ThresholdSignatures.ThresholdSignature CombineSignatures()
    {
        if (message == null)
            throw new InvalidOperationException("Message not set. Use WithMessage() first.");
        if (partialSignatures == null)
            throw new InvalidOperationException("Partial signatures not set. Use WithPartialSignatures() first.");
        if (publicKey == null)
            throw new InvalidOperationException("Public key not set. Use WithPublicKey() first.");

        return ThresholdSignatures.CombineSignatures(message, partialSignatures, publicKey, scheme);
    }

    /// <summary>
    /// Verifies a threshold signature.
    /// </summary>
    /// <param name="signature">The signature to verify.</param>
    /// <returns>True if the signature is valid.</returns>
    public bool VerifySignature(ThresholdSignatures.ThresholdSignature signature)
    {
        if (message == null)
            throw new InvalidOperationException("Message not set. Use WithMessage() first.");
        if (publicKey == null)
            throw new InvalidOperationException("Public key not set. Use WithPublicKey() first.");

        return ThresholdSignatures.VerifySignature(message, signature, publicKey);
    }
}

#endif
