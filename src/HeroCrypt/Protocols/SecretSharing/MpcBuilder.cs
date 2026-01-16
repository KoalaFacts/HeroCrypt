namespace HeroCrypt.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Fluent builder for Secure Multi-Party Computation operations.
/// </summary>
public sealed class MpcBuilder
{
    private int threshold = 2;
    private SecureMpc.SecurityModel model = SecureMpc.SecurityModel.SemiHonest;
    private byte[][]? partyInputs;
    private byte[][]? party1Set;
    private byte[][]? party2Set;

    /// <summary>
    /// Sets the reconstruction threshold.
    /// </summary>
    /// <param name="threshold">The threshold value.</param>
    /// <returns>This builder for chaining.</returns>
    public MpcBuilder WithThreshold(int threshold)
    {
        this.threshold = threshold;
        return this;
    }

    /// <summary>
    /// Sets the security model.
    /// </summary>
    /// <param name="model">The security model to use.</param>
    /// <returns>This builder for chaining.</returns>
    public MpcBuilder WithSecurityModel(SecureMpc.SecurityModel model)
    {
        this.model = model;
        return this;
    }

    /// <summary>
    /// Sets the inputs from all parties for sum computation.
    /// </summary>
    /// <param name="inputs">Array of inputs from each party.</param>
    /// <returns>This builder for chaining.</returns>
    public MpcBuilder WithPartyInputs(byte[][] inputs)
    {
        partyInputs = inputs;
        return this;
    }

    /// <summary>
    /// Sets the first party's set for intersection.
    /// </summary>
    /// <param name="set">The first party's set elements.</param>
    /// <returns>This builder for chaining.</returns>
    public MpcBuilder WithParty1Set(byte[][] set)
    {
        party1Set = set;
        return this;
    }

    /// <summary>
    /// Sets the second party's set for intersection.
    /// </summary>
    /// <param name="set">The second party's set elements.</param>
    /// <returns>This builder for chaining.</returns>
    public MpcBuilder WithParty2Set(byte[][] set)
    {
        party2Set = set;
        return this;
    }

    /// <summary>
    /// Computes the secure sum of all party inputs.
    /// </summary>
    /// <returns>The computation result containing the sum.</returns>
    public SecureMpc.ComputationResult ComputeSum()
    {
        if (partyInputs == null)
            throw new InvalidOperationException("Party inputs not set. Use WithPartyInputs() first.");

        return SecureMpc.SecureSum(partyInputs, threshold, model);
    }

    /// <summary>
    /// Computes the secure sum of the provided inputs.
    /// </summary>
    /// <param name="inputs">Array of inputs from each party.</param>
    /// <returns>The computation result containing the sum.</returns>
    public SecureMpc.ComputationResult ComputeSum(byte[][] inputs)
    {
        return SecureMpc.SecureSum(inputs, threshold, model);
    }

    /// <summary>
    /// Computes the private set intersection between two parties.
    /// </summary>
    /// <returns>Elements that appear in both sets.</returns>
    public byte[][] ComputeIntersection()
    {
        if (party1Set == null)
            throw new InvalidOperationException("Party 1 set not provided. Use WithParty1Set() first.");
        if (party2Set == null)
            throw new InvalidOperationException("Party 2 set not provided. Use WithParty2Set() first.");

        return SecureMpc.PrivateSetIntersection(party1Set, party2Set, model);
    }

    /// <summary>
    /// Computes the private set intersection between two parties.
    /// </summary>
    /// <param name="set1">First party's set.</param>
    /// <param name="set2">Second party's set.</param>
    /// <returns>Elements that appear in both sets.</returns>
    public byte[][] ComputeIntersection(byte[][] set1, byte[][] set2)
    {
        return SecureMpc.PrivateSetIntersection(set1, set2, model);
    }

    /// <summary>
    /// Generates Beaver triples for secure multiplication preprocessing.
    /// </summary>
    /// <param name="numParties">Number of parties.</param>
    /// <param name="valueLength">Length of values in bytes.</param>
    /// <returns>Beaver triples for each party.</returns>
    public SecureMpc.BeaverTriple[] GenerateBeaverTriples(int numParties, int valueLength)
    {
        return SecureMpc.GenerateBeaverTriples(numParties, threshold, valueLength);
    }
}

#endif
