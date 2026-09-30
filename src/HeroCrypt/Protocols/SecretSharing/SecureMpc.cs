using HeroCrypt.Security;

namespace HeroCrypt.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Reserved API for multi-party computation protocols.
/// </summary>
/// <remarks>
/// MPC, private set intersection, and Beaver triple generation are not supported.
/// The former local simulation did not provide distributed privacy or authenticated
/// computation. All operations throw <see cref="NotSupportedException"/> until a
/// reviewed protocol is implemented.
/// </remarks>
public sealed class SecureMpc
{
    private const string UnsupportedMessage =
        "Multi-party computation is not supported. The former simulation did not provide distributed privacy or authenticated computation.";

    /// <summary>
    /// Initializes the reserved MPC API.
    /// </summary>
    /// <param name="policy">Security policy for a future implementation.</param>
    public SecureMpc(SecurityPolicyOptions? policy = null)
    {
        _ = policy;
    }

    /// <summary>
    /// Reserved security model for a future MPC protocol
    /// </summary>
    public enum SecurityModel
    {
        /// <summary>Semi-honest (honest-but-curious) - parties follow protocol but try to learn extra info</summary>
        SemiHonest = 1,

        /// <summary>Malicious - parties may deviate arbitrarily from protocol</summary>
        Malicious = 2,

        /// <summary>Covert - malicious behavior with probability of detection</summary>
        Covert = 3
    }

    /// <summary>
    /// A share of a secret value held by one party in MPC protocols.
    /// </summary>
    public class MpcShare
    {
        /// <summary>Party ID holding this share</summary>
        public int PartyId { get; }

        /// <summary>The share value</summary>
        public byte[] Value { get; }

        /// <summary>Share index (for polynomial-based schemes)</summary>
        public byte ShareIndex { get; }

        internal MpcShare(int partyId, byte[] value, byte shareIndex)
        {
            PartyId = partyId;
            Value = value;
            ShareIndex = shareIndex;
        }
    }

    /// <summary>
    /// Result of an MPC computation
    /// </summary>
    public class ComputationResult
    {
        /// <summary>The computed result (revealed to all parties)</summary>
        public byte[] Result { get; }

        /// <summary>Number of parties that participated</summary>
        public int ParticipantCount { get; }

        /// <summary>Whether computation completed successfully</summary>
        public bool Success { get; }

        internal ComputationResult(byte[] result, int participantCount, bool success)
        {
            Result = result;
            ParticipantCount = participantCount;
            Success = success;
        }
    }

    /// <summary>
    /// Beaver triple for secure multiplication (preprocessing material)
    /// </summary>
    public class BeaverTriple
    {
        /// <summary>Share of random value a</summary>
        public MpcShare A { get; }

        /// <summary>Share of random value b</summary>
        public MpcShare B { get; }

        /// <summary>Share of product c = a * b</summary>
        public MpcShare C { get; }

        internal BeaverTriple(MpcShare a, MpcShare b, MpcShare c)
        {
            A = a;
            B = b;
            C = c;
        }
    }

    /// <summary>
    /// Reserved sum operation. No secure multi-party protocol is implemented.
    /// </summary>
    /// <param name="partyInputs">Inputs for a future protocol.</param>
    /// <param name="threshold">Reconstruction threshold for a future protocol.</param>
    /// <param name="model">Security model for a future protocol.</param>
    /// <returns>No result is produced.</returns>
    /// <exception cref="NotSupportedException">MPC operations are unsupported.</exception>
    public ComputationResult SecureSum(byte[][] partyInputs, int threshold,
        SecurityModel model = SecurityModel.SemiHonest)
        => throw new NotSupportedException(UnsupportedMessage);

    /// <summary>
    /// Reserved multiplication operation. No authenticated MPC protocol is implemented.
    /// </summary>
    /// <param name="xShares">First operand shares for a future protocol.</param>
    /// <param name="yShares">Second operand shares for a future protocol.</param>
    /// <param name="beaverTriple">Preprocessing shares for a future protocol.</param>
    /// <param name="threshold">Reconstruction threshold for a future protocol.</param>
    /// <returns>No result is produced.</returns>
    /// <exception cref="NotSupportedException">MPC operations are unsupported.</exception>
    public MpcShare[] SecureMultiply(MpcShare[] xShares, MpcShare[] yShares,
        BeaverTriple[] beaverTriple, int threshold)
        => throw new NotSupportedException(UnsupportedMessage);

    /// <summary>
    /// Reserved preprocessing operation. No secure Beaver triple protocol is implemented.
    /// </summary>
    /// <param name="numParties">Number of parties for a future protocol.</param>
    /// <param name="threshold">Reconstruction threshold for a future protocol.</param>
    /// <param name="valueLength">Value length for a future protocol.</param>
    /// <returns>No triples are produced.</returns>
    /// <exception cref="NotSupportedException">MPC operations are unsupported.</exception>
    public BeaverTriple[] GenerateBeaverTriples(int numParties, int threshold, int valueLength)
        => throw new NotSupportedException(UnsupportedMessage);

    /// <summary>
    /// Reserved set intersection operation. No private set intersection protocol is implemented.
    /// </summary>
    /// <param name="party1Set">First party's set for a future protocol.</param>
    /// <param name="party2Set">Second party's set for a future protocol.</param>
    /// <param name="model">Security model for a future protocol.</param>
    /// <returns>No intersection is produced.</returns>
    /// <exception cref="NotSupportedException">MPC operations are unsupported.</exception>
    public byte[][] PrivateSetIntersection(byte[][] party1Set, byte[][] party2Set,
        SecurityModel model = SecurityModel.SemiHonest)
        => throw new NotSupportedException(UnsupportedMessage);
}
#endif
