using HeroCrypt.Security;

namespace HeroCrypt.Protocols.SecretSharing;

#if !NETSTANDARD2_0

/// <summary>
/// Reserved API for threshold signature protocols.
/// </summary>
/// <remarks>
/// Threshold signatures are not supported. The former hash-based simulation did not
/// authenticate signatures and has been removed. All operations throw
/// <see cref="NotSupportedException"/> until a reviewed protocol is implemented.
/// </remarks>
public sealed class ThresholdSignatures
{
    private const string UnsupportedMessage =
        "Threshold signatures are not supported. The former simulation did not provide cryptographic authentication.";

    /// <summary>
    /// Initializes the reserved threshold signature API.
    /// </summary>
    /// <param name="policy">Security policy for a future implementation.</param>
    public ThresholdSignatures(SecurityPolicyOptions? policy = null)
    {
        _ = policy;
    }
    /// <summary>
    /// Signature scheme for threshold signatures
    /// </summary>
    public enum SignatureScheme
    {
        /// <summary>Schnorr threshold signatures (most efficient)</summary>
        Schnorr = 1,

        /// <summary>ECDSA threshold signatures (Bitcoin/Ethereum compatible)</summary>
        ECDSA = 2,

        /// <summary>EdDSA threshold signatures (Ed25519 compatible)</summary>
        EdDSA = 3,

        /// <summary>BLS threshold signatures (supports aggregation)</summary>
        BLS = 4
    }

    /// <summary>
    /// Key share held by one party
    /// </summary>
    public class KeyShare
    {
        /// <summary>Party ID</summary>
        public int PartyId { get; }

        /// <summary>Share index</summary>
        public byte ShareIndex { get; }

        /// <summary>Private key share</summary>
        public byte[] PrivateShare { get; }

        /// <summary>Public key (shared by all parties)</summary>
        public byte[] PublicKey { get; }

        /// <summary>Public polynomial commitments (for verification)</summary>
        public byte[][] PublicCommitments { get; }

        /// <summary>Threshold (t+1 parties needed)</summary>
        public int Threshold { get; }

        /// <summary>Total number of parties</summary>
        public int TotalParties { get; }

        /// <summary>Signature scheme</summary>
        public SignatureScheme Scheme { get; }

        internal KeyShare(int partyId, byte shareIndex, byte[] privateShare,
            byte[] publicKey, byte[][] publicCommitments, int threshold,
            int totalParties, SignatureScheme scheme)
        {
            PartyId = partyId;
            ShareIndex = shareIndex;
            PrivateShare = privateShare;
            PublicKey = publicKey;
            PublicCommitments = publicCommitments;
            Threshold = threshold;
            TotalParties = totalParties;
            Scheme = scheme;
        }
    }

    /// <summary>
    /// Partial signature from one party
    /// </summary>
    public class PartialSignature
    {
        /// <summary>Party ID that created this partial signature</summary>
        public int PartyId { get; }

        /// <summary>Share index</summary>
        public byte ShareIndex { get; }

        /// <summary>Partial signature value</summary>
        public byte[] Value { get; }

        /// <summary>Commitment (for verification)</summary>
        public byte[] Commitment { get; }

        internal PartialSignature(int partyId, byte shareIndex, byte[] value, byte[] commitment)
        {
            PartyId = partyId;
            ShareIndex = shareIndex;
            Value = value;
            Commitment = commitment;
        }
    }

    /// <summary>
    /// Complete threshold signature
    /// </summary>
    public class ThresholdSignature
    {
        /// <summary>Signature value (R component)</summary>
        public byte[] R { get; }

        /// <summary>Signature value (S component)</summary>
        public byte[] S { get; }

        /// <summary>List of signers (party IDs)</summary>
        public int[] Signers { get; }

        /// <summary>Signature scheme used</summary>
        public SignatureScheme Scheme { get; }

        internal ThresholdSignature(byte[] r, byte[] s, int[] signers, SignatureScheme scheme)
        {
            R = r;
            S = s;
            Signers = signers;
            Scheme = scheme;
        }

        /// <summary>
        /// Total size of the signature in bytes
        /// </summary>
        public int Size => R.Length + S.Length;
    }

    /// <summary>
    /// Result of distributed key generation
    /// </summary>
    public class KeyGenerationResult
    {
        /// <summary>Key share for each party</summary>
        public KeyShare[] KeyShares { get; }

        /// <summary>Public key</summary>
        public byte[] PublicKey { get; }

        /// <summary>Success status</summary>
        public bool Success { get; }

        internal KeyGenerationResult(KeyShare[] keyShares, byte[] publicKey, bool success)
        {
            KeyShares = keyShares;
            PublicKey = publicKey;
            Success = success;
        }
    }

    /// <summary>Threshold key generation is not supported.</summary>
    /// <param name="numParties">Total number of parties.</param>
    /// <param name="threshold">Threshold parameter.</param>
    /// <param name="scheme">Signature scheme.</param>
    /// <returns>No result; this operation is not supported.</returns>
    /// <exception cref="NotSupportedException">No secure threshold protocol is implemented.</exception>
    public KeyGenerationResult GenerateKeys(int numParties, int threshold,
        SignatureScheme scheme = SignatureScheme.Schnorr)
        => throw new NotSupportedException(UnsupportedMessage);

    /// <summary>Threshold partial signing is not supported.</summary>
    /// <param name="message">Message to sign.</param>
    /// <param name="keyShare">Party's key share.</param>
    /// <param name="signers">Participating parties.</param>
    /// <param name="nonce">Optional nonce.</param>
    /// <returns>No result; this operation is not supported.</returns>
    /// <exception cref="NotSupportedException">No secure threshold protocol is implemented.</exception>
    public PartialSignature SignPartial(ReadOnlySpan<byte> message, KeyShare keyShare,
        int[] signers, byte[]? nonce = null)
        => throw new NotSupportedException(UnsupportedMessage);

    /// <summary>Threshold signature combination is not supported.</summary>
    /// <param name="message">Message to sign.</param>
    /// <param name="partialSignatures">Partial signatures.</param>
    /// <param name="publicKey">Public key.</param>
    /// <param name="scheme">Signature scheme.</param>
    /// <returns>No result; this operation is not supported.</returns>
    /// <exception cref="NotSupportedException">No secure threshold protocol is implemented.</exception>
    public ThresholdSignature CombineSignatures(ReadOnlySpan<byte> message,
        PartialSignature[] partialSignatures, byte[] publicKey, SignatureScheme scheme)
        => throw new NotSupportedException(UnsupportedMessage);

    /// <summary>Threshold signature verification is not supported.</summary>
    /// <param name="message">Message to verify.</param>
    /// <param name="signature">Signature to verify.</param>
    /// <param name="publicKey">Public key.</param>
    /// <returns>No result; this operation is not supported.</returns>
    /// <exception cref="NotSupportedException">No secure threshold protocol is implemented.</exception>
    public bool VerifySignature(ReadOnlySpan<byte> message,
        ThresholdSignature signature, byte[] publicKey)
        => throw new NotSupportedException(UnsupportedMessage);
}
#endif
