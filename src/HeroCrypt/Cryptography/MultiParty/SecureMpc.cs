using System;
using System.Linq;
using System.Security.Cryptography;
using HeroCrypt.Cryptography.SecretSharing;
using HeroCrypt.Security;

namespace HeroCrypt.Cryptography.MultiParty;

/// <summary>
/// Secure Multi-Party Computation (MPC) protocols
///
/// MPC allows multiple parties to jointly compute a function over their private inputs
/// while keeping those inputs secret. No single party learns anything except the final result.
///
/// IMPORTANT: This is a simplified reference implementation for educational purposes.
/// Production MPC requires:
///
/// 1. Secure communication channels (TLS, authenticated encryption)
/// 2. Malicious security (Byzantine fault tolerance, zero-knowledge proofs)
/// 3. Optimized secret sharing (Shamir, replicated, additive)
/// 4. Beaver triples for multiplication
/// 5. Garbled circuits for general computation
/// 6. Oblivious transfer protocols
/// 7. Commitment schemes for input validation
/// 8. Network fault tolerance and timeouts
///
/// Based on:
/// - GMW Protocol (Goldreich-Micali-Wigderson, 1987)
/// - BGW Protocol (Ben-Or, Goldwasser, Wigderson, 1988)
/// - SPDZ Protocol (modern practical MPC, 2012)
///
/// Use cases:
/// - Private set intersection
/// - Secure auctions
/// - Privacy-preserving machine learning
/// - Confidential data analysis
/// - Secure voting
/// - Multi-signature wallets
/// </summary>
public static class SecureMpc
{
    /// <summary>
    /// Security model for MPC
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
    /// A share of a secret value held by one party
    /// </summary>
    public class Share
    {
        /// <summary>Party ID holding this share</summary>
        public int PartyId { get; }

        /// <summary>The share value</summary>
        public byte[] Value { get; }

        /// <summary>Share index (for polynomial-based schemes)</summary>
        public byte ShareIndex { get; }

        internal Share(int partyId, byte[] value, byte shareIndex)
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
        public Share A { get; }

        /// <summary>Share of random value b</summary>
        public Share B { get; }

        /// <summary>Share of product c = a * b</summary>
        public Share C { get; }

        internal BeaverTriple(Share a, Share b, Share c)
        {
            A = a;
            B = b;
            C = c;
        }
    }

    /// <summary>
    /// Securely computes the sum of private inputs from multiple parties.
    ///
    /// Each party provides a private input. The protocol reveals only the sum,
    /// not individual inputs.
    ///
    /// This is the simplest MPC operation (no multiplication required).
    /// </summary>
    /// <param name="partyInputs">Private inputs from each party</param>
    /// <param name="threshold">Number of shares needed to reconstruct (t+1)</param>
    /// <param name="model">Security model</param>
    /// <returns>Sum of all inputs</returns>
    public static ComputationResult SecureSum(byte[][] partyInputs, int threshold,
        SecurityModel model = SecurityModel.SemiHonest)
    {
        if (partyInputs == null || partyInputs.Length < 2)
            throw new ArgumentException("At least 2 parties required", nameof(partyInputs));
        if (threshold < 1 || threshold >= partyInputs.Length)
            throw new ArgumentException("Invalid threshold", nameof(threshold));

        int numParties = partyInputs.Length;

        try
        {
            // Protocol:
            // 1. Each party i secret-shares their input xi into shares [xi]1, [xi]2, ..., [xi]n
            // 2. Party j receives share [xi]j from each party i
            // 3. Each party locally computes [sum]j = Σ[xi]j
            // 4. Parties reconstruct the sum from threshold+1 shares

            // Share each party's input
            var allShares = new ShamirSecretSharing.Share[numParties][];
            for (int i = 0; i < numParties; i++)
            {
                allShares[i] = ShamirSecretSharing.Split(
                    partyInputs[i],
                    threshold,
                    numParties
                );
            }

            // Each party collects their shares and sums locally
            var sumShares = new ShamirSecretSharing.Share[numParties];
            for (int partyId = 0; partyId < numParties; partyId++)
            {
                // Collect share partyId from each input
                byte[] localSum = new byte[partyInputs[0].Length];

                for (int inputIdx = 0; inputIdx < numParties; inputIdx++)
                {
                    var share = allShares[inputIdx][partyId];

                    // Add shares in GF(256)
                    for (int byteIdx = 0; byteIdx < localSum.Length; byteIdx++)
                    {
                        localSum[byteIdx] ^= share.Data[byteIdx];
                    }
                }

                sumShares[partyId] = new ShamirSecretSharing.Share(
                    allShares[0][partyId].Index,
                    localSum
                );
            }

            // Reconstruct the sum (need threshold+1 shares)
            var reconstructionShares = sumShares.Take(threshold + 1).ToArray();
            var result = ShamirSecretSharing.Reconstruct(reconstructionShares);

            return new ComputationResult(result, numParties, true);
        }
        catch (Exception)
        {
            return new ComputationResult(Array.Empty<byte>(), numParties, false);
        }
    }

    /// <summary>
    /// Securely multiplies two secret-shared values.
    ///
    /// Given [x] and [y] (secret shared values), computes [x * y] without
    /// revealing x or y.
    ///
    /// Uses Beaver multiplication triples for efficiency.
    /// </summary>
    /// <param name="xShares">Shares of first operand</param>
    /// <param name="yShares">Shares of second operand</param>
    /// <param name="beaverTriple">Preprocessed Beaver triple for each party</param>
    /// <param name="threshold">Reconstruction threshold</param>
    /// <returns>Shares of the product x * y</returns>
    public static Share[] SecureMultiply(Share[] xShares, Share[] yShares,
        BeaverTriple[] beaverTriple, int threshold)
    {
        if (xShares == null || yShares == null || beaverTriple == null)
            throw new ArgumentNullException("Shares cannot be null");
        if (xShares.Length != yShares.Length || xShares.Length != beaverTriple.Length)
            throw new ArgumentException("Share arrays must have same length");

        int numParties = xShares.Length;

        // Beaver multiplication protocol:
        // Given: [x], [y], and Beaver triple ([a], [b], [c]) where c = a*b
        //
        // 1. Each party locally computes:
        //    [d] = [x] - [a]
        //    [e] = [y] - [b]
        //
        // 2. Parties reveal d and e (these are random due to a,b being random)
        //
        // 3. Each party locally computes:
        //    [x*y] = d*e + d*[b] + e*[a] + [c]
        //
        // This works because:
        //    x*y = (d+a)*(e+b) = d*e + d*b + e*a + a*b
        //                      = d*e + d*[b] + e*[a] + [c]

        var productShares = new Share[numParties];

        try
        {
            // Step 1: Compute [d] = [x] - [a] and [e] = [y] - [b]
            var dShares = new Share[numParties];
            var eShares = new Share[numParties];

            for (int i = 0; i < numParties; i++)
            {
                dShares[i] = SubtractShares(xShares[i], beaverTriple[i].A);
                eShares[i] = SubtractShares(yShares[i], beaverTriple[i].B);
            }

            // Step 2: Reconstruct d and e (these are safe to reveal)
            var dValue = ReconstructSecret(dShares.Select(s =>
                new ShamirSecretSharing.Share(s.ShareIndex, s.Value)).ToArray());
            var eValue = ReconstructSecret(eShares.Select(s =>
                new ShamirSecretSharing.Share(s.ShareIndex, s.Value)).ToArray());

            // Step 3: Each party computes [x*y] = d*e + d*[b] + e*[a] + [c]
            for (int i = 0; i < numParties; i++)
            {
                var result = new byte[xShares[i].Value.Length];

                // d * e (public multiplication)
                for (int j = 0; j < result.Length; j++)
                {
                    result[j] = GF256Multiply(dValue[j], eValue[j]);
                }

                // d * [b]
                for (int j = 0; j < result.Length; j++)
                {
                    result[j] ^= GF256Multiply(dValue[j], beaverTriple[i].B.Value[j]);
                }

                // e * [a]
                for (int j = 0; j < result.Length; j++)
                {
                    result[j] ^= GF256Multiply(eValue[j], beaverTriple[i].A.Value[j]);
                }

                // + [c]
                for (int j = 0; j < result.Length; j++)
                {
                    result[j] ^= beaverTriple[i].C.Value[j];
                }

                productShares[i] = new Share(i, result, xShares[i].ShareIndex);
            }

            return productShares;
        }
        catch
        {
            throw new InvalidOperationException("Secure multiplication failed");
        }
    }

    /// <summary>
    /// Generates Beaver triples for secure multiplication preprocessing.
    ///
    /// In production: Generated via distributed protocol or trusted dealer.
    /// Each party gets shares [a], [b], [c] where c = a*b.
    /// </summary>
    /// <param name="numParties">Number of parties</param>
    /// <param name="threshold">Reconstruction threshold</param>
    /// <param name="valueLength">Length of values in bytes</param>
    /// <returns>Beaver triple for each party</returns>
    public static BeaverTriple[] GenerateBeaverTriples(int numParties, int threshold, int valueLength)
    {
        if (numParties < 2)
            throw new ArgumentException("At least 2 parties required", nameof(numParties));
        if (threshold < 1 || threshold >= numParties)
            throw new ArgumentException("Invalid threshold", nameof(threshold));

        // In production: Generated via MPC protocol (no trusted dealer)
        // Or using homomorphic encryption, oblivious transfer, etc.

        // Generate random a and b
        var a = RandomNumberGenerator.GetBytes(valueLength);
        var b = RandomNumberGenerator.GetBytes(valueLength);

        // Compute c = a * b in GF(256)
        var c = new byte[valueLength];
        for (int i = 0; i < valueLength; i++)
        {
            c[i] = GF256Multiply(a[i], b[i]);
        }

        // Secret share a, b, and c
        var aShares = ShamirSecretSharing.Split(a, threshold, numParties);
        var bShares = ShamirSecretSharing.Split(b, threshold, numParties);
        var cShares = ShamirSecretSharing.Split(c, threshold, numParties);

        // Clean up secrets
        SecureMemoryOperations.ZeroMemory(a);
        SecureMemoryOperations.ZeroMemory(b);
        SecureMemoryOperations.ZeroMemory(c);

        // Create Beaver triples for each party
        var triples = new BeaverTriple[numParties];
        for (int i = 0; i < numParties; i++)
        {
            triples[i] = new BeaverTriple(
                new Share(i, aShares[i].Data, aShares[i].Index),
                new Share(i, bShares[i].Data, bShares[i].Index),
                new Share(i, cShares[i].Data, cShares[i].Index)
            );
        }

        return triples;
    }

    /// <summary>
    /// Computes private set intersection (PSI) between two parties.
    ///
    /// Returns elements that appear in both sets without revealing other elements.
    /// </summary>
    /// <param name="party1Set">Party 1's private set</param>
    /// <param name="party2Set">Party 2's private set</param>
    /// <param name="model">Security model</param>
    /// <returns>Intersection of the two sets</returns>
    public static byte[][] PrivateSetIntersection(byte[][] party1Set, byte[][] party2Set,
        SecurityModel model = SecurityModel.SemiHonest)
    {
        if (party1Set == null || party2Set == null)
            throw new ArgumentNullException("Sets cannot be null");

        // Simplified PSI protocol using hashing
        // Production implementations use:
        // - Diffie-Hellman PSI
        // - Circuit-based PSI
        // - Oblivious Polynomial Evaluation
        // - Bloom filters with oblivious transfer

        using var sha256 = SHA256.Create();

        // Hash both sets (simplified - real PSI uses more sophisticated cryptography)
        var set1Hashes = party1Set.Select(item => sha256.ComputeHash(item)).ToList();
        var set2Hashes = party2Set.Select(item => sha256.ComputeHash(item)).ToList();

        // Find intersection (in production: done obliviously)
        var intersection = new List<byte[]>();
        for (int i = 0; i < party1Set.Length; i++)
        {
            var hash1 = set1Hashes[i];
            if (set2Hashes.Any(hash2 => hash1.SequenceEqual(hash2)))
            {
                intersection.Add(party1Set[i]);
            }
        }

        return intersection.ToArray();
    }

    // Helper methods

    private static Share SubtractShares(Share a, Share b)
    {
        var result = new byte[a.Value.Length];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = (byte)(a.Value[i] ^ b.Value[i]); // XOR in GF(256) is addition/subtraction
        }
        return new Share(a.PartyId, result, a.ShareIndex);
    }

    private static byte[] ReconstructSecret(ShamirSecretSharing.Share[] shares)
    {
        return ShamirSecretSharing.Reconstruct(shares);
    }

    private static byte GF256Multiply(byte a, byte b)
    {
        // Multiplication in GF(256) using Rijndael's field
        byte p = 0;
        byte hi_bit_set;

        for (int counter = 0; counter < 8; counter++)
        {
            if ((b & 1) != 0)
                p ^= a;

            hi_bit_set = (byte)(a & 0x80);
            a <<= 1;

            if (hi_bit_set != 0)
                a ^= 0x1B; // Rijndael's irreducible polynomial

            b >>= 1;
        }

        return p;
    }
}
