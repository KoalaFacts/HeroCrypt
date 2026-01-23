using System.Text;

namespace HeroCrypt.Examples.UseCases;

/// <summary>
/// Demonstrates a multi-party approval worflow (e.g. corporate spending)
/// using Threshold Signatures where T out of N approvals are required.
/// </summary>
public static class CorporateApprovalExample
{
    public static async Task RunAsync()
    {
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine("Corporate Approval Example - Threshold Signatures");
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine();


        // Scenario: A transaction requires approval from 3 out of 5 executives
        int totalExecutives = 5;
        int approvalThreshold = 3;

        Console.WriteLine("1. Setup: Board of Executives");
        Console.WriteLine($"  Total Members: {totalExecutives}");
        Console.WriteLine($"  Required Approvals: {approvalThreshold}");
        Console.WriteLine();


        // 1. Generate Key Shares for each Executive
        // In a real scenario, a trusted dealer would do this, or distributed key generation (DKG) would be used.
        Console.WriteLine("2. Generating Key Shares for Executives...");

        var keyShares = HeroCryptBuilder.ThresholdSignature()
            .WithParties(totalExecutives)
            .WithThreshold(approvalThreshold)
            .GenerateKeys();

        // keyShares contains 1 Group Public Key (for verifying) and N Secret Key Shares
        var groupPublicKey = keyShares.PublicKey;
        var memberKeys = keyShares.KeyShares; // array of KeyShare objects

        Console.WriteLine($"  Group Public Key Generated: {Convert.ToBase64String(groupPublicKey)[..20]}...");
        Console.WriteLine("  Individual secret keys distributed to members.");
        Console.WriteLine();

        // 2. The Transaction Proposal
        string transactionId = "TX-2023-10-27-001";
        string transactionDetails = "Transfer $1,000,000 to Vendor X";
        string proposal = $"{transactionId}: {transactionDetails}";
        byte[] proposalBytes = Encoding.UTF8.GetBytes(proposal);

        Console.WriteLine("3. Transaction Proposal");
        Console.WriteLine($"  Proposal: \"{proposal}\"");
        Console.WriteLine("  Status: PENDING APPROVAL");
        Console.WriteLine();

        // 3. Collection Approvals (Partial Signatures)
        Console.WriteLine("4. Collecting Approvals (Need 3/5)...");
        var partialSignatures = new List<Protocols.SecretSharing.ThresholdSignatures.PartialSignature>();
        var approvedMembers = new List<int>();

        // Let's say Member 0, Member 2, and Member 4 approve it
        int[] approvingMemberIndices = [0, 2, 4];

        foreach (var memberIndex in approvingMemberIndices)
        {
            Console.WriteLine($"  Executive #{memberIndex + 1} approves and signs.");

            // Each member signs the proposal with their secret key share
            var partialSig = HeroCryptBuilder.ThresholdSignature()
                .WithMessage(proposalBytes)
                .WithKeyShare(memberKeys[memberIndex])
                .WithSigners(approvingMemberIndices)
                .SignPartial();

            partialSignatures.Add(partialSig);
            approvedMembers.Add(memberIndex);
        }
        Console.WriteLine($"  Collected {partialSignatures.Count} partial signatures.");
        Console.WriteLine();

        // 4. Aggregating Signatures
        Console.WriteLine("5. Aggregating Signature into Group Signature...");

        // Anyone can aggregate if they have enough valid partial shares
        var groupSignature = HeroCryptBuilder.ThresholdSignature()
            .WithMessage(proposalBytes)
            .WithPartialSignatures(partialSignatures.ToArray())
            .WithPublicKey(groupPublicKey)
            .CombineSignatures();

        // Assuming ThresholdSignature has a property to get bytes, or we just rely on object for verification
        // Let's assume it has a checkable property or just ToString
        Console.WriteLine($"  Group Signature Generated.");
        Console.WriteLine();

        // 5. Public Verification
        Console.WriteLine("6. Verifying the Transaction (Publicly)...");

        // Anyone with the Group Public Key can verify the signature
        bool isValid = HeroCryptBuilder.ThresholdSignature()
            .WithMessage(proposalBytes)
            .WithPublicKey(groupPublicKey)
            .VerifySignature(groupSignature);

        if (isValid)
        {
            Console.WriteLine("  SUCCESS: Transaction is VALID and APPROVED.");
            Console.WriteLine("  Funds released.");
        }
        else
        {
            Console.WriteLine("  FAILURE: Invalid signature. Transaction REJECTED.");
        }

        Console.WriteLine();
        await Task.CompletedTask;
    }
}
