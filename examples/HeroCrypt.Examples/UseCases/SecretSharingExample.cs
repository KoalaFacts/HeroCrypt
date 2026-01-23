using System.Text;

namespace HeroCrypt.Examples.UseCases;

/// <summary>
/// Demonstrates splitting a high-value secret into shares and reconstructing it.
/// </summary>
public static class SecretSharingExample
{
    public static async Task RunAsync()
    {
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine("Secret Sharing Example - Shamir's Secret Sharing");
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine();

        // 1. Determine the Secret
        string secretPassword = "correct-horse-battery-staple-super-secret-123";
        byte[] secretBytes = Encoding.UTF8.GetBytes(secretPassword);

        Console.WriteLine("1. The Secret to Protect");
        Console.WriteLine($"Secret Payload: \"{secretPassword}\"");
        Console.WriteLine($"Secret Size: {secretBytes.Length} bytes");
        Console.WriteLine();

        // 2. Define Sharing Parameters
        int totalShares = 5;
        int threshold = 3;

        Console.WriteLine("2. Configuration");
        Console.WriteLine($"Total Shares to Generate: {totalShares}");
        Console.WriteLine($"Threshold needed to reconstruct: {threshold}");
        Console.WriteLine("Meaning: Any 3 of the 5 shareholders can restore the secret.");
        Console.WriteLine();

        // 3. Split the Secret
        Console.WriteLine("3. Splitting the Secret...");
        var shares = HeroCryptBuilder.SecretSharing()
            .WithThreshold(threshold)
            .WithShareCount(totalShares)
            .Split(secretBytes);

        Console.WriteLine($"Generated {shares.Length} shares:");
        for (int i = 0; i < shares.Length; i++)
        {
            // Shares are objects with Index and Data. We display the Data.
            // In reality, these would be distributed to different people/locations
            Console.WriteLine($"  Share #{shares[i].Index}: {Convert.ToBase64String(shares[i].Data)[..20]}... ({shares[i].Data.Length} bytes)");
        }
        Console.WriteLine();

        // 4. Reconstruction Scenarios
        Console.WriteLine("4. Testing Reconstruction");

        // Scenario A: Insufficient Shares (2 out of 3 needed)
        Console.WriteLine("  A. Attempting reconstruction with 2 shares (Expected Failure)...");
        var insufficientShares = shares.Take(2).ToArray();
        try
        {
            var failedResult = HeroCryptBuilder.SecretSharing()
                .Reconstruct(insufficientShares);

            // Note: Depending on implementation specifics, it might return garbage or throw.
            // If it returns garbage, the check below ensures we know it failed.
            string recoveredText = Encoding.UTF8.GetString(failedResult);
            if (recoveredText != secretPassword)
            {
                Console.WriteLine("     Result: Failed (Output does not match original secret)");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"     Result: Failed with error: {ex.Message}");
        }

        // Scenario B: Sufficient Shares (3 out of 3 needed)
        Console.WriteLine("  B. Attempting reconstruction with 3 shares (Expected Success)...");

        // Let's pick shares 1, 3, and 5 just to show order doesn't matter
        var sufficientShares = new[] { shares[0], shares[2], shares[4] };

        try
        {
            var recoveredBytes = HeroCryptBuilder.SecretSharing()
                .Reconstruct(sufficientShares);

            string recoveredSecret = Encoding.UTF8.GetString(recoveredBytes);
            Console.WriteLine($"     Recovered Secret: \"{recoveredSecret}\"");

            if (recoveredSecret == secretPassword)
            {
                Console.WriteLine("     SUCCESS: Secret restored correctly!");
            }
            else
            {
                Console.WriteLine("     FAILURE: Restored data mismatch.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"     Result: Unexpected Error: {ex.Message}");
        }

        Console.WriteLine();
        await Task.CompletedTask;
    }
}
