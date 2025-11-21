using HeroCrypt.Hashing;

namespace HeroCrypt.Examples.UseCases;

/// <summary>
/// Demonstrates secure password storage using Argon2id
/// </summary>
public static class PasswordStorageExample
{
    public static async Task RunAsync()
    {
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine("Password Storage Example - Argon2id");
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine();

        // Simulate user registration
        Console.WriteLine("1. User Registration");
        Console.WriteLine("-".PadRight(60, '-'));

        string userPassword = "MySecurePassword123!";
        Console.WriteLine($"User password: {userPassword}");

        // Create Argon2 hashing service with high security settings
        Argon2Options argon2Options = new()
        {
            Type = Cryptography.Primitives.Kdf.Argon2Type.Argon2id,
            Iterations = 3,
            MemorySize = 65536,  // 64 MB
            Parallelism = 4,
            HashSize = 32,
            SaltSize = 16
        };

        Argon2HashingService hashingService = new(argon2Options);

        // Hash the password
        string passwordHash = await hashingService.HashAsync(userPassword);

        Console.WriteLine($"Password hash: {passwordHash[..50]}... (truncated)");
        Console.WriteLine();

        // Store in database (simulated)
        UserRecord userRecord = new()
        {
            UserId = "user123",
            PasswordHash = passwordHash
        };

        Console.WriteLine("✅ User registered successfully!");
        Console.WriteLine($"Stored in database: UserId={userRecord.UserId}");
        Console.WriteLine();

        // Simulate user login
        Console.WriteLine("2. User Login - Correct Password");
        Console.WriteLine("-".PadRight(60, '-'));

        string loginPassword = "MySecurePassword123!";
        Console.WriteLine($"Login attempt with: {loginPassword}");

        // Verify the password
        bool isValid = await hashingService.VerifyAsync(loginPassword, userRecord.PasswordHash);

        Console.WriteLine($"Password verification: {(isValid ? "✅ SUCCESS" : "❌ FAILED")}");
        Console.WriteLine();

        // Simulate failed login
        Console.WriteLine("3. User Login - Wrong Password");
        Console.WriteLine("-".PadRight(60, '-'));

        string wrongPassword = "WrongPassword123!";
        Console.WriteLine($"Login attempt with: {wrongPassword}");

        isValid = await hashingService.VerifyAsync(wrongPassword, userRecord.PasswordHash);

        Console.WriteLine($"Password verification: {(isValid ? "✅ SUCCESS" : "❌ FAILED")}");
        Console.WriteLine();

        // Password change example
        Console.WriteLine("4. Password Change");
        Console.WriteLine("-".PadRight(60, '-'));

        string newPassword = "NewSecurePassword456!";
        Console.WriteLine($"New password: {newPassword}");

        // Hash the new password
        string newPasswordHash = await hashingService.HashAsync(newPassword);

        // Update the user record
        userRecord.PasswordHash = newPasswordHash;

        Console.WriteLine("✅ Password updated successfully!");
        Console.WriteLine();

        // Security recommendations
        Console.WriteLine("5. Security Recommendations");
        Console.WriteLine("-".PadRight(60, '-'));
        Console.WriteLine("✅ Always use Argon2id (hybrid mode) for password hashing");
        Console.WriteLine("✅ Use minimum 3 iterations and 64 MB memory");
        Console.WriteLine("✅ Generate a unique random salt for each password");
        Console.WriteLine("✅ Store salt and hashing parameters with the hash");
        Console.WriteLine("✅ Use constant-time comparison to prevent timing attacks");
        Console.WriteLine("✅ Never log or expose password hashes");
        Console.WriteLine("✅ Implement rate limiting to prevent brute-force attacks");
        Console.WriteLine();

        await Task.CompletedTask;
    }
}

/// <summary>
/// Represents a user record in the database
/// </summary>
public class UserRecord
{
    public string UserId { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
}
