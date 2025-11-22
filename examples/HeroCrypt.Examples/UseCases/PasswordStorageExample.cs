using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Cryptography.Primitives.Kdf;
using HeroCrypt.Security;

namespace HeroCrypt.Examples.UseCases;

/// <summary>
/// Demonstrates secure password storage using Argon2id without exposing internal services.
/// </summary>
public static class PasswordStorageExample
{
    private const int ARGON_ITERATIONS = 3;
    private const int ARGON_MEMORY_SIZE_KB = 65536; // 64 MB
    private const int ARGON_PARALLELISM = 4;
    private const int ARGON_HASH_LENGTH = 32;

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

        // Hash the password using Argon2 core
        PasswordHash passwordHash = CreatePasswordHash(userPassword);

        Console.WriteLine($"Password hash: {passwordHash.Hash[..50]}... (truncated)");
        Console.WriteLine();

        // Store in database (simulated)
        UserRecord userRecord = new()
        {
            UserId = "user123",
            PasswordHash = passwordHash
        };

        Console.WriteLine("User registered successfully.");
        Console.WriteLine($"Stored in database: UserId={userRecord.UserId}");
        Console.WriteLine();

        // Simulate user login
        Console.WriteLine("2. User Login - Correct Password");
        Console.WriteLine("-".PadRight(60, '-'));

        string loginPassword = "MySecurePassword123!";
        Console.WriteLine($"Login attempt with: {loginPassword}");

        // Verify the password
        bool isValid = VerifyPassword(loginPassword, userRecord.PasswordHash);

        Console.WriteLine($"Password verification: {(isValid ? "SUCCESS" : "FAILED")}");
        Console.WriteLine();

        // Simulate failed login
        Console.WriteLine("3. User Login - Wrong Password");
        Console.WriteLine("-".PadRight(60, '-'));

        string wrongPassword = "WrongPassword123!";
        Console.WriteLine($"Login attempt with: {wrongPassword}");

        isValid = VerifyPassword(wrongPassword, userRecord.PasswordHash);

        Console.WriteLine($"Password verification: {(isValid ? "SUCCESS" : "FAILED")}");
        Console.WriteLine();

        // Password change example
        Console.WriteLine("4. Password Change");
        Console.WriteLine("-".PadRight(60, '-'));

        string newPassword = "NewSecurePassword456!";
        Console.WriteLine($"New password: {newPassword}");

        // Hash the new password
        PasswordHash newPasswordHash = CreatePasswordHash(newPassword);

        // Update the user record
        userRecord.PasswordHash = newPasswordHash;

        Console.WriteLine("Password updated successfully.");
        Console.WriteLine();

        // Security recommendations
        Console.WriteLine("5. Security Recommendations");
        Console.WriteLine("-".PadRight(60, '-'));
        Console.WriteLine("- Always use Argon2id (hybrid mode) for password hashing");
        Console.WriteLine("- Use minimum 3 iterations and 64 MB memory");
        Console.WriteLine("- Generate a unique random salt for each password");
        Console.WriteLine("- Store salt and hashing parameters with the hash");
        Console.WriteLine("- Use constant-time comparison to prevent timing attacks");
        Console.WriteLine("- Never log or expose password hashes");
        Console.WriteLine("- Implement rate limiting to prevent brute-force attacks");
        Console.WriteLine();

        await Task.CompletedTask;
    }

    private static PasswordHash CreatePasswordHash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        var hashBytes = Argon2Core.Hash(
            passwordBytes,
            salt,
            ARGON_ITERATIONS,
            ARGON_MEMORY_SIZE_KB,
            ARGON_PARALLELISM,
            ARGON_HASH_LENGTH,
            Argon2Type.Argon2id,
            secret: null,
            associatedData: null);

        return new PasswordHash(
            Convert.ToBase64String(salt),
            Convert.ToBase64String(hashBytes),
            ARGON_ITERATIONS,
            ARGON_MEMORY_SIZE_KB,
            ARGON_PARALLELISM,
            ARGON_HASH_LENGTH);
    }

    private static bool VerifyPassword(string password, PasswordHash stored)
    {
        var salt = Convert.FromBase64String(stored.Salt);
        var expectedHash = Convert.FromBase64String(stored.Hash);
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        var computed = Argon2Core.Hash(
            passwordBytes,
            salt,
            stored.Iterations,
            stored.MemorySizeKb,
            stored.Parallelism,
            stored.HashLength,
            Argon2Type.Argon2id,
            secret: null,
            associatedData: null);

        return SecureMemoryOperations.ConstantTimeEquals(computed, expectedHash);
    }
}

/// <summary>
/// Represents a user record in the database
/// </summary>
public class UserRecord
{
    public string UserId { get; set; } = string.Empty;
    public PasswordHash PasswordHash { get; set; } = PasswordHash.Empty;
}

/// <summary>
/// Simple container for storing Argon2 password hash material.
/// </summary>
public readonly record struct PasswordHash(
    string Salt,
    string Hash,
    int Iterations,
    int MemorySizeKb,
    int Parallelism,
    int HashLength)
{
    public static PasswordHash Empty { get; } = new(string.Empty, string.Empty, 0, 0, 0, 0);
}
