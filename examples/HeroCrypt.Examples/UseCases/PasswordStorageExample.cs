using HeroCrypt.Cryptography.Argon2;
using HeroCrypt.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;

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

        var userPassword = "MySecurePassword123!";
        Console.WriteLine($"User password: {userPassword}");

        // Generate a unique salt for this user
        var salt = new byte[16];  // 128-bit salt
        RandomNumberGenerator.Fill(salt);
        Console.WriteLine($"Generated salt: {Convert.ToBase64String(salt)}");

        // Hash the password with Argon2id
        var passwordHash = Argon2.Hash(
            Encoding.UTF8.GetBytes(userPassword),
            salt,
            iterations: 3,           // Minimum recommended
            memorySizeKB: 65536,     // 64 MB
            parallelism: 4,          // 4 threads
            hashLength: 32,          // 256-bit hash
            type: Argon2Type.Argon2id  // Hybrid mode (recommended)
        );

        Console.WriteLine($"Password hash: {Convert.ToBase64String(passwordHash)}");
        Console.WriteLine();

        // Store in database (simulated)
        var userRecord = new UserRecord
        {
            UserId = "user123",
            PasswordHash = passwordHash,
            Salt = salt,
            HashingParameters = new HashingParameters
            {
                Iterations = 3,
                MemorySizeKB = 65536,
                Parallelism = 4,
                Type = Argon2Type.Argon2id
            }
        };

        Console.WriteLine("✅ User registered successfully!");
        Console.WriteLine($"Stored in database: UserId={userRecord.UserId}");
        Console.WriteLine();

        // Simulate user login
        Console.WriteLine("2. User Login - Correct Password");
        Console.WriteLine("-".PadRight(60, '-'));

        var loginPassword = "MySecurePassword123!";
        Console.WriteLine($"Login attempt with: {loginPassword}");

        // Retrieve user record from database (simulated)
        var storedRecord = userRecord;  // In real app: await GetUserFromDatabase(userId);

        // Hash the provided password with stored parameters
        var loginHash = Argon2.Hash(
            Encoding.UTF8.GetBytes(loginPassword),
            storedRecord.Salt,
            storedRecord.HashingParameters.Iterations,
            storedRecord.HashingParameters.MemorySizeKB,
            storedRecord.HashingParameters.Parallelism,
            32,
            storedRecord.HashingParameters.Type
        );

        // Compare hashes using constant-time comparison
        bool isValid = loginHash.SequenceEqual(storedRecord.PasswordHash);

        Console.WriteLine($"Password verification: {(isValid ? "✅ SUCCESS" : "❌ FAILED")}");
        Console.WriteLine();

        // Simulate failed login
        Console.WriteLine("3. User Login - Wrong Password");
        Console.WriteLine("-".PadRight(60, '-'));

        var wrongPassword = "WrongPassword123!";
        Console.WriteLine($"Login attempt with: {wrongPassword}");

        var wrongHash = Argon2.Hash(
            Encoding.UTF8.GetBytes(wrongPassword),
            storedRecord.Salt,
            storedRecord.HashingParameters.Iterations,
            storedRecord.HashingParameters.MemorySizeKB,
            storedRecord.HashingParameters.Parallelism,
            32,
            storedRecord.HashingParameters.Type
        );

        isValid = wrongHash.SequenceEqual(storedRecord.PasswordHash);

        Console.WriteLine($"Password verification: {(isValid ? "✅ SUCCESS" : "❌ FAILED")}");
        Console.WriteLine();

        // Password change example
        Console.WriteLine("4. Password Change");
        Console.WriteLine("-".PadRight(60, '-'));

        var newPassword = "NewSecurePassword456!";
        Console.WriteLine($"New password: {newPassword}");

        // Generate a new salt
        var newSalt = new byte[16];
        RandomNumberGenerator.Fill(newSalt);

        // Hash the new password
        var newPasswordHash = Argon2.Hash(
            Encoding.UTF8.GetBytes(newPassword),
            newSalt,
            iterations: 3,
            memorySizeKB: 65536,
            parallelism: 4,
            hashLength: 32,
            type: Argon2Type.Argon2id
        );

        // Update the user record
        storedRecord.PasswordHash = newPasswordHash;
        storedRecord.Salt = newSalt;

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
    public byte[] PasswordHash { get; set; } = Array.Empty<byte>();
    public byte[] Salt { get; set; } = Array.Empty<byte>();
    public HashingParameters HashingParameters { get; set; } = new();
}

/// <summary>
/// Stores Argon2 hashing parameters
/// </summary>
public class HashingParameters
{
    public int Iterations { get; set; }
    public int MemorySizeKB { get; set; }
    public int Parallelism { get; set; }
    public Argon2Type Type { get; set; }
}
