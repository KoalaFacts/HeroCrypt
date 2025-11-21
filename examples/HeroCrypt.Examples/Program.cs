using System.Diagnostics;
using HeroCrypt.Cryptography.Primitives.Kdf;
using HeroCrypt.Encryption;
using HeroCrypt.Hashing;

Console.WriteLine("HeroCrypt Examples");
Console.WriteLine("==================\n");

await RunArgon2Examples();
await RunPgpExamples();

async Task RunArgon2Examples()
{
    Console.WriteLine("Argon2 Hashing Examples");
    Console.WriteLine("-----------------------");

    Argon2HashingService argon2Service = new(new Argon2Options
    {
        Type = Argon2Type.Argon2id,
        Iterations = 3,
        MemorySize = 65536,
        Parallelism = 4,
        HashSize = 32,
        SaltSize = 16
    });

    string password = "MySecurePassword123!";
    Console.WriteLine($"Password: {password}");

    Stopwatch sw = Stopwatch.StartNew();
    string hash = await argon2Service.HashAsync(password);
    sw.Stop();

    Console.WriteLine($"Hash: {hash}");
    Console.WriteLine($"Hashing time: {sw.ElapsedMilliseconds}ms");

    sw.Restart();
    bool isValid = await argon2Service.VerifyAsync(password, hash);
    sw.Stop();

    Console.WriteLine($"Verification result: {isValid}");
    Console.WriteLine($"Verification time: {sw.ElapsedMilliseconds}ms");

    sw.Restart();
    bool isInvalid = await argon2Service.VerifyAsync("WrongPassword", hash);
    sw.Stop();

    Console.WriteLine($"Wrong password verification: {isInvalid}");
    Console.WriteLine($"Wrong password verification time: {sw.ElapsedMilliseconds}ms");

    Console.WriteLine();
}

async Task RunPgpExamples()
{
    Console.WriteLine("PGP Encryption Examples");
    Console.WriteLine("-----------------------");

    PgpCryptographyService pgpService = new();

    Console.WriteLine("Generating RSA key pair (2048-bit)...");
    Stopwatch sw = Stopwatch.StartNew();
    var keyPair = await pgpService.GenerateKeyPairAsync("test@example.com", "", 2048);
    sw.Stop();
    Console.WriteLine($"Key generation time: {sw.ElapsedMilliseconds}ms");

    Console.WriteLine("\nPublic Key:");
    Console.WriteLine(keyPair.PublicKey);

    string message = "Hello, this is a secret message!";
    Console.WriteLine($"Original message: {message}");

    sw.Restart();
    string encryptedMessage = await pgpService.EncryptTextAsync(message, keyPair.PublicKey);
    sw.Stop();
    Console.WriteLine($"\nEncryption time: {sw.ElapsedMilliseconds}ms");
    Console.WriteLine("Encrypted message:");
    Console.WriteLine(encryptedMessage);

    sw.Restart();
    string decryptedMessage = await pgpService.DecryptTextAsync(encryptedMessage, keyPair.PrivateKey);
    sw.Stop();
    Console.WriteLine($"\nDecryption time: {sw.ElapsedMilliseconds}ms");
    Console.WriteLine($"Decrypted message: {decryptedMessage}");

    Console.WriteLine($"\nVerification: {message == decryptedMessage}");
}
