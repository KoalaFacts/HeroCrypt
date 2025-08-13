using HeroCrypt.Cryptography.Argon2;
using HeroCrypt.Services;
using System.Diagnostics;

Console.WriteLine("HeroCrypt Examples");
Console.WriteLine("==================\n");

await RunArgon2Examples();
await RunPgpExamples();

async Task RunArgon2Examples()
{
    Console.WriteLine("Argon2 Hashing Examples");
    Console.WriteLine("-----------------------");
    
    var argon2Service = new Argon2HashingService(new Argon2Options
    {
        Type = Argon2Type.Argon2id,
        Iterations = 3,
        MemorySize = 65536,
        Parallelism = 4,
        HashSize = 32,
        SaltSize = 16
    });
    
    var password = "MySecurePassword123!";
    Console.WriteLine($"Password: {password}");
    
    var sw = Stopwatch.StartNew();
    var hash = await argon2Service.HashAsync(password);
    sw.Stop();
    
    Console.WriteLine($"Hash: {hash}");
    Console.WriteLine($"Hashing time: {sw.ElapsedMilliseconds}ms");
    
    sw.Restart();
    var isValid = await argon2Service.VerifyAsync(password, hash);
    sw.Stop();
    
    Console.WriteLine($"Verification result: {isValid}");
    Console.WriteLine($"Verification time: {sw.ElapsedMilliseconds}ms");
    
    sw.Restart();
    var isInvalid = await argon2Service.VerifyAsync("WrongPassword", hash);
    sw.Stop();
    
    Console.WriteLine($"Wrong password verification: {isInvalid}");
    Console.WriteLine($"Wrong password verification time: {sw.ElapsedMilliseconds}ms");
    
    Console.WriteLine();
}

async Task RunPgpExamples()
{
    Console.WriteLine("PGP Encryption Examples");
    Console.WriteLine("-----------------------");
    
    var pgpService = new PgpCryptographyService();
    
    Console.WriteLine("Generating RSA key pair (2048-bit)...");
    var sw = Stopwatch.StartNew();
    var keyPair = await pgpService.GenerateKeyPairAsync("test@example.com", "", 2048);
    sw.Stop();
    Console.WriteLine($"Key generation time: {sw.ElapsedMilliseconds}ms");
    
    Console.WriteLine("\nPublic Key:");
    Console.WriteLine(keyPair.PublicKey);
    
    var message = "Hello, this is a secret message!";
    Console.WriteLine($"Original message: {message}");
    
    sw.Restart();
    var encryptedMessage = await pgpService.EncryptTextAsync(message, keyPair.PublicKey);
    sw.Stop();
    Console.WriteLine($"\nEncryption time: {sw.ElapsedMilliseconds}ms");
    Console.WriteLine("Encrypted message:");
    Console.WriteLine(encryptedMessage);
    
    sw.Restart();
    var decryptedMessage = await pgpService.DecryptTextAsync(encryptedMessage, keyPair.PrivateKey);
    sw.Stop();
    Console.WriteLine($"\nDecryption time: {sw.ElapsedMilliseconds}ms");
    Console.WriteLine($"Decrypted message: {decryptedMessage}");
    
    Console.WriteLine($"\nVerification: {message == decryptedMessage}");
}
