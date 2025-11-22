using HeroCrypt.Examples.UseCases;

Console.WriteLine("HeroCrypt Examples");
Console.WriteLine("==================\n");

await PasswordStorageExample.RunAsync();
await DataEncryptionExample.RunAsync();
