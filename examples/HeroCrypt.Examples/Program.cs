using HeroCrypt.Examples.UseCases;

Console.WriteLine("HeroCrypt Examples");
Console.WriteLine("==================\n");

await PasswordStorageExample.RunAsync();
await DataEncryptionExample.RunAsync();
await SecureMessagingExample.RunAsync();
await SecretSharingExample.RunAsync();
await CryptographicWalletExample.RunAsync();
await CorporateApprovalExample.RunAsync();
