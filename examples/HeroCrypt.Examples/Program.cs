using HeroCrypt.Examples;
using HeroCrypt.Examples.UseCases;

using Spectre.Console;

while (true)
{
    AnsiConsole.Clear();
    AnsiConsole.Write(
        new FigletText("HeroCrypt")
            .Color(Color.Cyan1));

    AnsiConsole.MarkupLine("[bold yellow]Choose an example to run:[/]");
    Console.WriteLine();

    var choice = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("Select an [green]example[/]:")
            .PageSize(10)
            .AddChoices([
                "1. Fluent API Demo (Text Encoding)",
                "2. Password Storage (Argon2id)",
                "3. Data Encryption (AES-GCM)",
                "4. Secure Messaging (Hybrid Encryption)",
                "5. Secret Sharing (Shamir's Scheme)",
                "6. Cryptographic Wallet (HD Wallet)",
                "7. Corporate Approval (Threshold Sigs)",
                "Exit"
            ]));

    switch (choice)
    {
        case "1. Fluent API Demo (Text Encoding)":
            await FluentApiDemo.RunAsync();
            break;
        case "2. Password Storage (Argon2id)":
            await PasswordStorageExample.RunAsync();
            break;
        case "3. Data Encryption (AES-GCM)":
            await DataEncryptionExample.RunAsync();
            break;
        case "4. Secure Messaging (Hybrid Encryption)":
            await SecureMessagingExample.RunAsync();
            break;
        case "5. Secret Sharing (Shamir's Scheme)":
            await SecretSharingExample.RunAsync();
            break;
        case "6. Cryptographic Wallet (HD Wallet)":
            await CryptographicWalletExample.RunAsync();
            break;
        case "7. Corporate Approval (Threshold Sigs)":
            await CorporateApprovalExample.RunAsync();
            break;
        case "Exit":
            return;
        default:
            break;
    }

    Console.WriteLine();
    AnsiConsole.MarkupLine("[grey]Press Enter to return to menu...[/]");
    Console.ReadLine();
}
