using HeroCrypt.Abstractions;
using HeroCrypt.Services;
using Microsoft.Extensions.DependencyInjection;

namespace HeroCrypt.Plugins.BuiltIn;

public class PgpPlugin : AlgorithmPluginBase
{
    public override string Name => "PGP/RSA";
    public override string Version => "1.0.0";
    public override string Description => "PGP-compatible encryption using RSA and AES";
    public override AlgorithmCategory Category => AlgorithmCategory.Encryption;

    public override void Register(IServiceCollection services)
    {
        services.AddSingleton<ICryptographyService, PgpCryptographyService>();
        services.AddSingleton<IKeyGenerationService, PgpCryptographyService>();
    }
}