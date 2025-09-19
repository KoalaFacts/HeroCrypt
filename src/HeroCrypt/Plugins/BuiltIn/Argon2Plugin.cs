using HeroCrypt.Abstractions;
using HeroCrypt.Services;
using Microsoft.Extensions.DependencyInjection;

namespace HeroCrypt.Plugins.BuiltIn;

public class Argon2Plugin : AlgorithmPluginBase
{
    public override string Name => "Argon2";
    public override string Version => "1.0.0";
    public override string Description => "RFC 9106 compliant Argon2 password hashing (Argon2d, Argon2i, Argon2id)";
    public override AlgorithmCategory Category => AlgorithmCategory.KeyDerivation;

    public override void Register(IServiceCollection services)
    {
        services.AddSingleton<IHashingService, Argon2HashingService>();
        services.AddSingleton<Argon2Options>();
    }
}