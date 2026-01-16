#if NET10_0_OR_GREATER
using HeroCrypt.Primitives.MLDsa;
using HeroCrypt.Primitives.MLKem;
using HeroCrypt.Primitives.SlhDsa;

namespace HeroCrypt.Examples.PostQuantum;

/// <summary>
/// Entry point for post-quantum examples. Keeps output minimal and avoids non-ASCII banners.
/// </summary>
public static class PostQuantumExamples
{
    public static void RunAll()
    {
        Console.WriteLine("HeroCrypt Post-Quantum Examples");
        if (!MLKemCore.IsSupported() && !MLDsaCore.IsSupported() && !SlhDsaCore.IsSupported())
        {
            Console.WriteLine("PQC not supported on this platform (.NET 10+ with PQC-capable crypto is required).");
            return;
        }

        HybridEncryptionExample.Run();
        DigitalSignatureExample.Run();
        DigitalSignatureExample.RunCodeSigning();
        DigitalSignatureExample.RunMultipartyApproval();
    }
}
#endif
