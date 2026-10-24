using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using HeroCrypt;
using HeroCrypt.Security;

// This runs on .NET 10 while loading the library's *netstandard2.0* assembly.
var assembly = typeof(SecureMemoryOperations).Assembly;
string? targetFramework = assembly.GetCustomAttribute<TargetFrameworkAttribute>()?.FrameworkName;
if (targetFramework != ".NETStandard,Version=v2.0")
{
    throw new InvalidOperationException("Unexpected HeroCrypt target: " + targetFramework);
}

byte[] data = Enumerable.Repeat((byte)0xA5, 1024).ToArray();
SecureMemoryOperations.SecureClear(data);
if (data.Any(value => value != 0))
{
    throw new InvalidOperationException("Array was not cleared.");
}

byte[] segment = Enumerable.Repeat((byte)0x5A, 20).ToArray();
SecureMemoryOperations.SecureClear(segment.AsSpan(4, 12));
if (segment.Take(4).Any(value => value != 0x5A)
    || segment.Skip(4).Take(12).Any(value => value != 0)
    || segment.Skip(16).Any(value => value != 0x5A))
{
    throw new InvalidOperationException("Span wipe modified an unrelated byte.");
}

var samples = new List<object>();
foreach ((int length, string expected) in new[]
{
    (1024, "D75EDC54BB5ACEE4CC8610568E82872CE79758AFD38C51DFE6CCFAB01C2D191F"),
    (16384, "96BF38F5A0D5DF76B3DE7EE5B137EB7AF5A1D86B5B1B0EAB2F91D18B76F035E8")
})
{
    var payload = new byte[length];
    for (int index = 0; index < payload.Length; index++)
    {
        payload[index] = (byte)(index % 251);
    }

    using var builder = HeroCryptBuilder.Blake2b().WithOutputLength(32);
    for (int warmup = 0; warmup < 2; warmup++)
    {
        if (Convert.ToHexString(builder.ComputeHash(payload.AsSpan())) != expected)
        {
            throw new InvalidOperationException("BLAKE2b warmup disagreed with Python hashlib.");
        }
    }

    for (int sample = 1; sample <= 3; sample++)
    {
        int g0 = GC.CollectionCount(0), g1 = GC.CollectionCount(1), g2 = GC.CollectionCount(2);
        long allocationBefore = GC.GetAllocatedBytesForCurrentThread();
        byte[] digest = builder.ComputeHash(payload.AsSpan());
        long allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - allocationBefore;
        int delta0 = GC.CollectionCount(0) - g0, delta1 = GC.CollectionCount(1) - g1,
            delta2 = GC.CollectionCount(2) - g2;

        if (Convert.ToHexString(digest) != expected)
        {
            throw new InvalidOperationException("BLAKE2b output disagreed with Python hashlib.");
        }
        // An ordinary host collection is possible. The old netstandard path
        // forced 16 or 256 Gen2 collections for these sizes, respectively.
        if (delta2 >= 4)
        {
            throw new InvalidOperationException(
                $"Unexpected Gen2 collection count for {length} bytes: {delta2}.");
        }
        samples.Add(new
        {
            inputBytes = length,
            sample,
            gcGen0 = delta0,
            gcGen1 = delta1,
            gcGen2 = delta2,
            allocatedBytes,
            digest = expected
        });
    }
}

Console.WriteLine(JsonSerializer.Serialize(new
{
    source = "netstandard2.0 assembly on .NET 10 host",
    assemblyTargetFramework = targetFramework,
    assemblySha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly.Location))),
    runtime = RuntimeInformation.FrameworkDescription,
    operatingSystem = RuntimeInformation.OSDescription,
    architecture = RuntimeInformation.ProcessArchitecture.ToString(),
    processorCount = Environment.ProcessorCount,
    warmupsPerInputSize = 2,
    samplesPerInputSize = 3,
    scope = "BLAKE2b-256 managed GC counts and allocations; not elapsed time, throughput, CLR/Mono legacy host, or proof of complete memory erasure",
    samples
}, new JsonSerializerOptions { WriteIndented = true }));
