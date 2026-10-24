# BLAKE2b builder span input allocation

`Blake2bBuilder.ComputeHash(ReadOnlySpan<byte>)` previously converted the full
input to an array before calling a core that already consumes a span
synchronously. Passing the span directly removes that redundant allocation.
The core algorithm, parameter validation, key handling and zeroization remain
unchanged.

## Recorded comparison

These are managed allocations per synchronous public-builder call, including
its returned digest. Input and builder creation, warmups and reporting are
outside the measured region. No elapsed-time or throughput claim is made.

- Baseline source: `1fe0db9884e70a9460992b52e68d27ed65da8acf`.
- After source: the same base plus the one-line builder change
  `input.ToArray()` to `input`, built from the modified worktree.
- SDK 10.0.402; runtime .NET 10.0.13; Release; `DOTNET_TieredCompilation=0`.
- Ubuntu 24.04.3 LTS, x64, AMD EPYC 9V74 80-Core Processor, eight visible
  processors.
- Unkeyed BLAKE2b-256 via
  `HeroCryptBuilder.Blake2b().WithOutputLength(32).ComputeHash(ReadOnlySpan<byte>)`.
- Input pattern `data[i] = (byte)(i % 251)`; 32 warmup calls per size,
  then three samples of 32 calls each.

All raw samples from the paired run are retained here:

| Input bytes | Sample | Before total bytes / 32 calls | Before bytes/call | After total bytes / 32 calls | After bytes/call |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 1 | 64,256 | 2,008 | 30,720 | 960 |
| 1,024 | 2 | 64,256 | 2,008 | 30,720 | 960 |
| 1,024 | 3 | 64,256 | 2,008 | 30,720 | 960 |
| 1,048,576 | 1 | 33,600,560 | 1,050,017.5 | 30,720 | 960 |
| 1,048,576 | 2 | 33,621,232 | 1,050,663.5 | 30,720 | 960 |
| 1,048,576 | 3 | 33,615,536 | 1,050,485.5 | 30,720 | 960 |

The 1 KiB difference is 1,048 bytes, consistent with removing the input array
and its header on this runtime. Larger-input baseline samples include some
additional runtime allocation noise. The after samples remain 960 bytes/call
for both sizes. These figures demonstrate removal of the input-sized copy;
they do not establish a universal fixed allocation count or a speedup.

The actual copied assemblies used for measurement had these SHA-256 hashes:

| Assembly | SHA-256 |
| --- | --- |
| Before | `bbc51f03574c26e2f949784e5d899a9a62c593fb19cc152f2742b17bce262fba` |
| After | `2470a350bae91094cdaa301865266af9742f0c3338250cbaa88779923bad12de` |

Both assemblies reported informational version
`1.1.0+1fe0db9884e70a9460992b52e68d27ed65da8acf`: the after assembly was
built before committing. The source state, assembly hashes and explicit
before/after labels distinguish them. A later rebuild may have a different
assembly hash.

Every measured hash was independently verified with Python `hashlib.blake2b`:

| Input bytes | Expected 32-byte digest, hexadecimal |
| ---: | --- |
| 1,024 | `D75EDC54BB5ACEE4CC8610568E82872CE79758AFD38C51DFE6CCFAB01C2D191F` |
| 1,048,576 | `8A5A7A9DC3CF203ED374B0A1EEA930601AD2ACBFE2B4BC62CF83DE4EE536528B` |

## Reproduce the allocation measurement

Use the same SDK/runtime for both builds. Build the baseline and changed
sources in separate worktrees with the repository's locked dependencies,
then preserve a copy of each Release `net10.0/HeroCrypt.dll`. Create separate
measurement directories for before and after; place the appropriate copied
assembly at `lib/HeroCrypt.dll` in each. Use these identical project and
program files in both directories. This harness has no package references.
Keep it outside the repository so repository-wide project properties do not
change its setup.

`AllocationBaseline.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="HeroCrypt">
      <HintPath>lib/HeroCrypt.dll</HintPath>
    </Reference>
  </ItemGroup>
</Project>
```

`Program.cs`:

```csharp
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using HeroCrypt;

const int warmupIterations = 32;
const int measuredIterations = 32;
const int sampleCount = 3;
var assembly = typeof(HeroCryptBuilder).Assembly;
var informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
var samples = new List<object>();

foreach (int payloadBytes in new[] { 1024, 1024 * 1024 })
{
    byte[] data = new byte[payloadBytes];
    for (int i = 0; i < data.Length; i++)
        data[i] = (byte)(i % 251);
    using var builder = HeroCryptBuilder.Blake2b().WithOutputLength(32);
    int checksum = 0;
    for (int i = 0; i < warmupIterations; i++)
        checksum ^= builder.ComputeHash(data.AsSpan())[0];

    for (int sample = 1; sample <= sampleCount; sample++)
    {
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < measuredIterations; i++)
            checksum ^= builder.ComputeHash(data.AsSpan())[0];
        long allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - before;
        samples.Add(new
        {
            payloadBytes,
            sample,
            iterations = measuredIterations,
            totalAllocatedBytes = allocatedBytes,
            allocatedBytesPerCall = allocatedBytes / (double)measuredIterations,
            hash = Convert.ToHexString(builder.ComputeHash(data.AsSpan())),
            checksum
        });
    }
}

string cpu = File.ReadLines("/proc/cpuinfo")
    .FirstOrDefault(line => line.StartsWith("model name", StringComparison.Ordinal))?
    .Split(':', 2)[1].Trim() ?? "unknown";
var report = new
{
    kind = Environment.GetEnvironmentVariable("BLAKE2B_MEASUREMENT_KIND") ?? "UNLABELED",
    sourceState = Environment.GetEnvironmentVariable("BLAKE2B_SOURCE_STATE") ?? "unknown",
    sourceCommit = "1fe0db9884e70a9460992b52e68d27ed65da8acf",
    assemblyInformationalVersion = informationalVersion,
    assemblySha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly.Location))).ToLowerInvariant(),
    sdkVersion = "10.0.402",
    runtime = RuntimeInformation.FrameworkDescription,
    tieredCompilationEnvironment = Environment.GetEnvironmentVariable("DOTNET_TieredCompilation") ?? "runtime default",
    os = RuntimeInformation.OSDescription,
    architecture = RuntimeInformation.ProcessArchitecture.ToString(),
    cpu,
    visibleProcessorCount = Environment.ProcessorCount,
    warmupIterationsPerSize = warmupIterations,
    measuredIterationsPerSample = measuredIterations,
    samplesPerSize = sampleCount,
    algorithm = "BLAKE2b-256, unkeyed",
    api = "HeroCryptBuilder.Blake2b().WithOutputLength(32).ComputeHash(ReadOnlySpan<byte>)",
    inputPattern = "byte[i] = i % 251",
    method = "GC.GetAllocatedBytesForCurrentThread around synchronous calls; Release build; no stopwatch; no forced GC",
    scope = "Per-call managed allocation including result arrays; excludes builder/input setup and reporting; allocation-only comparison; not throughput, cross-platform, netstandard2.0, or security evidence",
    samples
};
Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
```

In each measurement directory, pin SDK 10.0.402 with `global.json` and use a
`NuGet.Config` containing `<configuration><packageSources><clear /></packageSources></configuration>`.
Restore and build once, then run with the appropriate source-state label:

```bash
dotnet restore AllocationBaseline.csproj --configfile NuGet.Config
dotnet build AllocationBaseline.csproj -c Release --no-restore -m:1 -p:UseSharedCompilation=false -v:minimal
DOTNET_TieredCompilation=0 BLAKE2B_MEASUREMENT_KIND=BEFORE_RETAINED_BASELINE BLAKE2B_SOURCE_STATE=clean-base-1fe0db9 dotnet bin/Release/net10.0/AllocationBaseline.dll > before.json
# In the separate after directory, after building against its copied DLL:
DOTNET_TieredCompilation=0 BLAKE2B_MEASUREMENT_KIND=AFTER_MODIFIED_WORKTREE BLAKE2B_SOURCE_STATE=modified-builder-span-input dotnet bin/Release/net10.0/AllocationBaseline.dll > after.json
```

Verify each JSON sample independently:

```python
import hashlib
import json
from pathlib import Path

for filename in ("before.json", "after.json"):
    report = json.loads(Path(filename).read_text())
    for sample in report["samples"]:
        data = bytes(i % 251 for i in range(sample["payloadBytes"]))
        expected = hashlib.blake2b(data, digest_size=32).hexdigest().upper()
        assert sample["hash"] == expected
```

## Regression coverage and limits

Public-builder tests use independent literal digests for offset input slices
at lengths 0, 1, 127, 128, 129 and 257, with keyed and unkeyed hashing,
salt/personalization combinations and 1/32/64-byte outputs. They verify the
entire caller buffer remains unchanged.

The allocation regression creates its 1 MiB input and builder before
measurement, warms 32 calls, then measures four synchronous calls using
`GC.GetAllocatedBytesForCurrentThread`. Its generous limit is 64 KiB per call,
well below an input-sized copy. Before the fix it failed at 1,051,390 bytes per
call; after the fix it passed. It uses no timing threshold or forced GC.

The focused builder/core tests passed on .NET 8.0.32, 9.0.21 and 10.0.13.
The allocation table measures only .NET 10 on the environment above, unkeyed
hashing and the specified sizes. It is not evidence about throughput,
netstandard2.0 runtime behavior, all platforms, or security properties.
