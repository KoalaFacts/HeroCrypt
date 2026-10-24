# .NET Standard 2.0 secure clearing and collection cost

This change removes the two forced full collections performed by every
`SecureMemoryOperations.SecureClear(byte[])` call in the library's
`netstandard2.0` target. A caller can still hold the supplied array, so
`GC.Collect` cannot reclaim it. The old path additionally created a
random-number generator and overwrote the same buffer three times.

The replacement delegates array clearing to the span overload, which uses
`Volatile.Write(ref byte, 0)` for each byte, then `Thread.MemoryBarrier()`.
It clears the requested managed bytes and avoids an intentional collection.
It is **best-effort**; no guarantee is made about other managed copies, native
provider state, JIT spills, memory snapshots or older-runtime optimizers.
The modern .NET 8/9/10 path remains `CryptographicOperations.ZeroMemory`.

## Earlier baseline and its limits

Prior to this change, a separate run on .NET 10.0.13/Linux x64 loaded a
`netstandard2.0` assembly (SHA-256
`bff71a9ef65ed549860d7f9f7ec424fab9966ec3bed6e187e31957327d93adc1`)
and compared it with the matching `net10.0` assembly (SHA-256
`3051a2cd6b2c751a2f1dec79d099e895a7659e307417294486aec41e3ea25de9`).
For unkeyed BLAKE2b-256, each netstandard sample reported per-generation
collection deltas of 16/16/16 (1 KiB input) and 256/256/256 (16 KiB input),
versus 0/0/0 for the net10 assembly. These are overlapping generation counts,
**not additive**. No elapsed-time or throughput comparison was made. The
earlier temporary raw logs are not included here, so those baseline counts
should be treated as historical observations, not a newly reproduced run.

## Reproduce on the current source

From the repository root with the pinned SDK available:

```bash
dotnet restore src/HeroCrypt/HeroCrypt.csproj --locked-mode
dotnet build src/HeroCrypt/HeroCrypt.csproj -c Release -f netstandard2.0 --no-restore -p:GeneratePackageOnBuild=false
dotnet restore tests/HeroCrypt.NetstandardClearConsumer/HeroCrypt.NetstandardClearConsumer.csproj
dotnet run --project tests/HeroCrypt.NetstandardClearConsumer/HeroCrypt.NetstandardClearConsumer.csproj -c Release
```

The consumer is a real .NET 10 executable with a direct assembly reference
to the **netstandard2.0** output. It rejects an unexpected assembly TFM,
checks array and slice wiping, cross-checks 1 KiB and 16 KiB hashes with
independent Python `hashlib.blake2b` digests, and emits three GC/allocation
samples per size after two warmups. A conservative Gen2 threshold (<4 per
call) catches the historical 16/256 forced collections while tolerating
occasional unrelated host activity.

The CI job retains the JSON report with runtime, OS, process architecture,
assembly SHA-256 and raw samples. A pass establishes only this measured
netstandard assembly on the reported modern .NET host; it does not establish
.NET Framework/Mono behavior, a throughput improvement, or exhaustive erasure
of secret material. Review the retained artifact before drawing conclusions.
