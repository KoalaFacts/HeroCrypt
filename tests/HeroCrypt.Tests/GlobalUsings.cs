global using Xunit;

// Resolve namespace ambiguities for .NET 10+ post-quantum crypto
#if NET10_0_OR_GREATER
// Use fully qualified names to avoid conflicts between System.Security.Cryptography and HeroCrypt wrappers
global using BclMLKem = System.Security.Cryptography.MLKem;
global using BclMLDsa = System.Security.Cryptography.MLDsa;
global using BclSlhDsa = System.Security.Cryptography.SlhDsa;
#endif
