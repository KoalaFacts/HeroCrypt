using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;

namespace HeroCrypt.Tests.Protocols.X3dh;

internal static class X3dhReference
{
    internal static byte[] Key(string name) => SHA256.HashData(Encoding.UTF8.GetBytes("profile " + name));
    internal static byte[] Public(byte[] key)
    {
        var output = new byte[32]; BcX25519.GeneratePublicKey(key, 0, output, 0); return output;
    }
    internal static byte[] Dh(byte[] key, byte[] other)
    {
        var output = new byte[32]; Assert.True(BcX25519.CalculateAgreement(key, 0, other, 0, output, 0)); return output;
    }
    internal static byte[] Secret(bool opk)
    {
        var a = Key("Alice identity"); var e = Key("Alice ephemeral");
        var input = new List<byte>(Enumerable.Repeat((byte)255, 32));
        input.AddRange(Dh(a, Public(Key("signed prekey"))));
        input.AddRange(Dh(e, Public(Key("Bob identity")))); input.AddRange(Dh(e, Public(Key("signed prekey"))));
        if (opk) input.AddRange(Dh(e, Public(Key("one time"))));
        var generator = new HkdfBytesGenerator(new Sha256Digest());
        generator.Init(new HkdfParameters(input.ToArray(), new byte[32], "HeroCrypt.X3DH.v1"u8.ToArray()));
        var result = new byte[32]; generator.GenerateBytes(result, 0, 32); return result;
    }
}
