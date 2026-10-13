using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using HeroCrypt.Primitives.Hkdf;
using HeroCrypt.Security;

namespace HeroCrypt.Protocols.DoubleRatchet;

internal static class DoubleRatchetKdf
{
    private static readonly byte[] RootInfo = Encoding.ASCII.GetBytes("HeroCrypt.DoubleRatchet.Root.v1");
    private static readonly byte[] MessageDomain = Encoding.ASCII.GetBytes("HeroCrypt.DoubleRatchet.v1");

    internal static (byte[] Root, byte[] Chain) Root(byte[] root, byte[] dh, SecurityPolicyOptions policy)
    {
        if (root.Length != 32 || dh.Length != 32) throw new ArgumentException("Root and DH keys must be 32 bytes.");
        var material = new HkdfCore(policy).DeriveKey(dh, root, RootInfo, 64, HashAlgorithmName.SHA256);
        try
        {
            return (material.AsSpan(0, 32).ToArray(), material.AsSpan(32, 32).ToArray());
        }
        finally
        {
            SecureMemoryOperations.SecureClear(material);
        }
    }

    internal static (byte[] Next, byte[] Message) Chain(byte[] chain)
    {
        if (chain.Length != 32) throw new ArgumentException("Chain key must be 32 bytes.", nameof(chain));
        using var hmac = new HMACSHA256(chain);
        var message = hmac.ComputeHash([1]);
        return (hmac.ComputeHash([2]), message);
    }

    internal static byte[] AssociatedData(byte[] context, ReadOnlySpan<byte> data, ReadOnlySpan<byte> header)
    {
        var output = new byte[MessageDomain.Length + 8 + context.Length + data.Length + header.Length];
        var span = output.AsSpan();
        MessageDomain.CopyTo(span);
        var offset = MessageDomain.Length;
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, 4), (uint)context.Length);
        offset += 4;
        context.CopyTo(span.Slice(offset));
        offset += context.Length;
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, 4), (uint)data.Length);
        offset += 4;
        data.CopyTo(span.Slice(offset));
        offset += data.Length;
        header.CopyTo(span.Slice(offset));
        return output;
    }
}
