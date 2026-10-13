using HeroCrypt.Security;

namespace HeroCrypt.Primitives.Ed25519;

internal sealed partial class Ed25519Impl
{
    internal byte[] SignXEdDsa(ReadOnlySpan<byte> message, ReadOnlySpan<byte> clampedPrivateKey, ReadOnlySpan<byte> randomness)
    {
        if (clampedPrivateKey.Length != 32 || randomness.Length != 64)
            throw new ArgumentException("XEdDSA requires a 32-byte scalar and 64-byte randomness.");
        byte[] scalar = []; byte[] negative = []; byte[] publicKey = [];
        long[] work = []; byte[] input = []; byte[] challengeInput = [];
        byte[] nonce = [];
        byte[] challenge = [];
        long[][] point = [];
        try
        {
            scalar = clampedPrivateKey.ToArray(); negative = new byte[32]; publicKey = new byte[32]; work = new long[64];
            input = new byte[checked(message.Length + 128)]; challengeInput = new byte[checked(message.Length + 64)];
            point = NewXEdPoint();
            Scalarbase(point, scalar); Pack(publicKey, point);
            var sign = publicKey[31] >> 7;
            for (var i = 0; i < 32; i++) work[i] = -scalar[i];
            ModL(negative, 0, work);
            var mask = -sign;
            for (var i = 0; i < 32; i++) scalar[i] = (byte)((scalar[i] & ~mask) | (negative[i] & mask));
            publicKey[31] &= 127;
            input[0] = 0xFE;
            for (var i = 1; i < 32; i++) input[i] = 0xFF;
            scalar.CopyTo(input, 32); message.CopyTo(input.AsSpan(64));
            randomness.CopyTo(input.AsSpan(64 + message.Length));
            nonce = Sha512(input); Reduce(nonce);
            Scalarbase(point, nonce);
            var signature = new byte[64];
            Pack(signature, point);
            signature.AsSpan(0, 32).CopyTo(challengeInput);
            publicKey.CopyTo(challengeInput, 32); message.CopyTo(challengeInput.AsSpan(64));
            challenge = Sha512(challengeInput); Reduce(challenge);
            Array.Clear(work, 0, work.Length);
            for (var i = 0; i < 32; i++) work[i] = nonce[i];
            for (var i = 0; i < 32; i++)
                for (var j = 0; j < 32; j++) work[i + j] += (long)challenge[i] * scalar[j];
            ModL(signature, 32, work);
            return signature;
        }
        finally
        {
            ClearArray(scalar); ClearArray(negative); ClearArray(publicKey); ClearArray(input);
            ClearArray(challengeInput); ClearArray(nonce); ClearArray(challenge); ClearLongArray(work); ClearXEdPoint(point);
        }
    }

    internal bool VerifyXEdDsa(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> montgomeryPublicKey)
    {
        if (!XEdCanonical(montgomeryPublicKey, false) || !XEdCanonical(signature[..32], true)) return false;
        for (var i = 31; i >= 0; i--)
        {
            if (signature[32 + i] < L[i]) break;
            if (signature[32 + i] > L[i] || i == 0) return false;
        }
        foreach (var key in XEdLowOrder)
            if (SecureMemoryOperations.ConstantTimeEquals(key, montgomeryPublicKey)) return false;
        var u = new long[16]; var numerator = new long[16]; var denominator = new long[16]; var inverse = new long[16];
        var ed = new byte[32]; byte[] msg = []; byte[] sig = [];
        long[][] publicPoint = []; long[][] rPoint = [];
        try
        {
            Unpack25519(u, montgomeryPublicKey.ToArray());
            var one = Gf1();
            Z(numerator, u, one); A(denominator, u, one); Inv25519(inverse, denominator);
            M(numerator, numerator, inverse); Pack25519(ed, numerator);
            publicPoint = NewXEdPoint(); rPoint = NewXEdPoint();
            if (!Unpackneg(publicPoint, ed) || !Unpackneg(rPoint, signature[..32].ToArray())) return false;
            // Reject the noncanonical sign-one encoding of a point whose x is zero.
            var x = new byte[32]; Pack25519(x, rPoint[0]);
            if ((signature[31] & 128) != 0 && x.All(b => b == 0)) return false;
            msg = message.ToArray(); sig = signature.ToArray();
            return Verify(msg, sig, ed);
        }
        finally
        {
            ClearLongArray(u); ClearLongArray(numerator); ClearLongArray(denominator); ClearLongArray(inverse);
            ClearArray(ed); ClearArray(msg); ClearArray(sig); ClearXEdPoint(publicPoint); ClearXEdPoint(rPoint);
        }
    }

    private static bool XEdCanonical(ReadOnlySpan<byte> key, bool signBit)
    {
        if (key.Length != 32 || (!signBit && (key[31] & 128) != 0)) return false;
        for (var i = 31; i >= 0; i--)
        {
            var b = i == 31 ? key[i] & 127 : key[i];
            var p = i == 31 ? 127 : i == 0 ? 237 : 255;
            if (b < p) return true;
            if (b > p) return false;
        }
        return false;
    }

    private static long[][] NewXEdPoint()
    {
        var point = new long[4][];
        try { for (var i = 0; i < 4; i++) point[i] = new long[16]; return point; }
        catch { ClearXEdPoint(point); throw; }
    }

    private static void ClearXEdPoint(long[][] point)
    {
        foreach (var coordinate in point)
            if (coordinate != null) SecureMemoryOperations.SecureClear(coordinate.AsSpan());
    }

    private static readonly byte[][] XEdLowOrder =
    [
        new byte[32], [1, .. new byte[31]],
        [0xE0,0xEB,0x7A,0x7C,0x3B,0x41,0xB8,0xAE,0x16,0x56,0xE3,0xFA,0xF1,0x9F,0xC4,0x6A,0xDA,0x09,0x8D,0xEB,0x9C,0x32,0xB1,0xFD,0x86,0x62,0x05,0x16,0x5F,0x49,0xB8,0x00],
        [0x5F,0x9C,0x95,0xBC,0xA3,0x50,0x8C,0x24,0xB1,0xD0,0xB1,0x55,0x9C,0x83,0xEF,0x5B,0x04,0x44,0x5C,0xC4,0x58,0x1C,0x8E,0x86,0xD8,0x22,0x4E,0xDD,0xD0,0x9F,0x11,0x57],
        [0xEC, .. Enumerable.Repeat((byte)0xFF, 30), 0x7F]
    ];
}
