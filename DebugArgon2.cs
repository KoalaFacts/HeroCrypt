using System;
using System.Text;
using HeroCrypt.Cryptography.Argon2;

namespace DebugArgon2
{
class Program
{
    static void Main()
    {
        // RFC 9106 Test Vector 1 for Argon2d
        var password = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
        
        var salt = new byte[] { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                               0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
        
        var secret = new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 };
        
        var ad = new byte[] { 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                             0x04, 0x04, 0x04, 0x04 };
        
        var expected = "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb";
        
        var result = Argon2Core.Hash(
            password: password,
            salt: salt,
            iterations: 3,
            memorySize: 32,
            parallelism: 4,
            hashLength: 32,
            type: Argon2Type.Argon2d,
            associatedData: ad,
            secret: secret
        );
        
        var resultHex = BitConverter.ToString(result).Replace("-", "").ToLower();
        
        Console.WriteLine($"Expected: {expected}");
        Console.WriteLine($"Actual:   {resultHex}");
        Console.WriteLine($"Match:    {expected == resultHex}");
    }
}
}