using System.Text;
using HeroCrypt.Cryptography.Blake2b;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for Blake2b implementation according to RFC 7693
/// </summary>
public class Blake2bTests
{
    /// <summary>
    /// Test vector from RFC 7693 Appendix A
    /// </summary>
    [Fact]
    public void Blake2b_512_EmptyInput()
    {
        var data = Array.Empty<byte>();
        var hash = Blake2bCore.ComputeHash(data, 64);
        
        var expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
                      "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
        
        var actual = BitConverter.ToString(hash).Replace("-", "").ToLower();
        Assert.Equal(expected, actual);
    }
    
    /// <summary>
    /// Test vector from RFC 7693 - "abc"
    /// </summary>
    [Fact]
    public void Blake2b_512_ABC()
    {
        var data = Encoding.ASCII.GetBytes("abc");
        var hash = Blake2bCore.ComputeHash(data, 64);
        
        var expected = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
                      "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
        
        var actual = BitConverter.ToString(hash).Replace("-", "").ToLower();
        Assert.Equal(expected, actual);
    }
    
    /// <summary>
    /// Test with different output sizes
    /// </summary>
    [Theory]
    [InlineData(16)]
    [InlineData(20)]
    [InlineData(32)]
    [InlineData(48)]
    [InlineData(64)]
    public void Blake2b_VariableOutputSize(int outputSize)
    {
        var data = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        var hash = Blake2bCore.ComputeHash(data, outputSize);
        
        Assert.Equal(outputSize, hash.Length);
        
        // Verify that different output sizes produce different hashes
        var hash32 = Blake2bCore.ComputeHash(data, 32);
        var hash64 = Blake2bCore.ComputeHash(data, 64);
        
        // First 32 bytes should be different due to parameter encoding
        var hash64Truncated = new byte[32];
        Array.Copy(hash64, hash64Truncated, 32);
        
        Assert.NotEqual(hash32, hash64Truncated);
    }
    
    /// <summary>
    /// Test Blake2b with key (keyed hash/MAC mode)
    /// </summary>
    [Fact]
    public void Blake2b_WithKey()
    {
        var data = Encoding.UTF8.GetBytes("message");
        var key = Encoding.UTF8.GetBytes("key");
        
        var hashWithKey = Blake2bCore.ComputeHash(data, 32, key);
        var hashWithoutKey = Blake2bCore.ComputeHash(data, 32);
        
        Assert.NotEqual(hashWithKey, hashWithoutKey);
        Assert.Equal(32, hashWithKey.Length);
    }
    
    /// <summary>
    /// Test Blake2b-Long for output > 64 bytes
    /// </summary>
    [Fact]
    public void Blake2b_Long_128Bytes()
    {
        var data = Encoding.UTF8.GetBytes("test data for blake2b long output");
        var hash = Blake2bCore.ComputeHashLong(data, 128);
        
        Assert.Equal(128, hash.Length);
        
        // Verify it's different from truncated 64-byte hash
        var hash64 = Blake2bCore.ComputeHash(data, 64);
        var first64 = new byte[64];
        Array.Copy(hash, first64, 64);
        
        // Should be different due to length prepending in Blake2b-Long
        Assert.NotEqual(hash64, first64);
    }
    
    /// <summary>
    /// Test incremental hashing produces same result
    /// </summary>
    [Fact]
    public void Blake2b_ConsistentResults()
    {
        var data = Encoding.UTF8.GetBytes("consistent hashing test");
        
        var hash1 = Blake2bCore.ComputeHash(data, 64);
        var hash2 = Blake2bCore.ComputeHash(data, 64);
        
        Assert.Equal(hash1, hash2);
    }
    
    /// <summary>
    /// Test with maximum key size
    /// </summary>
    [Fact]
    public void Blake2b_MaxKeySize()
    {
        var data = Encoding.UTF8.GetBytes("data");
        var key = new byte[64]; // Maximum key size
        for (var i = 0; i < key.Length; i++)
        {
            key[i] = (byte)i;
        }
        
        var hash = Blake2bCore.ComputeHash(data, 32, key);
        Assert.Equal(32, hash.Length);
    }
    
    /// <summary>
    /// Test error handling for invalid parameters
    /// </summary>
    [Fact]
    public void Blake2b_InvalidParameters()
    {
        var data = new byte[10];
        
        // Hash size too large
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Blake2bCore.ComputeHash(data, 65));
        
        // Hash size too small
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Blake2bCore.ComputeHash(data, 0));
        
        // Key too large
        var largeKey = new byte[65];
        Assert.Throws<ArgumentException>(() =>
            Blake2bCore.ComputeHash(data, 32, largeKey));
        
        // Null data
        Assert.Throws<ArgumentNullException>(() =>
            Blake2bCore.ComputeHash(null!, 32));
    }
    
    /// <summary>
    /// Test known test vector for Blake2b-256
    /// </summary>
    [Fact]
    public void Blake2b_256_KnownVector()
    {
        var data = Encoding.UTF8.GetBytes("hello world");
        var hash = Blake2bCore.ComputeHash(data, 32);
        
        // Known output for "hello world" with Blake2b-256
        var expected = "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610";
        
        var actual = BitConverter.ToString(hash).Replace("-", "").ToLower();
        Assert.Equal(expected, actual);
    }
}