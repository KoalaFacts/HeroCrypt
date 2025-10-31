using HeroCrypt.Security;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for hardware-accelerated random number generation
/// </summary>
public class HardwareRandomNumberGeneratorTests
{
    [Fact]
    public void Constructor_NoLogger_Success()
    {
        // Act
        using var rng = new HardwareRandomNumberGenerator();

        // Assert
        Assert.NotNull(rng);
    }

    [Fact]
    public void GetBytes_Array_GeneratesRandomData()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        var buffer1 = new byte[32];
        var buffer2 = new byte[32];

        // Act
        rng.GetBytes(buffer1);
        rng.GetBytes(buffer2);

        // Assert
        Assert.NotEqual(buffer1, buffer2); // Should be extremely unlikely to be equal
        Assert.All(buffer1, b => Assert.True(b >= 0 && b <= 255)); // Valid bytes
    }

    [Fact]
    public void GetBytes_Span_GeneratesRandomData()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        Span<byte> buffer1 = stackalloc byte[32];
        Span<byte> buffer2 = stackalloc byte[32];

        // Act
        rng.GetBytes(buffer1);
        rng.GetBytes(buffer2);

        // Assert
        Assert.False(buffer1.SequenceEqual(buffer2)); // Should be extremely unlikely to be equal
    }

    [Fact]
    public void GetBytes_EmptyArray_Success()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        var buffer = Array.Empty<byte>();

        // Act & Assert - Should not throw
        rng.GetBytes(buffer);
    }

    [Fact]
    public void GetBytes_EmptySpan_Success()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        Span<byte> buffer = Span<byte>.Empty;

        // Act & Assert - Should not throw
        rng.GetBytes(buffer);
    }

    [Fact]
    public void GetBytes_NullArray_ThrowsArgumentNullException()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => rng.GetBytes((byte[])null!));
    }

    [Fact]
    public void GetBytes_LargeBuffer_Success()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        var buffer = new byte[10000];

        // Act
        rng.GetBytes(buffer);

        // Assert
        Assert.NotEqual(new byte[10000], buffer); // Should not be all zeros
    }

    [Fact]
    public void GetUInt32_GeneratesRandomValues()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        var values = new HashSet<uint>();

        // Act - Generate 100 values
        for (var i = 0; i < 100; i++)
        {
            values.Add(rng.GetUInt32());
        }

        // Assert - Should have many unique values (extremely unlikely to have duplicates)
        Assert.True(values.Count > 95, $"Expected >95 unique values, got {values.Count}");
    }

    [Fact]
    public void GetUInt64_GeneratesRandomValues()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        var values = new HashSet<ulong>();

        // Act - Generate 100 values
        for (var i = 0; i < 100; i++)
        {
            values.Add(rng.GetUInt64());
        }

        // Assert - Should have many unique values
        Assert.True(values.Count > 95, $"Expected >95 unique values, got {values.Count}");
    }

    [Fact]
    public void Statistics_InitialState_ReturnsZeros()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();

        // Act
        var stats = rng.Statistics;

        // Assert
        Assert.Equal(0, stats.HardwareGeneratedBytes);
        Assert.Equal(0, stats.FallbackGeneratedBytes);
        Assert.Equal(0, stats.HardwareFailureCount);
        Assert.Equal(0, stats.TotalBytesGenerated);
        Assert.Equal(0.0, stats.EfficiencyRatio);
    }

    [Fact]
    public void Statistics_AfterGeneration_TracksBytes()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        var buffer = new byte[100];

        // Act
        rng.GetBytes(buffer);
        var stats = rng.Statistics;

        // Assert
        Assert.Equal(100, stats.TotalBytesGenerated);
        Assert.True(stats.HardwareGeneratedBytes + stats.FallbackGeneratedBytes == 100);

        // Either hardware or fallback should have generated the bytes
        Assert.True(stats.HardwareGeneratedBytes == 100 || stats.FallbackGeneratedBytes == 100);
    }

    [Fact]
    public void Statistics_MultipleOperations_AccumulatesCorrectly()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();

        // Act
        rng.GetBytes(new byte[32]);
        rng.GetUInt32(); // 4 bytes
        rng.GetUInt64(); // 8 bytes
        var stats = rng.Statistics;

        // Assert
        Assert.Equal(44, stats.TotalBytesGenerated); // 32 + 4 + 8
    }

    [Fact]
    public void Statistics_EfficiencyRatio_ValidRange()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        var buffer = new byte[1000];

        // Act
        rng.GetBytes(buffer);
        var stats = rng.Statistics;

        // Assert
        Assert.InRange(stats.EfficiencyRatio, 0.0, 1.0);
    }

    [Fact]
    public void Dispose_MultipleCalls_Success()
    {
        // Arrange
        var rng = new HardwareRandomNumberGenerator();

        // Act & Assert - Multiple dispose calls should not throw
        rng.Dispose();
        rng.Dispose();
    }

    [Fact]
    public void Dispose_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var rng = new HardwareRandomNumberGenerator();
        rng.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => rng.GetBytes(new byte[32]));
        Assert.Throws<ObjectDisposedException>(() => rng.GetUInt32());
        Assert.Throws<ObjectDisposedException>(() => rng.GetUInt64());
    }

    [Fact]
    public void GetBytes_VariousSizes_AllSizesWork()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        var sizes = new[] { 1, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 100, 256 };

        // Act & Assert
        foreach (var size in sizes)
        {
            var buffer = new byte[size];
            rng.GetBytes(buffer);

            // Verify at least some non-zero bytes (extremely unlikely to be all zeros)
            Assert.Contains(buffer, b => b != 0);
        }
    }

    [Fact]
    public void StatisticsToString_ReturnsValidString()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        rng.GetBytes(new byte[100]);

        // Act
        var statsString = rng.Statistics.ToString();

        // Assert
        Assert.Contains("Hardware", statsString);
        Assert.Contains("bytes", statsString);
    }

    [Fact]
    public void ConcurrentAccess_MultipleThreads_Success()
    {
        // Arrange
        using var rng = new HardwareRandomNumberGenerator();
        var tasks = new List<Task>();
        var results = new System.Collections.Concurrent.ConcurrentBag<byte[]>();

        // Act - Generate random data from multiple threads
        for (var i = 0; i < 10; i++)
        {
            tasks.Add(Task.Run(() =>
            {
                var buffer = new byte[32];
                rng.GetBytes(buffer);
                results.Add(buffer);
            }));
        }

        Task.WaitAll(tasks.ToArray());

        // Assert
        Assert.Equal(10, results.Count);
        var stats = rng.Statistics;
        Assert.Equal(320, stats.TotalBytesGenerated); // 10 * 32
    }
}
