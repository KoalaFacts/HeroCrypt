using System.Collections.Concurrent;
using HeroCrypt.Security;

namespace HeroCrypt.Tests.Security;

/// <summary>
/// Tests for <see cref="SecurityPolicy"/> and <see cref="SecurityPolicyOptions"/>.
/// </summary>
public class SecurityPolicyTests
{
    /// <summary>
    /// Thread safety tests for SecurityPolicy.
    /// Verifies that AsyncLocal-based scoping works correctly across parallel execution contexts.
    /// </summary>
    [Trait("Category", TestCategories.THREAD_SAFETY)]
    public class ThreadSafetyTests
    {
        private const int ConcurrentOperations = 100;
        private const int ThreadCount = 10;

        [Fact]
        public void Override_InParallelThreads_EachThreadSeesOwnValue()
        {
            // Arrange
            var results = new ConcurrentDictionary<int, SecurityLevel>();
            var levels = new[]
            {
                SecurityLevel.None,
                SecurityLevel.Standard,
                SecurityLevel.Strict,
                SecurityLevel.Compliance
            };

            // Act - Each thread overrides to a different level
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                var expectedLevel = levels[i % levels.Length];
                using (SecurityPolicy.Override(expectedLevel))
                {
                    // Small delay to increase chance of interleaving
                    Thread.SpinWait(100);

                    // Each thread should see its own override, not another thread's
                    results[i] = SecurityPolicy.Current;
                }
            });

            // Assert - Each thread saw its assigned level
            for (int i = 0; i < ConcurrentOperations; i++)
            {
                var expectedLevel = levels[i % levels.Length];
                Assert.Equal(expectedLevel, results[i]);
            }
        }

        [Fact]
        public void Override_DoesNotLeakBetweenThreads()
        {
            // Arrange
            var beforeOverride = new ConcurrentBag<SecurityLevel>();
            var duringOverride = new ConcurrentBag<SecurityLevel>();
            var afterOverride = new ConcurrentBag<SecurityLevel>();
            var barrier = new Barrier(ThreadCount);

            // Act
            Parallel.For(0, ThreadCount, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                // Capture before any override
                beforeOverride.Add(SecurityPolicy.Current);

                barrier.SignalAndWait(); // Sync all threads

                if (i == 0)
                {
                    // Only thread 0 overrides
                    using (SecurityPolicy.Override(SecurityLevel.Compliance))
                    {
                        duringOverride.Add(SecurityPolicy.Current);
                        barrier.SignalAndWait(); // Let other threads check
                        barrier.SignalAndWait(); // Wait for others to finish checking
                    }
                }
                else
                {
                    barrier.SignalAndWait(); // Wait for thread 0 to set override
                    // Other threads should NOT see thread 0's override
                    duringOverride.Add(SecurityPolicy.Current);
                    barrier.SignalAndWait(); // Signal done checking
                }

                afterOverride.Add(SecurityPolicy.Current);
            });

            // Assert
            // Thread 0 should have seen Compliance, others should have seen Standard (default)
            Assert.Contains(SecurityLevel.Compliance, duringOverride);
            Assert.Equal(1, duringOverride.Count(l => l == SecurityLevel.Compliance));
            Assert.Equal(ThreadCount - 1, duringOverride.Count(l => l == SecurityLevel.Standard));
        }

        [Fact]
        public void NestedOverrides_InParallelThreads_WorkCorrectly()
        {
            // Arrange
            var outerResults = new ConcurrentDictionary<int, SecurityLevel>();
            var innerResults = new ConcurrentDictionary<int, SecurityLevel>();
            var afterInnerResults = new ConcurrentDictionary<int, SecurityLevel>();

            // Act
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                using (SecurityPolicy.Override(SecurityLevel.Strict))
                {
                    outerResults[i] = SecurityPolicy.Current;

                    using (SecurityPolicy.Override(SecurityLevel.Compliance))
                    {
                        innerResults[i] = SecurityPolicy.Current;
                    }

                    // After inner scope, should be back to outer level
                    afterInnerResults[i] = SecurityPolicy.Current;
                }
            });

            // Assert - All operations should have consistent results
            Assert.All(outerResults.Values, level => Assert.Equal(SecurityLevel.Strict, level));
            Assert.All(innerResults.Values, level => Assert.Equal(SecurityLevel.Compliance, level));
            Assert.All(afterInnerResults.Values, level => Assert.Equal(SecurityLevel.Strict, level));
        }

        [Fact]
        public async Task Override_FlowsCorrectlyThroughAsyncAwaitAsync()
        {
            // Arrange & Act
            SecurityLevel beforeAsync;
            SecurityLevel duringAsync;
            SecurityLevel afterAwait;

            using (SecurityPolicy.Override(SecurityLevel.Compliance))
            {
                beforeAsync = SecurityPolicy.Current;

                await Task.Delay(10); // Cross async boundary

                duringAsync = SecurityPolicy.Current;
            }

            afterAwait = SecurityPolicy.Current;

            // Assert - AsyncLocal should flow through await
            Assert.Equal(SecurityLevel.Compliance, beforeAsync);
            Assert.Equal(SecurityLevel.Compliance, duringAsync);
            Assert.Equal(SecurityLevel.Standard, afterAwait); // Back to default
        }

        [Fact]
        public async Task Override_InParallelAsyncTasks_EachTaskSeesOwnValueAsync()
        {
            // Arrange
            var results = new ConcurrentDictionary<int, SecurityLevel>();
            var levels = new[]
            {
                SecurityLevel.None,
                SecurityLevel.Standard,
                SecurityLevel.Strict,
                SecurityLevel.Compliance
            };

            // Act
            var tasks = Enumerable.Range(0, ConcurrentOperations).Select(async i =>
            {
                var expectedLevel = levels[i % levels.Length];
                using (SecurityPolicy.Override(expectedLevel))
                {
                    await Task.Delay(Random.Shared.Next(1, 10)); // Random delay
                    results[i] = SecurityPolicy.Current;
                }
            });

            await Task.WhenAll(tasks);

            // Assert
            for (int i = 0; i < ConcurrentOperations; i++)
            {
                var expectedLevel = levels[i % levels.Length];
                Assert.Equal(expectedLevel, results[i]);
            }
        }

        [Fact]
        public void WithLevel_InParallelThreads_EachThreadSeesOwnValue()
        {
            // Arrange
            var results = new ConcurrentDictionary<int, SecurityLevel>();
            var levels = new[]
            {
                SecurityLevel.None,
                SecurityLevel.Standard,
                SecurityLevel.Strict,
                SecurityLevel.Compliance
            };

            // Act
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                var expectedLevel = levels[i % levels.Length];
                SecurityPolicy.WithLevel(expectedLevel, () =>
                {
                    Thread.SpinWait(100);
                    results[i] = SecurityPolicy.Current;
                });
            });

            // Assert
            for (int i = 0; i < ConcurrentOperations; i++)
            {
                var expectedLevel = levels[i % levels.Length];
                Assert.Equal(expectedLevel, results[i]);
            }
        }

        [Fact]
        public void WithLevelFunc_InParallelThreads_ReturnsCorrectValues()
        {
            // Arrange
            var results = new ConcurrentDictionary<int, (SecurityLevel seen, int computed)>();

            // Act
            Parallel.For(0, ConcurrentOperations, new ParallelOptions { MaxDegreeOfParallelism = ThreadCount }, i =>
            {
                var level = (SecurityLevel)(i % 4);
                var result = SecurityPolicy.WithLevel(level, () =>
                {
                    Thread.SpinWait(100);
                    return (SecurityPolicy.Current, i * 2);
                });
                results[i] = result;
            });

            // Assert
            for (int i = 0; i < ConcurrentOperations; i++)
            {
                var expectedLevel = (SecurityLevel)(i % 4);
                Assert.Equal(expectedLevel, results[i].seen);
                Assert.Equal(i * 2, results[i].computed);
            }
        }
    }

    /// <summary>
    /// Tests for SecurityPolicy scope behavior.
    /// </summary>
    public class ScopeTests
    {
        [Fact]
        public void Override_RestoresPreviousLevel_WhenDisposed()
        {
            // Arrange
            var originalLevel = SecurityPolicy.Current;

            // Act
            using (SecurityPolicy.Override(SecurityLevel.Compliance))
            {
                Assert.Equal(SecurityLevel.Compliance, SecurityPolicy.Current);
            }

            // Assert
            Assert.Equal(originalLevel, SecurityPolicy.Current);
        }

        [Fact]
        public void NestedOverrides_RestoreCorrectly()
        {
            // Arrange
            var originalLevel = SecurityPolicy.Current;

            // Act & Assert
            using (SecurityPolicy.Override(SecurityLevel.Strict))
            {
                Assert.Equal(SecurityLevel.Strict, SecurityPolicy.Current);

                using (SecurityPolicy.Override(SecurityLevel.Compliance))
                {
                    Assert.Equal(SecurityLevel.Compliance, SecurityPolicy.Current);

                    using (SecurityPolicy.Override(SecurityLevel.None))
                    {
                        Assert.Equal(SecurityLevel.None, SecurityPolicy.Current);
                    }

                    Assert.Equal(SecurityLevel.Compliance, SecurityPolicy.Current);
                }

                Assert.Equal(SecurityLevel.Strict, SecurityPolicy.Current);
            }

            Assert.Equal(originalLevel, SecurityPolicy.Current);
        }

        [Fact]
        public void ComplianceScope_SetsComplianceLevel()
        {
            using (SecurityPolicy.ComplianceScope())
            {
                Assert.Equal(SecurityLevel.Compliance, SecurityPolicy.Current);
            }
        }

        [Fact]
        public void LegacyScope_SetsNoneLevel()
        {
            using (SecurityPolicy.LegacyScope())
            {
                Assert.Equal(SecurityLevel.None, SecurityPolicy.Current);
            }
        }

        [Fact]
        public void TestingScope_SetsNoneLevel()
        {
            using (SecurityPolicy.TestingScope())
            {
                Assert.Equal(SecurityLevel.None, SecurityPolicy.Current);
            }
        }
    }

    /// <summary>
    /// Tests for SecurityPolicyOptions validation behavior.
    /// </summary>
    public class ValidationTests
    {
        [Fact]
        public void Default_HasStandardLevel()
        {
            Assert.Equal(SecurityLevel.Standard, SecurityPolicyOptions.Default.Level);
        }

        [Fact]
        public void Testing_HasNoneLevel()
        {
            Assert.Equal(SecurityLevel.None, SecurityPolicyOptions.Testing.Level);
        }

        [Fact]
        public void ValidateHash_Sha256_AllowedAtAllLevels()
        {
            var levels = new[]
            {
                SecurityLevel.None,
                SecurityLevel.Standard,
                SecurityLevel.Strict,
                SecurityLevel.Compliance
            };

            foreach (var level in levels)
            {
                var policy = new SecurityPolicyOptions(level);
                var exception = Record.Exception(() => policy.ValidateHash("SHA256"));
                Assert.Null(exception);
            }
        }

        [Fact]
        public void ValidateHash_Sha1_BlockedAtStandardAndAbove()
        {
            var policy = new SecurityPolicyOptions(SecurityLevel.Standard);
            Assert.Throws<SecurityPolicyException>(() => policy.ValidateHash("SHA1"));
        }

        [Fact]
        public void ValidateHash_Sha1_AllowedAtNoneLevel()
        {
            var policy = new SecurityPolicyOptions(SecurityLevel.None);
            var exception = Record.Exception(() => policy.ValidateHash("SHA1"));
            Assert.Null(exception);
        }

        [Fact]
        public void GetEffective_ReturnsProvidedOptions_WhenNotNull()
        {
            var options = new SecurityPolicyOptions(SecurityLevel.Compliance);
            var effective = SecurityPolicy.GetEffective(options);
            Assert.Same(options, effective);
        }

        [Fact]
        public void GetEffective_ReturnsCurrentPolicy_WhenNull()
        {
            using (SecurityPolicy.Override(SecurityLevel.Strict))
            {
                var effective = SecurityPolicy.GetEffective(null);
                Assert.Equal(SecurityLevel.Strict, effective.Level);
            }
        }
    }
}
