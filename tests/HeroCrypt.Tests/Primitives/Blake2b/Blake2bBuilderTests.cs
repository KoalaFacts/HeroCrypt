namespace HeroCrypt.Tests.Primitives.Blake2b;

public class Blake2bBuilderTests
{
    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.KNOWN_ANSWER)]
    [Trait("Category", TestCategories.FAST)]
    public class KnownAnswerTests
    {
        // Independent Python hashlib.blake2b vectors: backing[i] = i % 251,
        // input = backing[7..(7 + inputLength)], key = bytes(range(32)),
        // salt = b"0123456789ABCDEF", person = b"HeroCrypt-Tests!".
        [Theory]
        [InlineData(0, 64, false, false, false,
            "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE")]
        [InlineData(1, 1, false, false, false, "1C")]
        [InlineData(127, 32, false, false, false,
            "DD0BC1828708ACDCB060FAF36EA98DC846E8F6EE1D07C37CEB18BF4DD37FE4FA")]
        [InlineData(128, 64, true, false, false,
            "B2353C0066C4113D05B28B79FE6F4299A361411FB2C9F132EC6F90E25693AECC52385D77115FC45A234DCF718FC4CC448D7A936C99AD4F91601724577A4E253F")]
        [InlineData(129, 32, true, true, true,
            "C6102B809A9527A908F69F4B8DC60E8A59AD72395E251F5F9E74F62FA2F63027")]
        [InlineData(257, 64, false, true, true,
            "9C0A7028704AEFD1C81FDF2582A40D2030C9748BF31F1B27915704A8ADB0823AC0ACCF9A558F30E003909A3A79B9DE95FA48429C96C873C188DFA3954A143BDB")]
        [InlineData(129, 32, false, true, false,
            "E8F979311EE502AE6B16D37A5CD9B59062CB5E6708FA6DECA9F99FDE8C69B492")]
        [InlineData(128, 32, false, false, true,
            "DC4C11D744CA04292C266F36D9975C43B80CF5B3E1E35E9EEFB1B90452EFED18")]
        public void ComputeHash_InputSlice_MatchesKnownAnswerAndPreservesCallerInput(
            int inputLength, int outputLength, bool keyed, bool salted, bool personalized, string expectedHex)
        {
            var backing = new byte[inputLength + 19];
            for (int i = 0; i < backing.Length; i++)
            {
                backing[i] = (byte)(i % 251);
            }

            var original = backing.ToArray();
            using var builder = HeroCryptBuilder.Blake2b().WithOutputLength(outputLength);
            if (keyed)
            {
                builder.WithKey(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray());
            }

            if (salted)
            {
                builder.WithSalt("0123456789ABCDEF"u8);
            }

            if (personalized)
            {
                builder.WithPersonalization("HeroCrypt-Tests!"u8);
            }

            var hash = builder.ComputeHash(backing.AsSpan(7, inputLength));

            Assert.Equal(expectedHex, Convert.ToHexString(hash));
            Assert.Equal(original, backing);
        }
    }

    [Trait("Category", TestCategories.UNIT)]
    [Trait("Category", TestCategories.MEMORY)]
    [Trait("Category", TestCategories.SLOW)]
    public class Performance
    {
        [Fact]
        public void ComputeHash_LargeInputSpan_DoesNotAllocateInputSizedCopy()
        {
            const int iterations = 4;
            const int maximumBytesPerCall = 64 * 1024;
            var input = new byte[1024 * 1024];
            using var builder = HeroCryptBuilder.Blake2b().WithOutputLength(32);
            for (int i = 0; i < 32; i++)
            {
                builder.ComputeHash(input.AsSpan());
            }

            byte[] hash = [];
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < iterations; i++)
            {
                hash = builder.ComputeHash(input.AsSpan());
            }

            long allocatedBytes = GC.GetAllocatedBytesForCurrentThread() - before;

            Assert.Equal(32, hash.Length);
            Assert.True(allocatedBytes < (long)maximumBytesPerCall * iterations,
                $"Expected less than {maximumBytesPerCall} allocated bytes per call; observed {allocatedBytes / iterations}.");
        }
    }
}
