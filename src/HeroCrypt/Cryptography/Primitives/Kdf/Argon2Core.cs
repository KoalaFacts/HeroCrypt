#if NETSTANDARD2_0
using System;
#else
using System.Buffers.Binary;
#endif
using System.Runtime.CompilerServices;
using HeroCrypt.Cryptography.Primitives.Hash;

namespace HeroCrypt.Cryptography.Primitives.Kdf;

/// <summary>
/// Core implementation of the Argon2 password hashing algorithm
/// Implements RFC 9106 specification for Argon2d, Argon2i, and Argon2id variants
/// </summary>
public static class Argon2Core
{
    private const int BLOCK_SIZE = 1024;
    private const int VERSION = 0x13; // Argon2 VERSION 19

    /// <summary>
    /// Computes an Argon2 hash using the specified parameters
    /// </summary>
    /// <param name="password">Password to hash</param>
    /// <param name="salt">Salt value (should be at least 8 bytes)</param>
    /// <param name="iterations">Number of iterations (time cost)</param>
    /// <param name="memorySize">Memory usage in KB (must be at least 8 * parallelism)</param>
    /// <param name="parallelism">Parallelism level (number of lanes)</param>
    /// <param name="hashLength">Output hash length in bytes</param>
    /// <param name="type">Argon2 variant to use</param>
    /// <param name="associatedData">Optional associated data</param>
    /// <param name="secret">Optional secret key</param>
    /// <returns>Computed hash as byte array</returns>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid</exception>
    public static byte[] Hash(
        byte[] password,
        byte[] salt,
        int iterations,
        int memorySize,
        int parallelism,
        int hashLength,
        Argon2Type type,
        byte[]? associatedData = null,
        byte[]? secret = null)
    {
        // Validate inputs
        if (iterations < 1)
        {
            throw new ArgumentException("Iterations must be positive", nameof(iterations));
        }
        if (memorySize < 1)
        {
            throw new ArgumentException("Memory size must be positive", nameof(memorySize));
        }
        if (parallelism < 1)
        {
            throw new ArgumentException("Parallelism must be positive", nameof(parallelism));
        }
        if (hashLength < 1)
        {
            throw new ArgumentException("Hash length must be positive", nameof(hashLength));
        }
        if (parallelism > memorySize)
        {
            throw new ArgumentException("Parallelism cannot exceed memory size", nameof(parallelism));
        }

        // RFC 9106: The memory size m MUST be at least 8*p KB
        if (memorySize < 8 * parallelism)
        {
            throw new ArgumentException($"Memory size must be at least {8 * parallelism} KB for {parallelism} parallelism", nameof(memorySize));
        }

        // Password and salt can be empty for Argon2, but not null
        password = password ?? Array.Empty<byte>();
        salt = salt ?? Array.Empty<byte>();

        var context = new Argon2Context
        {
            Password = password,
            Salt = salt,
            Secret = secret ?? Array.Empty<byte>(),
            AssociatedData = associatedData ?? Array.Empty<byte>(),
            Iterations = iterations,
            Memory = memorySize,
            Lanes = parallelism,
            HashLength = hashLength,
            Type = type
        };

        return ComputeHash(context);
    }

    private static byte[] ComputeHash(Argon2Context context)
    {
        // Calculate actual memory blocks - must be divisible by 4 * lanes
        var blocksPerLane = context.Memory / context.Lanes;
        var actualMemoryBlocks = blocksPerLane * context.Lanes;
        var segmentLength = blocksPerLane / 4;

        var memory = new Block[actualMemoryBlocks];
        for (var i = 0; i < memory.Length; i++)
        {
            memory[i] = new Block();
        }

        InitializeMemory(context, memory);

        for (var pass = 0; pass < context.Iterations; pass++)
        {
            for (var slice = 0; slice < 4; slice++)
            {
                for (var lane = 0; lane < context.Lanes; lane++)
                {
                    FillSegment(context, memory, pass, lane, slice, segmentLength);
                }
            }
        }

        return Finalize(context, memory);
    }

    /// <summary>
    /// Initialize memory with first two blocks per lane
    /// RFC 9106 Section 3.2
    /// </summary>
    private static void InitializeMemory(Argon2Context context, Block[] memory)
    {
        // Calculate H_0 as per RFC 9106 Section 3.2
        var h0Input = BuildH0Input(context);

        var h0 = Blake2bCore.ComputeHash(h0Input, 64);

        var blocksPerLane = context.Memory / context.Lanes;

        // Initialize first two blocks of each lane
        for (var lane = 0; lane < context.Lanes; lane++)
        {
            var startIdx = lane * blocksPerLane;

            // B[i][0] = H'^(1024)(H_0 || LE32(0) || LE32(i))
            var block0Input = new byte[h0.Length + 8];
            Array.Copy(h0, 0, block0Input, 0, h0.Length);
#if NETSTANDARD2_0
            WriteInt32LittleEndian(block0Input, h0.Length, 0);
            WriteInt32LittleEndian(block0Input, h0.Length + 4, lane);
#else
            BinaryPrimitives.WriteInt32LittleEndian(block0Input.AsSpan(h0.Length), 0);
            BinaryPrimitives.WriteInt32LittleEndian(block0Input.AsSpan(h0.Length + 4), lane);
#endif

            var block0Data = Blake2bCore.ComputeLongHash(block0Input, BLOCK_SIZE);
            BytesToBlock(block0Data, memory[startIdx]);

            // B[i][1] = H'^(1024)(H_0 || LE32(1) || LE32(i))
            var block1Input = new byte[h0.Length + 8];
            Array.Copy(h0, 0, block1Input, 0, h0.Length);
#if NETSTANDARD2_0
            WriteInt32LittleEndian(block1Input, h0.Length, 1);
            WriteInt32LittleEndian(block1Input, h0.Length + 4, lane);
#else
            BinaryPrimitives.WriteInt32LittleEndian(block1Input.AsSpan(h0.Length), 1);
            BinaryPrimitives.WriteInt32LittleEndian(block1Input.AsSpan(h0.Length + 4), lane);
#endif

            var block1Data = Blake2bCore.ComputeLongHash(block1Input, BLOCK_SIZE);
            BytesToBlock(block1Data, memory[startIdx + 1]);
        }
    }

    /// <summary>
    /// Build input for H_0 calculation according to RFC 9106
    /// H_0 = H^(64)(LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y) ||
    ///               LE32(length(P)) || P || LE32(length(S)) || S ||
    ///               LE32(length(K)) || K || LE32(length(X)) || X)
    /// </summary>
    private static byte[] BuildH0Input(Argon2Context context)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[4];

        // p: parallelism degree
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, context.Lanes);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Lanes);
#endif
        ms.Write(buffer, 0, 4);

        // T: tag length in bytes
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, context.HashLength);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.HashLength);
#endif
        ms.Write(buffer, 0, 4);

        // m: memory size in KB
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, context.Memory);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Memory);
#endif
        ms.Write(buffer, 0, 4);

        // t: number of iterations
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, context.Iterations);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Iterations);
#endif
        ms.Write(buffer, 0, 4);

        // v: VERSION number (19 = 0x13)
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, VERSION);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, VERSION);
#endif
        ms.Write(buffer, 0, 4);

        // y: Argon2 type (0=Argon2d, 1=Argon2i, 2=Argon2id)
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, (int)context.Type);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, (int)context.Type);
#endif
        ms.Write(buffer, 0, 4);

        // Password with length prefix
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, context.Password.Length);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Password.Length);
#endif
        ms.Write(buffer, 0, 4);
        ms.Write(context.Password, 0, context.Password.Length);

        // Salt with length prefix
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, context.Salt.Length);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Salt.Length);
#endif
        ms.Write(buffer, 0, 4);
        ms.Write(context.Salt, 0, context.Salt.Length);

        // Secret with length prefix
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, context.Secret.Length);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Secret.Length);
#endif
        ms.Write(buffer, 0, 4);
        ms.Write(context.Secret, 0, context.Secret.Length);

        // Associated data with length prefix
#if NETSTANDARD2_0
        WriteInt32LittleEndian(buffer, 0, context.AssociatedData.Length);
#else
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.AssociatedData.Length);
#endif
        ms.Write(buffer, 0, 4);
        ms.Write(context.AssociatedData, 0, context.AssociatedData.Length);

        return ms.ToArray();
    }

    /// <summary>
    /// Fill a segment of memory blocks
    /// RFC 9106 Section 3.4
    /// </summary>
    private static void FillSegment(Argon2Context context, Block[] memory, int pass, int lane, int slice, int segmentLength)
    {
        // Determine addressing mode
        var dataIndependentAddressing = context.Type == Argon2Type.Argon2i ||
                                       (context.Type == Argon2Type.Argon2id && pass == 0 && slice < 2);

        var blocksPerLane = context.Memory / context.Lanes;
        var startingIndex = lane * blocksPerLane + slice * segmentLength;
        var currentIndex = startingIndex;

        // Skip first two blocks in first segment of first pass
        if (pass == 0 && slice == 0)
        {
            currentIndex += 2;
        }

        // Initialize address generation for data-independent addressing
        Block? addressBlock = null;
        Block? inputBlock = null;
        Block? zeroBlock = null;

        if (dataIndependentAddressing)
        {
            addressBlock = new Block();
            inputBlock = new Block();
            zeroBlock = new Block();

            // Initialize input block for address generation
            inputBlock.Data[0] = (ulong)pass;
            inputBlock.Data[1] = (ulong)lane;
            inputBlock.Data[2] = (ulong)slice;
            inputBlock.Data[3] = (ulong)context.Memory;
            inputBlock.Data[4] = (ulong)context.Iterations;
            inputBlock.Data[5] = (ulong)context.Type;
            inputBlock.Data[6] = 1; // Counter for address generation (starts at 1 per RFC)

            // Clear remaining positions
            for (var j = 7; j < 128; j++)
            {
                inputBlock.Data[j] = 0;
            }

            // Generate initial addresses
            GenerateAddresses(inputBlock, zeroBlock, addressBlock);
        }

        // Process each block in the segment
        var endIndex = startingIndex + segmentLength;
        for (var i = currentIndex; i < endIndex; i++)
        {
            ulong pseudoRandom;

            if (dataIndependentAddressing)
            {
                var addressIndex = (i - currentIndex) % 128;
                if (addressIndex == 0 && i != currentIndex)
                {
                    // Generate new addresses when needed
                    GenerateAddresses(inputBlock!, zeroBlock!, addressBlock!);
                }
                pseudoRandom = addressBlock!.Data[addressIndex];
            }
            else
            {
                // Data-dependent addressing: use previous block's first word
                var prevIndex = i - 1;
                if (prevIndex < lane * blocksPerLane)
                {
                    prevIndex = (lane + 1) * blocksPerLane - 1; // Wrap to end of lane
                }
                pseudoRandom = memory[prevIndex].Data[0];
            }

            // Determine reference lane
            var refLane = (int)((pseudoRandom >> 32) % (ulong)context.Lanes);

            // First slice of first pass can only reference same lane
            if (pass == 0 && slice == 0)
            {
                refLane = lane;
            }

            // Calculate reference block index
            var segmentIndex = i - startingIndex;
            var refIndex = IndexAlpha(context, pass, lane, slice, segmentIndex, (uint)pseudoRandom, refLane == lane);
            var refBlock = memory[refLane * blocksPerLane + refIndex];

            // Get previous block
            var prevBlockIndex = i - 1;
            if (prevBlockIndex < lane * blocksPerLane)
            {
                prevBlockIndex = (lane + 1) * blocksPerLane - 1; // Wrap to end of lane
            }
            var prevBlock = memory[prevBlockIndex];

            // Fill the current block
            FillBlock(prevBlock, refBlock, memory[i], pass > 0);
        }
    }

    /// <summary>
    /// IndexAlpha: Calculate block reference index
    /// RFC 9106 Section 3.4
    /// </summary>
    private static int IndexAlpha(Argon2Context context, int pass, int lane, int slice, int index, uint pseudoRandom, bool sameLane)
    {
        _ = lane;

        var blocksPerLane = context.Memory / context.Lanes;
        var segmentLength = blocksPerLane / 4;

        // Calculate reference area size W
        int referenceAreaSize;

        if (pass == 0)
        {
            // First pass
            if (slice == 0)
            {
                // First slice: can only reference previous blocks in same lane
                referenceAreaSize = index - 1;
            }
            else
            {
                if (sameLane)
                {
                    // Same lane: all previous segments + current segment up to index
                    referenceAreaSize = slice * segmentLength + index - 1;
                }
                else
                {
                    // Different lane: all previous complete segments
                    referenceAreaSize = slice * segmentLength + ((index == 0) ? -1 : 0);
                }
            }
        }
        else
        {
            // Subsequent passes: can reference all memory except current segment
            if (sameLane)
            {
                // Same lane: all blocks except current segment + blocks in current segment up to index
                referenceAreaSize = blocksPerLane - segmentLength + index - 1;
            }
            else
            {
                // Different lane: all blocks except current segment
                referenceAreaSize = blocksPerLane - segmentLength + ((index == 0) ? -1 : 0);
            }
        }

        if (referenceAreaSize <= 0)
        {
            return 0;
        }

        // Apply mapping function: phi(x) = W * (1 - x^2 / 2^64)
        // Use 64-bit arithmetic for precision
        var x = (ulong)pseudoRandom;
        var xSquared = x * x;
        var relativePosition = (ulong)referenceAreaSize - 1UL - (((ulong)referenceAreaSize * (xSquared >> 32)) >> 32);

        // Calculate starting position in lane
        int startPosition = 0;
        if (pass != 0)
        {
            // For subsequent passes, start from next segment (wrapping to 0 for slice 3)
            startPosition = ((slice + 1) % 4) * segmentLength;
        }

        return (int)(((ulong)startPosition + relativePosition) % (ulong)blocksPerLane);
    }

    /// <summary>
    /// FillBlock: Argon2 compression function
    /// RFC 9106 Section 3.4
    /// </summary>
    private static void FillBlock(Block prevBlock, Block refBlock, Block nextBlock, bool withXor)
    {
        var blockR = new Block();
        var blockZ = new Block();

        // Save original nextBlock content if needed for XOR
        var originalNext = withXor ? new Block() : null;
        if (withXor)
        {
            Array.Copy(nextBlock.Data, originalNext!.Data, 128);
        }

        // Step 1: R = prevBlock XOR refBlock
        for (var i = 0; i < 128; i++)
        {
            blockR.Data[i] = prevBlock.Data[i] ^ refBlock.Data[i];
        }

        // Step 2: Z = R
        Array.Copy(blockR.Data, blockZ.Data, 128);

        // Step 3: Apply permutation P
        ApplyBlake2bPermutation(blockZ);

        // Step 4: Final result = Z XOR R
        for (var i = 0; i < 128; i++)
        {
            nextBlock.Data[i] = blockZ.Data[i] ^ blockR.Data[i];
        }

        // Step 5: If this is not the first pass, XOR with original content
        if (withXor)
        {
            for (var i = 0; i < 128; i++)
            {
                nextBlock.Data[i] ^= originalNext!.Data[i];
            }
        }
    }

    /// <summary>
    /// Apply Blake2b-based permutation P to a block
    /// RFC 9106 Section 3.4
    /// </summary>
    private static void ApplyBlake2bPermutation(Block block)
    {
        // Apply column-wise mixing (8 columns of 16 elements each)
        for (var col = 0; col < 8; col++)
        {
            var column = new ulong[16];
            for (var i = 0; i < 16; i++)
            {
                column[i] = block.Data[col * 16 + i];
            }

            Blake2bRoundFunction(column);

            for (var i = 0; i < 16; i++)
            {
                block.Data[col * 16 + i] = column[i];
            }
        }

        // Apply row-wise mixing (8 rows of 16 elements each)
        for (var row = 0; row < 8; row++)
        {
            var rowData = new ulong[16];

            // Extract row elements (2 elements from each column)
            for (var col = 0; col < 8; col++)
            {
                rowData[col * 2] = block.Data[col * 16 + row * 2];
                rowData[col * 2 + 1] = block.Data[col * 16 + row * 2 + 1];
            }

            Blake2bRoundFunction(rowData);

            // Write back row elements
            for (var col = 0; col < 8; col++)
            {
                block.Data[col * 16 + row * 2] = rowData[col * 2];
                block.Data[col * 16 + row * 2 + 1] = rowData[col * 2 + 1];
            }
        }
    }

    /// <summary>
    /// Blake2b round function for 16 64-bit words
    /// This is the modified Blake2b round with Argon2's multiplication
    /// </summary>
    private static void Blake2bRoundFunction(ulong[] v)
    {
        // Column step
        GB(v, 0, 4, 8, 12);
        GB(v, 1, 5, 9, 13);
        GB(v, 2, 6, 10, 14);
        GB(v, 3, 7, 11, 15);

        // Diagonal step
        GB(v, 0, 5, 10, 15);
        GB(v, 1, 6, 11, 12);
        GB(v, 2, 7, 8, 13);
        GB(v, 3, 4, 9, 14);
    }

    /// <summary>
    /// GB function: Modified Blake2b mixing function with multiplication
    /// RFC 9106 Section 3.4
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GB(ulong[] v, int a, int b, int c, int d)
    {
        v[a] = v[a] + v[b] + 2 * Mul(v[a], v[b]);
        v[d] = RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d] + 2 * Mul(v[c], v[d]);
        v[b] = RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + 2 * Mul(v[a], v[b]);
        v[d] = RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d] + 2 * Mul(v[c], v[d]);
        v[b] = RotateRight(v[b] ^ v[c], 63);
    }

    /// <summary>
    /// Multiplication function for Argon2: Mul(x,y) = (x &amp; 0xFFFFFFFF) * (y &amp; 0xFFFFFFFF)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Mul(ulong x, ulong y)
    {
        return (x & 0xFFFFFFFFUL) * (y & 0xFFFFFFFFUL);
    }



    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong RotateRight(ulong value, int bits)
    {
        return (value >> bits) | (value << (64 - bits));
    }

    /// <summary>
    /// Generate addresses for data-independent addressing (Argon2i)
    /// RFC 9106 Section 3.4
    /// </summary>
    private static void GenerateAddresses(Block input, Block zero, Block output)
    {
        FillBlock(zero, input, output, false);
        FillBlock(zero, output, output, false);
        input.Data[6]++; // Increment counter after generating addresses
    }

    private static byte[] Finalize(Argon2Context context, Block[] memory)
    {
        var blocksPerLane = context.Memory / context.Lanes;
        var finalBlock = new Block();

        for (var lane = 0; lane < context.Lanes; lane++)
        {
            var lastBlockInLane = memory[(lane + 1) * blocksPerLane - 1];
            for (var i = 0; i < 128; i++)
            {
                finalBlock.Data[i] ^= lastBlockInLane.Data[i];
            }
        }

        var finalBlockBytes = BlockToBytes(finalBlock);
        return Blake2bCore.ComputeLongHash(finalBlockBytes, context.HashLength);
    }

    private static byte[] BlockToBytes(Block block)
    {
        var bytes = new byte[1024];
        for (var i = 0; i < 128; i++)
        {
#if NETSTANDARD2_0
            WriteUInt64LittleEndian(bytes, i * 8, block.Data[i]);
#else
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(i * 8), block.Data[i]);
#endif
        }
        return bytes;
    }

    private static void BytesToBlock(byte[] bytes, Block block)
    {
        for (var i = 0; i < 128; i++)
        {
#if NETSTANDARD2_0
            block.Data[i] = ReadUInt64LittleEndian(bytes, i * 8);
#else
            block.Data[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(i * 8));
#endif
        }
    }

    /// <summary>
    /// Represents a 1024-byte Argon2 memory block.
    /// </summary>
    /// <remarks>
    /// Each block contains 128 64-bit words (1024 bytes total) and represents
    /// the fundamental unit of memory manipulation in Argon2. Blocks are used
    /// for mixing operations during the memory-hard hashing process.
    /// </remarks>
    private sealed class Block
    {
        /// <summary>
        /// Block data as an array of 128 64-bit unsigned integers (1024 bytes total).
        /// </summary>
        public readonly ulong[] Data = new ulong[128];
    }

    internal sealed class Argon2Context
    {
        public byte[] Password { get; set; } = [];
        public byte[] Salt { get; set; } = [];
        public byte[] Secret { get; set; } = [];
        public byte[] AssociatedData { get; set; } = [];
        public int Iterations { get; set; }
        public int Memory { get; set; }
        public int Lanes { get; set; }
        public int HashLength { get; set; }
        public Argon2Type Type { get; set; }
    }

#if NETSTANDARD2_0
    // Helper methods for .NET Standard 2.0 compatibility
    private static void WriteInt32LittleEndian(byte[] destination, int offset, int value)
    {
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
        destination[offset + 2] = (byte)(value >> 16);
        destination[offset + 3] = (byte)(value >> 24);
    }

    private static void WriteUInt64LittleEndian(byte[] destination, int offset, ulong value)
    {
        destination[offset] = (byte)value;
        destination[offset + 1] = (byte)(value >> 8);
        destination[offset + 2] = (byte)(value >> 16);
        destination[offset + 3] = (byte)(value >> 24);
        destination[offset + 4] = (byte)(value >> 32);
        destination[offset + 5] = (byte)(value >> 40);
        destination[offset + 6] = (byte)(value >> 48);
        destination[offset + 7] = (byte)(value >> 56);
    }

    private static ulong ReadUInt64LittleEndian(byte[] source, int offset)
    {
        return (ulong)source[offset] |
               ((ulong)source[offset + 1] << 8) |
               ((ulong)source[offset + 2] << 16) |
               ((ulong)source[offset + 3] << 24) |
               ((ulong)source[offset + 4] << 32) |
               ((ulong)source[offset + 5] << 40) |
               ((ulong)source[offset + 6] << 48) |
               ((ulong)source[offset + 7] << 56);
    }
#endif
}
