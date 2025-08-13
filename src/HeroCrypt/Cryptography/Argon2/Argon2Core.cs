#if NETSTANDARD2_0
using HeroCrypt.Compatibility;
using BinaryPrimitives = HeroCrypt.Compatibility.BinaryPrimitivesCompat;
#else
using System.Buffers.Binary;
#endif
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace HeroCrypt.Cryptography.Argon2;

public static class Argon2Core
{
    private const int BlockSize = 1024;
    private const int Version = 0x13; // Argon2 version 19
    
    // Blake2b initialization vectors
    private static readonly ulong[] Blake2bIv = 
    {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };
    
    // Blake2b message schedule permutation table
    private static readonly byte[,] Blake2bSigma = new byte[10, 16]
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
    };

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
        if (iterations < 1) throw new ArgumentException("Iterations must be at least 1", nameof(iterations));
        if (memorySize < 8 * parallelism) throw new ArgumentException("Memory size must be at least 8 * parallelism", nameof(memorySize));
        if (parallelism < 1) throw new ArgumentException("Parallelism must be at least 1", nameof(parallelism));
        if (hashLength < 4) throw new ArgumentException("Hash length must be at least 4", nameof(hashLength));

        var context = new Argon2Context
        {
            Password = password ?? [],
            Salt = salt ?? [],
            Secret = secret ?? [],
            AssociatedData = associatedData ?? [],
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
        var h0 = new byte[64];
        Blake2b(h0Input, h0, 64);

        var blocksPerLane = context.Memory / context.Lanes;

        // Initialize first two blocks of each lane
        for (var lane = 0; lane < context.Lanes; lane++)
        {
            var startIdx = lane * blocksPerLane;
            
            // B[i][0] = H'^(1024)(H_0 || LE32(0) || LE32(i))
            var block0Input = new byte[h0.Length + 8];
            Array.Copy(h0, 0, block0Input, 0, h0.Length);
            BinaryPrimitives.WriteInt32LittleEndian(block0Input.AsSpan(h0.Length), 0);
            BinaryPrimitives.WriteInt32LittleEndian(block0Input.AsSpan(h0.Length + 4), lane);
            
            var block0Data = new byte[BlockSize];
            Blake2bLong(block0Input, block0Data, BlockSize);
            BytesToBlock(block0Data, memory[startIdx]);
            
            // B[i][1] = H'^(1024)(H_0 || LE32(1) || LE32(i))
            var block1Input = new byte[h0.Length + 8];
            Array.Copy(h0, 0, block1Input, 0, h0.Length);
            BinaryPrimitives.WriteInt32LittleEndian(block1Input.AsSpan(h0.Length), 1);
            BinaryPrimitives.WriteInt32LittleEndian(block1Input.AsSpan(h0.Length + 4), lane);
            
            var block1Data = new byte[BlockSize];
            Blake2bLong(block1Input, block1Data, BlockSize);
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
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Lanes);
        ms.Write(buffer, 0, 4);
        
        // T: tag length in bytes
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.HashLength);
        ms.Write(buffer, 0, 4);
        
        // m: memory size in KB
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Memory);
        ms.Write(buffer, 0, 4);
        
        // t: number of iterations
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Iterations);
        ms.Write(buffer, 0, 4);
        
        // v: version number (19 = 0x13)
        BinaryPrimitives.WriteInt32LittleEndian(buffer, Version);
        ms.Write(buffer, 0, 4);
        
        // y: Argon2 type (0=Argon2d, 1=Argon2i, 2=Argon2id)
        BinaryPrimitives.WriteInt32LittleEndian(buffer, (int)context.Type);
        ms.Write(buffer, 0, 4);
        
        // Password with length prefix
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Password.Length);
        ms.Write(buffer, 0, 4);
        ms.Write(context.Password, 0, context.Password.Length);
        
        // Salt with length prefix
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Salt.Length);
        ms.Write(buffer, 0, 4);
        ms.Write(context.Salt, 0, context.Salt.Length);
        
        // Secret with length prefix
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.Secret.Length);
        ms.Write(buffer, 0, 4);
        ms.Write(context.Secret, 0, context.Secret.Length);
        
        // Associated data with length prefix
        BinaryPrimitives.WriteInt32LittleEndian(buffer, context.AssociatedData.Length);
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
            inputBlock.Data[6] = 0; // Counter for address generation
            
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
            return 0;

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
        input.Data[6]++; // Increment counter for address generation
        FillBlock(zero, input, output, false);
        FillBlock(zero, output, output, false);
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

        var result = new byte[context.HashLength];
        Blake2bLong(BlockToBytes(finalBlock), result, context.HashLength);
        
        return result;
    }

    private static byte[] BlockToBytes(Block block)
    {
        var bytes = new byte[1024];
        for (var i = 0; i < 128; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(i * 8), block.Data[i]);
        }
        return bytes;
    }
    
    private static void BytesToBlock(byte[] bytes, Block block)
    {
        for (var i = 0; i < 128; i++)
        {
            block.Data[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(i * 8));
        }
    }

    /// <summary>
    /// H' function: Variable-length hash function based on Blake2b
    /// RFC 9106 Section 2.4
    /// </summary>
    private static void Blake2bLong(byte[] input, byte[] output, int outputLength)
    {
        // Create input with prepended length: LE32(T) || A
        var inputWithLength = new byte[4 + input.Length];
        BinaryPrimitives.WriteInt32LittleEndian(inputWithLength.AsSpan(0), outputLength);
        Array.Copy(input, 0, inputWithLength, 4, input.Length);
        
        if (outputLength <= 64)
        {
            // For T <= 64: H'(A) = H^T(LE32(T) || A)
            Blake2b(inputWithLength, output, outputLength);
        }
        else
        {
            // For T > 64: Use multi-stage approach
            // r = ceil(T/32) - 2
            var r = (outputLength + 31) / 32 - 2;
            
            // V_1 = H^(64)(LE32(T) || A)
            var v = new byte[64];
            Blake2b(inputWithLength, v, 64);
            
            // W_1: first 32 bytes of V_1
            Array.Copy(v, 0, output, 0, 32);
            var position = 32;
            
            // Generate V_2, V_3, ..., V_r
            for (var i = 1; i < r; i++)
            {
                Blake2b(v, v, 64);
                Array.Copy(v, 0, output, position, 32);
                position += 32;
            }
            
            // Final block V_{r+1} with reduced length
            var finalLength = outputLength - 32 * r;
            if (finalLength > 0)
            {
                var finalBlock = new byte[finalLength];
                Blake2b(v, finalBlock, finalLength);
                Array.Copy(finalBlock, 0, output, position, finalLength);
            }
        }
    }

    /// <summary>
    /// Blake2b hash function implementation
    /// RFC 9106 Section 2.3
    /// </summary>
    private static void Blake2b(byte[] input, byte[] output, int outputLength)
    {
        // Initialize hash state
        var h = new ulong[8];
        Array.Copy(Blake2bIv, h, 8);
        h[0] ^= 0x01010000UL ^ (uint)outputLength; // Parameter block: depth=1, fanout=1, digest_size=outputLength

        // Process input in 128-byte chunks
        var bytesCompressed = 0;
        while (bytesCompressed < input.Length)
        {
            var chunkSize = Math.Min(128, input.Length - bytesCompressed);
            var isLastBlock = bytesCompressed + chunkSize == input.Length;
            
            // Prepare message block (128 bytes, zero-padded if necessary)
            var messageBlock = new byte[128];
            Array.Copy(input, bytesCompressed, messageBlock, 0, chunkSize);
            
            CompressBlake2b(h, messageBlock, bytesCompressed + chunkSize, isLastBlock);
            bytesCompressed += chunkSize;
        }
        
        // Handle empty input
        if (input.Length == 0)
        {
            var emptyBlock = new byte[128];
            CompressBlake2b(h, emptyBlock, 0, true);
        }

        // Output hash bytes
        for (var i = 0; i < outputLength / 8; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(i * 8), h[i]);
        }
        
        // Handle remaining bytes
        if (outputLength % 8 != 0)
        {
            var lastBytes = new byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(lastBytes, h[outputLength / 8]);
            Array.Copy(lastBytes, 0, output, (outputLength / 8) * 8, outputLength % 8);
        }
    }
    
    private static void CompressBlake2b(ulong[] h, byte[] messageBlock, int bytesCompressed, bool isLastBlock)
    {
        // Convert message block to 16 64-bit words
        var m = new ulong[16];
        for (var i = 0; i < 16; i++)
        {
            m[i] = BinaryPrimitives.ReadUInt64LittleEndian(messageBlock.AsSpan(i * 8));
        }

        // Initialize working vector
        var v = new ulong[16];
        Array.Copy(h, v, 8);
        Array.Copy(Blake2bIv, 0, v, 8, 8);
        
        // XOR in counter and final block flag
        v[12] ^= (ulong)bytesCompressed; // Low 64 bits of counter
        v[13] ^= 0; // High 64 bits of counter (always 0 for our use)
        if (isLastBlock)
        {
            v[14] ^= 0xFFFFFFFFFFFFFFFFUL; // Invert all bits for final block
        }

        // 12 rounds of mixing
        for (var round = 0; round < 12; round++)
        {
            // Column step
            G(v, 0, 4, 8, 12, m[Blake2bSigma[round % 10, 0]], m[Blake2bSigma[round % 10, 1]]);
            G(v, 1, 5, 9, 13, m[Blake2bSigma[round % 10, 2]], m[Blake2bSigma[round % 10, 3]]);
            G(v, 2, 6, 10, 14, m[Blake2bSigma[round % 10, 4]], m[Blake2bSigma[round % 10, 5]]);
            G(v, 3, 7, 11, 15, m[Blake2bSigma[round % 10, 6]], m[Blake2bSigma[round % 10, 7]]);
            
            // Diagonal step
            G(v, 0, 5, 10, 15, m[Blake2bSigma[round % 10, 8]], m[Blake2bSigma[round % 10, 9]]);
            G(v, 1, 6, 11, 12, m[Blake2bSigma[round % 10, 10]], m[Blake2bSigma[round % 10, 11]]);
            G(v, 2, 7, 8, 13, m[Blake2bSigma[round % 10, 12]], m[Blake2bSigma[round % 10, 13]]);
            G(v, 3, 4, 9, 14, m[Blake2bSigma[round % 10, 14]], m[Blake2bSigma[round % 10, 15]]);
        }

        // Finalize hash value
        for (var i = 0; i < 8; i++)
        {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = RotateRight(v[b] ^ v[c], 63);
    }




    private sealed class Block
    {
        public readonly ulong[] Data = new ulong[128];
    }

    private sealed class Argon2Context
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
}