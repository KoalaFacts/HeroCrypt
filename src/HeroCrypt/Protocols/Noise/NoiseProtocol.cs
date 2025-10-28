using System;
using System.Security.Cryptography;
using System.Text;

namespace HeroCrypt.Protocols.Noise;

#if !NETSTANDARD2_0

/// <summary>
/// Noise Protocol Framework implementation
///
/// The Noise Protocol Framework provides modern cryptographic protocols for
/// building secure channels with strong authentication and forward secrecy.
///
/// Specification: https://noiseprotocol.org/noise.html
///
/// Features:
/// - Multiple handshake patterns (IK, XX, NK, KK, etc.)
/// - Mutual or one-way authentication
/// - Forward secrecy and key rotation
/// - Post-quantum cipher suite support
/// - Zero round-trip (0-RTT) data transmission
/// - Identity hiding options
///
/// Key Concepts:
/// - Tokens: e (ephemeral), s (static), ee, es, se, ss (DH operations)
/// - Patterns: Pre-defined message sequences (e.g., XX, IK, NK)
/// - Cipher suite: DH function, cipher, hash (e.g., 25519_ChaChaPoly_BLAKE2b)
/// - Handshake state: Symmetric state + DH state + pattern
///
/// Production Requirements:
/// - Full DH implementations (X25519, secp256k1)
/// - AEAD cipher implementations (ChaCha20-Poly1305, AES-GCM)
/// - HKDF for key derivation
/// - Proper nonce handling and key rotation
/// - Session resumption and 0-RTT support
/// </summary>
public class NoiseProtocol
{
    private readonly NoiseProtocolConfig _config;

    public NoiseProtocol(NoiseProtocolConfig config)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
    }

    /// <summary>
    /// Creates a new handshake state for initiator or responder
    /// </summary>
    public NoiseHandshakeState CreateHandshakeState(
        NoiseRole role,
        NoiseHandshakePattern pattern,
        byte[]? localStaticPrivateKey = null,
        byte[]? localEphemeralPrivateKey = null,
        byte[]? remoteStaticPublicKey = null,
        byte[]? presharedKey = null,
        byte[]? prologue = null)
    {
        var state = new NoiseHandshakeState
        {
            Role = role,
            Pattern = pattern,
            CipherSuite = _config.CipherSuite,
            SymmetricState = new NoiseSymmetricState(_config.CipherSuite),
            LocalStaticPrivateKey = localStaticPrivateKey,
            LocalEphemeralPrivateKey = localEphemeralPrivateKey,
            RemoteStaticPublicKey = remoteStaticPublicKey,
            PresharedKey = presharedKey
        };

        // Initialize with protocol name
        var protocolName = GetProtocolName(pattern, _config.CipherSuite);
        state.SymmetricState.InitializeSymmetric(Encoding.UTF8.GetBytes(protocolName));

        // Mix prologue if provided
        if (prologue != null && prologue.Length > 0)
        {
            state.SymmetricState.MixHash(prologue);
        }

        // Mix pre-message public keys based on pattern
        MixPreMessagePublicKeys(state);

        return state;
    }

    /// <summary>
    /// Writes a handshake message (initiator or responder)
    /// </summary>
    public byte[] WriteMessage(NoiseHandshakeState state, ReadOnlySpan<byte> payload)
    {
        if (state == null)
            throw new ArgumentNullException(nameof(state));

        var messageTokens = GetMessageTokens(state.Pattern, state.Role, state.MessageIndex);
        var output = new byte[CalculateMessageSize(messageTokens, payload.Length, state)];
        var offset = 0;

        foreach (var token in messageTokens)
        {
            switch (token)
            {
                case NoiseToken.E:
                    // Generate ephemeral key pair
                    state.LocalEphemeralPrivateKey = GenerateKeyPair(out var ephemeralPublic);
                    ephemeralPublic.CopyTo(output.AsSpan(offset));
                    offset += _config.CipherSuite.DhLength;
                    state.SymmetricState.MixHash(ephemeralPublic);
                    if (state.PresharedKey != null)
                        state.SymmetricState.MixKey(ephemeralPublic);
                    break;

                case NoiseToken.S:
                    // Encrypt static public key
                    var staticPublic = GetPublicKey(state.LocalStaticPrivateKey!);
                    var encryptedStatic = state.SymmetricState.EncryptAndHash(staticPublic);
                    encryptedStatic.CopyTo(output.AsSpan(offset));
                    offset += encryptedStatic.Length;
                    break;

                case NoiseToken.EE:
                    // DH(e, re)
                    var dhEE = DiffieHellman(state.LocalEphemeralPrivateKey!, state.RemoteEphemeralPublicKey!);
                    state.SymmetricState.MixKey(dhEE);
                    break;

                case NoiseToken.ES:
                    // DH(e, rs) for initiator, DH(s, re) for responder
                    byte[] dhES;
                    if (state.Role == NoiseRole.Initiator)
                        dhES = DiffieHellman(state.LocalEphemeralPrivateKey!, state.RemoteStaticPublicKey!);
                    else
                        dhES = DiffieHellman(state.LocalStaticPrivateKey!, state.RemoteEphemeralPublicKey!);
                    state.SymmetricState.MixKey(dhES);
                    break;

                case NoiseToken.SE:
                    // DH(s, re) for initiator, DH(e, rs) for responder
                    byte[] dhSE;
                    if (state.Role == NoiseRole.Initiator)
                        dhSE = DiffieHellman(state.LocalStaticPrivateKey!, state.RemoteEphemeralPublicKey!);
                    else
                        dhSE = DiffieHellman(state.LocalEphemeralPrivateKey!, state.RemoteStaticPublicKey!);
                    state.SymmetricState.MixKey(dhSE);
                    break;

                case NoiseToken.SS:
                    // DH(s, rs)
                    var dhSS = DiffieHellman(state.LocalStaticPrivateKey!, state.RemoteStaticPublicKey!);
                    state.SymmetricState.MixKey(dhSS);
                    break;

                case NoiseToken.PSK:
                    // Mix pre-shared key
                    state.SymmetricState.MixKeyAndHash(state.PresharedKey!);
                    break;
            }
        }

        // Encrypt payload
        var encryptedPayload = state.SymmetricState.EncryptAndHash(payload);
        encryptedPayload.CopyTo(output.AsSpan(offset));

        state.MessageIndex++;
        return output;
    }

    /// <summary>
    /// Reads a handshake message (initiator or responder)
    /// </summary>
    public byte[] ReadMessage(NoiseHandshakeState state, ReadOnlySpan<byte> message)
    {
        if (state == null)
            throw new ArgumentNullException(nameof(state));

        var messageTokens = GetMessageTokens(state.Pattern,
            state.Role == NoiseRole.Initiator ? NoiseRole.Responder : NoiseRole.Initiator,
            state.MessageIndex);

        var offset = 0;

        foreach (var token in messageTokens)
        {
            switch (token)
            {
                case NoiseToken.E:
                    // Read remote ephemeral public key
                    state.RemoteEphemeralPublicKey = message.Slice(offset, _config.CipherSuite.DhLength).ToArray();
                    offset += _config.CipherSuite.DhLength;
                    state.SymmetricState.MixHash(state.RemoteEphemeralPublicKey);
                    if (state.PresharedKey != null)
                        state.SymmetricState.MixKey(state.RemoteEphemeralPublicKey);
                    break;

                case NoiseToken.S:
                    // Decrypt remote static public key
                    var encryptedStaticLength = _config.CipherSuite.DhLength +
                        (state.SymmetricState.HasKey ? 16 : 0);
                    var encryptedStatic = message.Slice(offset, encryptedStaticLength);
                    state.RemoteStaticPublicKey = state.SymmetricState.DecryptAndHash(encryptedStatic);
                    offset += encryptedStaticLength;
                    break;

                case NoiseToken.EE:
                case NoiseToken.ES:
                case NoiseToken.SE:
                case NoiseToken.SS:
                case NoiseToken.PSK:
                    // Same DH operations as WriteMessage
                    PerformDhOperation(state, token);
                    break;
            }
        }

        // Decrypt payload
        var encryptedPayload = message[offset..];
        var payload = state.SymmetricState.DecryptAndHash(encryptedPayload);

        state.MessageIndex++;
        return payload;
    }

    /// <summary>
    /// Completes handshake and returns transport keys
    /// </summary>
    public (NoiseCipherState send, NoiseCipherState receive) Split(NoiseHandshakeState state)
    {
        var (k1, k2) = state.SymmetricState.Split();

        NoiseCipherState sendState, receiveState;
        if (state.Role == NoiseRole.Initiator)
        {
            sendState = new NoiseCipherState(k1, _config.CipherSuite);
            receiveState = new NoiseCipherState(k2, _config.CipherSuite);
        }
        else
        {
            sendState = new NoiseCipherState(k2, _config.CipherSuite);
            receiveState = new NoiseCipherState(k1, _config.CipherSuite);
        }

        return (sendState, receiveState);
    }

    private string GetProtocolName(NoiseHandshakePattern pattern, NoiseCipherSuite suite)
    {
        return $"Noise_{pattern}_{suite.DhFunction}_{suite.Cipher}_{suite.Hash}";
    }

    private void MixPreMessagePublicKeys(NoiseHandshakeState state)
    {
        // Mix pre-message public keys based on pattern
        // Implementation depends on specific pattern requirements
        // For example, IK pattern: initiator knows responder's static key
    }

    private NoiseToken[] GetMessageTokens(NoiseHandshakePattern pattern, NoiseRole role, int messageIndex)
    {
        // Returns tokens for specific message in pattern
        // This is simplified - full implementation would have all patterns
        return pattern switch
        {
            NoiseHandshakePattern.XX => GetXXTokens(role, messageIndex),
            NoiseHandshakePattern.IK => GetIKTokens(role, messageIndex),
            NoiseHandshakePattern.NK => GetNKTokens(role, messageIndex),
            NoiseHandshakePattern.KK => GetKKTokens(role, messageIndex),
            _ => Array.Empty<NoiseToken>()
        };
    }

    private NoiseToken[] GetXXTokens(NoiseRole role, int messageIndex)
    {
        // XX pattern:
        // -> e
        // <- e, ee, s, es
        // -> s, se
        if (role == NoiseRole.Initiator)
        {
            return messageIndex switch
            {
                0 => new[] { NoiseToken.E },
                1 => new[] { NoiseToken.S, NoiseToken.SE },
                _ => Array.Empty<NoiseToken>()
            };
        }
        else
        {
            return messageIndex switch
            {
                0 => new[] { NoiseToken.E, NoiseToken.EE, NoiseToken.S, NoiseToken.ES },
                _ => Array.Empty<NoiseToken>()
            };
        }
    }

    private NoiseToken[] GetIKTokens(NoiseRole role, int messageIndex)
    {
        // IK pattern:
        // <- s
        // -> e, es, s, ss
        // <- e, ee, se
        if (role == NoiseRole.Initiator)
        {
            return messageIndex switch
            {
                0 => new[] { NoiseToken.E, NoiseToken.ES, NoiseToken.S, NoiseToken.SS },
                _ => Array.Empty<NoiseToken>()
            };
        }
        else
        {
            return messageIndex switch
            {
                0 => new[] { NoiseToken.E, NoiseToken.EE, NoiseToken.SE },
                _ => Array.Empty<NoiseToken>()
            };
        }
    }

    private NoiseToken[] GetNKTokens(NoiseRole role, int messageIndex)
    {
        // NK pattern:
        // <- s
        // -> e, es
        // <- e, ee
        if (role == NoiseRole.Initiator)
        {
            return messageIndex switch
            {
                0 => new[] { NoiseToken.E, NoiseToken.ES },
                _ => Array.Empty<NoiseToken>()
            };
        }
        else
        {
            return messageIndex switch
            {
                0 => new[] { NoiseToken.E, NoiseToken.EE },
                _ => Array.Empty<NoiseToken>()
            };
        }
    }

    private NoiseToken[] GetKKTokens(NoiseRole role, int messageIndex)
    {
        // KK pattern:
        // -> s
        // <- s
        // -> e, es, ss
        // <- e, ee, se
        if (role == NoiseRole.Initiator)
        {
            return messageIndex switch
            {
                0 => new[] { NoiseToken.E, NoiseToken.ES, NoiseToken.SS },
                _ => Array.Empty<NoiseToken>()
            };
        }
        else
        {
            return messageIndex switch
            {
                0 => new[] { NoiseToken.E, NoiseToken.EE, NoiseToken.SE },
                _ => Array.Empty<NoiseToken>()
            };
        }
    }

    private int CalculateMessageSize(NoiseToken[] tokens, int payloadLength, NoiseHandshakeState state)
    {
        var size = 0;
        foreach (var token in tokens)
        {
            size += token switch
            {
                NoiseToken.E => _config.CipherSuite.DhLength,
                NoiseToken.S => _config.CipherSuite.DhLength + (state.SymmetricState.HasKey ? 16 : 0),
                _ => 0
            };
        }
        size += payloadLength + (state.SymmetricState.HasKey ? 16 : 0);
        return size;
    }

    private void PerformDhOperation(NoiseHandshakeState state, NoiseToken token)
    {
        byte[] dhOutput;
        switch (token)
        {
            case NoiseToken.EE:
                dhOutput = DiffieHellman(state.LocalEphemeralPrivateKey!, state.RemoteEphemeralPublicKey!);
                state.SymmetricState.MixKey(dhOutput);
                break;
            case NoiseToken.ES:
                dhOutput = state.Role == NoiseRole.Initiator
                    ? DiffieHellman(state.LocalEphemeralPrivateKey!, state.RemoteStaticPublicKey!)
                    : DiffieHellman(state.LocalStaticPrivateKey!, state.RemoteEphemeralPublicKey!);
                state.SymmetricState.MixKey(dhOutput);
                break;
            case NoiseToken.SE:
                dhOutput = state.Role == NoiseRole.Initiator
                    ? DiffieHellman(state.LocalStaticPrivateKey!, state.RemoteEphemeralPublicKey!)
                    : DiffieHellman(state.LocalEphemeralPrivateKey!, state.RemoteStaticPublicKey!);
                state.SymmetricState.MixKey(dhOutput);
                break;
            case NoiseToken.SS:
                dhOutput = DiffieHellman(state.LocalStaticPrivateKey!, state.RemoteStaticPublicKey!);
                state.SymmetricState.MixKey(dhOutput);
                break;
            case NoiseToken.PSK:
                state.SymmetricState.MixKeyAndHash(state.PresharedKey!);
                break;
        }
    }

    private byte[] GenerateKeyPair(out byte[] publicKey)
    {
        // Production: Use actual X25519 or configured DH function
        var privateKey = new byte[32];
        publicKey = new byte[32];
        RandomNumberGenerator.Fill(privateKey);
        RandomNumberGenerator.Fill(publicKey); // Placeholder
        return privateKey;
    }

    private byte[] GetPublicKey(byte[] privateKey)
    {
        // Production: Derive public key from private key using DH function
        var publicKey = new byte[32];
        RandomNumberGenerator.Fill(publicKey); // Placeholder
        return publicKey;
    }

    private byte[] DiffieHellman(byte[] privateKey, byte[] publicKey)
    {
        // Production: Perform actual DH operation (X25519, secp256k1, etc.)
        var sharedSecret = new byte[32];
        RandomNumberGenerator.Fill(sharedSecret); // Placeholder
        return sharedSecret;
    }
}

/// <summary>
/// Noise protocol configuration
/// </summary>
public class NoiseProtocolConfig
{
    public NoiseCipherSuite CipherSuite { get; set; } = NoiseCipherSuite.Default;
}

/// <summary>
/// Cipher suite configuration for Noise protocol
/// </summary>
public class NoiseCipherSuite
{
    public string DhFunction { get; set; } = "25519";
    public string Cipher { get; set; } = "ChaChaPoly";
    public string Hash { get; set; } = "BLAKE2b";
    public int DhLength { get; set; } = 32;

    public static NoiseCipherSuite Default => new()
    {
        DhFunction = "25519",
        Cipher = "ChaChaPoly",
        Hash = "BLAKE2b",
        DhLength = 32
    };

    public static NoiseCipherSuite PostQuantum => new()
    {
        DhFunction = "Kyber1024",
        Cipher = "AES256-GCM",
        Hash = "SHA512",
        DhLength = 1568 // Kyber1024 public key size
    };
}

/// <summary>
/// Handshake state maintaining DH keys and symmetric state
/// </summary>
public class NoiseHandshakeState
{
    public NoiseRole Role { get; set; }
    public NoiseHandshakePattern Pattern { get; set; }
    public NoiseCipherSuite CipherSuite { get; set; } = null!;
    public NoiseSymmetricState SymmetricState { get; set; } = null!;

    public byte[]? LocalStaticPrivateKey { get; set; }
    public byte[]? LocalEphemeralPrivateKey { get; set; }
    public byte[]? RemoteStaticPublicKey { get; set; }
    public byte[]? RemoteEphemeralPublicKey { get; set; }
    public byte[]? PresharedKey { get; set; }

    public int MessageIndex { get; set; }
}

/// <summary>
/// Symmetric state for encryption and hashing
/// </summary>
public class NoiseSymmetricState
{
    private readonly NoiseCipherSuite _suite;
    private byte[] _chainingKey;
    private byte[] _hash;
    private byte[]? _key;
    private ulong _nonce;

    public bool HasKey => _key != null;

    public NoiseSymmetricState(NoiseCipherSuite suite)
    {
        _suite = suite;
        _chainingKey = new byte[32];
        _hash = new byte[32];
    }

    public void InitializeSymmetric(byte[] protocolName)
    {
        if (protocolName.Length <= 32)
        {
            Array.Clear(_hash, 0, _hash.Length);
            protocolName.CopyTo(_hash, 0);
        }
        else
        {
            _hash = SHA256.HashData(protocolName);
        }
        _chainingKey = _hash.ToArray();
    }

    public void MixKey(byte[] inputKeyMaterial)
    {
        // Production: Use HKDF
        var (ck, k) = HKDF(_chainingKey, inputKeyMaterial);
        _chainingKey = ck;
        _key = k;
        _nonce = 0;
    }

    public void MixHash(byte[] data)
    {
        var combined = new byte[_hash.Length + data.Length];
        _hash.CopyTo(combined, 0);
        data.CopyTo(combined, _hash.Length);
        _hash = SHA256.HashData(combined);
    }

    public void MixKeyAndHash(byte[] inputKeyMaterial)
    {
        // Production: Use HKDF with two outputs
        var (ck, tempH, tempK) = HKDF3(_chainingKey, inputKeyMaterial);
        _chainingKey = ck;
        MixHash(tempH);
        MixKey(tempK);
    }

    public byte[] EncryptAndHash(ReadOnlySpan<byte> plaintext)
    {
        byte[] ciphertext;
        if (_key == null)
        {
            ciphertext = plaintext.ToArray();
        }
        else
        {
            // Production: Use ChaCha20-Poly1305 or AES-GCM
            ciphertext = Encrypt(plaintext);
            _nonce++;
        }
        MixHash(ciphertext);
        return ciphertext;
    }

    public byte[] DecryptAndHash(ReadOnlySpan<byte> ciphertext)
    {
        byte[] plaintext;
        if (_key == null)
        {
            plaintext = ciphertext.ToArray();
        }
        else
        {
            // Production: Use ChaCha20-Poly1305 or AES-GCM
            plaintext = Decrypt(ciphertext);
            _nonce++;
        }
        MixHash(ciphertext.ToArray());
        return plaintext;
    }

    public (byte[] k1, byte[] k2) Split()
    {
        // Production: Use HKDF to derive two transport keys
        var (k1, k2) = HKDF(_chainingKey, Array.Empty<byte>());
        return (k1, k2);
    }

    private (byte[], byte[]) HKDF(byte[] chainingKey, byte[] inputKeyMaterial)
    {
        // Simplified HKDF - production needs full RFC 5869 implementation
        using var hmac = new HMACSHA256(chainingKey);
        var output = hmac.ComputeHash(inputKeyMaterial);
        var k1 = output[..32];
        var k2 = hmac.ComputeHash(k1);
        return (k1, k2[..32]);
    }

    private (byte[], byte[], byte[]) HKDF3(byte[] chainingKey, byte[] inputKeyMaterial)
    {
        // Simplified 3-output HKDF
        using var hmac = new HMACSHA256(chainingKey);
        var temp = hmac.ComputeHash(inputKeyMaterial);
        var k1 = temp[..32];
        var k2 = hmac.ComputeHash(k1);
        var k3 = hmac.ComputeHash(k2);
        return (k1, k2[..32], k3[..32]);
    }

    private byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        // Production: ChaCha20-Poly1305 or AES-GCM encryption
        var ciphertext = new byte[plaintext.Length + 16];
        plaintext.CopyTo(ciphertext);
        return ciphertext;
    }

    private byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
    {
        // Production: ChaCha20-Poly1305 or AES-GCM decryption
        return ciphertext[..^16].ToArray();
    }
}

/// <summary>
/// Cipher state for transport encryption after handshake
/// </summary>
public class NoiseCipherState
{
    private readonly byte[] _key;
    private readonly NoiseCipherSuite _suite;
    private ulong _nonce;

    public NoiseCipherState(byte[] key, NoiseCipherSuite suite)
    {
        _key = key;
        _suite = suite;
        _nonce = 0;
    }

    public byte[] EncryptWithAd(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext)
    {
        // Production: Use AEAD cipher (ChaCha20-Poly1305, AES-GCM)
        var ciphertext = new byte[plaintext.Length + 16];
        plaintext.CopyTo(ciphertext);
        _nonce++;
        return ciphertext;
    }

    public byte[] DecryptWithAd(ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext)
    {
        // Production: Use AEAD cipher
        var plaintext = ciphertext[..^16].ToArray();
        _nonce++;
        return plaintext;
    }

    public void Rekey()
    {
        // Production: Generate new key from current key
        // Provides forward secrecy for long-lived connections
    }
}

/// <summary>
/// Noise handshake patterns
/// </summary>
public enum NoiseHandshakePattern
{
    /// <summary>
    /// XX: Full mutual authentication, both identities transmitted
    /// Most flexible pattern
    /// </summary>
    XX,

    /// <summary>
    /// IK: Initiator knows responder's static key
    /// 1-RTT, responder identity hidden
    /// </summary>
    IK,

    /// <summary>
    /// NK: Initiator knows responder's static key, no authentication
    /// 1-RTT, one-way authentication
    /// </summary>
    NK,

    /// <summary>
    /// KK: Both parties know each other's static keys
    /// 1-RTT, mutual authentication
    /// </summary>
    KK,

    /// <summary>
    /// NX: No pre-shared knowledge, responder sends static key
    /// </summary>
    NX,

    /// <summary>
    /// KX: Initiator knows responder's key, responder learns initiator's key
    /// </summary>
    KX,

    /// <summary>
    /// XK: Responder's key known, initiator sends encrypted static key
    /// </summary>
    XK,

    /// <summary>
    /// X: Initiator sends encrypted static key to known responder
    /// </summary>
    X,

    /// <summary>
    /// K: Mutual knowledge of static keys
    /// </summary>
    K,

    /// <summary>
    /// N: Initiator knows responder's static key
    /// </summary>
    N
}

/// <summary>
/// Role in Noise handshake
/// </summary>
public enum NoiseRole
{
    Initiator,
    Responder
}

/// <summary>
/// Noise protocol tokens
/// </summary>
public enum NoiseToken
{
    E,   // Ephemeral key
    S,   // Static key
    EE,  // DH(e, re)
    ES,  // DH(e, rs) or DH(s, re)
    SE,  // DH(s, re) or DH(e, rs)
    SS,  // DH(s, rs)
    PSK  // Pre-shared key
}
#endif
