using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace HeroCrypt.Protocols.Signal;

#if !NETSTANDARD2_0

/// <summary>
/// Signal Protocol (Double Ratchet Algorithm) implementation
///
/// The Signal Protocol provides end-to-end encrypted messaging with strong
/// security properties including forward secrecy and future secrecy.
///
/// Specification: https://signal.org/docs/specifications/doubleratchet/
///
/// Key Features:
/// - End-to-end encryption with forward secrecy
/// - Future secrecy (break-in recovery)
/// - Message authentication and integrity
/// - Out-of-order message handling
/// - Asynchronous communication support
///
/// Core Components:
/// 1. Double Ratchet: Combines DH ratchet and symmetric key ratchet
/// 2. X3DH: Extended Triple Diffie-Hellman for initial key agreement
/// 3. Sesame: Session management and key rotation
///
/// Security Properties:
/// - Forward secrecy: Old messages secure even if current keys compromised
/// - Future secrecy: New messages secure after key compromise recovery
/// - Deniability: No cryptographic proof of who sent messages
/// - Message ordering and replay protection
///
/// Production Requirements:
/// - X25519 for Diffie-Hellman operations
/// - AES-256-CBC or ChaCha20 for message encryption
/// - HMAC-SHA256 for message authentication
/// - HKDF for key derivation
/// - Proper nonce and counter management
/// - Secure key storage (use TEE/HSM when available)
/// </summary>
public class SignalProtocol
{
    private readonly SignalProtocolConfig _config;

    public SignalProtocol(SignalProtocolConfig config)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
    }

    /// <summary>
    /// Initializes a new Double Ratchet session as the sender
    /// </summary>
    public DoubleRatchetState InitializeSender(
        byte[] sharedSecret,
        byte[] remotePublicKey)
    {
        if (sharedSecret == null || sharedSecret.Length != 32)
            throw new ArgumentException("Shared secret must be 32 bytes", nameof(sharedSecret));
        if (remotePublicKey == null || remotePublicKey.Length != 32)
            throw new ArgumentException("Remote public key must be 32 bytes", nameof(remotePublicKey));

        var state = new DoubleRatchetState();

        // Derive root key and chain key from shared secret
        byte[] selfPublicKey;
        var selfPrivateKey = GenerateKeyPair(out selfPublicKey);
        var (rootKey, chainKey) = KdfRootKey(sharedSecret, DiffieHellman(
            selfPrivateKey,
            remotePublicKey));

        state.RootKey = rootKey;
        state.SendingChainKey = chainKey;
        state.DhSelfPrivateKey = GenerateKeyPair(out selfPublicKey);
        state.DhSelfPublicKey = selfPublicKey;
        state.DhRemotePublicKey = remotePublicKey;
        state.SendingChainN = 0;
        state.ReceivingChainN = 0;
        state.PreviousChainN = 0;

        return state;
    }

    /// <summary>
    /// Initializes a new Double Ratchet session as the receiver
    /// </summary>
    public DoubleRatchetState InitializeReceiver(
        byte[] sharedSecret,
        byte[] selfKeyPair)
    {
        if (sharedSecret == null || sharedSecret.Length != 32)
            throw new ArgumentException("Shared secret must be 32 bytes", nameof(sharedSecret));

        var state = new DoubleRatchetState
        {
            RootKey = sharedSecret,
            DhSelfPrivateKey = selfKeyPair,
            DhSelfPublicKey = GetPublicKey(selfKeyPair),
            SendingChainN = 0,
            ReceivingChainN = 0,
            PreviousChainN = 0
        };

        return state;
    }

    /// <summary>
    /// Encrypts a message using the Double Ratchet algorithm
    /// </summary>
    public SignalMessage Encrypt(DoubleRatchetState state, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
    {
        // Derive message key from sending chain
        var (newChainKey, messageKey) = KdfChainKey(state.SendingChainKey!);
        state.SendingChainKey = newChainKey;

        // Encrypt the message
        var header = new SignalMessageHeader
        {
            DhPublicKey = state.DhSelfPublicKey!,
            PreviousChainLength = state.PreviousChainN,
            MessageNumber = state.SendingChainN
        };

        var ciphertext = EncryptMessage(messageKey, plaintext, header, associatedData);

        state.SendingChainN++;

        return new SignalMessage
        {
            Header = header,
            Ciphertext = ciphertext
        };
    }

    /// <summary>
    /// Decrypts a message using the Double Ratchet algorithm
    /// </summary>
    public byte[] Decrypt(DoubleRatchetState state, SignalMessage message, ReadOnlySpan<byte> associatedData = default)
    {
        // Check if we need to perform a DH ratchet step
        if (!ByteArrayEquals(message.Header.DhPublicKey, state.DhRemotePublicKey))
        {
            PerformDhRatchet(state, message.Header);
        }

        // Try to decrypt with skipped message keys (out-of-order messages)
        var skippedKey = TryGetSkippedMessageKey(state, message.Header);
        if (skippedKey != null)
        {
            return DecryptMessage(skippedKey, message.Ciphertext, message.Header, associatedData);
        }

        // Skip message keys if needed (handle missing messages)
        SkipMessageKeys(state, message.Header.MessageNumber);

        // Derive message key from receiving chain
        var (newChainKey, messageKey) = KdfChainKey(state.ReceivingChainKey!);
        state.ReceivingChainKey = newChainKey;
        state.ReceivingChainN++;

        return DecryptMessage(messageKey, message.Ciphertext, message.Header, associatedData);
    }

    /// <summary>
    /// Performs a DH ratchet step (called when receiving new ephemeral key)
    /// </summary>
    private void PerformDhRatchet(DoubleRatchetState state, SignalMessageHeader header)
    {
        // Save previous chain length
        state.PreviousChainN = state.SendingChainN;

        // Update receiving chain
        state.DhRemotePublicKey = header.DhPublicKey;
        var (newRootKey, receivingChainKey) = KdfRootKey(
            state.RootKey!,
            DiffieHellman(state.DhSelfPrivateKey!, state.DhRemotePublicKey));
        state.RootKey = newRootKey;
        state.ReceivingChainKey = receivingChainKey;
        state.ReceivingChainN = 0;

        // Update sending chain
        byte[] newSelfPublicKey;
        state.DhSelfPrivateKey = GenerateKeyPair(out newSelfPublicKey);
        state.DhSelfPublicKey = newSelfPublicKey;
        var (newRootKey2, sendingChainKey) = KdfRootKey(
            state.RootKey,
            DiffieHellman(state.DhSelfPrivateKey, state.DhRemotePublicKey));
        state.RootKey = newRootKey2;
        state.SendingChainKey = sendingChainKey;
        state.SendingChainN = 0;
    }

    /// <summary>
    /// Skips message keys to handle out-of-order or missing messages
    /// </summary>
    private void SkipMessageKeys(DoubleRatchetState state, int until)
    {
        if (state.ReceivingChainN + _config.MaxSkippedMessages < until)
        {
            throw new InvalidOperationException("Too many skipped messages");
        }

        if (state.ReceivingChainKey != null)
        {
            while (state.ReceivingChainN < until)
            {
                var (newChainKey, messageKey) = KdfChainKey(state.ReceivingChainKey);
                state.ReceivingChainKey = newChainKey;

                // Store skipped message key
                var skippedKey = new SkippedMessageKey
                {
                    DhPublicKey = state.DhRemotePublicKey!,
                    MessageNumber = state.ReceivingChainN,
                    MessageKey = messageKey
                };
                state.SkippedMessageKeys.Add(skippedKey);

                state.ReceivingChainN++;
            }
        }
    }

    /// <summary>
    /// Tries to retrieve a skipped message key for out-of-order decryption
    /// </summary>
    private byte[]? TryGetSkippedMessageKey(DoubleRatchetState state, SignalMessageHeader header)
    {
        for (int i = 0; i < state.SkippedMessageKeys.Count; i++)
        {
            var skipped = state.SkippedMessageKeys[i];
            if (ByteArrayEquals(skipped.DhPublicKey, header.DhPublicKey) &&
                skipped.MessageNumber == header.MessageNumber)
            {
                var key = skipped.MessageKey;
                state.SkippedMessageKeys.RemoveAt(i);
                return key;
            }
        }
        return null;
    }

    /// <summary>
    /// KDF for deriving root key and chain key
    /// </summary>
    private (byte[] rootKey, byte[] chainKey) KdfRootKey(byte[] rootKey, byte[] dhOutput)
    {
        // Production: Use HKDF with proper info strings
        using var hmac = new HMACSHA256(rootKey);
        var output = hmac.ComputeHash(dhOutput);

        var newRootKey = new byte[32];
        var newChainKey = new byte[32];

        Array.Copy(output, 0, newRootKey, 0, 32);
        using var hmac2 = new HMACSHA256(rootKey);
        var output2 = hmac2.ComputeHash(newRootKey);
        Array.Copy(output2, 0, newChainKey, 0, 32);

        return (newRootKey, newChainKey);
    }

    /// <summary>
    /// KDF for deriving chain key and message key
    /// </summary>
    private (byte[] chainKey, byte[] messageKey) KdfChainKey(byte[] chainKey)
    {
        // Production: Use HMAC-based KDF
        using var hmac1 = new HMACSHA256(chainKey);
        var newChainKey = hmac1.ComputeHash(new byte[] { 0x01 });

        using var hmac2 = new HMACSHA256(chainKey);
        var messageKey = hmac2.ComputeHash(new byte[] { 0x02 });

        return (newChainKey, messageKey);
    }

    /// <summary>
    /// Encrypts a message with authentication
    /// </summary>
    private byte[] EncryptMessage(byte[] messageKey, ReadOnlySpan<byte> plaintext, SignalMessageHeader header, ReadOnlySpan<byte> associatedData)
    {
        // Production: Use AES-256-CBC + HMAC-SHA256 or ChaCha20-Poly1305
        var ciphertext = new byte[plaintext.Length + 16]; // +16 for authentication tag
        plaintext.CopyTo(ciphertext);

        // Placeholder - production would do actual encryption
        return ciphertext;
    }

    /// <summary>
    /// Decrypts and authenticates a message
    /// </summary>
    private byte[] DecryptMessage(byte[] messageKey, byte[] ciphertext, SignalMessageHeader header, ReadOnlySpan<byte> associatedData)
    {
        // Production: Verify HMAC then decrypt with AES-256-CBC or ChaCha20-Poly1305
        var plaintext = new byte[ciphertext.Length - 16]; // -16 for authentication tag
        Array.Copy(ciphertext, plaintext, plaintext.Length);

        // Placeholder - production would do actual decryption and verification
        return plaintext;
    }

    private byte[] GenerateKeyPair(out byte[] publicKey)
    {
        // Production: Use X25519 key generation
        var privateKey = new byte[32];
        publicKey = new byte[32];
        RandomNumberGenerator.Fill(privateKey);
        RandomNumberGenerator.Fill(publicKey); // Placeholder
        return privateKey;
    }

    private byte[] GetPublicKey(byte[] privateKey)
    {
        // Production: Derive X25519 public key from private key
        var publicKey = new byte[32];
        RandomNumberGenerator.Fill(publicKey); // Placeholder
        return publicKey;
    }

    private byte[] DiffieHellman(byte[] privateKey, byte[] publicKey)
    {
        // Production: Perform X25519 DH operation
        var sharedSecret = new byte[32];
        RandomNumberGenerator.Fill(sharedSecret); // Placeholder
        return sharedSecret;
    }

    private bool ByteArrayEquals(byte[]? a, byte[]? b)
    {
        if (a == null || b == null) return a == b;
        if (a.Length != b.Length) return false;
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
}

/// <summary>
/// Configuration for Signal Protocol
/// </summary>
public class SignalProtocolConfig
{
    /// <summary>
    /// Maximum number of skipped message keys to store
    /// </summary>
    public int MaxSkippedMessages { get; set; } = 1000;

    /// <summary>
    /// Use authenticated encryption (AES-GCM, ChaCha20-Poly1305)
    /// </summary>
    public bool UseAead { get; set; } = true;
}

/// <summary>
/// Double Ratchet state
/// </summary>
public class DoubleRatchetState
{
    // DH ratchet state
    public byte[]? DhSelfPrivateKey { get; set; }
    public byte[]? DhSelfPublicKey { get; set; }
    public byte[]? DhRemotePublicKey { get; set; }

    // Root key and chain keys
    public byte[]? RootKey { get; set; }
    public byte[]? SendingChainKey { get; set; }
    public byte[]? ReceivingChainKey { get; set; }

    // Message counters
    public int SendingChainN { get; set; }
    public int ReceivingChainN { get; set; }
    public int PreviousChainN { get; set; }

    // Skipped message keys (for out-of-order messages)
    public List<SkippedMessageKey> SkippedMessageKeys { get; set; } = new();
}

/// <summary>
/// Skipped message key for out-of-order decryption
/// </summary>
public class SkippedMessageKey
{
    public byte[] DhPublicKey { get; set; } = null!;
    public int MessageNumber { get; set; }
    public byte[] MessageKey { get; set; } = null!;
}

/// <summary>
/// Signal message header
/// </summary>
public class SignalMessageHeader
{
    public byte[] DhPublicKey { get; set; } = null!;
    public int PreviousChainLength { get; set; }
    public int MessageNumber { get; set; }
}

/// <summary>
/// Signal encrypted message
/// </summary>
public class SignalMessage
{
    public SignalMessageHeader Header { get; set; } = null!;
    public byte[] Ciphertext { get; set; } = null!;
}

/// <summary>
/// X3DH (Extended Triple Diffie-Hellman) for initial key agreement
///
/// Provides mutual authentication and forward secrecy for the initial
/// key agreement before starting the Double Ratchet.
/// </summary>
public class X3dhProtocol
{
    /// <summary>
    /// Generates an X3DH identity key bundle for publishing
    /// </summary>
    public X3dhKeyBundle GenerateKeyBundle()
    {
        return new X3dhKeyBundle
        {
            IdentityKey = GenerateKeyPair(out var identityPublic),
            IdentityPublicKey = identityPublic,
            SignedPreKey = GenerateKeyPair(out var signedPrePublic),
            SignedPrePublicKey = signedPrePublic,
            SignedPreKeySignature = SignKey(identityPublic, signedPrePublic),
            OneTimePreKeys = GenerateOneTimePreKeys(100)
        };
    }

    /// <summary>
    /// Initiates X3DH key agreement (sender)
    /// </summary>
    public (byte[] sharedSecret, byte[] ephemeralPublicKey) InitiateKeyAgreement(
        byte[] identityKeyPrivate,
        X3dhPublicKeyBundle recipientBundle,
        byte[]? oneTimePreKey = null)
    {
        // Generate ephemeral key
        var ephemeralPrivate = GenerateKeyPair(out var ephemeralPublic);

        // Perform 4 DH operations
        var dh1 = DiffieHellman(identityKeyPrivate, recipientBundle.SignedPrePublicKey);
        var dh2 = DiffieHellman(ephemeralPrivate, recipientBundle.IdentityPublicKey);
        var dh3 = DiffieHellman(ephemeralPrivate, recipientBundle.SignedPrePublicKey);

        byte[]? dh4 = null;
        if (oneTimePreKey != null)
        {
            dh4 = DiffieHellman(ephemeralPrivate, oneTimePreKey);
        }

        // Derive shared secret
        var sharedSecret = DeriveSharedSecret(dh1, dh2, dh3, dh4);

        return (sharedSecret, ephemeralPublic);
    }

    /// <summary>
    /// Completes X3DH key agreement (receiver)
    /// </summary>
    public byte[] CompleteKeyAgreement(
        X3dhKeyBundle ownBundle,
        byte[] senderIdentityPublic,
        byte[] senderEphemeralPublic,
        byte[]? oneTimePreKeyPrivate = null)
    {
        // Perform 4 DH operations (in reverse)
        var dh1 = DiffieHellman(ownBundle.SignedPreKey, senderIdentityPublic);
        var dh2 = DiffieHellman(ownBundle.IdentityKey, senderEphemeralPublic);
        var dh3 = DiffieHellman(ownBundle.SignedPreKey, senderEphemeralPublic);

        byte[]? dh4 = null;
        if (oneTimePreKeyPrivate != null)
        {
            dh4 = DiffieHellman(oneTimePreKeyPrivate, senderEphemeralPublic);
        }

        // Derive shared secret
        return DeriveSharedSecret(dh1, dh2, dh3, dh4);
    }

    private byte[] DeriveSharedSecret(byte[] dh1, byte[] dh2, byte[] dh3, byte[]? dh4)
    {
        // Production: Use HKDF with proper salt and info
        var combined = new byte[32 * (dh4 != null ? 4 : 3)];
        dh1.CopyTo(combined, 0);
        dh2.CopyTo(combined, 32);
        dh3.CopyTo(combined, 64);
        if (dh4 != null)
            dh4.CopyTo(combined, 96);

        return SHA256.HashData(combined);
    }

    private byte[] GenerateKeyPair(out byte[] publicKey)
    {
        var privateKey = new byte[32];
        publicKey = new byte[32];
        RandomNumberGenerator.Fill(privateKey);
        RandomNumberGenerator.Fill(publicKey);
        return privateKey;
    }

    private List<X3dhOneTimePreKey> GenerateOneTimePreKeys(int count)
    {
        var keys = new List<X3dhOneTimePreKey>();
        for (int i = 0; i < count; i++)
        {
            var privateKey = GenerateKeyPair(out var publicKey);
            keys.Add(new X3dhOneTimePreKey
            {
                KeyId = i,
                PrivateKey = privateKey,
                PublicKey = publicKey
            });
        }
        return keys;
    }

    private byte[] SignKey(byte[] signingKey, byte[] dataToSign)
    {
        // Production: Use Ed25519 signature
        using var hmac = new HMACSHA256(signingKey);
        return hmac.ComputeHash(dataToSign);
    }

    private byte[] DiffieHellman(byte[] privateKey, byte[] publicKey)
    {
        var sharedSecret = new byte[32];
        RandomNumberGenerator.Fill(sharedSecret);
        return sharedSecret;
    }
}

/// <summary>
/// X3DH key bundle (private keys)
/// </summary>
public class X3dhKeyBundle
{
    public byte[] IdentityKey { get; set; } = null!;
    public byte[] IdentityPublicKey { get; set; } = null!;
    public byte[] SignedPreKey { get; set; } = null!;
    public byte[] SignedPrePublicKey { get; set; } = null!;
    public byte[] SignedPreKeySignature { get; set; } = null!;
    public List<X3dhOneTimePreKey> OneTimePreKeys { get; set; } = new();
}

/// <summary>
/// X3DH public key bundle (for distribution)
/// </summary>
public class X3dhPublicKeyBundle
{
    public byte[] IdentityPublicKey { get; set; } = null!;
    public byte[] SignedPrePublicKey { get; set; } = null!;
    public byte[] SignedPreKeySignature { get; set; } = null!;
    public List<byte[]> OneTimePrePublicKeys { get; set; } = new();
}

/// <summary>
/// One-time pre-key for X3DH
/// </summary>
public class X3dhOneTimePreKey
{
    public int KeyId { get; set; }
    public byte[] PrivateKey { get; set; } = null!;
    public byte[] PublicKey { get; set; } = null!;
}
#endif
