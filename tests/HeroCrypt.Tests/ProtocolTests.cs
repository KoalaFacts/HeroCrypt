// Disabled: These tests reference implementations that have been removed
#if FALSE
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using HeroCrypt.Protocols.Noise;
using HeroCrypt.Protocols.Signal;
using HeroCrypt.Protocols.Otr;
using HeroCrypt.Protocols.Opaque;
using HeroCrypt.Protocols.Tls;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for cryptographic protocol implementations
/// </summary>
public class ProtocolTests
{
    private readonly ITestOutputHelper _output;

    public ProtocolTests(ITestOutputHelper output)
    {
        _output = output;
    }

    #region Noise Protocol Tests

    [Fact]
    public void NoiseProtocol_CreateHandshakeState_Succeeds()
    {
        // Arrange
        var config = new NoiseProtocolConfig();
        var noise = new NoiseProtocol(config);

        // Act
        var state = noise.CreateHandshakeState(
            NoiseRole.Initiator,
            NoiseHandshakePattern.XX);

        // Assert
        Assert.NotNull(state);
        Assert.Equal(NoiseRole.Initiator, state.Role);
        Assert.Equal(NoiseHandshakePattern.XX, state.Pattern);
        Assert.NotNull(state.SymmetricState);
    }

    [Theory]
    [InlineData(NoiseHandshakePattern.XX)]
    [InlineData(NoiseHandshakePattern.IK)]
    [InlineData(NoiseHandshakePattern.NK)]
    [InlineData(NoiseHandshakePattern.KK)]
    public void NoiseProtocol_SupportsMultipleHandshakePatterns(NoiseHandshakePattern pattern)
    {
        // Arrange
        var config = new NoiseProtocolConfig();
        var noise = new NoiseProtocol(config);

        // Act
        var state = noise.CreateHandshakeState(NoiseRole.Initiator, pattern);

        // Assert
        Assert.NotNull(state);
        Assert.Equal(pattern, state.Pattern);
    }

    [Fact]
    public void NoiseProtocol_WriteReadMessage_Succeeds()
    {
        // Arrange
        var config = new NoiseProtocolConfig();
        var noise = new NoiseProtocol(config);
        var initiatorState = noise.CreateHandshakeState(NoiseRole.Initiator, NoiseHandshakePattern.XX);
        var responderState = noise.CreateHandshakeState(NoiseRole.Responder, NoiseHandshakePattern.XX);

        // Act - First message (initiator → responder)
        var payload1 = new byte[] { 1, 2, 3 };
        var message1 = noise.WriteMessage(initiatorState, payload1);

        // Assert
        Assert.NotNull(message1);
        Assert.True(message1.Length > 0);
        _output.WriteLine($"Noise message 1 size: {message1.Length} bytes");
    }

    [Fact]
    public void NoiseCipherSuite_DefaultValues_AreCorrect()
    {
        // Arrange & Act
        var suite = NoiseCipherSuite.Default;

        // Assert
        Assert.Equal("25519", suite.DhFunction);
        Assert.Equal("ChaChaPoly", suite.Cipher);
        Assert.Equal("BLAKE2b", suite.Hash);
        Assert.Equal(32, suite.DhLength);
    }

    [Fact]
    public void NoiseCipherSuite_PostQuantum_HasCorrectParameters()
    {
        // Arrange & Act
        var suite = NoiseCipherSuite.PostQuantum;

        // Assert
        Assert.Equal("Kyber1024", suite.DhFunction);
        Assert.Equal("AES256-GCM", suite.Cipher);
        Assert.Equal("SHA512", suite.Hash);
        Assert.Equal(1568, suite.DhLength);
    }

    #endregion

    #region Signal Protocol Tests

    [Fact]
    public void SignalProtocol_InitializeSender_Succeeds()
    {
        // Arrange
        var config = new SignalProtocolConfig();
        var signal = new SignalProtocol(config);
        var sharedSecret = new byte[32];
        var remotePublicKey = new byte[32];

        // Act
        var state = signal.InitializeSender(sharedSecret, remotePublicKey);

        // Assert
        Assert.NotNull(state);
        Assert.NotNull(state.RootKey);
        Assert.NotNull(state.SendingChainKey);
        Assert.NotNull(state.DhSelfPublicKey);
        Assert.Equal(0, state.SendingChainN);
    }

    [Fact]
    public void SignalProtocol_InitializeReceiver_Succeeds()
    {
        // Arrange
        var config = new SignalProtocolConfig();
        var signal = new SignalProtocol(config);
        var sharedSecret = new byte[32];
        var selfKeyPair = new byte[32];

        // Act
        var state = signal.InitializeReceiver(sharedSecret, selfKeyPair);

        // Assert
        Assert.NotNull(state);
        Assert.NotNull(state.RootKey);
        Assert.NotNull(state.DhSelfPrivateKey);
        Assert.Equal(0, state.ReceivingChainN);
    }

    [Fact]
    public void SignalProtocol_EncryptMessage_ProducesValidMessage()
    {
        // Arrange
        var config = new SignalProtocolConfig();
        var signal = new SignalProtocol(config);
        var sharedSecret = new byte[32];
        var remotePublicKey = new byte[32];
        var state = signal.InitializeSender(sharedSecret, remotePublicKey);

        // Act
        var plaintext = new byte[] { 1, 2, 3, 4, 5 };
        var message = signal.Encrypt(state, plaintext);

        // Assert
        Assert.NotNull(message);
        Assert.NotNull(message.Header);
        Assert.NotNull(message.Ciphertext);
        Assert.Equal(0, message.Header.MessageNumber);
        _output.WriteLine($"Signal message size: {message.Ciphertext.Length} bytes");
    }

    [Fact]
    public void SignalProtocol_DoubleRatchetState_TracksCounters()
    {
        // Arrange
        var config = new SignalProtocolConfig();
        var signal = new SignalProtocol(config);
        var sharedSecret = new byte[32];
        var remotePublicKey = new byte[32];
        var state = signal.InitializeSender(sharedSecret, remotePublicKey);

        // Act - Encrypt multiple messages
        for (int i = 0; i < 5; i++)
        {
            signal.Encrypt(state, new byte[] { (byte)i });
        }

        // Assert
        Assert.Equal(5, state.SendingChainN);
    }

    [Fact]
    public void X3dhProtocol_GenerateKeyBundle_Succeeds()
    {
        // Arrange
        var x3dh = new X3dhProtocol();

        // Act
        var bundle = x3dh.GenerateKeyBundle();

        // Assert
        Assert.NotNull(bundle);
        Assert.NotNull(bundle.IdentityKey);
        Assert.NotNull(bundle.IdentityPublicKey);
        Assert.NotNull(bundle.SignedPreKey);
        Assert.NotNull(bundle.SignedPrePublicKey);
        Assert.NotNull(bundle.SignedPreKeySignature);
        Assert.NotEmpty(bundle.OneTimePreKeys);
        Assert.Equal(100, bundle.OneTimePreKeys.Count);
    }

    #endregion

    #region OTR Protocol Tests

    [Fact]
    public void OtrProtocol_CreateSession_Succeeds()
    {
        // Arrange
        var config = new OtrProtocolConfig();
        var otr = new OtrProtocol(config);
        var privateKey = new byte[32];
        var publicKey = new byte[32];

        // Act
        var session = otr.CreateSession(privateKey, publicKey);

        // Assert
        Assert.NotNull(session);
        Assert.Equal(OtrState.PlainText, session.State);
        Assert.Equal(privateKey, session.PrivateKey);
    }

    [Fact]
    public void OtrProtocol_InitiateOtr_ReturnsQueryMessage()
    {
        // Arrange
        var config = new OtrProtocolConfig { ProtocolVersion = OtrVersion.Version3 };
        var otr = new OtrProtocol(config);
        var session = otr.CreateSession(new byte[32], new byte[32]);

        // Act
        var queryMessage = otr.InitiateOtr(session);

        // Assert
        Assert.NotNull(queryMessage);
        Assert.Contains("?OTRv", queryMessage);
        Assert.Contains("3", queryMessage);
        _output.WriteLine($"OTR Query: {queryMessage}");
    }

    [Fact]
    public void OtrProtocol_BeginAke_CreatesCommitMessage()
    {
        // Arrange
        var config = new OtrProtocolConfig();
        var otr = new OtrProtocol(config);
        var session = otr.CreateSession(new byte[32], new byte[32]);

        // Act
        var akeMessage = otr.BeginAke(session);

        // Assert
        Assert.NotNull(akeMessage);
        Assert.Equal(OtrMessageType.DhCommit, akeMessage.Type);
        Assert.NotNull(akeMessage.EncryptedGx);
        Assert.NotNull(akeMessage.HashedGx);
        Assert.NotNull(akeMessage.R);
    }

    [Fact]
    public void OtrProtocol_RespondToAke_CreatesDhKeyMessage()
    {
        // Arrange
        var config = new OtrProtocolConfig();
        var otr = new OtrProtocol(config);
        var initiatorSession = otr.CreateSession(new byte[32], new byte[32]);
        var responderSession = otr.CreateSession(new byte[32], new byte[32]);

        var dhCommit = otr.BeginAke(initiatorSession);

        // Act
        var dhKey = otr.RespondToAke(responderSession, dhCommit);

        // Assert
        Assert.NotNull(dhKey);
        Assert.Equal(OtrMessageType.DhKey, dhKey.Type);
        Assert.NotNull(dhKey.DhPublicKey);
    }

    [Fact]
    public void OtrProtocol_SocialistMillionaires_InitiateSmp()
    {
        // Arrange
        var config = new OtrProtocolConfig();
        var otr = new OtrProtocol(config);
        var session = otr.CreateSession(new byte[32], new byte[32]);

        // Act
        var smpMessage = otr.InitiateSmp(session, "shared-secret");

        // Assert
        Assert.NotNull(smpMessage);
        Assert.Equal(SmpMessageType.Step1, smpMessage.Type);
        Assert.NotNull(smpMessage.G2a);
        Assert.NotNull(smpMessage.G3a);
        Assert.NotNull(smpMessage.Proof2);
        Assert.NotNull(smpMessage.Proof3);
    }

    #endregion

    #region OPAQUE Protocol Tests

    [Fact]
    public void OpaqueProtocol_CreateRegistrationRequest_Succeeds()
    {
        // Arrange
        var config = new OpaqueConfig();
        var opaque = new OpaqueProtocol(config);

        // Act
        var (request, state) = opaque.CreateRegistrationRequest("password123");

        // Assert
        Assert.NotNull(request);
        Assert.NotNull(request.BlindedElement);
        Assert.NotNull(state);
        Assert.NotNull(state.Blind);
        Assert.Equal("password123", state.Password);
    }

    [Fact]
    public void OpaqueProtocol_CreateRegistrationResponse_Succeeds()
    {
        // Arrange
        var config = new OpaqueConfig();
        var opaque = new OpaqueProtocol(config);
        var (request, _) = opaque.CreateRegistrationRequest("password123");

        var serverPrivateKey = new byte[32];
        var serverPublicKey = new byte[32];

        // Act
        var response = opaque.CreateRegistrationResponse(request, serverPrivateKey, serverPublicKey);

        // Assert
        Assert.NotNull(response);
        Assert.NotNull(response.EvaluatedElement);
        Assert.Equal(serverPublicKey, response.ServerPublicKey);
    }

    [Fact]
    public void OpaqueProtocol_FinalizeRegistration_ProducesRecord()
    {
        // Arrange
        var config = new OpaqueConfig();
        var opaque = new OpaqueProtocol(config);
        var (request, state) = opaque.CreateRegistrationRequest("password123");

        var serverPrivateKey = new byte[32];
        var serverPublicKey = new byte[32];
        var response = opaque.CreateRegistrationResponse(request, serverPrivateKey, serverPublicKey);

        // Act
        var (record, exportKey) = opaque.FinalizeRegistration(state, response);

        // Assert
        Assert.NotNull(record);
        Assert.NotNull(record.ClientPublicKey);
        Assert.NotNull(record.MaskingKey);
        Assert.NotNull(record.Envelope);
        Assert.NotNull(exportKey);
        Assert.Equal(32, exportKey.Length);
    }

    [Fact]
    public void OpaqueProtocol_CreateCredentialRequest_Succeeds()
    {
        // Arrange
        var config = new OpaqueConfig();
        var opaque = new OpaqueProtocol(config);

        // Act
        var (request, state) = opaque.CreateCredentialRequest("password123");

        // Assert
        Assert.NotNull(request);
        Assert.NotNull(request.BlindedElement);
        Assert.NotNull(request.ClientNonce);
        Assert.NotNull(request.ClientEphemeralPublic);
        Assert.NotNull(state.ClientEphemeralPrivate);
    }

    [Theory]
    [InlineData(OpaqueGroup.Ristretto255)]
    [InlineData(OpaqueGroup.P256)]
    [InlineData(OpaqueGroup.P384)]
    public void OpaqueProtocol_SupportedGroups_AreValid(OpaqueGroup group)
    {
        // Arrange
        var config = new OpaqueConfig { Group = group };
        var opaque = new OpaqueProtocol(config);

        // Act
        var (request, state) = opaque.CreateRegistrationRequest("password");

        // Assert
        Assert.NotNull(request);
        Assert.NotNull(state);
    }

    #endregion

    #region TLS 1.3 Tests

    [Fact]
    public void Tls13Protocol_CreateClientHello_Succeeds()
    {
        // Arrange
        var config = new Tls13Config();
        var tls = new Tls13Protocol(config);
        var clientConfig = new Tls13ClientConfig
        {
            ServerName = "example.com"
        };

        // Act
        var clientHello = tls.CreateClientHello(clientConfig);

        // Assert
        Assert.NotNull(clientHello);
        Assert.NotNull(clientHello.Random);
        Assert.Equal(32, clientHello.Random.Length);
        Assert.NotEmpty(clientHello.CipherSuites);
        Assert.NotEmpty(clientHello.SupportedGroups);
        Assert.NotNull(clientHello.KeyShare);
        Assert.Equal("example.com", clientHello.ServerName);
    }

    [Fact]
    public void Tls13Protocol_CreateServerHello_Succeeds()
    {
        // Arrange
        var config = new Tls13Config();
        var tls = new Tls13Protocol(config);
        var clientConfig = new Tls13ClientConfig();
        var serverConfig = new Tls13ServerConfig();

        var clientHello = tls.CreateClientHello(clientConfig);

        // Act
        var serverHello = tls.CreateServerHello(clientHello, serverConfig);

        // Assert
        Assert.NotNull(serverHello);
        Assert.NotNull(serverHello.Random);
        Assert.NotNull(serverHello.KeyShare);
        Assert.Contains(serverHello.SelectedCipherSuite, clientHello.CipherSuites);
    }

    [Fact]
    public void Tls13Protocol_DeriveHandshakeKeys_Succeeds()
    {
        // Arrange
        var config = new Tls13Config();
        var tls = new Tls13Protocol(config);

        var sharedSecret = new byte[32];
        var clientHelloHash = new byte[32];
        var serverHelloHash = new byte[32];

        // Act
        var keys = tls.DeriveHandshakeKeys(
            sharedSecret,
            clientHelloHash,
            serverHelloHash,
            Tls13CipherSuite.TLS_AES_256_GCM_SHA384);

        // Assert
        Assert.NotNull(keys);
        Assert.NotNull(keys.ClientHandshakeTrafficSecret);
        Assert.NotNull(keys.ServerHandshakeTrafficSecret);
        Assert.NotNull(keys.MasterSecret);
        Assert.NotNull(keys.ClientHandshakeKey);
        Assert.NotNull(keys.ClientHandshakeIv);
        Assert.Equal(32, keys.ClientHandshakeKey.Length);
        Assert.Equal(12, keys.ClientHandshakeIv.Length);
    }

    [Fact]
    public void Tls13Protocol_DeriveApplicationKeys_Succeeds()
    {
        // Arrange
        var config = new Tls13Config();
        var tls = new Tls13Protocol(config);

        var masterSecret = new byte[32];
        var handshakeHash = new byte[32];

        // Act
        var keys = tls.DeriveApplicationKeys(masterSecret, handshakeHash);

        // Assert
        Assert.NotNull(keys);
        Assert.NotNull(keys.ClientApplicationTrafficSecret);
        Assert.NotNull(keys.ServerApplicationTrafficSecret);
        Assert.NotNull(keys.ClientApplicationKey);
        Assert.NotNull(keys.ClientApplicationIv);
        Assert.NotNull(keys.ExporterMasterSecret);
    }

    [Fact]
    public void Tls13Protocol_CreateNewSessionTicket_Succeeds()
    {
        // Arrange
        var config = new Tls13Config();
        var tls = new Tls13Protocol(config);

        var resumptionMasterSecret = new byte[32];
        var handshakeHash = new byte[32];

        // Act
        var ticket = tls.CreateNewSessionTicket(resumptionMasterSecret, handshakeHash, 86400);

        // Assert
        Assert.NotNull(ticket);
        Assert.Equal(86400u, ticket.TicketLifetime);
        Assert.NotNull(ticket.TicketNonce);
        Assert.NotNull(ticket.Ticket);
        Assert.True(ticket.MaxEarlyDataSize > 0);
    }

    [Theory]
    [InlineData(Tls13CipherSuite.TLS_AES_128_GCM_SHA256)]
    [InlineData(Tls13CipherSuite.TLS_AES_256_GCM_SHA384)]
    [InlineData(Tls13CipherSuite.TLS_CHACHA20_POLY1305_SHA256)]
    public void Tls13CipherSuite_AllSuites_AreSupported(Tls13CipherSuite suite)
    {
        // Arrange
        var clientConfig = new Tls13ClientConfig();

        // Act & Assert
        Assert.Contains(suite, clientConfig.SupportedCipherSuites);
    }

    [Theory]
    [InlineData(Tls13NamedGroup.X25519)]
    [InlineData(Tls13NamedGroup.Secp256r1)]
    [InlineData(Tls13NamedGroup.Secp384r1)]
    public void Tls13NamedGroup_CommonGroups_AreSupported(Tls13NamedGroup group)
    {
        // Arrange
        var clientConfig = new Tls13ClientConfig();

        // Act & Assert
        Assert.Contains(group, clientConfig.SupportedGroups);
    }

    [Fact]
    public void Tls13Protocol_EncryptEarlyData_Succeeds()
    {
        // Arrange
        var config = new Tls13Config { AllowEarlyData = true };
        var tls = new Tls13Protocol(config);

        var earlyTrafficSecret = new byte[32];
        var plaintext = new byte[] { 1, 2, 3, 4, 5 };

        // Act
        var ciphertext = tls.EncryptEarlyData(plaintext, earlyTrafficSecret);

        // Assert
        Assert.NotNull(ciphertext);
        Assert.True(ciphertext.Length >= plaintext.Length);
    }

    #endregion

    #region Integration Tests

    [Fact]
    public void Protocols_AllImplementations_AreInstantiable()
    {
        // Arrange & Act
        var noiseProtocol = new NoiseProtocol(new NoiseProtocolConfig());
        var signalProtocol = new SignalProtocol(new SignalProtocolConfig());
        var otrProtocol = new OtrProtocol(new OtrProtocolConfig());
        var opaqueProtocol = new OpaqueProtocol(new OpaqueConfig());
        var tlsProtocol = new Tls13Protocol(new Tls13Config());

        // Assert
        Assert.NotNull(noiseProtocol);
        Assert.NotNull(signalProtocol);
        Assert.NotNull(otrProtocol);
        Assert.NotNull(opaqueProtocol);
        Assert.NotNull(tlsProtocol);

        _output.WriteLine("All protocol implementations instantiated successfully");
    }

    #endregion
}
#endif
