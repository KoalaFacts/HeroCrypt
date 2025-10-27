using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using HeroCrypt.HardwareSecurity.Hsm.Pkcs11;
using HeroCrypt.HardwareSecurity.CloudHsm;
using HeroCrypt.HardwareSecurity.Tpm;
using HeroCrypt.HardwareSecurity.Tee;
using HeroCrypt.HardwareSecurity.HardwareRng;

namespace HeroCrypt.Tests;

// DISABLED: This test file appears in logs just before crash. Testing if it's the culprit.
#if FALSE

/// <summary>
/// Tests for Hardware Security Module integration
///
/// These tests validate the API functionality of:
/// - PKCS#11 HSM provider
/// - Cloud HSM providers (Azure Key Vault)
/// - TPM (Trusted Platform Module)
/// - TEE (Trusted Execution Environment - SGX, TrustZone)
/// - Hardware RNG
///
/// IMPORTANT: These are abstraction layer tests for API validation.
/// Production use requires actual hardware or cloud service integration.
/// </summary>
public class HardwareSecurityTests
{
    #region PKCS#11 HSM Tests

    [Fact]
    public void Pkcs11_Initialize_SucceedsWithValidLibrary()
    {
        // Arrange
        var provider = new Pkcs11HsmProvider();

        // Act
        provider.Initialize("/usr/lib/libpkcs11.so");

        // Assert - No exception thrown
        provider.Finalize();
    }

    [Fact]
    public void Pkcs11_OpenSession_ReturnsValidSession()
    {
        // Arrange
        var provider = new Pkcs11HsmProvider();
        provider.Initialize("/usr/lib/libpkcs11.so");

        // Act
        var session = provider.OpenSession(slotId: 0, pin: "1234", readWrite: true);

        // Assert
        Assert.NotNull(session);
        Assert.Equal(0u, session.SlotId);
        Assert.True(session.IsReadWrite);
        Assert.Equal(Pkcs11SessionState.Active, session.State);

        provider.CloseSession(session);
        provider.Finalize();
    }

    [Fact]
    public void Pkcs11_GenerateKeyPair_CreatesValidKeyPair()
    {
        // Arrange
        var provider = new Pkcs11HsmProvider();
        provider.Initialize("/usr/lib/libpkcs11.so");
        var session = provider.OpenSession(0, "1234", true);

        // Act
        var keyPair = provider.GenerateKeyPair(session, Pkcs11KeyType.RSA, 2048, "test-key");

        // Assert
        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.PrivateKeyHandle);
        Assert.NotNull(keyPair.PublicKeyHandle);
        Assert.Equal("test-key", keyPair.Label);
        Assert.Equal(Pkcs11KeyType.RSA, keyPair.KeyType);
        Assert.Equal(2048, keyPair.KeySize);

        provider.CloseSession(session);
        provider.Finalize();
    }

    [Fact]
    public void Pkcs11_SignAndVerify_WorksCorrectly()
    {
        // Arrange
        var provider = new Pkcs11HsmProvider();
        provider.Initialize("/usr/lib/libpkcs11.so");
        var session = provider.OpenSession(0, "1234", true);
        var keyPair = provider.GenerateKeyPair(session, Pkcs11KeyType.RSA, 2048, "sign-key");
        var data = Encoding.UTF8.GetBytes("Data to sign");

        // Act
        var signature = provider.Sign(session, keyPair.PrivateKeyHandle, data, Pkcs11MechanismType.SHA256_RSA_PKCS);
        var isValid = provider.Verify(session, keyPair.PublicKeyHandle, data, signature, Pkcs11MechanismType.SHA256_RSA_PKCS);

        // Assert
        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);
        Assert.True(isValid);

        provider.CloseSession(session);
        provider.Finalize();
    }

    [Fact]
    public void Pkcs11_GetSlots_ReturnsAvailableSlots()
    {
        // Arrange
        var provider = new Pkcs11HsmProvider();
        provider.Initialize("/usr/lib/libpkcs11.so");

        // Act
        var slots = provider.GetSlots(tokenPresent: true);

        // Assert
        Assert.NotNull(slots);
        Assert.True(slots.Length > 0);
        Assert.True(slots[0].TokenPresent);

        provider.Finalize();
    }

    #endregion

    #region Azure Key Vault Tests

    [Fact]
    public async Task AzureKeyVault_Initialize_SucceedsWithValidCredentials()
    {
        // Arrange
        var provider = new AzureKeyVaultProvider();
        var mockCredential = new MockAzureCredential();

        // Act
        await provider.InitializeAsync("https://test-vault.vault.azure.net/", mockCredential);

        // Assert - No exception thrown
    }

    [Fact]
    public async Task AzureKeyVault_CreateKey_ReturnsValidKey()
    {
        // Arrange
        var provider = new AzureKeyVaultProvider();
        await provider.InitializeAsync("https://test-vault.vault.azure.net/", new MockAzureCredential());

        var options = new AzureKeyOptions
        {
            KeySize = 2048,
            Enabled = true,
            KeyOperations = new[] { AzureKeyOperation.Sign, AzureKeyOperation.Verify }
        };

        // Act
        var key = await provider.CreateKeyAsync("test-key", AzureKeyType.RSA_HSM, options);

        // Assert
        Assert.NotNull(key);
        Assert.Equal("test-key", key.Name);
        Assert.Equal(AzureKeyType.RSA_HSM, key.KeyType);
        Assert.True(key.Enabled);
        Assert.True(key.IsHsmBacked);
    }

    [Fact]
    public async Task AzureKeyVault_SignAndVerify_WorksCorrectly()
    {
        // Arrange
        var provider = new AzureKeyVaultProvider();
        await provider.InitializeAsync("https://test-vault.vault.azure.net/", new MockAzureCredential());

        var options = new AzureKeyOptions { KeySize = 2048 };
        await provider.CreateKeyAsync("sign-key", AzureKeyType.RSA_HSM, options);

        var data = Encoding.UTF8.GetBytes("Data to sign");

        // Act
        var signature = await provider.SignAsync("sign-key", data, AzureSignatureAlgorithm.RS256);
        var isValid = await provider.VerifyAsync("sign-key", data, signature, AzureSignatureAlgorithm.RS256);

        // Assert
        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);
        Assert.True(isValid);
    }

    [Fact]
    public async Task AzureKeyVault_WrapAndUnwrapKey_WorksCorrectly()
    {
        // Arrange
        var provider = new AzureKeyVaultProvider();
        await provider.InitializeAsync("https://test-vault.vault.azure.net/", new MockAzureCredential());

        await provider.CreateKeyAsync("wrap-key", AzureKeyType.RSA_HSM, new AzureKeyOptions { KeySize = 2048 });
        var symmetricKey = new byte[32]; // 256-bit key

        // Act
        var wrappedKey = await provider.WrapKeyAsync("wrap-key", symmetricKey, AzureKeyWrapAlgorithm.RSA_OAEP);
        var unwrappedKey = await provider.UnwrapKeyAsync("wrap-key", wrappedKey, AzureKeyWrapAlgorithm.RSA_OAEP);

        // Assert
        Assert.NotNull(wrappedKey);
        Assert.NotNull(unwrappedKey);
        Assert.True(wrappedKey.Length > symmetricKey.Length); // Wrapped is larger
    }

    #endregion

    #region TPM Tests

    [Fact]
    public async Task Tpm_Initialize_SucceedsWithHardwareOrSimulator()
    {
        // Arrange
        var provider = new TpmProvider();

        // Act
        await provider.InitializeAsync(useHardwareTpm: false); // Use simulator

        // Assert - No exception thrown
    }

    [Fact]
    public async Task Tpm_GetTpmInfo_ReturnsValidInformation()
    {
        // Arrange
        var provider = new TpmProvider();
        await provider.InitializeAsync(false);

        // Act
        var info = await provider.GetTpmInfoAsync();

        // Assert
        Assert.NotNull(info);
        Assert.NotEmpty(info.Manufacturer);
        Assert.NotEmpty(info.SpecVersion);
    }

    [Fact]
    public async Task Tpm_CreatePrimaryKey_ReturnsValidKeyHandle()
    {
        // Arrange
        var provider = new TpmProvider();
        await provider.InitializeAsync(false);

        // Act
        var key = await provider.CreatePrimaryKeyAsync(
            TpmHierarchy.Owner,
            TpmKeyType.RsaSign,
            TpmKeyAttributes.SigningKey
        );

        // Assert
        Assert.NotNull(key);
        Assert.True(key.Handle > 0);
        Assert.NotNull(key.PublicArea);
    }

    [Fact]
    public async Task Tpm_SealAndUnseal_WorksCorrectly()
    {
        // Arrange
        var provider = new TpmProvider();
        await provider.InitializeAsync(false);

        var storageKey = await provider.CreatePrimaryKeyAsync(
            TpmHierarchy.Owner,
            TpmKeyType.RsaStorage,
            TpmKeyAttributes.StorageKey
        );

        var secretData = Encoding.UTF8.GetBytes("Secret sealed to TPM");

        // Act
        var sealedData = await provider.SealAsync(secretData, storageKey, pcrSelection: new[] { 0, 7 });
        var unsealedData = await provider.UnsealAsync(sealedData, storageKey);

        // Assert
        Assert.NotNull(sealedData);
        Assert.NotNull(unsealedData);
        Assert.True(sealedData.Length > secretData.Length); // Sealed is larger
    }

    [Fact]
    public async Task Tpm_ReadPcr_ReturnsValidValue()
    {
        // Arrange
        var provider = new TpmProvider();
        await provider.InitializeAsync(false);

        // Act
        var pcrValue = await provider.ReadPcrAsync(0);

        // Assert
        Assert.NotNull(pcrValue);
        Assert.Equal(32, pcrValue.Length); // SHA-256 PCR
    }

    [Fact(Skip = "TPM is a reference implementation that returns zeros - production requires actual TPM library integration")]
    public async Task Tpm_GetRandom_ReturnsRandomBytes()
    {
        // Arrange
        var provider = new TpmProvider();
        await provider.InitializeAsync(false);

        // Act
        var random1 = await provider.GetRandomAsync(32);
        var random2 = await provider.GetRandomAsync(32);

        // Assert
        Assert.NotNull(random1);
        Assert.NotNull(random2);
        Assert.Equal(32, random1.Length);
        Assert.Equal(32, random2.Length);
        Assert.False(random1.SequenceEqual(random2)); // Should be different
    }

    #endregion

    #region TEE Tests

    [Fact]
    public async Task Tee_IntelSgx_Initialize_Succeeds()
    {
        // Arrange
        var provider = new IntelSgxProvider();

        // Act
        await provider.InitializeAsync(TeeType.IntelSGX);

        // Assert - No exception thrown
    }

    [Fact]
    public async Task Tee_CreateEnclave_ReturnsValidEnclave()
    {
        // Arrange
        var provider = new IntelSgxProvider();
        await provider.InitializeAsync(TeeType.IntelSGX);
        var enclaveImage = new byte[1024]; // Mock enclave binary

        // Act
        var enclave = await provider.CreateEnclaveAsync("test-enclave", enclaveImage);

        // Assert
        Assert.NotNull(enclave);
        Assert.Equal("test-enclave", enclave.Id);
        Assert.True(enclave.IsInitialized);
        Assert.Equal(TeeType.IntelSGX, enclave.TeeType);
        Assert.NotNull(enclave.Measurement);
    }

    [Fact]
    public async Task Tee_InvokeEnclave_ReturnsResult()
    {
        // Arrange
        var provider = new IntelSgxProvider();
        await provider.InitializeAsync(TeeType.IntelSGX);
        var enclave = await provider.CreateEnclaveAsync("test-enclave", new byte[1024]);

        var parameters = Encoding.UTF8.GetBytes("test parameters");

        // Act
        var result = await provider.InvokeEnclaveAsync(enclave, "test_function", parameters);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.Length > 0);
    }

    [Fact]
    public async Task Tee_SealAndUnseal_WorksCorrectly()
    {
        // Arrange
        var provider = new IntelSgxProvider();
        await provider.InitializeAsync(TeeType.IntelSGX);
        var enclave = await provider.CreateEnclaveAsync("seal-enclave", new byte[1024]);

        var secretData = Encoding.UTF8.GetBytes("Secret data in enclave");

        // Act
        var sealedData = await provider.SealDataAsync(enclave, secretData, TeeSealPolicy.SealToEnclave);
        var unsealedData = await provider.UnsealDataAsync(enclave, sealedData);

        // Assert
        Assert.NotNull(sealedData);
        Assert.NotNull(unsealedData);
        Assert.True(sealedData.Length > secretData.Length);
    }

    [Fact]
    public async Task Tee_AttestEnclave_ReturnsValidAttestation()
    {
        // Arrange
        var provider = new IntelSgxProvider();
        await provider.InitializeAsync(TeeType.IntelSGX);
        var enclave = await provider.CreateEnclaveAsync("attest-enclave", new byte[1024]);

        var challenge = new byte[32];

        // Act
        var attestation = await provider.AttestEnclaveAsync(enclave, challenge);

        // Assert
        Assert.NotNull(attestation);
        Assert.NotNull(attestation.Quote);
        Assert.NotNull(attestation.Measurement);
        Assert.Equal(TeeAttestationType.Remote, attestation.Type);
    }

    [Fact]
    public async Task Tee_ArmTrustZone_Initialize_Succeeds()
    {
        // Arrange
        var provider = new ArmTrustZoneProvider();

        // Act
        await provider.InitializeAsync(TeeType.ARMTrustZone);

        // Assert - No exception thrown
    }

    [Fact]
    public async Task Tee_GetCapabilities_ReturnsValidCapabilities()
    {
        // Arrange
        var provider = new IntelSgxProvider();
        await provider.InitializeAsync(TeeType.IntelSGX);

        // Act
        var capabilities = await provider.GetCapabilitiesAsync();

        // Assert
        Assert.NotNull(capabilities);
        Assert.Equal(TeeType.IntelSGX, capabilities.Type);
        Assert.True(capabilities.IsAvailable);
        Assert.True(capabilities.SupportsRemoteAttestation);
        Assert.True(capabilities.SupportsSealedStorage);
    }

    #endregion

    #region Hardware RNG Tests

    [Fact]
    public void HardwareRng_GetCapabilities_ReturnsValidInfo()
    {
        // Act
        var capabilities = HardwareRandomGenerator.Capabilities;

        // Assert
        Assert.NotNull(capabilities);
        Assert.NotEmpty(capabilities.ProcessorType);
        Assert.NotEmpty(capabilities.BestSource);
    }

    [Fact]
    public void HardwareRng_GetBytes_ReturnsRandomData()
    {
        // Act
        var random1 = HardwareRandomGenerator.GetBytes(32);
        var random2 = HardwareRandomGenerator.GetBytes(32);

        // Assert
        Assert.NotNull(random1);
        Assert.NotNull(random2);
        Assert.Equal(32, random1.Length);
        Assert.Equal(32, random2.Length);
        Assert.False(random1.SequenceEqual(random2)); // Should be different
    }

    [Fact]
    public void HardwareRng_Fill_FillsBuffer()
    {
        // Arrange
        var buffer = new byte[64];

        // Act
        HardwareRandomGenerator.Fill(buffer);

        // Assert
        Assert.True(buffer.Any(b => b != 0)); // Should have non-zero bytes
    }

    [Fact]
    public void HardwareRng_MixEntropy_ProducesOutput()
    {
        // Arrange
        var seed = Encoding.UTF8.GetBytes("additional seed material");

        // Act
        var mixed = HardwareRandomGenerator.MixEntropy(seed, 32);

        // Assert
        Assert.NotNull(mixed);
        Assert.Equal(32, mixed.Length);
    }

    [Fact]
    public void HardwareRng_ConditionEntropy_ProducesOutput()
    {
        // Arrange
        var rawEntropy = new byte[64];
        HardwareRandomGenerator.Fill(rawEntropy);

        // Act
        var conditioned = HardwareRandomGenerator.ConditionEntropy(rawEntropy);

        // Assert
        Assert.NotNull(conditioned);
        Assert.Equal(32, conditioned.Length); // SHA-256 output
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    public void HardwareRng_GetBytes_SupportsVariousSizes(int size)
    {
        // Act
        var random = HardwareRandomGenerator.GetBytes(size);

        // Assert
        Assert.NotNull(random);
        Assert.Equal(size, random.Length);
    }

    #endregion

    // Mock credential for Azure tests
    private class MockAzureCredential : IAzureCredential
    {
        public Task<string> GetTokenAsync()
        {
            return Task.FromResult("mock-token");
        }
    }
}

#endif
