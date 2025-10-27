using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using HeroCrypt.Enterprise.CertificateAuthority;
using HeroCrypt.Enterprise.Compliance;
using HeroCrypt.Enterprise.KeyManagement;

namespace HeroCrypt.Tests;

/// <summary>
/// Tests for enterprise features (CA, Compliance, KMS)
/// </summary>
public class EnterpriseTests
{
    private readonly ITestOutputHelper _output;

    public EnterpriseTests(ITestOutputHelper output)
    {
        _output = output;
    }

    #region Certificate Authority Tests

    [Fact]
    public void CertificateAuthority_GenerateRootCertificate_Succeeds()
    {
        // Act
        var rootCert = CertificateAuthority.GenerateRootCertificate(
            "HeroCrypt Test Root CA",
            keySize: 2048,
            validityYears: 10);

        // Assert
        Assert.NotNull(rootCert);
        Assert.True(rootCert.HasPrivateKey);
        Assert.Contains("HeroCrypt Test Root CA", rootCert.Subject);

        // Check basic constraints
        var basicConstraints = rootCert.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .FirstOrDefault();
        Assert.NotNull(basicConstraints);
        Assert.True(basicConstraints.CertificateAuthority);

        _output.WriteLine($"Root CA Subject: {rootCert.Subject}");
        _output.WriteLine($"Root CA Thumbprint: {rootCert.Thumbprint}");
    }

    [Fact]
    public void CertificateAuthority_IssueCertificate_Succeeds()
    {
        // Arrange
        var rootCert = CertificateAuthority.GenerateRootCertificate("Test CA", 2048, 10);
        var ca = new CertificateAuthority(new CertificateAuthorityConfig(), rootCert);

        using var rsa = RSA.Create(2048);
        var request = CertificateAuthority.CreateCertificateRequest(
            "test.example.com",
            rsa,
            CertificateProfile.ServerAuthentication);

        // Act
        var cert = ca.IssueCertificate(request, CertificateProfile.ServerAuthentication);

        // Assert
        Assert.NotNull(cert);
        Assert.Contains("test.example.com", cert.Subject);
        Assert.Equal(rootCert.Subject, cert.Issuer);

        _output.WriteLine($"Issued Cert Subject: {cert.Subject}");
        _output.WriteLine($"Issued Cert Issuer: {cert.Issuer}");
    }

    [Fact]
    public void CertificateAuthority_ValidateCertificateChain_Succeeds()
    {
        // Arrange
        var rootCert = CertificateAuthority.GenerateRootCertificate("Test Root", 2048, 10);
        var ca = new CertificateAuthority(new CertificateAuthorityConfig(), rootCert);

        using var rsa = RSA.Create(2048);
        var request = CertificateAuthority.CreateCertificateRequest(
            "test.example.com",
            rsa,
            CertificateProfile.ServerAuthentication);

        var issuedCert = ca.IssueCertificate(request, CertificateProfile.ServerAuthentication);

        var additionalCerts = new X509Certificate2Collection { rootCert };

        // Act
        var result = ca.ValidateCertificateChain(
            issuedCert,
            additionalCerts,
            new CertificateValidationOptions { CheckRevocation = false });

        // Assert
        Assert.NotNull(result);
        _output.WriteLine($"Chain valid: {result.IsValid}");
        _output.WriteLine($"Chain elements: {result.ChainElements.Count}");
    }

    [Fact]
    public void CertificateAuthority_RevokeCertificate_AddsToRevocationList()
    {
        // Arrange
        var rootCert = CertificateAuthority.GenerateRootCertificate("Test CA", 2048, 10);
        var config = new CertificateAuthorityConfig();
        var ca = new CertificateAuthority(config, rootCert);

        using var rsa = RSA.Create(2048);
        var request = CertificateAuthority.CreateCertificateRequest(
            "revoked.example.com",
            rsa,
            CertificateProfile.ServerAuthentication);

        var cert = ca.IssueCertificate(request, CertificateProfile.ServerAuthentication);

        // Act
        ca.RevokeCertificate(cert, CertificateRevocationReason.KeyCompromise);

        // Assert
        Assert.Single(config.RevokedCertificates);
        Assert.Equal(cert.SerialNumber, config.RevokedCertificates[0].SerialNumber);
        Assert.Equal(CertificateRevocationReason.KeyCompromise, config.RevokedCertificates[0].Reason);
    }

    [Fact]
    public void CertificateAuthority_CheckCertificateStatus_ReturnsCorrectStatus()
    {
        // Arrange
        var rootCert = CertificateAuthority.GenerateRootCertificate("Test CA", 2048, 10);
        var ca = new CertificateAuthority(new CertificateAuthorityConfig(), rootCert);

        using var rsa = RSA.Create(2048);
        var request = CertificateAuthority.CreateCertificateRequest(
            "test.example.com",
            rsa,
            CertificateProfile.ServerAuthentication);

        var cert = ca.IssueCertificate(request, CertificateProfile.ServerAuthentication);

        // Act - Check before revocation
        var statusBefore = ca.CheckCertificateStatus(cert);

        // Revoke certificate
        ca.RevokeCertificate(cert, CertificateRevocationReason.KeyCompromise);

        // Act - Check after revocation
        var statusAfter = ca.CheckCertificateStatus(cert);

        // Assert
        Assert.NotNull(statusBefore);
        Assert.NotNull(statusAfter);
        Assert.Equal(OcspCertificateStatus.Revoked, statusAfter.Status);
        Assert.Equal(CertificateRevocationReason.KeyCompromise, statusAfter.RevocationReason);

        _output.WriteLine($"Status before: {statusBefore.Status}");
        _output.WriteLine($"Status after: {statusAfter.Status}");
    }

    [Theory]
    [InlineData(365)] // 1 year
    [InlineData(730)] // 2 years
    [InlineData(1095)] // 3 years
    public void CertificateProfile_ValidityDays_ConfiguresCorrectly(int days)
    {
        // Arrange
        var profile = new CertificateProfile { ValidityDays = days };

        // Assert
        Assert.Equal(days, profile.ValidityDays);
    }

    #endregion

    #region Compliance Framework Tests

    [Fact]
    public void ComplianceFramework_EnableFipsMode_ConfiguresCorrectly()
    {
        // Arrange
        var config = new ComplianceConfig();
        var logger = new InMemoryAuditLogger();
        var compliance = new ComplianceFramework(config, logger);

        // Act
        compliance.EnableFipsMode();

        // Assert
        Assert.True(config.FipsMode);
        Assert.Contains("SHA256", config.AllowedHashAlgorithms);
        Assert.Contains("AES-256-GCM", config.AllowedEncryptionAlgorithms);
        Assert.DoesNotContain("MD5", config.AllowedHashAlgorithms);
        Assert.DoesNotContain("DES", config.AllowedEncryptionAlgorithms);

        Assert.Equal(1, logger.Count);
        _output.WriteLine($"Audit events logged: {logger.Count}");
    }

    [Fact]
    public void ComplianceFramework_IsAlgorithmCompliant_ValidatesCorrectly()
    {
        // Arrange
        var config = new ComplianceConfig();
        var logger = new InMemoryAuditLogger();
        var compliance = new ComplianceFramework(config, logger);
        compliance.EnableFipsMode();

        // Act & Assert - FIPS-approved algorithms
        Assert.True(compliance.IsAlgorithmCompliant("SHA256", "hash"));
        Assert.True(compliance.IsAlgorithmCompliant("AES-256-GCM", "encryption"));

        // Act & Assert - Non-FIPS algorithms
        Assert.False(compliance.IsAlgorithmCompliant("MD5", "hash"));
        Assert.False(compliance.IsAlgorithmCompliant("DES", "encryption"));
    }

    [Fact]
    public void ComplianceFramework_IsKeyLengthCompliant_ValidatesCorrectly()
    {
        // Arrange
        var config = new ComplianceConfig();
        var logger = new InMemoryAuditLogger();
        var compliance = new ComplianceFramework(config, logger);
        compliance.EnableFipsMode();

        // Act & Assert
        Assert.True(compliance.IsKeyLengthCompliant("RSA", 2048));
        Assert.True(compliance.IsKeyLengthCompliant("RSA", 4096));
        Assert.False(compliance.IsKeyLengthCompliant("RSA", 1024));
        Assert.True(compliance.IsKeyLengthCompliant("AES", 256));
        Assert.False(compliance.IsKeyLengthCompliant("AES", 64));
    }

    [Fact]
    public void ComplianceFramework_AuditLog_RecordsEvents()
    {
        // Arrange
        var config = new ComplianceConfig();
        var logger = new InMemoryAuditLogger();
        var compliance = new ComplianceFramework(config, logger);

        var auditEvent = new AuditEvent
        {
            EventType = AuditEventType.CryptographicOperation,
            Severity = AuditSeverity.Medium,
            Description = "Test encryption operation",
            Success = true,
            UserId = "test-user"
        };

        // Act
        compliance.AuditLog(auditEvent);

        // Assert
        Assert.Equal(1, logger.Count);
        var events = logger.GetEvents(DateTimeOffset.MinValue, DateTimeOffset.MaxValue);
        Assert.Single(events);
        Assert.Equal("Test encryption operation", events[0].Description);
        Assert.True(events[0].Success);
    }

    [Fact]
    public void ComplianceFramework_GenerateComplianceReport_CreatesReport()
    {
        // Arrange
        var config = new ComplianceConfig();
        var logger = new InMemoryAuditLogger();
        var compliance = new ComplianceFramework(config, logger);

        // Log some events
        for (int i = 0; i < 10; i++)
        {
            compliance.AuditLog(new AuditEvent
            {
                EventType = AuditEventType.CryptographicOperation,
                Severity = AuditSeverity.Low,
                Description = $"Operation {i}",
                Success = i % 2 == 0
            });
        }

        // Act
        var report = compliance.GenerateComplianceReport(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1),
            ComplianceStandard.FIPS140_2);

        // Assert
        Assert.NotNull(report);
        Assert.Equal(ComplianceStandard.FIPS140_2, report.Standard);
        Assert.Equal(10, report.TotalEvents);
        Assert.Equal(10, report.CryptographicOperations);
        Assert.Equal(5, report.FailedOperations);

        _output.WriteLine($"Total Events: {report.TotalEvents}");
        _output.WriteLine($"Compliance Score: {report.ComplianceScore:F2}");
        _output.WriteLine($"Success Rate: {report.SecurityMetrics.SuccessRate:F2}%");
    }

    [Theory]
    [InlineData(ComplianceStandard.FIPS140_2)]
    [InlineData(ComplianceStandard.CommonCriteria)]
    [InlineData(ComplianceStandard.SOC2)]
    [InlineData(ComplianceStandard.PCI_DSS)]
    public void ComplianceFramework_ValidateConfiguration_WorksForAllStandards(ComplianceStandard standard)
    {
        // Arrange
        var config = new ComplianceConfig
        {
            FipsMode = true,
            AuditLoggingEnabled = true,
            AccessControlEnabled = true,
            EncryptionAtRest = true,
            EncryptionInTransit = true,
            KeyRotationEnabled = true
        };
        var logger = new InMemoryAuditLogger();
        var compliance = new ComplianceFramework(config, logger);
        if (standard == ComplianceStandard.FIPS140_2)
        {
            compliance.EnableFipsMode();
        }

        // Act
        var result = compliance.ValidateConfiguration(standard);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(standard, result.Standard);
        _output.WriteLine($"{standard} - Compliant: {result.IsCompliant}, Findings: {result.Findings.Count}");
    }

    #endregion

    #region Key Management Service Tests

    [Fact]
    public void KeyManagementService_GenerateKey_CreatesKey()
    {
        // Arrange
        var config = new KeyManagementConfig { MasterKey = new byte[32] };
        var keyStore = new InMemoryKeyStore();
        var accessControl = new SimpleAccessControlService();
        var kms = new KeyManagementService(config, keyStore, accessControl);

        var request = new KeyGenerationRequest
        {
            KeyType = KeyType.Symmetric,
            Algorithm = "AES",
            KeySize = 256,
            Purpose = KeyPurpose.Encryption
        };

        // Act
        var metadata = kms.GenerateKey(request, "user-123");

        // Assert
        Assert.NotNull(metadata);
        Assert.NotEqual(Guid.Empty.ToString(), metadata.KeyId);
        Assert.Equal(1, metadata.Version);
        Assert.Equal(KeyType.Symmetric, metadata.KeyType);
        Assert.Equal(256, metadata.KeySize);
        Assert.Equal(KeyState.Active, metadata.State);

        _output.WriteLine($"Generated Key ID: {metadata.KeyId}");
        _output.WriteLine($"Key Algorithm: {metadata.Algorithm}");
    }

    [Fact]
    public void KeyManagementService_UseKey_RetrievesKey()
    {
        // Arrange
        var config = new KeyManagementConfig { MasterKey = new byte[32] };
        RandomNumberGenerator.Fill(config.MasterKey);

        var keyStore = new InMemoryKeyStore();
        var accessControl = new SimpleAccessControlService();
        var kms = new KeyManagementService(config, keyStore, accessControl);

        var metadata = kms.GenerateKey(new KeyGenerationRequest
        {
            KeyType = KeyType.Symmetric,
            KeySize = 256,
            Purpose = KeyPurpose.Encryption
        }, "user-123");

        var context = new KeyUsageContext { Operation = "encrypt" };

        // Act
        var keyMaterial = kms.UseKey(metadata.KeyId, "user-123", context);

        // Assert
        Assert.NotNull(keyMaterial);
        Assert.Equal(32, keyMaterial.Length); // 256 bits = 32 bytes
    }

    [Fact]
    public void KeyManagementService_RotateKey_CreatesNewVersion()
    {
        // Arrange
        var config = new KeyManagementConfig { MasterKey = new byte[32] };
        RandomNumberGenerator.Fill(config.MasterKey);

        var keyStore = new InMemoryKeyStore();
        var accessControl = new SimpleAccessControlService();
        var kms = new KeyManagementService(config, keyStore, accessControl);

        var originalKey = kms.GenerateKey(new KeyGenerationRequest
        {
            KeyType = KeyType.Symmetric,
            KeySize = 256,
            Purpose = KeyPurpose.Encryption
        }, "user-123");

        // Act
        var rotatedKey = kms.RotateKey(originalKey.KeyId, "user-123");

        // Assert
        Assert.NotNull(rotatedKey);
        Assert.Equal(originalKey.KeyId, rotatedKey.KeyId);
        Assert.Equal(2, rotatedKey.Version);
        Assert.Equal(KeyState.Active, rotatedKey.State);

        _output.WriteLine($"Original Version: {originalKey.Version}");
        _output.WriteLine($"Rotated Version: {rotatedKey.Version}");
    }

    [Fact]
    public void KeyManagementService_BackupAndRestoreKey_Succeeds()
    {
        // Arrange
        var config = new KeyManagementConfig { MasterKey = new byte[32] };
        RandomNumberGenerator.Fill(config.MasterKey);

        var keyStore = new InMemoryKeyStore();
        var accessControl = new SimpleAccessControlService();
        accessControl.AddUserRole("admin", "Administrator");

        var kms = new KeyManagementService(config, keyStore, accessControl);

        var originalKey = kms.GenerateKey(new KeyGenerationRequest
        {
            KeyType = KeyType.Symmetric,
            KeySize = 256,
            Purpose = KeyPurpose.Encryption
        }, "admin");

        // Act - Backup
        var backup = kms.BackupKey(originalKey.KeyId, "admin");

        // Assert - Backup
        Assert.NotNull(backup);
        Assert.Equal(originalKey.KeyId, backup.KeyId);
        Assert.NotNull(backup.EncryptedKeyMaterial);

        // Act - Destroy original
        kms.DestroyKey(originalKey.KeyId, "admin");

        // Act - Restore
        var restoredKey = kms.RestoreKey(backup, "admin");

        // Assert - Restore
        Assert.NotNull(restoredKey);
        Assert.Equal(originalKey.KeyId, restoredKey.KeyId);
        Assert.Equal(KeyState.Active, restoredKey.State);

        _output.WriteLine($"Backup ID: {backup.BackupId}");
        _output.WriteLine($"Restored Key State: {restoredKey.State}");
    }

    [Fact]
    public void KeyManagementService_DestroyKey_MarksKeyAsDestroyed()
    {
        // Arrange
        var config = new KeyManagementConfig { MasterKey = new byte[32] };
        RandomNumberGenerator.Fill(config.MasterKey);

        var keyStore = new InMemoryKeyStore();
        var accessControl = new SimpleAccessControlService();
        var kms = new KeyManagementService(config, keyStore, accessControl);

        var metadata = kms.GenerateKey(new KeyGenerationRequest
        {
            KeyType = KeyType.Symmetric,
            KeySize = 256,
            Purpose = KeyPurpose.Encryption
        }, "admin");

        // Act
        kms.DestroyKey(metadata.KeyId, "admin");

        // Assert
        var keyEntry = keyStore.Retrieve(metadata.KeyId);
        Assert.NotNull(keyEntry);
        Assert.Equal(KeyState.Destroyed, keyEntry.State);
        Assert.Null(keyEntry.WrappedKeyMaterial); // Material should be erased
    }

    [Fact]
    public void KeyManagementService_ListKeys_FiltersCorrectly()
    {
        // Arrange
        var config = new KeyManagementConfig { MasterKey = new byte[32] };
        RandomNumberGenerator.Fill(config.MasterKey);

        var keyStore = new InMemoryKeyStore();
        var accessControl = new SimpleAccessControlService();
        var kms = new KeyManagementService(config, keyStore, accessControl);

        // Generate multiple keys
        for (int i = 0; i < 5; i++)
        {
            kms.GenerateKey(new KeyGenerationRequest
            {
                KeyType = KeyType.Symmetric,
                KeySize = 256,
                Purpose = KeyPurpose.Encryption
            }, "user-123");
        }

        for (int i = 0; i < 3; i++)
        {
            kms.GenerateKey(new KeyGenerationRequest
            {
                KeyType = KeyType.Symmetric,
                KeySize = 256,
                Purpose = KeyPurpose.Signing
            }, "user-123");
        }

        // Act
        var encryptionKeys = kms.ListKeys(
            new KeyListFilter { Purpose = KeyPurpose.Encryption },
            "user-123");

        var signingKeys = kms.ListKeys(
            new KeyListFilter { Purpose = KeyPurpose.Signing },
            "user-123");

        var allKeys = kms.ListKeys(new KeyListFilter(), "user-123");

        // Assert
        Assert.Equal(5, encryptionKeys.Count);
        Assert.Equal(3, signingKeys.Count);
        Assert.Equal(8, allKeys.Count);

        _output.WriteLine($"Encryption keys: {encryptionKeys.Count}");
        _output.WriteLine($"Signing keys: {signingKeys.Count}");
        _output.WriteLine($"Total keys: {allKeys.Count}");
    }

    [Theory]
    [InlineData(KeyType.Symmetric, 128)]
    [InlineData(KeyType.Symmetric, 256)]
    [InlineData(KeyType.AsymmetricPrivate, 2048)]
    [InlineData(KeyType.AsymmetricPrivate, 4096)]
    public void KeyManagementService_GenerateKey_SupportsMultipleKeySizes(KeyType keyType, int keySize)
    {
        // Arrange
        var config = new KeyManagementConfig { MasterKey = new byte[32] };
        RandomNumberGenerator.Fill(config.MasterKey);

        var keyStore = new InMemoryKeyStore();
        var accessControl = new SimpleAccessControlService();
        var kms = new KeyManagementService(config, keyStore, accessControl);

        var request = new KeyGenerationRequest
        {
            KeyType = keyType,
            KeySize = keySize,
            Purpose = KeyPurpose.Encryption
        };

        // Act
        var metadata = kms.GenerateKey(request, "user-123");

        // Assert
        Assert.Equal(keySize, metadata.KeySize);
        Assert.Equal(keyType, metadata.KeyType);
    }

    #endregion

    #region Integration Tests

    [Fact]
    public void Enterprise_AllComponents_AreInstantiable()
    {
        // Arrange & Act
        var rootCert = CertificateAuthority.GenerateRootCertificate("Test CA", 2048, 10);
        var ca = new CertificateAuthority(new CertificateAuthorityConfig(), rootCert);

        var complianceConfig = new ComplianceConfig();
        var auditLogger = new InMemoryAuditLogger();
        var compliance = new ComplianceFramework(complianceConfig, auditLogger);

        var kmsConfig = new KeyManagementConfig { MasterKey = new byte[32] };
        var keyStore = new InMemoryKeyStore();
        var accessControl = new SimpleAccessControlService();
        var kms = new KeyManagementService(kmsConfig, keyStore, accessControl);

        // Assert
        Assert.NotNull(ca);
        Assert.NotNull(compliance);
        Assert.NotNull(kms);

        _output.WriteLine("All enterprise components instantiated successfully");
    }

    [Fact]
    public void Enterprise_ComplianceIntegration_TracksCAOperations()
    {
        // Arrange
        var complianceConfig = new ComplianceConfig();
        var auditLogger = new InMemoryAuditLogger();
        var compliance = new ComplianceFramework(complianceConfig, auditLogger);

        var rootCert = CertificateAuthority.GenerateRootCertificate("Test CA", 2048, 10);
        var ca = new CertificateAuthority(new CertificateAuthorityConfig(), rootCert);

        // Act - Issue certificate and log
        using var rsa = RSA.Create(2048);
        var request = CertificateAuthority.CreateCertificateRequest(
            "test.example.com",
            rsa,
            CertificateProfile.ServerAuthentication);

        var cert = ca.IssueCertificate(request, CertificateProfile.ServerAuthentication);

        compliance.AuditLog(new AuditEvent
        {
            EventType = AuditEventType.CertificateOperation,
            Severity = AuditSeverity.Medium,
            Description = $"Issued certificate for {cert.Subject}",
            Success = true,
            UserId = "ca-admin"
        });

        // Assert
        var events = auditLogger.GetEvents(DateTimeOffset.MinValue, DateTimeOffset.MaxValue);
        Assert.Single(events);
        Assert.Equal(AuditEventType.CertificateOperation, events[0].EventType);
    }

    #endregion
}
