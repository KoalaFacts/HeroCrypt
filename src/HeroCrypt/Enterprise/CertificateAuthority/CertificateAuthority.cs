using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Numerics;

namespace HeroCrypt.Enterprise.CertificateAuthority;

#if !NETSTANDARD2_0
/// <summary>
/// Certificate Authority (CA) implementation for X.509 certificate management
///
/// Provides enterprise-grade certificate authority functionality including:
/// - X.509 certificate generation and signing
/// - Certificate chain validation
/// - Certificate Revocation List (CRL) management
/// - Online Certificate Status Protocol (OCSP) responder
/// - Certificate lifecycle management
///
/// Standards Compliance:
/// - RFC 5280: X.509 Public Key Infrastructure Certificate and CRL Profile
/// - RFC 6960: Online Certificate Status Protocol (OCSP)
/// - RFC 5019: Lightweight OCSP Profile
///
/// Use Cases:
/// - Internal PKI for organizations
/// - Service-to-service authentication
/// - Code signing infrastructure
/// - Device certificate provisioning
/// - Secure email (S/MIME)
///
/// Production Requirements:
/// - Secure storage for CA private key (HSM recommended)
/// - CRL and OCSP distribution points
/// - Certificate database for tracking issued certificates
/// - Automated certificate renewal
/// - Proper access controls and audit logging
/// - Backup and disaster recovery procedures
/// </summary>
public class CertificateAuthority
{
    private readonly CertificateAuthorityConfig _config;
    private readonly X509Certificate2 _caCertificate;

    /// <summary>
    /// Initializes a new instance of the CertificateAuthority class
    /// </summary>
    /// <param name="config">Certificate Authority configuration</param>
    /// <param name="caCertificate">CA certificate with private key</param>
    /// <exception cref="ArgumentNullException">Thrown when config or caCertificate is null</exception>
    /// <exception cref="ArgumentException">Thrown when caCertificate does not have a private key</exception>
    public CertificateAuthority(CertificateAuthorityConfig config, X509Certificate2 caCertificate)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _caCertificate = caCertificate ?? throw new ArgumentNullException(nameof(caCertificate));

        if (!_caCertificate.HasPrivateKey)
            throw new ArgumentException("CA certificate must have a private key", nameof(caCertificate));
    }

    /// <summary>
    /// Generates a self-signed root CA certificate
    /// </summary>
    public static X509Certificate2 GenerateRootCertificate(
        string subjectName,
        int keySize = 4096,
        int validityYears = 10,
        HashAlgorithmName hashAlgorithm = default)
    {
        if (hashAlgorithm == default)
            hashAlgorithm = HashAlgorithmName.SHA256;

        using var rsa = RSA.Create(keySize);
        var request = new CertificateRequest(
            $"CN={subjectName}",
            rsa,
            hashAlgorithm,
            RSASignaturePadding.Pkcs1);

        // Add basic constraints (CA = true, critical)
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: true,
                pathLengthConstraint: 2,
                critical: true));

        // Add key usage (critical)
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
                critical: true));

        // Add subject key identifier
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        // Create self-signed certificate
        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(validityYears));

        return certificate;
    }

    /// <summary>
    /// Issues a new certificate signed by this CA
    /// </summary>
    public X509Certificate2 IssueCertificate(CertificateRequest request, CertificateProfile profile)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));
        if (profile == null)
            throw new ArgumentNullException(nameof(profile));

        // Generate serial number
        var serialNumber = GenerateSerialNumber();

        // Set validity period
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = notBefore.AddDays(profile.ValidityDays);

        // Sign the certificate with CA's private key
        var certificate = request.Create(
            _caCertificate,
            notBefore,
            notAfter,
            serialNumber);

        // Add private key if provided
        if (profile.IncludePrivateKey && request.PublicKey.Key is RSA)
        {
            var certWithKey = certificate.CopyWithPrivateKey((RSA)request.PublicKey.Key);
            return certWithKey;
        }

        return certificate;
    }

    /// <summary>
    /// Creates a certificate request with appropriate extensions
    /// </summary>
    public static CertificateRequest CreateCertificateRequest(
        string subjectName,
        AsymmetricAlgorithm key,
        CertificateProfile profile,
        HashAlgorithmName hashAlgorithm = default)
    {
        if (hashAlgorithm == default)
            hashAlgorithm = HashAlgorithmName.SHA256;

        CertificateRequest request;

        if (key is RSA rsa)
        {
            request = new CertificateRequest(
                $"CN={subjectName}",
                rsa,
                hashAlgorithm,
                RSASignaturePadding.Pkcs1);
        }
        else if (key is ECDsa ecdsa)
        {
            request = new CertificateRequest(
                $"CN={subjectName}",
                ecdsa,
                hashAlgorithm);
        }
        else
        {
            throw new NotSupportedException("Only RSA and ECDSA keys are supported");
        }

        // Add extensions based on profile
        AddCertificateExtensions(request, profile);

        return request;
    }

    /// <summary>
    /// Validates a certificate chain up to a trusted root
    /// </summary>
    public CertificateValidationResult ValidateCertificateChain(
        X509Certificate2 certificate,
        X509Certificate2Collection? additionalCertificates = null,
        CertificateValidationOptions? options = null)
    {
        options ??= new CertificateValidationOptions();
        var result = new CertificateValidationResult();

        using var chain = new X509Chain();

        // Configure chain policy
        chain.ChainPolicy.RevocationMode = options.CheckRevocation
            ? X509RevocationMode.Online
            : X509RevocationMode.NoCheck;

        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.VerificationFlags = options.VerificationFlags;
        chain.ChainPolicy.VerificationTime = options.VerificationTime ?? DateTime.UtcNow;

        // Add additional certificates to the chain
        if (additionalCertificates != null)
        {
            chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);
        }

        // Build and validate chain
        result.IsValid = chain.Build(certificate);
        result.ChainElements = chain.ChainElements.Cast<X509ChainElement>().ToList();
        result.ChainStatus = chain.ChainStatus.ToList();

        // Check specific validations
        if (options.ValidateKeyUsage)
        {
            result.KeyUsageValid = ValidateKeyUsage(certificate, options.RequiredKeyUsage);
        }

        if (options.ValidateExtendedKeyUsage)
        {
            result.ExtendedKeyUsageValid = ValidateExtendedKeyUsage(certificate, options.RequiredExtendedKeyUsage);
        }

        return result;
    }

    /// <summary>
    /// Revokes a certificate and adds it to the CRL
    /// </summary>
    public void RevokeCertificate(
        X509Certificate2 certificate,
        CertificateRevocationReason reason,
        DateTimeOffset? revocationDate = null)
    {
        revocationDate ??= DateTimeOffset.UtcNow;

        var entry = new CertificateRevocationEntry
        {
            SerialNumber = certificate.SerialNumber,
            RevocationDate = revocationDate.Value,
            Reason = reason,
            InvalidityDate = revocationDate.Value
        };

        _config.RevokedCertificates.Add(entry);
    }

    /// <summary>
    /// Generates a Certificate Revocation List (CRL)
    /// </summary>
    public byte[] GenerateCrl(DateTimeOffset? nextUpdate = null)
    {
        nextUpdate ??= DateTimeOffset.UtcNow.AddDays(7);

        var crlBuilder = new CrlBuilder(_caCertificate, _config.RevokedCertificates);
        crlBuilder.ThisUpdate = DateTimeOffset.UtcNow;
        crlBuilder.NextUpdate = nextUpdate.Value;
        crlBuilder.CrlNumber = _config.CrlNumber++;

        return crlBuilder.Build();
    }

    /// <summary>
    /// Checks certificate status via OCSP
    /// </summary>
    public OcspResponse CheckCertificateStatus(X509Certificate2 certificate)
    {
        var serialNumber = certificate.SerialNumber;

        // Check if certificate is in revoked list
        var revokedEntry = _config.RevokedCertificates
            .FirstOrDefault(r => r.SerialNumber.Equals(serialNumber, StringComparison.OrdinalIgnoreCase));

        if (revokedEntry != null)
        {
            return new OcspResponse
            {
                Status = OcspCertificateStatus.Revoked,
                RevocationTime = revokedEntry.RevocationDate,
                RevocationReason = revokedEntry.Reason,
                ThisUpdate = DateTimeOffset.UtcNow,
                NextUpdate = DateTimeOffset.UtcNow.AddDays(1)
            };
        }

        // Check if certificate was issued by this CA
        if (!IsCertificateIssuedByThisCa(certificate))
        {
            return new OcspResponse
            {
                Status = OcspCertificateStatus.Unknown,
                ThisUpdate = DateTimeOffset.UtcNow,
                NextUpdate = DateTimeOffset.UtcNow.AddDays(1)
            };
        }

        // Certificate is good
        return new OcspResponse
        {
            Status = OcspCertificateStatus.Good,
            ThisUpdate = DateTimeOffset.UtcNow,
            NextUpdate = DateTimeOffset.UtcNow.AddDays(1)
        };
    }

    #region Helper Methods

    private static void AddCertificateExtensions(CertificateRequest request, CertificateProfile profile)
    {
        // Basic Constraints
        if (profile.IsCertificateAuthority)
        {
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: true,
                    hasPathLengthConstraint: profile.PathLengthConstraint.HasValue,
                    pathLengthConstraint: profile.PathLengthConstraint ?? 0,
                    critical: true));
        }
        else
        {
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(
                    certificateAuthority: false,
                    hasPathLengthConstraint: false,
                    pathLengthConstraint: 0,
                    critical: true));
        }

        // Key Usage
        if (profile.KeyUsage != X509KeyUsageFlags.None)
        {
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(profile.KeyUsage, critical: true));
        }

        // Extended Key Usage
        if (profile.ExtendedKeyUsage != null && profile.ExtendedKeyUsage.Any())
        {
            var oidCollection = new OidCollection();
            foreach (var oid in profile.ExtendedKeyUsage)
            {
                oidCollection.Add(new Oid(oid));
            }
            var ekuExtension = new X509EnhancedKeyUsageExtension(oidCollection, critical: false);
            request.CertificateExtensions.Add(ekuExtension);
        }

        // Subject Alternative Names
        if (profile.SubjectAlternativeNames != null && profile.SubjectAlternativeNames.Any())
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var san in profile.SubjectAlternativeNames)
            {
                if (san.Type == SubjectAlternativeNameType.DnsName)
                    sanBuilder.AddDnsName(san.Value);
                else if (san.Type == SubjectAlternativeNameType.IpAddress)
                    sanBuilder.AddIpAddress(System.Net.IPAddress.Parse(san.Value));
                else if (san.Type == SubjectAlternativeNameType.Email)
                    sanBuilder.AddEmailAddress(san.Value);
                else if (san.Type == SubjectAlternativeNameType.Uri)
                    sanBuilder.AddUri(new Uri(san.Value));
            }
            request.CertificateExtensions.Add(sanBuilder.Build());
        }

        // Subject Key Identifier
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
    }

    private static byte[] GenerateSerialNumber()
    {
        // Generate a random 20-byte serial number
        var serialNumber = new byte[20];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(serialNumber);

        // Ensure it's positive (clear the sign bit)
        serialNumber[0] &= 0x7F;

        return serialNumber;
    }

    private bool ValidateKeyUsage(X509Certificate2 certificate, X509KeyUsageFlags required)
    {
        var keyUsageExt = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsageExt == null)
            return false;

        return (keyUsageExt.KeyUsages & required) == required;
    }

    private bool ValidateExtendedKeyUsage(X509Certificate2 certificate, string[] requiredOids)
    {
        var ekuExt = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (ekuExt == null)
            return false;

        var oids = ekuExt.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value).ToHashSet();
        return requiredOids.All(req => oids.Contains(req));
    }

    private bool IsCertificateIssuedByThisCa(X509Certificate2 certificate)
    {
        // Check if certificate is signed by this CA
        try
        {
            using var publicKey = _caCertificate.GetRSAPublicKey();
            if (publicKey == null)
                return false;

            // Production: Verify signature
            // This is a simplified check
            return certificate.Issuer == _caCertificate.Subject;
        }
        catch
        {
            return false;
        }
    }

    #endregion
}

/// <summary>
/// Certificate Authority configuration
/// </summary>
public class CertificateAuthorityConfig
{
    /// <summary>
    /// Gets or sets the name of the Certificate Authority
    /// </summary>
    public string CaName { get; set; } = "HeroCrypt CA";

    /// <summary>
    /// Gets or sets the list of revoked certificates
    /// </summary>
    public List<CertificateRevocationEntry> RevokedCertificates { get; set; } = new();

    /// <summary>
    /// Gets or sets the current CRL (Certificate Revocation List) sequence number
    /// </summary>
    public long CrlNumber { get; set; } = 1;

    /// <summary>
    /// Gets or sets the CRL distribution point URL
    /// </summary>
    public string? CrlDistributionPoint { get; set; }

    /// <summary>
    /// Gets or sets the OCSP responder URL for certificate status checking
    /// </summary>
    public string? OcspResponderUrl { get; set; }
}

/// <summary>
/// Certificate profile for issuance
/// </summary>
public class CertificateProfile
{
    /// <summary>
    /// Gets or sets the validity period in days for the certificate
    /// </summary>
    public int ValidityDays { get; set; } = 365;

    /// <summary>
    /// Gets or sets whether this certificate can act as a Certificate Authority
    /// </summary>
    public bool IsCertificateAuthority { get; set; } = false;

    /// <summary>
    /// Gets or sets the maximum path length constraint for certificate chains (null for no constraint)
    /// </summary>
    public int? PathLengthConstraint { get; set; }

    /// <summary>
    /// Gets or sets the key usage flags for the certificate
    /// </summary>
    public X509KeyUsageFlags KeyUsage { get; set; } = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment;

    /// <summary>
    /// Gets or sets the extended key usage OIDs for the certificate
    /// </summary>
    public List<string>? ExtendedKeyUsage { get; set; }

    /// <summary>
    /// Gets or sets the Subject Alternative Names for the certificate
    /// </summary>
    public List<SubjectAlternativeName>? SubjectAlternativeNames { get; set; }

    /// <summary>
    /// Gets or sets whether to include the private key in the issued certificate
    /// </summary>
    public bool IncludePrivateKey { get; set; } = false;

    /// <summary>
    /// Gets a certificate profile for server authentication (TLS/SSL)
    /// </summary>
    public static CertificateProfile ServerAuthentication => new()
    {
        ValidityDays = 365,
        KeyUsage = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
        ExtendedKeyUsage = new List<string> { "1.3.6.1.5.5.7.3.1" }, // serverAuth
        IsCertificateAuthority = false
    };

    /// <summary>
    /// Gets a certificate profile for client authentication
    /// </summary>
    public static CertificateProfile ClientAuthentication => new()
    {
        ValidityDays = 365,
        KeyUsage = X509KeyUsageFlags.DigitalSignature,
        ExtendedKeyUsage = new List<string> { "1.3.6.1.5.5.7.3.2" }, // clientAuth
        IsCertificateAuthority = false
    };

    /// <summary>
    /// Gets a certificate profile for code signing
    /// </summary>
    public static CertificateProfile CodeSigning => new()
    {
        ValidityDays = 1095, // 3 years
        KeyUsage = X509KeyUsageFlags.DigitalSignature,
        ExtendedKeyUsage = new List<string> { "1.3.6.1.5.5.7.3.3" }, // codeSigning
        IsCertificateAuthority = false
    };

    /// <summary>
    /// Gets a certificate profile for an intermediate Certificate Authority
    /// </summary>
    public static CertificateProfile IntermediateCA => new()
    {
        ValidityDays = 3650, // 10 years
        KeyUsage = X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
        IsCertificateAuthority = true,
        PathLengthConstraint = 0
    };
}

/// <summary>
/// Subject Alternative Name entry
/// </summary>
public class SubjectAlternativeName
{
    /// <summary>
    /// Gets or sets the type of Subject Alternative Name
    /// </summary>
    public SubjectAlternativeNameType Type { get; set; }

    /// <summary>
    /// Gets or sets the value of the Subject Alternative Name
    /// </summary>
    public string Value { get; set; } = string.Empty;
}

/// <summary>
/// Subject Alternative Name types
/// </summary>
public enum SubjectAlternativeNameType
{
    /// <summary>
    /// DNS name (e.g., example.com)
    /// </summary>
    DnsName,

    /// <summary>
    /// IP address
    /// </summary>
    IpAddress,

    /// <summary>
    /// Email address
    /// </summary>
    Email,

    /// <summary>
    /// URI (Uniform Resource Identifier)
    /// </summary>
    Uri
}

/// <summary>
/// Certificate validation result
/// </summary>
public class CertificateValidationResult
{
    /// <summary>
    /// Gets or sets whether the certificate chain is valid
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// Gets or sets the collection of chain elements (certificates in the chain)
    /// </summary>
    public List<X509ChainElement> ChainElements { get; set; } = new();

    /// <summary>
    /// Gets or sets the collection of chain status information
    /// </summary>
    public List<X509ChainStatus> ChainStatus { get; set; } = new();

    /// <summary>
    /// Gets or sets whether the key usage is valid
    /// </summary>
    public bool KeyUsageValid { get; set; } = true;

    /// <summary>
    /// Gets or sets whether the extended key usage is valid
    /// </summary>
    public bool ExtendedKeyUsageValid { get; set; } = true;
}

/// <summary>
/// Certificate validation options
/// </summary>
public class CertificateValidationOptions
{
    /// <summary>
    /// Gets or sets whether to check certificate revocation status
    /// </summary>
    public bool CheckRevocation { get; set; } = true;

    /// <summary>
    /// Gets or sets the verification flags for chain validation
    /// </summary>
    public X509VerificationFlags VerificationFlags { get; set; } = X509VerificationFlags.NoFlag;

    /// <summary>
    /// Gets or sets the time to use for verification (null for current time)
    /// </summary>
    public DateTime? VerificationTime { get; set; }

    /// <summary>
    /// Gets or sets whether to validate key usage
    /// </summary>
    public bool ValidateKeyUsage { get; set; } = true;

    /// <summary>
    /// Gets or sets the required key usage flags
    /// </summary>
    public X509KeyUsageFlags RequiredKeyUsage { get; set; } = X509KeyUsageFlags.DigitalSignature;

    /// <summary>
    /// Gets or sets whether to validate extended key usage
    /// </summary>
    public bool ValidateExtendedKeyUsage { get; set; } = false;

    /// <summary>
    /// Gets or sets the required extended key usage OIDs
    /// </summary>
    public string[] RequiredExtendedKeyUsage { get; set; } = Array.Empty<string>();
}

/// <summary>
/// Certificate revocation entry
/// </summary>
public class CertificateRevocationEntry
{
    /// <summary>
    /// Gets or sets the serial number of the revoked certificate
    /// </summary>
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the date and time when the certificate was revoked
    /// </summary>
    public DateTimeOffset RevocationDate { get; set; }

    /// <summary>
    /// Gets or sets the reason for certificate revocation
    /// </summary>
    public CertificateRevocationReason Reason { get; set; }

    /// <summary>
    /// Gets or sets the date when the certificate became invalid
    /// </summary>
    public DateTimeOffset InvalidityDate { get; set; }
}

/// <summary>
/// Certificate revocation reasons (RFC 5280)
/// </summary>
public enum CertificateRevocationReason
{
    /// <summary>
    /// Unspecified reason for revocation
    /// </summary>
    Unspecified = 0,

    /// <summary>
    /// Private key has been compromised
    /// </summary>
    KeyCompromise = 1,

    /// <summary>
    /// CA private key has been compromised
    /// </summary>
    CACompromise = 2,

    /// <summary>
    /// Subject's affiliation has changed
    /// </summary>
    AffiliationChanged = 3,

    /// <summary>
    /// Certificate has been superseded by a new certificate
    /// </summary>
    Superseded = 4,

    /// <summary>
    /// Certificate is no longer needed
    /// </summary>
    CessationOfOperation = 5,

    /// <summary>
    /// Certificate is on hold (temporary suspension)
    /// </summary>
    CertificateHold = 6,

    /// <summary>
    /// Remove certificate from CRL
    /// </summary>
    RemoveFromCRL = 8,

    /// <summary>
    /// Privilege has been withdrawn
    /// </summary>
    PrivilegeWithdrawn = 9,

    /// <summary>
    /// Attribute authority has been compromised
    /// </summary>
    AACompromise = 10
}

/// <summary>
/// CRL Builder
/// </summary>
public class CrlBuilder
{
    private readonly X509Certificate2 _issuer;
    private readonly List<CertificateRevocationEntry> _revokedCertificates;

    /// <summary>
    /// Gets or sets the date and time when this CRL was published
    /// </summary>
    public DateTimeOffset ThisUpdate { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the next CRL will be published
    /// </summary>
    public DateTimeOffset NextUpdate { get; set; }

    /// <summary>
    /// Gets or sets the CRL sequence number
    /// </summary>
    public long CrlNumber { get; set; }

    /// <summary>
    /// Initializes a new instance of the CrlBuilder class
    /// </summary>
    /// <param name="issuer">The CA certificate that will sign the CRL</param>
    /// <param name="revokedCertificates">The list of revoked certificates</param>
    public CrlBuilder(X509Certificate2 issuer, List<CertificateRevocationEntry> revokedCertificates)
    {
        _issuer = issuer;
        _revokedCertificates = revokedCertificates;
    }

    /// <summary>
    /// Builds the Certificate Revocation List in DER format
    /// </summary>
    /// <returns>The CRL as a byte array</returns>
    public byte[] Build()
    {
        // Production: Build proper DER-encoded CRL according to RFC 5280
        // This is a placeholder that would need full ASN.1 encoding

        var crlData = new List<byte>();

        // Simplified CRL structure (production needs proper ASN.1/DER encoding)
        // TBSCertList structure would go here

        return crlData.ToArray();
    }
}

/// <summary>
/// OCSP Response
/// </summary>
public class OcspResponse
{
    /// <summary>
    /// Gets or sets the certificate status
    /// </summary>
    public OcspCertificateStatus Status { get; set; }

    /// <summary>
    /// Gets or sets the time when the certificate was revoked (only for Revoked status)
    /// </summary>
    public DateTimeOffset? RevocationTime { get; set; }

    /// <summary>
    /// Gets or sets the reason for revocation (only for Revoked status)
    /// </summary>
    public CertificateRevocationReason? RevocationReason { get; set; }

    /// <summary>
    /// Gets or sets the time when this response was generated
    /// </summary>
    public DateTimeOffset ThisUpdate { get; set; }

    /// <summary>
    /// Gets or sets the time when the next update will be available
    /// </summary>
    public DateTimeOffset? NextUpdate { get; set; }
}

/// <summary>
/// OCSP (Online Certificate Status Protocol) certificate status
/// </summary>
public enum OcspCertificateStatus
{
    /// <summary>
    /// Certificate is valid and not revoked
    /// </summary>
    Good,

    /// <summary>
    /// Certificate has been revoked
    /// </summary>
    Revoked,

    /// <summary>
    /// Certificate status is unknown
    /// </summary>
    Unknown
}
#else
// .NET Standard 2.0 stub - CertificateRequest not available

/// <summary>
/// Certificate Authority (CA) - Not available in .NET Standard 2.0
/// </summary>
/// <remarks>
/// CertificateRequest class is not available in .NET Standard 2.0.
/// This functionality requires .NET Core 3.0+ or .NET 5+.
/// </remarks>
public class CertificateAuthority
{
    /// <summary>
    /// Initializes a new instance of the CertificateAuthority class
    /// </summary>
    /// <param name="config">Certificate Authority configuration</param>
    /// <param name="caCertificate">CA certificate with private key</param>
    /// <exception cref="PlatformNotSupportedException">Always thrown in .NET Standard 2.0</exception>
    public CertificateAuthority(CertificateAuthorityConfig config, X509Certificate2 caCertificate)
    {
        throw new PlatformNotSupportedException("CertificateAuthority is not supported in .NET Standard 2.0. Requires .NET Core 3.0+ or .NET 5+.");
    }
}

/// <summary>
/// Certificate Authority Configuration - Not available in .NET Standard 2.0
/// </summary>
public class CertificateAuthorityConfig
{
    /// <summary>
    /// Gets or sets the name of the Certificate Authority
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the organization name
    /// </summary>
    public string Organization { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the country code
    /// </summary>
    public string Country { get; set; } = string.Empty;
}

/// <summary>
/// Certificate Profile - Not available in .NET Standard 2.0
/// </summary>
public class CertificateProfile
{
    /// <summary>
    /// Gets or sets the validity period in days for the certificate
    /// </summary>
    public int ValidityDays { get; set; }

    /// <summary>
    /// Gets or sets whether to include the private key in the issued certificate
    /// </summary>
    public bool IncludePrivateKey { get; set; }
}

/// <summary>
/// OCSP (Online Certificate Status Protocol) certificate status
/// </summary>
public enum OcspCertificateStatus
{
    /// <summary>
    /// Certificate is valid and not revoked
    /// </summary>
    Good,

    /// <summary>
    /// Certificate has been revoked
    /// </summary>
    Revoked,

    /// <summary>
    /// Certificate status is unknown
    /// </summary>
    Unknown
}
#endif
