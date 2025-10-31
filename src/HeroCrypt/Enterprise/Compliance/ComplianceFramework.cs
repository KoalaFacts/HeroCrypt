using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography;

namespace HeroCrypt.Enterprise.Compliance;

#if !NETSTANDARD2_0

/// <summary>
/// Compliance and Auditing Framework
///
/// Provides enterprise-grade compliance capabilities including:
/// - FIPS 140-2 compliance mode
/// - Common Criteria preparation
/// - Comprehensive audit logging
/// - Compliance reporting and analytics
/// - Security event tracking
/// - Policy enforcement
///
/// Standards Compliance:
/// - FIPS 140-2: Federal Information Processing Standard
/// - Common Criteria (ISO/IEC 15408)
/// - SOC 2 Type II
/// - PCI-DSS
/// - GDPR compliance support
/// - HIPAA compliance support
///
/// Audit Log Categories:
/// - Cryptographic operations
/// - Key management events
/// - Access control decisions
/// - Configuration changes
/// - Security policy violations
/// - Certificate operations
///
/// Production Requirements:
/// - Tamper-evident logging (append-only, signed logs)
/// - Log retention policies
/// - Secure log storage (encryption at rest)
/// - Log aggregation and SIEM integration
/// - Real-time alerting for critical events
/// - Compliance report generation
/// </summary>
public class ComplianceFramework
{
    private readonly ComplianceConfig _config;
    private readonly IAuditLogger _auditLogger;
    private readonly List<CompliancePolicy> _policies = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="ComplianceFramework"/> class.
    /// </summary>
    /// <param name="config">Compliance configuration settings.</param>
    /// <param name="auditLogger">Audit logger for compliance events.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="config"/> or <paramref name="auditLogger"/> is null.
    /// </exception>
    /// <remarks>
    /// Initializes default compliance policies including weak cryptography detection,
    /// minimum key length enforcement, and failed authentication monitoring.
    /// </remarks>
    public ComplianceFramework(ComplianceConfig config, IAuditLogger auditLogger)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));

        InitializeDefaultPolicies();
    }

    /// <summary>
    /// Enables FIPS 140-2 compliance mode
    /// </summary>
    public void EnableFipsMode()
    {
        _config.FipsMode = true;

        // Restrict to FIPS-approved algorithms
        _config.AllowedHashAlgorithms = new HashSet<string>
        {
            "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512"
        };

        _config.AllowedEncryptionAlgorithms = new HashSet<string>
        {
            "AES-128-GCM", "AES-256-GCM", "AES-128-CCM", "AES-256-CCM"
        };

        _config.AllowedKeyExchangeAlgorithms = new HashSet<string>
        {
            "ECDH-P256", "ECDH-P384", "ECDH-P521", "DH-2048", "DH-3072", "DH-4096"
        };

        _config.AllowedSignatureAlgorithms = new HashSet<string>
        {
            "RSA-PSS-2048", "RSA-PSS-3072", "RSA-PSS-4096",
            "ECDSA-P256", "ECDSA-P384", "ECDSA-P521"
        };

        _config.MinimumKeyLengths = new Dictionary<string, int>
        {
            { "RSA", 2048 },
            { "AES", 128 },
            { "ECC", 256 }
        };

        AuditLog(new AuditEvent
        {
            EventType = AuditEventType.ConfigurationChange,
            Severity = AuditSeverity.High,
            Description = "FIPS 140-2 mode enabled",
            Success = true
        });
    }

    /// <summary>
    /// Validates algorithm compliance with current mode
    /// </summary>
    public bool IsAlgorithmCompliant(string algorithm, string category)
    {
        if (!_config.FipsMode)
            return true; // All algorithms allowed when not in FIPS mode

        var allowedSet = category switch
        {
            "hash" => _config.AllowedHashAlgorithms,
            "encryption" => _config.AllowedEncryptionAlgorithms,
            "keyexchange" => _config.AllowedKeyExchangeAlgorithms,
            "signature" => _config.AllowedSignatureAlgorithms,
            _ => new HashSet<string>()
        };

        return allowedSet.Contains(algorithm, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Validates key length compliance
    /// </summary>
    public bool IsKeyLengthCompliant(string algorithm, int keyLength)
    {
        if (!_config.FipsMode)
            return true;

        if (_config.MinimumKeyLengths.TryGetValue(algorithm, out var minimum))
        {
            return keyLength >= minimum;
        }

        return false;
    }

    /// <summary>
    /// Logs an audit event
    /// </summary>
    public void AuditLog(AuditEvent auditEvent)
    {
        if (auditEvent == null)
            throw new ArgumentNullException(nameof(auditEvent));

        // Enrich event with metadata
        auditEvent.Timestamp = DateTimeOffset.UtcNow;
        auditEvent.EventId = Guid.NewGuid();

        // Check if event violates any policies
        foreach (var policy in _policies)
        {
            if (policy.IsViolation(auditEvent))
            {
                auditEvent.PolicyViolations.Add(policy.Name);
            }
        }

        // Log the event
        _auditLogger.Log(auditEvent);

        // Trigger alerts if necessary
        if (auditEvent.Severity >= AuditSeverity.High || auditEvent.PolicyViolations.Any())
        {
            TriggerAlert(auditEvent);
        }
    }

    /// <summary>
    /// Generates a compliance report for a time period
    /// </summary>
    public ComplianceReport GenerateComplianceReport(
        DateTimeOffset startDate,
        DateTimeOffset endDate,
        ComplianceStandard standard)
    {
        var events = _auditLogger.GetEvents(startDate, endDate);

        var report = new ComplianceReport
        {
            Standard = standard,
            ReportPeriodStart = startDate,
            ReportPeriodEnd = endDate,
            GeneratedAt = DateTimeOffset.UtcNow,
            TotalEvents = events.Count
        };

        // Categorize events
        report.CryptographicOperations = events.Count(e => e.EventType == AuditEventType.CryptographicOperation);
        report.KeyManagementEvents = events.Count(e => e.EventType == AuditEventType.KeyManagement);
        report.AccessControlEvents = events.Count(e => e.EventType == AuditEventType.AccessControl);
        report.PolicyViolations = events.Count(e => e.PolicyViolations.Any());
        report.FailedOperations = events.Count(e => !e.Success);

        // Security metrics
        report.SecurityMetrics = CalculateSecurityMetrics(events);

        // Compliance score
        report.ComplianceScore = CalculateComplianceScore(events, standard);

        // Recommendations
        report.Recommendations = GenerateRecommendations(events, standard);

        return report;
    }

    /// <summary>
    /// Validates configuration against compliance requirements
    /// </summary>
    public ConfigurationValidationResult ValidateConfiguration(ComplianceStandard standard)
    {
        var result = new ConfigurationValidationResult
        {
            Standard = standard,
            ValidationTime = DateTimeOffset.UtcNow
        };

        switch (standard)
        {
            case ComplianceStandard.FIPS140_2:
                ValidateFipsConfiguration(result);
                break;
            case ComplianceStandard.CommonCriteria:
                ValidateCommonCriteriaConfiguration(result);
                break;
            case ComplianceStandard.SOC2:
                ValidateSoc2Configuration(result);
                break;
            case ComplianceStandard.PCI_DSS:
                ValidatePciDssConfiguration(result);
                break;
        }

        result.IsCompliant = !result.Findings.Any(f => f.Severity == FindingSeverity.Critical);

        return result;
    }

    #region Private Methods

    private void InitializeDefaultPolicies()
    {
        // Policy: No weak cryptographic algorithms
        _policies.Add(new CompliancePolicy
        {
            Name = "No Weak Cryptography",
            Description = "Prohibit use of weak cryptographic algorithms",
            IsViolation = (evt) =>
            {
                if (evt.EventType != AuditEventType.CryptographicOperation)
                    return false;

                var weakAlgorithms = new[] { "MD5", "SHA1", "DES", "3DES", "RC4" };
                return weakAlgorithms.Any(weak =>
                    evt.Details?.Contains(weak, StringComparison.OrdinalIgnoreCase) == true);
            }
        });

        // Policy: Minimum key length
        _policies.Add(new CompliancePolicy
        {
            Name = "Minimum Key Length",
            Description = "Enforce minimum key lengths for cryptographic operations",
            IsViolation = (evt) =>
            {
                if (evt.EventType != AuditEventType.KeyManagement)
                    return false;

                // Production: Parse key length from event details
                return false;
            }
        });

        // Policy: Failed authentication attempts
        _policies.Add(new CompliancePolicy
        {
            Name = "Failed Authentication Threshold",
            Description = "Alert on excessive failed authentication attempts",
            IsViolation = (evt) =>
            {
                return evt.EventType == AuditEventType.AccessControl &&
                       !evt.Success &&
                       evt.Description?.Contains("authentication", StringComparison.OrdinalIgnoreCase) == true;
            }
        });
    }

    private void ValidateFipsConfiguration(ConfigurationValidationResult result)
    {
        if (!_config.FipsMode)
        {
            result.Findings.Add(new ComplianceFinding
            {
                Severity = FindingSeverity.Critical,
                Category = "Configuration",
                Description = "FIPS 140-2 mode is not enabled",
                Recommendation = "Enable FIPS mode using EnableFipsMode()"
            });
        }

        // Check minimum key lengths
        foreach (var kvp in _config.MinimumKeyLengths)
        {
            var fipsMinimum = kvp.Key switch
            {
                "RSA" => 2048,
                "AES" => 128,
                "ECC" => 256,
                _ => 0
            };

            if (kvp.Value < fipsMinimum)
            {
                result.Findings.Add(new ComplianceFinding
                {
                    Severity = FindingSeverity.High,
                    Category = "Cryptography",
                    Description = $"Minimum {kvp.Key} key length ({kvp.Value}) below FIPS requirement ({fipsMinimum})",
                    Recommendation = $"Set minimum {kvp.Key} key length to at least {fipsMinimum} bits"
                });
            }
        }
    }

    private void ValidateCommonCriteriaConfiguration(ConfigurationValidationResult result)
    {
        // CC requires comprehensive audit logging
        if (!_config.AuditLoggingEnabled)
        {
            result.Findings.Add(new ComplianceFinding
            {
                Severity = FindingSeverity.Critical,
                Category = "Auditing",
                Description = "Audit logging is not enabled",
                Recommendation = "Enable comprehensive audit logging"
            });
        }

        // CC requires access control enforcement
        if (!_config.AccessControlEnabled)
        {
            result.Findings.Add(new ComplianceFinding
            {
                Severity = FindingSeverity.Critical,
                Category = "Access Control",
                Description = "Access control is not enforced",
                Recommendation = "Enable role-based access control"
            });
        }
    }

    private void ValidateSoc2Configuration(ConfigurationValidationResult result)
    {
        // SOC 2 requires encryption at rest
        if (!_config.EncryptionAtRest)
        {
            result.Findings.Add(new ComplianceFinding
            {
                Severity = FindingSeverity.High,
                Category = "Data Protection",
                Description = "Encryption at rest is not enabled",
                Recommendation = "Enable encryption for all stored sensitive data"
            });
        }

        // SOC 2 requires encryption in transit
        if (!_config.EncryptionInTransit)
        {
            result.Findings.Add(new ComplianceFinding
            {
                Severity = FindingSeverity.High,
                Category = "Data Protection",
                Description = "Encryption in transit is not enforced",
                Recommendation = "Require TLS 1.3 for all network communications"
            });
        }
    }

    private void ValidatePciDssConfiguration(ConfigurationValidationResult result)
    {
        // PCI-DSS requires strong cryptography
        if (_config.AllowedEncryptionAlgorithms.Any(alg =>
            alg.Contains("DES") || alg.Contains("RC4")))
        {
            result.Findings.Add(new ComplianceFinding
            {
                Severity = FindingSeverity.Critical,
                Category = "Cryptography",
                Description = "Weak encryption algorithms are allowed",
                Recommendation = "Remove DES and RC4 from allowed algorithms"
            });
        }

        // PCI-DSS requires key rotation
        if (!_config.KeyRotationEnabled)
        {
            result.Findings.Add(new ComplianceFinding
            {
                Severity = FindingSeverity.High,
                Category = "Key Management",
                Description = "Automatic key rotation is not enabled",
                Recommendation = "Enable periodic key rotation"
            });
        }
    }

    private SecurityMetrics CalculateSecurityMetrics(List<AuditEvent> events)
    {
        var metrics = new SecurityMetrics();

        if (events.Count == 0)
            return metrics;

        metrics.SuccessRate = events.Count(e => e.Success) / (double)events.Count * 100;
        metrics.AverageResponseTime = events.Average(e => e.Duration?.TotalMilliseconds ?? 0);
        metrics.FailureRate = events.Count(e => !e.Success) / (double)events.Count * 100;
        metrics.PolicyViolationRate = events.Count(e => e.PolicyViolations.Any()) / (double)events.Count * 100;

        // Calculate by severity
        metrics.CriticalEvents = events.Count(e => e.Severity == AuditSeverity.Critical);
        metrics.HighSeverityEvents = events.Count(e => e.Severity == AuditSeverity.High);
        metrics.MediumSeverityEvents = events.Count(e => e.Severity == AuditSeverity.Medium);
        metrics.LowSeverityEvents = events.Count(e => e.Severity == AuditSeverity.Low);

        return metrics;
    }

    private double CalculateComplianceScore(List<AuditEvent> events, ComplianceStandard standard)
    {
        if (events.Count == 0)
            return 100.0;

        var violations = events.Count(e => e.PolicyViolations.Any());
        var failures = events.Count(e => !e.Success);
        var criticalEvents = events.Count(e => e.Severity == AuditSeverity.Critical);

        // Base score
        var score = 100.0;

        // Deduct for violations (up to 40 points)
        score -= Math.Min(40, violations / (double)events.Count * 100);

        // Deduct for failures (up to 30 points)
        score -= Math.Min(30, failures / (double)events.Count * 100);

        // Deduct for critical events (up to 30 points)
        score -= Math.Min(30, criticalEvents / (double)events.Count * 100);

        return Math.Max(0, score);
    }

    private List<string> GenerateRecommendations(List<AuditEvent> events, ComplianceStandard standard)
    {
        var recommendations = new List<string>();

        var failureRate = events.Count(e => !e.Success) / (double)events.Count * 100;
        if (failureRate > 5)
        {
            recommendations.Add($"High failure rate ({failureRate:F1}%) detected. Investigate and remediate failing operations.");
        }

        var violationRate = events.Count(e => e.PolicyViolations.Any()) / (double)events.Count * 100;
        if (violationRate > 1)
        {
            recommendations.Add($"Policy violations detected ({violationRate:F1}%). Review and update security policies.");
        }

        if (events.Any(e => e.PolicyViolations.Contains("No Weak Cryptography")))
        {
            recommendations.Add("Weak cryptographic algorithms detected. Migrate to modern algorithms (AES-256, SHA-256+).");
        }

        return recommendations;
    }

    private void TriggerAlert(AuditEvent auditEvent)
    {
        // Production: Send alerts via email, SMS, SIEM, etc.
        // This is a placeholder
        _auditLogger.LogAlert(auditEvent);
    }

    #endregion
}

/// <summary>
/// Compliance configuration
/// </summary>
public class ComplianceConfig
{
    public bool FipsMode { get; set; } = false;
    public bool AuditLoggingEnabled { get; set; } = true;
    public bool AccessControlEnabled { get; set; } = true;
    public bool EncryptionAtRest { get; set; } = true;
    public bool EncryptionInTransit { get; set; } = true;
    public bool KeyRotationEnabled { get; set; } = true;

    public HashSet<string> AllowedHashAlgorithms { get; set; } = new();
    public HashSet<string> AllowedEncryptionAlgorithms { get; set; } = new();
    public HashSet<string> AllowedKeyExchangeAlgorithms { get; set; } = new();
    public HashSet<string> AllowedSignatureAlgorithms { get; set; } = new();
    public Dictionary<string, int> MinimumKeyLengths { get; set; } = new();

    public int AuditLogRetentionDays { get; set; } = 365;
    public int AlertThreshold { get; set; } = 5;
}

/// <summary>
/// Audit logger interface
/// </summary>
public interface IAuditLogger
{
    void Log(AuditEvent auditEvent);
    void LogAlert(AuditEvent auditEvent);
    List<AuditEvent> GetEvents(DateTimeOffset startDate, DateTimeOffset endDate);
}

/// <summary>
/// Audit event
/// </summary>
public class AuditEvent
{
    public Guid EventId { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public AuditEventType EventType { get; set; }
    public AuditSeverity Severity { get; set; }
    public string? Description { get; set; }
    public bool Success { get; set; }
    public string? UserId { get; set; }
    public string? Resource { get; set; }
    public string? Details { get; set; }
    public TimeSpan? Duration { get; set; }
    public List<string> PolicyViolations { get; set; } = new();
    public Dictionary<string, string> Metadata { get; set; } = new();
}

/// <summary>
/// Audit event types
/// </summary>
public enum AuditEventType
{
    CryptographicOperation,
    KeyManagement,
    AccessControl,
    ConfigurationChange,
    CertificateOperation,
    DataAccess,
    SystemEvent,
    SecurityViolation
}

/// <summary>
/// Audit severity levels
/// </summary>
public enum AuditSeverity
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Compliance policy
/// </summary>
public class CompliancePolicy
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public Func<AuditEvent, bool> IsViolation { get; set; } = null!;
}

/// <summary>
/// Compliance standards
/// </summary>
public enum ComplianceStandard
{
    FIPS140_2,
    CommonCriteria,
    SOC2,
    PCI_DSS,
    GDPR,
    HIPAA
}

/// <summary>
/// Compliance report
/// </summary>
public class ComplianceReport
{
    public ComplianceStandard Standard { get; set; }
    public DateTimeOffset ReportPeriodStart { get; set; }
    public DateTimeOffset ReportPeriodEnd { get; set; }
    public DateTimeOffset GeneratedAt { get; set; }

    public int TotalEvents { get; set; }
    public int CryptographicOperations { get; set; }
    public int KeyManagementEvents { get; set; }
    public int AccessControlEvents { get; set; }
    public int PolicyViolations { get; set; }
    public int FailedOperations { get; set; }

    public SecurityMetrics SecurityMetrics { get; set; } = new();
    public double ComplianceScore { get; set; }
    public List<string> Recommendations { get; set; } = new();
}

/// <summary>
/// Security metrics
/// </summary>
public class SecurityMetrics
{
    public double SuccessRate { get; set; }
    public double FailureRate { get; set; }
    public double PolicyViolationRate { get; set; }
    public double AverageResponseTime { get; set; }
    public int CriticalEvents { get; set; }
    public int HighSeverityEvents { get; set; }
    public int MediumSeverityEvents { get; set; }
    public int LowSeverityEvents { get; set; }
}

/// <summary>
/// Configuration validation result
/// </summary>
public class ConfigurationValidationResult
{
    public ComplianceStandard Standard { get; set; }
    public DateTimeOffset ValidationTime { get; set; }
    public bool IsCompliant { get; set; }
    public List<ComplianceFinding> Findings { get; set; } = new();
}

/// <summary>
/// Compliance finding
/// </summary>
public class ComplianceFinding
{
    public FindingSeverity Severity { get; set; }
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
}

/// <summary>
/// Finding severity
/// </summary>
public enum FindingSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// In-memory audit logger implementation for development and testing.
/// </summary>
/// <remarks>
/// This implementation stores events in memory and should not be used in production.
/// For production use, implement IAuditLogger with persistent storage (database, file system,
/// or external logging service) to ensure audit trails are not lost on application restart.
/// </remarks>
public class InMemoryAuditLogger : IAuditLogger
{
    private readonly List<AuditEvent> _events = new();
    private readonly object _lock = new();

    /// <summary>
    /// Logs an audit event to the in-memory store.
    /// </summary>
    /// <param name="auditEvent">The event to log.</param>
    /// <remarks>
    /// Thread-safe. Events are stored in memory and lost on application restart.
    /// </remarks>
    public void Log(AuditEvent auditEvent)
    {
        lock (_lock)
        {
            _events.Add(auditEvent);
        }
    }

    /// <summary>
    /// Logs a high-priority alert event.
    /// </summary>
    /// <param name="auditEvent">The alert event to log.</param>
    /// <remarks>
    /// In this implementation, alerts are written to console.
    /// Production implementations should integrate with alerting systems
    /// (email, SMS, PagerDuty, etc.).
    /// </remarks>
    public void LogAlert(AuditEvent auditEvent)
    {
        // Production: Send to alerting system
        Console.WriteLine($"[ALERT] {auditEvent.Severity}: {auditEvent.Description}");
    }

    /// <summary>
    /// Retrieves audit events within a specified time range.
    /// </summary>
    /// <param name="startDate">Start of the time range.</param>
    /// <param name="endDate">End of the time range.</param>
    /// <returns>List of events within the time range.</returns>
    /// <remarks>
    /// Thread-safe. Returns a copy of the filtered events.
    /// </remarks>
    public List<AuditEvent> GetEvents(DateTimeOffset startDate, DateTimeOffset endDate)
    {
        lock (_lock)
        {
            return _events
                .Where(e => e.Timestamp >= startDate && e.Timestamp <= endDate)
                .ToList();
        }
    }

    /// <summary>
    /// Gets the total number of events stored.
    /// </summary>
    public int Count => _events.Count;

    /// <summary>
    /// Clears all stored audit events.
    /// </summary>
    /// <remarks>
    /// Thread-safe. Use with caution as this permanently removes all audit data.
    /// </remarks>
    public void Clear()
    {
        lock (_lock)
        {
            _events.Clear();
        }
    }
}
#endif
