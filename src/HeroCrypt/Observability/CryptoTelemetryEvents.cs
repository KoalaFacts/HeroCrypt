namespace HeroCrypt.Observability;

/// <summary>
/// Event arguments for crypto operation events
/// </summary>
public class CryptoOperationEvent : EventArgs
{
    /// <summary>
    /// Unique operation identifier
    /// </summary>
    public string OperationId { get; set; } = string.Empty;

    /// <summary>
    /// Type of cryptographic operation
    /// </summary>
    public string OperationType { get; set; } = string.Empty;

    /// <summary>
    /// Algorithm used for the operation
    /// </summary>
    public string AlgorithmUsed { get; set; } = string.Empty;

    /// <summary>
    /// Timestamp when operation occurred
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Size of data being processed (in bytes)
    /// </summary>
    public long DataSize { get; set; }

    /// <summary>
    /// Whether hardware acceleration was used
    /// </summary>
    public bool HardwareAccelerated { get; set; }

    /// <summary>
    /// Duration of the operation (set when operation completes)
    /// </summary>
    public TimeSpan Duration { get; set; }

    /// <summary>
    /// Whether the operation was successful
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Error message if operation failed
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Additional context or metadata
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new();
}

/// <summary>
/// Event arguments for security audit events
/// </summary>
public class SecurityAuditEvent : EventArgs
{
    /// <summary>
    /// Unique event identifier
    /// </summary>
    public string EventId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Type of security event
    /// </summary>
    public SecurityEventType EventType { get; set; }

    /// <summary>
    /// Severity level of the event
    /// </summary>
    public SecuritySeverity Severity { get; set; }

    /// <summary>
    /// Timestamp of the event
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Component that generated the event
    /// </summary>
    public string Component { get; set; } = string.Empty;

    /// <summary>
    /// Event description
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Related operation ID if applicable
    /// </summary>
    public string? RelatedOperationId { get; set; }

    /// <summary>
    /// Additional event data
    /// </summary>
    public Dictionary<string, object> Data { get; set; } = new();
}

/// <summary>
/// Types of security events
/// </summary>
public enum SecurityEventType
{
    /// <summary>
    /// Configuration change
    /// </summary>
    ConfigurationChange,

    /// <summary>
    /// Security policy violation
    /// </summary>
    PolicyViolation,

    /// <summary>
    /// Unusual pattern detected
    /// </summary>
    AnomalyDetected,

    /// <summary>
    /// Hardware change detected
    /// </summary>
    HardwareChange,

    /// <summary>
    /// Key lifecycle event
    /// </summary>
    KeyLifecycle,

    /// <summary>
    /// Access control event
    /// </summary>
    AccessControl,

    /// <summary>
    /// Performance degradation
    /// </summary>
    PerformanceDegradation
}

/// <summary>
/// Security event severity levels
/// </summary>
public enum SecuritySeverity
{
    /// <summary>
    /// Informational event
    /// </summary>
    Info = 0,

    /// <summary>
    /// Low severity event
    /// </summary>
    Low = 1,

    /// <summary>
    /// Medium severity event
    /// </summary>
    Medium = 2,

    /// <summary>
    /// High severity event
    /// </summary>
    High = 3,

    /// <summary>
    /// Critical security event
    /// </summary>
    Critical = 4
}

/// <summary>
/// Health metrics for the crypto system
/// </summary>
public class HealthMetrics
{
    /// <summary>
    /// Total number of operations performed
    /// </summary>
    public long TotalOperations { get; set; }

    /// <summary>
    /// Number of successful operations
    /// </summary>
    public long SuccessfulOperations { get; set; }

    /// <summary>
    /// Number of failed operations
    /// </summary>
    public long FailedOperations { get; set; }

    /// <summary>
    /// Average operation duration
    /// </summary>
    public TimeSpan AverageOperationDuration { get; set; }

    /// <summary>
    /// Operations performed in the last minute
    /// </summary>
    public long OperationsPerMinute { get; set; }

    /// <summary>
    /// Current memory usage
    /// </summary>
    public long MemoryUsageBytes { get; set; }

    /// <summary>
    /// Hardware acceleration usage percentage
    /// </summary>
    public double HardwareAccelerationUsage { get; set; }

    /// <summary>
    /// System uptime
    /// </summary>
    public TimeSpan Uptime { get; set; }

    /// <summary>
    /// Last health check timestamp
    /// </summary>
    public DateTime LastHealthCheck { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// System load factors
    /// </summary>
    public Dictionary<string, double> LoadFactors { get; set; } = new();

    /// <summary>
    /// Overall health status
    /// </summary>
    public HealthStatus Status { get; set; }
}

/// <summary>
/// Overall health status
/// </summary>
public enum HealthStatus
{
    /// <summary>
    /// System is healthy
    /// </summary>
    Healthy,

    /// <summary>
    /// System is degraded but functional
    /// </summary>
    Degraded,

    /// <summary>
    /// System is unhealthy
    /// </summary>
    Unhealthy,

    /// <summary>
    /// System status is unknown
    /// </summary>
    Unknown
}

/// <summary>
/// Performance metrics for specific operations
/// </summary>
public class OperationMetrics
{
    /// <summary>
    /// Operation type
    /// </summary>
    public string OperationType { get; set; } = string.Empty;

    /// <summary>
    /// Algorithm used
    /// </summary>
    public string Algorithm { get; set; } = string.Empty;

    /// <summary>
    /// Total count of this operation type
    /// </summary>
    public long Count { get; set; }

    /// <summary>
    /// Average duration for this operation
    /// </summary>
    public TimeSpan AverageDuration { get; set; }

    /// <summary>
    /// Minimum duration recorded
    /// </summary>
    public TimeSpan MinDuration { get; set; }

    /// <summary>
    /// Maximum duration recorded
    /// </summary>
    public TimeSpan MaxDuration { get; set; }

    /// <summary>
    /// Standard deviation of durations
    /// </summary>
    public TimeSpan StandardDeviation { get; set; }

    /// <summary>
    /// Success rate percentage (0-100)
    /// </summary>
    public double SuccessRate { get; set; }

    /// <summary>
    /// Throughput (operations per second)
    /// </summary>
    public double Throughput { get; set; }

    /// <summary>
    /// Hardware acceleration usage for this operation
    /// </summary>
    public double HardwareAccelerationUsage { get; set; }
}