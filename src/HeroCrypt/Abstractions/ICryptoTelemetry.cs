using HeroCrypt.Observability;

namespace HeroCrypt.Abstractions;

/// <summary>
/// Interface for cryptographic telemetry and observability
/// </summary>
public interface ICryptoTelemetry
{
    /// <summary>
    /// Fired when a cryptographic operation starts
    /// </summary>
    event EventHandler<CryptoOperationEvent> OperationStarted;

    /// <summary>
    /// Fired when a cryptographic operation completes (success or failure)
    /// </summary>
    event EventHandler<CryptoOperationEvent> OperationCompleted;

    /// <summary>
    /// Fired when a security-related event occurs
    /// </summary>
    event EventHandler<SecurityAuditEvent> SecurityEventOccurred;

    /// <summary>
    /// Records the start of a cryptographic operation
    /// </summary>
    /// <param name="operationType">Type of operation</param>
    /// <param name="algorithm">Algorithm being used</param>
    /// <param name="dataSize">Size of data being processed</param>
    /// <param name="hardwareAccelerated">Whether hardware acceleration is used</param>
    /// <param name="metadata">Additional metadata</param>
    /// <returns>Operation ID for tracking</returns>
    string StartOperation(
        string operationType,
        string algorithm,
        long dataSize,
        bool hardwareAccelerated = false,
        Dictionary<string, object>? metadata = null);

    /// <summary>
    /// Records the completion of a cryptographic operation
    /// </summary>
    /// <param name="operationId">Operation ID from StartOperation</param>
    /// <param name="success">Whether operation succeeded</param>
    /// <param name="errorMessage">Error message if failed</param>
    void CompleteOperation(string operationId, bool success, string? errorMessage = null);

    /// <summary>
    /// Records a security audit event
    /// </summary>
    /// <param name="eventType">Type of security event</param>
    /// <param name="severity">Event severity</param>
    /// <param name="component">Component generating the event</param>
    /// <param name="description">Event description</param>
    /// <param name="relatedOperationId">Related operation ID if applicable</param>
    /// <param name="data">Additional event data</param>
    void RecordSecurityEvent(
        SecurityEventType eventType,
        SecuritySeverity severity,
        string component,
        string description,
        string? relatedOperationId = null,
        Dictionary<string, object>? data = null);

    /// <summary>
    /// Gets current health metrics for the system
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Current health metrics</returns>
    Task<HealthMetrics> GetHealthMetricsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets performance metrics for specific operations
    /// </summary>
    /// <param name="operationType">Optional filter by operation type</param>
    /// <param name="timeWindow">Time window for metrics</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Operation metrics</returns>
    Task<IEnumerable<OperationMetrics>> GetOperationMetricsAsync(
        string? operationType = null,
        TimeSpan? timeWindow = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets security events within a time window
    /// </summary>
    /// <param name="timeWindow">Time window to search</param>
    /// <param name="severityFilter">Optional severity filter</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Security events</returns>
    Task<IEnumerable<SecurityAuditEvent>> GetSecurityEventsAsync(
        TimeSpan timeWindow,
        SecuritySeverity? severityFilter = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Clears old telemetry data beyond retention period
    /// </summary>
    /// <param name="retentionPeriod">Data retention period</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Number of records cleaned up</returns>
    Task<long> CleanupOldDataAsync(TimeSpan retentionPeriod, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exports telemetry data for external analysis
    /// </summary>
    /// <param name="format">Export format</param>
    /// <param name="timeWindow">Time window for export</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Exported data</returns>
    Task<byte[]> ExportTelemetryDataAsync(
        TelemetryExportFormat format,
        TimeSpan timeWindow,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Telemetry export formats
/// </summary>
public enum TelemetryExportFormat
{
    /// <summary>
    /// JSON format
    /// </summary>
    Json,

    /// <summary>
    /// CSV format
    /// </summary>
    Csv,

    /// <summary>
    /// XML format
    /// </summary>
    Xml,

    /// <summary>
    /// Binary format (compact)
    /// </summary>
    Binary
}

/// <summary>
/// Extension methods for simplified telemetry usage
/// </summary>
public static class TelemetryExtensions
{
    /// <summary>
    /// Creates a scoped operation tracker that automatically completes on disposal
    /// </summary>
    /// <param name="telemetry">Telemetry instance</param>
    /// <param name="operationType">Operation type</param>
    /// <param name="algorithm">Algorithm</param>
    /// <param name="dataSize">Data size</param>
    /// <param name="hardwareAccelerated">Hardware acceleration flag</param>
    /// <returns>Disposable operation tracker</returns>
    public static IOperationTracker TrackOperation(
        this ICryptoTelemetry telemetry,
        string operationType,
        string algorithm,
        long dataSize,
        bool hardwareAccelerated = false)
    {
        return new OperationTracker(telemetry, operationType, algorithm, dataSize, hardwareAccelerated);
    }
}

/// <summary>
/// Tracks a crypto operation and automatically completes it on disposal
/// </summary>
public interface IOperationTracker : IDisposable
{
    /// <summary>
    /// Operation ID
    /// </summary>
    string OperationId { get; }

    /// <summary>
    /// Marks the operation as successful
    /// </summary>
    void MarkSuccess();

    /// <summary>
    /// Marks the operation as failed
    /// </summary>
    /// <param name="errorMessage">Error message</param>
    void MarkFailure(string errorMessage);

    /// <summary>
    /// Adds metadata to the operation
    /// </summary>
    /// <param name="key">Metadata key</param>
    /// <param name="value">Metadata value</param>
    void AddMetadata(string key, object value);
}

/// <summary>
/// Internal implementation of operation tracker
/// </summary>
internal sealed class OperationTracker : IOperationTracker
{
    private readonly ICryptoTelemetry _telemetry;
    private bool _completed;
    private bool _success = true;
    private string? _errorMessage;

    public string OperationId { get; }

    public OperationTracker(
        ICryptoTelemetry telemetry,
        string operationType,
        string algorithm,
        long dataSize,
        bool hardwareAccelerated)
    {
        _telemetry = telemetry;
        OperationId = telemetry.StartOperation(operationType, algorithm, dataSize, hardwareAccelerated);
    }

    public void MarkSuccess()
    {
        _success = true;
        _errorMessage = null;
    }

    public void MarkFailure(string errorMessage)
    {
        _success = false;
        _errorMessage = errorMessage;
    }

    public void AddMetadata(string key, object value)
    {
        // Implementation would store metadata for later use
    }

    public void Dispose()
    {
        if (!_completed)
        {
            _telemetry.CompleteOperation(OperationId, _success, _errorMessage);
            _completed = true;
        }
    }
}