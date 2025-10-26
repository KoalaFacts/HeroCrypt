using HeroCrypt.Abstractions;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

namespace HeroCrypt.Observability;

/// <summary>
/// Default implementation of crypto telemetry
/// </summary>
public sealed class DefaultCryptoTelemetry : ICryptoTelemetry
{
    private readonly ConcurrentDictionary<string, CryptoOperationEvent> _activeOperations = new();
    private readonly ConcurrentQueue<CryptoOperationEvent> _completedOperations = new();
    private readonly ConcurrentQueue<SecurityAuditEvent> _securityEvents = new();

    // Metrics tracking
    private long _totalOperations;
    private long _successfulOperations;
    private long _failedOperations;
    private readonly ConcurrentDictionary<string, OperationMetrics> _operationMetrics = new();
    private readonly DateTime _startTime = DateTime.UtcNow;

    // Events
    public event EventHandler<CryptoOperationEvent>? OperationStarted;
    public event EventHandler<CryptoOperationEvent>? OperationCompleted;
    public event EventHandler<SecurityAuditEvent>? SecurityEventOccurred;

    public string StartOperation(
        string operationType,
        string algorithm,
        long dataSize,
        bool hardwareAccelerated = false,
        Dictionary<string, object>? metadata = null)
    {
        var operationId = Guid.NewGuid().ToString();
        var operationEvent = new CryptoOperationEvent
        {
            OperationId = operationId,
            OperationType = operationType,
            AlgorithmUsed = algorithm,
            DataSize = dataSize,
            HardwareAccelerated = hardwareAccelerated,
            Timestamp = DateTime.UtcNow,
            Metadata = metadata ?? new Dictionary<string, object>()
        };

        _activeOperations.TryAdd(operationId, operationEvent);

        // Fire event
        OperationStarted?.Invoke(this, operationEvent);

        // Update metrics
        Interlocked.Increment(ref _totalOperations);

        return operationId;
    }

    public void CompleteOperation(string operationId, bool success, string? errorMessage = null)
    {
        if (_activeOperations.TryRemove(operationId, out var operationEvent))
        {
            operationEvent.Duration = DateTime.UtcNow - operationEvent.Timestamp;
            operationEvent.Success = success;
            operationEvent.ErrorMessage = errorMessage;

            // Update completion metrics
            if (success)
            {
                Interlocked.Increment(ref _successfulOperations);
            }
            else
            {
                Interlocked.Increment(ref _failedOperations);
            }

            // Store completed operation
            _completedOperations.Enqueue(operationEvent);

            // Update operation-specific metrics
            UpdateOperationMetrics(operationEvent);

            // Fire event
            OperationCompleted?.Invoke(this, operationEvent);
        }
    }

    public void RecordSecurityEvent(
        SecurityEventType eventType,
        SecuritySeverity severity,
        string component,
        string description,
        string? relatedOperationId = null,
        Dictionary<string, object>? data = null)
    {
        var securityEvent = new SecurityAuditEvent
        {
            EventType = eventType,
            Severity = severity,
            Component = component,
            Description = description,
            RelatedOperationId = relatedOperationId,
            Data = data ?? []
        };

        _securityEvents.Enqueue(securityEvent);

        // Fire event
        SecurityEventOccurred?.Invoke(this, securityEvent);

        // Log high-severity events immediately
        if (severity >= SecuritySeverity.High)
        {
            Debug.WriteLine($"[SECURITY] {severity}: {description} in {component}");
        }
    }

    public async Task<HealthMetrics> GetHealthMetricsAsync(CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask; // Placeholder for any async operations

        var totalOps = _totalOperations;
        var successOps = _successfulOperations;
        var failedOps = _failedOperations;

        var uptime = DateTime.UtcNow - _startTime;
        var opsPerMinute = totalOps > 0 ? (long)(totalOps / uptime.TotalMinutes) : 0;

        // Calculate average duration from recent operations
        var recentOperations = GetRecentOperations(TimeSpan.FromMinutes(5));
        var avgDuration = recentOperations.Any()
            ? TimeSpan.FromMilliseconds(recentOperations.Average(op => op.Duration.TotalMilliseconds))
            : TimeSpan.Zero;

        // Calculate hardware acceleration usage
        var hardwareAccelUsage = recentOperations.Any()
            ? recentOperations.Count(op => op.HardwareAccelerated) / (double)recentOperations.Count() * 100
            : 0;

        // Determine health status
        var healthStatus = DetermineHealthStatus(successOps, failedOps, uptime);

        return new HealthMetrics
        {
            TotalOperations = totalOps,
            SuccessfulOperations = successOps,
            FailedOperations = failedOps,
            AverageOperationDuration = avgDuration,
            OperationsPerMinute = opsPerMinute,
            MemoryUsageBytes = GC.GetTotalMemory(false),
            HardwareAccelerationUsage = hardwareAccelUsage,
            Uptime = uptime,
            Status = healthStatus,
            LoadFactors = new Dictionary<string, double>
            {
                ["cpu_utilization"] = GetCpuUtilization(),
                ["memory_pressure"] = GetMemoryPressure(),
                ["operation_queue_depth"] = _activeOperations.Count
            }
        };
    }

    public async Task<IEnumerable<OperationMetrics>> GetOperationMetricsAsync(
        string? operationType = null,
        TimeSpan? timeWindow = null,
        CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask; // Placeholder for any async operations

        var metrics = _operationMetrics.Values.ToList();

        if (!string.IsNullOrEmpty(operationType))
        {
            metrics = metrics.Where(m => m.OperationType.Equals(operationType, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        return metrics;
    }

    public async Task<IEnumerable<SecurityAuditEvent>> GetSecurityEventsAsync(
        TimeSpan timeWindow,
        SecuritySeverity? severityFilter = null,
        CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask; // Placeholder for any async operations

        var cutoffTime = DateTime.UtcNow - timeWindow;
        var events = new List<SecurityAuditEvent>();

        // Drain queue and filter events
        while (_securityEvents.TryDequeue(out var securityEvent))
        {
            if (securityEvent.Timestamp >= cutoffTime)
            {
                if (severityFilter == null || securityEvent.Severity >= severityFilter.Value)
                {
                    events.Add(securityEvent);
                }
            }
        }

        return events.OrderByDescending(e => e.Timestamp);
    }

    public async Task<long> CleanupOldDataAsync(TimeSpan retentionPeriod, CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask; // Placeholder for any async operations

        var cutoffTime = DateTime.UtcNow - retentionPeriod;
        long cleanedCount = 0;

        // Clean up completed operations
        var tempList = new List<CryptoOperationEvent>();
        while (_completedOperations.TryDequeue(out var operation))
        {
            if (operation.Timestamp >= cutoffTime)
            {
                tempList.Add(operation);
            }
            else
            {
                cleanedCount++;
            }
        }

        // Re-enqueue recent operations
        foreach (var operation in tempList)
        {
            _completedOperations.Enqueue(operation);
        }

        // Clean up security events
        var tempSecurityEvents = new List<SecurityAuditEvent>();
        while (_securityEvents.TryDequeue(out var securityEvent))
        {
            if (securityEvent.Timestamp >= cutoffTime)
            {
                tempSecurityEvents.Add(securityEvent);
            }
            else
            {
                cleanedCount++;
            }
        }

        // Re-enqueue recent events
        foreach (var securityEvent in tempSecurityEvents)
        {
            _securityEvents.Enqueue(securityEvent);
        }

        return cleanedCount;
    }

    public async Task<byte[]> ExportTelemetryDataAsync(
        TelemetryExportFormat format,
        TimeSpan timeWindow,
        CancellationToken cancellationToken = default)
    {
        // Collect data within time window
        var operations = GetRecentOperations(timeWindow).ToList();
        var securityEvents = (await GetSecurityEventsAsync(timeWindow, cancellationToken: cancellationToken)).ToList();

        var exportData = new
        {
            ExportTimestamp = DateTime.UtcNow,
            TimeWindow = timeWindow.ToString(),
            Operations = operations,
            SecurityEvents = securityEvents,
            Metrics = await GetOperationMetricsAsync(cancellationToken: cancellationToken)
        };

        return format switch
        {
            TelemetryExportFormat.Json => JsonSerializer.SerializeToUtf8Bytes(exportData, new JsonSerializerOptions
            {
                WriteIndented = true
            }),
            TelemetryExportFormat.Csv => throw new NotSupportedException(
                "CSV export format is not yet implemented. Use TelemetryExportFormat.Json for now. " +
                "Future implementation will provide comma-separated values with headers for metrics data."),
            TelemetryExportFormat.Xml => throw new NotSupportedException(
                "XML export format is not yet implemented. Use TelemetryExportFormat.Json for now. " +
                "Future implementation will provide XML serialization of telemetry data."),
            TelemetryExportFormat.Binary => throw new NotSupportedException(
                "Binary export format is not yet implemented. Use TelemetryExportFormat.Json for now. " +
                "Future implementation will provide compact binary serialization using MessagePack or Protocol Buffers."),
            _ => throw new ArgumentException($"Unsupported export format: {format}")
        };
    }

    private void UpdateOperationMetrics(CryptoOperationEvent operationEvent)
    {
        var key = $"{operationEvent.OperationType}:{operationEvent.AlgorithmUsed}";

        _operationMetrics.AddOrUpdate(key,
            // Add new metric
            new OperationMetrics
            {
                OperationType = operationEvent.OperationType,
                Algorithm = operationEvent.AlgorithmUsed,
                Count = 1,
                AverageDuration = operationEvent.Duration,
                MinDuration = operationEvent.Duration,
                MaxDuration = operationEvent.Duration,
                SuccessRate = operationEvent.Success ? 100.0 : 0.0,
                Throughput = 1.0 / operationEvent.Duration.TotalSeconds,
                HardwareAccelerationUsage = operationEvent.HardwareAccelerated ? 100.0 : 0.0
            },
            // Update existing metric
            (_, existing) =>
            {
                var newCount = existing.Count + 1;
                var successCount = (long)(existing.SuccessRate / 100.0 * existing.Count) + (operationEvent.Success ? 1 : 0);
                var hardwareCount = (long)(existing.HardwareAccelerationUsage / 100.0 * existing.Count) + (operationEvent.HardwareAccelerated ? 1 : 0);

                // Calculate new average duration
                var totalMs = existing.AverageDuration.TotalMilliseconds * existing.Count + operationEvent.Duration.TotalMilliseconds;
                var newAvgMs = totalMs / newCount;

                return new OperationMetrics
                {
                    OperationType = existing.OperationType,
                    Algorithm = existing.Algorithm,
                    Count = newCount,
                    AverageDuration = TimeSpan.FromMilliseconds(newAvgMs),
                    MinDuration = operationEvent.Duration < existing.MinDuration ? operationEvent.Duration : existing.MinDuration,
                    MaxDuration = operationEvent.Duration > existing.MaxDuration ? operationEvent.Duration : existing.MaxDuration,
                    SuccessRate = (successCount / (double)newCount) * 100.0,
                    Throughput = 1.0 / TimeSpan.FromMilliseconds(newAvgMs).TotalSeconds,
                    HardwareAccelerationUsage = (hardwareCount / (double)newCount) * 100.0
                };
            });
    }

    private IEnumerable<CryptoOperationEvent> GetRecentOperations(TimeSpan timeWindow)
    {
        var cutoffTime = DateTime.UtcNow - timeWindow;
        var operations = new List<CryptoOperationEvent>();

        // Get from completed operations queue
        var tempList = new List<CryptoOperationEvent>();
        while (_completedOperations.TryDequeue(out var operation))
        {
            tempList.Add(operation);
            if (operation.Timestamp >= cutoffTime)
            {
                operations.Add(operation);
            }
        }

        // Re-enqueue all operations
        foreach (var operation in tempList)
        {
            _completedOperations.Enqueue(operation);
        }

        return operations;
    }

    private static HealthStatus DetermineHealthStatus(long successOps, long failedOps, TimeSpan uptime)
    {
        var totalOps = successOps + failedOps;

        if (totalOps == 0)
            return HealthStatus.Unknown;

        var successRate = successOps / (double)totalOps;

        if (successRate >= 0.99)
            return HealthStatus.Healthy;

        if (successRate >= 0.95)
            return HealthStatus.Degraded;

        return HealthStatus.Unhealthy;
    }

    private static double GetCpuUtilization()
    {
        // Placeholder - would integrate with system monitoring
        return 0.0;
    }

    private static double GetMemoryPressure()
    {
        // Simple memory pressure calculation
        var totalMemory = GC.GetTotalMemory(false);
        return Math.Min(100.0, (totalMemory / (1024.0 * 1024.0 * 100.0)) * 100.0); // Normalize to percentage
    }
}
