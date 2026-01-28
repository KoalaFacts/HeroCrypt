using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace HeroCrypt.Security;

/// <summary>
/// Provides cryptographic operation auditing and deprecation warning infrastructure.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CryptoAudit"/> enables tracking of cryptographic operations for security
/// auditing, compliance monitoring, and deprecation management.
/// </para>
/// <para>
/// <b>Features:</b>
/// <list type="bullet">
///   <item>Operation logging for encryption, hashing, signing, and key derivation</item>
///   <item>Deprecation warnings for legacy algorithms</item>
///   <item>Weak algorithm detection and alerting</item>
///   <item>Thread-safe event dispatching</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Subscribe to audit events
/// CryptoAudit.OnCryptoOperation += (sender, e) =>
/// {
///     logger.LogInformation("Crypto: {Operation} using {Algorithm}", e.Operation, e.Algorithm);
/// };
///
/// // Subscribe to deprecation warnings
/// CryptoAudit.OnDeprecationWarning += (sender, e) =>
/// {
///     logger.LogWarning("Deprecated: {Algorithm}. Use {Alternative}", e.Algorithm, e.Alternative);
/// };
///
/// // Subscribe to weak algorithm alerts
/// CryptoAudit.OnWeakAlgorithmUsed += (sender, e) =>
/// {
///     logger.LogError("Weak algorithm: {Algorithm}. {Reason}", e.Algorithm, e.Reason);
/// };
/// </code>
/// </example>
public static class CryptoAudit
{
    private static readonly AsyncLocal<bool?> AuditEnabledState = new();
    private static readonly ConcurrentDictionary<string, DateTime> DeprecationWarningsEmitted = new();
    private static readonly TimeSpan WarningCooldown = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets whether auditing is enabled.
    /// </summary>
    /// <remarks>
    /// When disabled, no events are raised and overhead is minimized.
    /// Default is <c>false</c>.
    /// </remarks>
    public static bool Enabled
    {
        get => AuditEnabledState.Value ?? false;
        set => AuditEnabledState.Value = value;
    }

    /// <summary>
    /// Occurs when a cryptographic operation is performed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This event fires for all cryptographic operations when auditing is enabled.
    /// Use for compliance logging and security monitoring.
    /// </para>
    /// <para>
    /// <b>Important:</b> Event handlers should be fast and non-blocking to avoid
    /// impacting cryptographic operation performance.
    /// </para>
    /// </remarks>
    public static event EventHandler<CryptoOperationEventArgs>? OnCryptoOperation;

    /// <summary>
    /// Occurs when a deprecated algorithm is used.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This event fires when algorithms marked as deprecated are used.
    /// Deprecation warnings are rate-limited to avoid log flooding.
    /// </para>
    /// </remarks>
    public static event EventHandler<DeprecationWarningEventArgs>? OnDeprecationWarning;

    /// <summary>
    /// Occurs when a weak or insecure algorithm is used.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This event fires for algorithms with known security weaknesses.
    /// Unlike deprecation warnings, weak algorithm alerts are always emitted.
    /// </para>
    /// </remarks>
    public static event EventHandler<WeakAlgorithmEventArgs>? OnWeakAlgorithmUsed;

    /// <summary>
    /// Logs a cryptographic operation.
    /// </summary>
    /// <param name="operation">The type of operation (e.g., "Encrypt", "Hash", "Sign").</param>
    /// <param name="algorithm">The algorithm used.</param>
    /// <param name="keySizeBits">Optional key size in bits.</param>
    /// <param name="inputSizeBytes">Optional input data size in bytes.</param>
    /// <param name="callerMemberName">Automatically populated caller member name.</param>
    /// <param name="callerFilePath">Automatically populated caller file path.</param>
    public static void LogOperation(
        string operation,
        string algorithm,
        int? keySizeBits = null,
        long? inputSizeBytes = null,
        [CallerMemberName] string callerMemberName = "",
        [CallerFilePath] string callerFilePath = "")
    {
        if (!Enabled || OnCryptoOperation == null)
        {
            return;
        }

        var eventArgs = new CryptoOperationEventArgs(
            operation,
            algorithm,
            keySizeBits,
            inputSizeBytes,
            DateTime.UtcNow,
            callerMemberName,
            callerFilePath);

        OnCryptoOperation?.Invoke(null, eventArgs);
    }

    /// <summary>
    /// Emits a deprecation warning for a legacy algorithm.
    /// </summary>
    /// <param name="algorithm">The deprecated algorithm.</param>
    /// <param name="alternative">The recommended alternative.</param>
    /// <param name="removalDate">Optional planned removal date.</param>
    /// <remarks>
    /// Warnings are rate-limited to one per algorithm per 5-minute window.
    /// </remarks>
    public static void WarnDeprecated(string algorithm, string alternative, DateTime? removalDate = null)
    {
        if (OnDeprecationWarning == null)
        {
            return;
        }

        // Rate-limit warnings
        var key = algorithm.ToUpperInvariant();
        var now = DateTime.UtcNow;

        if (DeprecationWarningsEmitted.TryGetValue(key, out var lastWarning))
        {
            if (now - lastWarning < WarningCooldown)
            {
                return; // Skip, within cooldown period
            }
        }

        DeprecationWarningsEmitted[key] = now;

        var eventArgs = new DeprecationWarningEventArgs(algorithm, alternative, removalDate);
        OnDeprecationWarning?.Invoke(null, eventArgs);
    }

    /// <summary>
    /// Alerts about use of a weak or insecure algorithm.
    /// </summary>
    /// <param name="algorithm">The weak algorithm.</param>
    /// <param name="reason">The reason it's considered weak.</param>
    /// <param name="alternative">The recommended alternative.</param>
    /// <param name="severity">The severity level.</param>
    public static void AlertWeakAlgorithm(
        string algorithm,
        string reason,
        string alternative,
        WeakAlgorithmSeverity severity = WeakAlgorithmSeverity.Warning)
    {
        if (OnWeakAlgorithmUsed == null)
        {
            return;
        }

        var eventArgs = new WeakAlgorithmEventArgs(algorithm, reason, alternative, severity);
        OnWeakAlgorithmUsed?.Invoke(null, eventArgs);
    }

    /// <summary>
    /// Checks an algorithm and emits appropriate warnings if deprecated or weak.
    /// </summary>
    /// <param name="algorithm">The algorithm to check.</param>
    public static void CheckAlgorithm(string algorithm)
    {
        var normalizedAlgorithm = algorithm.ToUpperInvariant();

        // Check for weak/broken algorithms
        switch (normalizedAlgorithm)
        {
            case "MD5":
                AlertWeakAlgorithm(
                    algorithm,
                    "MD5 has trivial collision attacks. Do not use for security purposes.",
                    "SHA-256",
                    WeakAlgorithmSeverity.Critical);
                WarnDeprecated(algorithm, "SHA-256", new DateTime(2027, 1, 1));
                break;

            case "SHA1":
            case "SHA-1":
                AlertWeakAlgorithm(
                    algorithm,
                    "SHA-1 has practical collision attacks (SHAttered, 2017).",
                    "SHA-256",
                    WeakAlgorithmSeverity.High);
                WarnDeprecated(algorithm, "SHA-256", new DateTime(2027, 1, 1));
                break;

            case "3DES":
            case "TRIPLEDES":
            case "DES-EDE":
                AlertWeakAlgorithm(
                    algorithm,
                    "3DES has 64-bit block size vulnerable to Sweet32 attack. NIST disallowed after 2023.",
                    "AES-256",
                    WeakAlgorithmSeverity.High);
                WarnDeprecated(algorithm, "AES-256", new DateTime(2028, 1, 1));
                break;

            case "BLOWFISH":
                AlertWeakAlgorithm(
                    algorithm,
                    "Blowfish has 64-bit block size and weak key schedule.",
                    "AES-256 or ChaCha20-Poly1305",
                    WeakAlgorithmSeverity.Warning);
                WarnDeprecated(algorithm, "AES-256", new DateTime(2028, 1, 1));
                break;

            case "CAST5":
                AlertWeakAlgorithm(
                    algorithm,
                    "CAST5 has 64-bit block size.",
                    "AES-256",
                    WeakAlgorithmSeverity.Warning);
                WarnDeprecated(algorithm, "AES-256", new DateTime(2028, 1, 1));
                break;

            case "IDEA":
                AlertWeakAlgorithm(
                    algorithm,
                    "IDEA has 64-bit block size.",
                    "AES-256",
                    WeakAlgorithmSeverity.Warning);
                WarnDeprecated(algorithm, "AES-256", new DateTime(2028, 1, 1));
                break;

            case "RC4":
                AlertWeakAlgorithm(
                    algorithm,
                    "RC4 is completely broken with multiple practical attacks.",
                    "ChaCha20-Poly1305 or AES-GCM",
                    WeakAlgorithmSeverity.Critical);
                break;

            case "DES":
                AlertWeakAlgorithm(
                    algorithm,
                    "DES has 56-bit key size, trivially breakable.",
                    "AES-256",
                    WeakAlgorithmSeverity.Critical);
                break;

            case "PBKDF2-SHA1":
                WarnDeprecated(algorithm, "PBKDF2-SHA256", new DateTime(2028, 1, 1));
                break;

            default:
                // Algorithm is not in the weak/deprecated list - no action needed
                break;
        }
    }

    /// <summary>
    /// Clears all cached deprecation warning timestamps.
    /// Useful for testing.
    /// </summary>
    public static void ClearWarningCache()
    {
        DeprecationWarningsEmitted.Clear();
    }
}

/// <summary>
/// Event arguments for cryptographic operation auditing.
/// </summary>
public class CryptoOperationEventArgs : EventArgs
{
    /// <summary>
    /// Gets the type of operation (e.g., "Encrypt", "Decrypt", "Hash", "Sign", "Verify").
    /// </summary>
    public string Operation { get; }

    /// <summary>
    /// Gets the algorithm used.
    /// </summary>
    public string Algorithm { get; }

    /// <summary>
    /// Gets the key size in bits, if applicable.
    /// </summary>
    public int? KeySizeBits { get; }

    /// <summary>
    /// Gets the input data size in bytes, if applicable.
    /// </summary>
    public long? InputSizeBytes { get; }

    /// <summary>
    /// Gets the timestamp of the operation.
    /// </summary>
    public DateTime Timestamp { get; }

    /// <summary>
    /// Gets the caller member name.
    /// </summary>
    public string CallerMemberName { get; }

    /// <summary>
    /// Gets the caller file path.
    /// </summary>
    public string CallerFilePath { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="CryptoOperationEventArgs"/>.
    /// </summary>
    public CryptoOperationEventArgs(
        string operation,
        string algorithm,
        int? keySizeBits,
        long? inputSizeBytes,
        DateTime timestamp,
        string callerMemberName,
        string callerFilePath)
    {
        Operation = operation;
        Algorithm = algorithm;
        KeySizeBits = keySizeBits;
        InputSizeBytes = inputSizeBytes;
        Timestamp = timestamp;
        CallerMemberName = callerMemberName;
        CallerFilePath = callerFilePath;
    }

    /// <inheritdoc />
    public override string ToString()
    {
        var keyInfo = KeySizeBits.HasValue ? $", {KeySizeBits}bits" : "";
        var sizeInfo = InputSizeBytes.HasValue ? $", {InputSizeBytes}bytes" : "";
        return $"[{Timestamp:O}] {Operation}: {Algorithm}{keyInfo}{sizeInfo}";
    }
}

/// <summary>
/// Event arguments for deprecation warnings.
/// </summary>
public class DeprecationWarningEventArgs : EventArgs
{
    /// <summary>
    /// Gets the deprecated algorithm.
    /// </summary>
    public string Algorithm { get; }

    /// <summary>
    /// Gets the recommended alternative.
    /// </summary>
    public string Alternative { get; }

    /// <summary>
    /// Gets the planned removal date, if known.
    /// </summary>
    public DateTime? RemovalDate { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="DeprecationWarningEventArgs"/>.
    /// </summary>
    public DeprecationWarningEventArgs(string algorithm, string alternative, DateTime? removalDate)
    {
        Algorithm = algorithm;
        Alternative = alternative;
        RemovalDate = removalDate;
    }

    /// <inheritdoc />
    public override string ToString()
    {
        var removalInfo = RemovalDate.HasValue ? $" Removal planned for {RemovalDate:yyyy-MM-dd}." : "";
        return $"Warning: '{Algorithm}' is deprecated. Use '{Alternative}' instead.{removalInfo}";
    }
}

/// <summary>
/// Event arguments for weak algorithm alerts.
/// </summary>
public class WeakAlgorithmEventArgs : EventArgs
{
    /// <summary>
    /// Gets the weak algorithm.
    /// </summary>
    public string Algorithm { get; }

    /// <summary>
    /// Gets the reason the algorithm is considered weak.
    /// </summary>
    public string Reason { get; }

    /// <summary>
    /// Gets the recommended alternative.
    /// </summary>
    public string Alternative { get; }

    /// <summary>
    /// Gets the severity level.
    /// </summary>
    public WeakAlgorithmSeverity Severity { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="WeakAlgorithmEventArgs"/>.
    /// </summary>
    public WeakAlgorithmEventArgs(
        string algorithm,
        string reason,
        string alternative,
        WeakAlgorithmSeverity severity)
    {
        Algorithm = algorithm;
        Reason = reason;
        Alternative = alternative;
        Severity = severity;
    }

    /// <inheritdoc />
    public override string ToString()
    {
        return $"[{Severity}] {Algorithm}: {Reason} Use '{Alternative}' instead.";
    }
}

/// <summary>
/// Severity levels for weak algorithm alerts.
/// </summary>
public enum WeakAlgorithmSeverity
{
    /// <summary>
    /// Algorithm has minor weaknesses but may still be acceptable for non-critical uses.
    /// </summary>
    Warning,

    /// <summary>
    /// Algorithm has significant weaknesses and should be avoided.
    /// </summary>
    High,

    /// <summary>
    /// Algorithm is completely broken and must not be used for security.
    /// </summary>
    Critical
}
