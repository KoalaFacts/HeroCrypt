namespace HeroCrypt.Operations;

/// <summary>
/// Indicates that an algorithm or feature is defined but not yet implemented.
/// </summary>
/// <remarks>
/// This attribute is used to mark enum values that are planned for future implementation.
/// Attempting to use an algorithm marked with this attribute will result in a
/// <see cref="NotImplementedException"/> or <see cref="NotSupportedException"/>.
/// </remarks>
[AttributeUsage(AttributeTargets.Field | AttributeTargets.Method | AttributeTargets.Property, AllowMultiple = false)]
public sealed class NotImplementedAttribute : Attribute
{
    /// <summary>
    /// Gets the reason or notes about why this is not implemented.
    /// </summary>
    public string? Reason { get; }

    /// <summary>
    /// Gets or sets the estimated priority for implementation (1 = highest, 5 = lowest).
    /// </summary>
    public int Priority { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="NotImplementedAttribute"/> class.
    /// </summary>
    public NotImplementedAttribute()
    {
        Priority = 3;
    }

    /// <summary>
    /// Initializes a new instance with a reason.
    /// </summary>
    /// <param name="reason">The reason or notes about the pending implementation.</param>
    public NotImplementedAttribute(string reason)
    {
        Reason = reason;
        Priority = 3;
    }

    /// <summary>
    /// Initializes a new instance with a reason and priority.
    /// </summary>
    /// <param name="reason">The reason or notes about the pending implementation.</param>
    /// <param name="priority">Implementation priority (1 = highest, 5 = lowest).</param>
    public NotImplementedAttribute(string reason, int priority)
    {
        Reason = reason;
        Priority = priority;
    }
}
