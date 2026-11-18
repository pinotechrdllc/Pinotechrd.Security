namespace Pinotechrd.Security.Entities;

/// <summary>
/// A predefined subscription tier with specific modules and features.
/// </summary>
public class SubscriptionPlan : SecurityBaseEntity
{
    /// <summary>
    /// Display name of the plan.
    /// </summary>
    public virtual string Name { get; set; } = string.Empty;

    /// <summary>
    /// Stable plan code.
    /// </summary>
    public virtual string Code { get; set; } = string.Empty;

    /// <summary>
    /// Optional plan description.
    /// </summary>
    public virtual string? Description { get; set; }

    /// <summary>
    /// Indicates whether the plan is currently active.
    /// </summary>
    public virtual bool IsActive { get; set; } = true;

    /// <summary>
    /// Optional recurring monthly price.
    /// </summary>
    public virtual decimal? MonthlyPrice { get; set; }

    /// <summary>
    /// Modules included in the plan.
    /// </summary>
    public virtual ICollection<SubscriptionPlanModule> PlanModules { get; set; } = new List<SubscriptionPlanModule>();

    /// <summary>
    /// Feature flags and values linked to the plan.
    /// </summary>
    public virtual ICollection<SubscriptionPlanFeature> PlanFeatures { get; set; } = new List<SubscriptionPlanFeature>();

    /// <summary>
    /// Subscriptions currently using this plan.
    /// </summary>
    public virtual ICollection<SystemSubscription> SystemSubscriptions { get; set; } = new List<SystemSubscription>();

    /// <summary>
    /// Creates an empty plan instance for ORM materialization.
    /// </summary>
    public SubscriptionPlan() { }

    /// <summary>
    /// Creates a new subscription plan.
    /// </summary>
    public static SubscriptionPlan Create(string name, string code, string? description, decimal? monthlyPrice)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Plan name is required.");
        if (string.IsNullOrWhiteSpace(code)) throw new ArgumentException("Plan code is required.");

        return new SubscriptionPlan
        {
            Id = Guid.NewGuid(),
            Name = name,
            Code = code.ToUpperInvariant(),
            Description = description,
            MonthlyPrice = monthlyPrice,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Updates mutable plan metadata.
    /// </summary>
    public virtual void Update(string name, string? description, decimal? monthlyPrice)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        Description = description;
        MonthlyPrice = monthlyPrice;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Deactivates the plan.
    /// </summary>
    public virtual void Deactivate()
    {
        IsActive = false;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Activates the plan.
    /// </summary>
    public virtual void Activate()
    {
        IsActive = true;
        UpdatedAt = DateTime.UtcNow;
    }
}
