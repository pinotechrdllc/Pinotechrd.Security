namespace Pinotechrd.Security.Entities;

/// <summary>
/// Mapping between a subscription plan and authorized modules.
/// </summary>
public class SubscriptionPlanModule : SecurityBaseEntity
{
    /// <summary>
    /// Identifier of the subscription plan.
    /// </summary>
    public virtual Guid PlanId { get; set; }

    /// <summary>
    /// Identifier of the enabled module.
    /// </summary>
    public virtual Guid ModuleId { get; set; }

    /// <summary>
    /// Navigation property to the plan.
    /// </summary>
    public virtual SubscriptionPlan Plan { get; set; } = null!;

    /// <summary>
    /// Navigation property to the module.
    /// </summary>
    public virtual SecurityModule Module { get; set; } = null!;

    /// <summary>
    /// Creates an empty mapping instance for ORM materialization.
    /// </summary>
    public SubscriptionPlanModule() { }

    /// <summary>
    /// Creates a new plan-module mapping.
    /// </summary>
    public static SubscriptionPlanModule Create(Guid planId, Guid moduleId)
    {
        return new SubscriptionPlanModule
        {
            Id = Guid.NewGuid(),
            PlanId = planId,
            ModuleId = moduleId,
            CreatedAt = DateTime.UtcNow
        };
    }
}

/// <summary>
/// Specific features enabled for a subscription plan.
/// </summary>
public class SubscriptionPlanFeature : SecurityBaseEntity
{
    /// <summary>
    /// Identifier of the subscription plan.
    /// </summary>
    public virtual Guid PlanId { get; set; }

    /// <summary>
    /// Stable feature code.
    /// </summary>
    public virtual string Code { get; set; } = string.Empty;

    /// <summary>
    /// Optional feature value.
    /// </summary>
    public virtual string? Value { get; set; }

    /// <summary>
    /// Optional feature description.
    /// </summary>
    public virtual string? Description { get; set; }

    /// <summary>
    /// Navigation property to the plan.
    /// </summary>
    public virtual SubscriptionPlan Plan { get; set; } = null!;

    /// <summary>
    /// Creates an empty feature instance for ORM materialization.
    /// </summary>
    public SubscriptionPlanFeature() { }

    /// <summary>
    /// Creates a new plan feature.
    /// </summary>
    public static SubscriptionPlanFeature Create(Guid planId, string code, string? value, string? description)
    {
        return new SubscriptionPlanFeature
        {
            Id = Guid.NewGuid(),
            PlanId = planId,
            Code = code.ToUpperInvariant(),
            Value = value,
            Description = description,
            CreatedAt = DateTime.UtcNow
        };
    }
}
