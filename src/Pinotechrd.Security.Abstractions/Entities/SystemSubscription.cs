using Pinotechrd.Security.Enums;

namespace Pinotechrd.Security.Entities;

/// <summary>
/// Represents a tenant's active subscription to a specific plan.
/// Live in the "public" schema.
/// </summary>
public class SystemSubscription : SecurityBaseEntity
{
    /// <summary>
    /// Customer legal or business name.
    /// </summary>
    public virtual string CustomerName { get; set; } = string.Empty;

    /// <summary>
    /// Tenant display name associated with the subscription.
    /// </summary>
    public virtual string TenantName { get; set; } = string.Empty;

    /// <summary>
    /// Referenced subscription plan identifier.
    /// </summary>
    public virtual Guid PlanId { get; set; }

    /// <summary>
    /// Inclusive subscription start date.
    /// </summary>
    public virtual DateOnly StartDate { get; set; }

    /// <summary>
    /// Optional subscription end date.
    /// </summary>
    public virtual DateOnly? EndDate { get; set; }

    /// <summary>
    /// Indicates whether the subscription is active.
    /// </summary>
    public virtual bool IsActive { get; set; } = true;

    /// <summary>
    /// Current lifecycle status.
    /// </summary>
    public virtual TenantStatus Status { get; set; } = TenantStatus.Active;

    /// <summary>
    /// Optional primary contact email.
    /// </summary>
    public virtual string? ContactEmail { get; set; }

    /// <summary>
    /// Optional primary contact phone.
    /// </summary>
    public virtual string? ContactPhone { get; set; }

    /// <summary>
    /// UTC timestamp when the subscription was activated.
    /// </summary>
    public virtual DateTime? ActivatedAt { get; set; }

    /// <summary>
    /// UTC timestamp when the subscription was suspended.
    /// </summary>
    public virtual DateTime? SuspendedAt { get; set; }

    /// <summary>
    /// Navigation property to the referenced plan.
    /// </summary>
    public virtual SubscriptionPlan Plan { get; set; } = null!;

    /// <summary>
    /// Tenants operating under this subscription.
    /// </summary>
    public virtual ICollection<Tenant> Tenants { get; set; } = new List<Tenant>();

    /// <summary>
    /// Creates an empty subscription instance for ORM materialization.
    /// </summary>
    public SystemSubscription() { }

    /// <summary>
    /// Creates a new active system subscription.
    /// </summary>
    public static SystemSubscription Create(
        string customerName, 
        string tenantName, 
        Guid planId, 
        DateOnly startDate, 
        string? contactEmail = null, 
        string? contactPhone = null, 
        DateOnly? endDate = null)
    {
        return new SystemSubscription
        {
            Id = Guid.NewGuid(),
            CustomerName = customerName,
            TenantName = tenantName,
            PlanId = planId,
            StartDate = startDate,
            EndDate = endDate,
            ContactEmail = contactEmail,
            ContactPhone = contactPhone,
            IsActive = true,
            Status = TenantStatus.Active,
            ActivatedAt = DateTime.UtcNow,
            CreatedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Updates mutable subscription metadata.
    /// </summary>
    public virtual void Update(string customerName, string? contactEmail, string? contactPhone, DateOnly? endDate)
    {
        CustomerName = customerName ?? throw new ArgumentNullException(nameof(customerName));
        ContactEmail = contactEmail;
        ContactPhone = contactPhone;
        EndDate = endDate;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Activates the subscription.
    /// </summary>
    public virtual void Activate()
    {
        IsActive = true;
        Status = TenantStatus.Active;
        ActivatedAt = DateTime.UtcNow;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Suspends the subscription.
    /// </summary>
    public virtual void Suspend()
    {
        IsActive = false;
        Status = TenantStatus.Suspended;
        SuspendedAt = DateTime.UtcNow;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Cancels the subscription and closes validity period.
    /// </summary>
    public virtual void Cancel()
    {
        IsActive = false;
        Status = TenantStatus.Cancelled;
        EndDate = DateOnly.FromDateTime(DateTime.UtcNow);
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Indicates whether the subscription is active and currently within date range.
    /// </summary>
    public virtual bool IsValid() 
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        return IsActive && StartDate <= today && (!EndDate.HasValue || EndDate >= today);
    }
}
