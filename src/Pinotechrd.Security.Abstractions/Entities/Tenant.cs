using Pinotechrd.Security.Enums;

namespace Pinotechrd.Security.Entities;

/// <summary>
/// Core tenant entity for the multi-tenant system.
/// </summary>
public class Tenant : SecurityBaseEntity
{
    /// <summary>
    /// Linked subscription identifier.
    /// </summary>
    public virtual Guid SubscriptionId { get; set; }

    /// <summary>
    /// Tenant display name.
    /// </summary>
    public virtual string Name { get; set; } = string.Empty;

    /// <summary>
    /// URL-safe unique tenant identifier.
    /// </summary>
    public virtual string Identifier { get; set; } = string.Empty;

    /// <summary>
    /// Optional database schema for schema-per-tenant deployments.
    /// </summary>
    public virtual string? DbSchema { get; set; } 

    /// <summary>
    /// Optional dedicated database name for database-per-tenant deployments.
    /// </summary>
    public virtual string? DbName { get; set; }

    /// <summary>
    /// Optional tenant-specific connection string.
    /// </summary>
    public virtual string? ConnectionString { get; set; }

    /// <summary>
    /// Current provisioning lifecycle state.
    /// </summary>
    public virtual TenantStatus Status { get; set; } = TenantStatus.Provisioning;

    /// <summary>
    /// Last provisioning error message.
    /// </summary>
    public virtual string? ProvisioningError { get; set; }

    /// <summary>
    /// Number of provisioning attempts.
    /// </summary>
    public virtual int ProvisioningAttempts { get; set; }

    /// <summary>
    /// UTC date when current provisioning cycle started.
    /// </summary>
    public virtual DateTime? ProvisioningStartedAt { get; set; }

    /// <summary>
    /// UTC date when provisioning completed successfully.
    /// </summary>
    public virtual DateTime? ProvisioningCompletedAt { get; set; }

    /// <summary>
    /// UTC date when tenant was suspended.
    /// </summary>
    public virtual DateTime? SuspendedAt { get; set; }

    /// <summary>
    /// Last applied schema version.
    /// </summary>
    public virtual string? CurrentSchemaVersion { get; set; }

    /// <summary>
    /// Navigation property to the active subscription.
    /// </summary>
    public virtual SystemSubscription Subscription { get; set; } = null!;

    /// <summary>
    /// Creates an empty tenant instance for EF materialization.
    /// </summary>
    public Tenant() { }

    /// <summary>
    /// Factory method that initializes a tenant in provisioning state.
    /// </summary>
    public static Tenant Create(Guid subscriptionId, string name, string identifier, string dbSchema)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Name is required.");
        if (string.IsNullOrWhiteSpace(identifier)) throw new ArgumentException("Identifier is required.");

        return new Tenant
        {
            Id = Guid.NewGuid(),
            SubscriptionId = subscriptionId,
            Name = name,
            Identifier = identifier.ToLowerInvariant().Replace(" ", "-"),
            DbSchema = dbSchema,
            Status = TenantStatus.Provisioning,
            ProvisioningAttempts = 0,
            CreatedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Renames the tenant.
    /// </summary>
    public virtual void Rename(string newName)
    {
        if (string.IsNullOrWhiteSpace(newName)) throw new ArgumentException("Name is required.");
        Name = newName;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Updates the stored schema version marker.
    /// </summary>
    public virtual void UpdateSchemaVersion(string version)
    {
        CurrentSchemaVersion = version;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Registers a provisioning failure without changing lifecycle stage.
    /// </summary>
    public virtual void MarkAsFailed(string error)
    {
        Status = TenantStatus.Provisioning;
        ProvisioningError = error;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Marks the tenant as being provisioned and increments the attempt counter.
    /// </summary>
    public virtual void MarkAsProvisioning()
    {
        Status = TenantStatus.Provisioning;
        ProvisioningAttempts++;
        ProvisioningStartedAt = DateTime.UtcNow;
        ProvisioningError = null;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Marks the tenant as active after successful provisioning.
    /// </summary>
    public virtual void MarkAsProvisioned()
    {
        Status = TenantStatus.Active;
        ProvisioningCompletedAt = DateTime.UtcNow;
        ProvisioningError = null;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Suspends the tenant.
    /// </summary>
    public virtual void Suspend()
    {
        Status = TenantStatus.Suspended;
        SuspendedAt = DateTime.UtcNow;
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Reactivates the tenant.
    /// </summary>
    public virtual void Activate()
    {
        Status = TenantStatus.Active;
        UpdatedAt = DateTime.UtcNow;
    }
}
