using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Entities;

/// <summary>
/// Base class for all security entities that require identification and tenant context.
/// </summary>
public abstract class BaseSecurityEntity : SecurityBaseEntity, ITenantEntity
{
    /// <summary>
    /// Gets or sets the associated tenant identifier.
    /// </summary>
    public string TenantId { get; set; } = string.Empty;
}
