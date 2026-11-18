namespace Pinotechrd.Security.Entities;

/// <summary>
/// Base class for all entities in the security kernel.
/// </summary>
public abstract class SecurityBaseEntity
{
    /// <summary>
    /// Gets or sets the primary identifier.
    /// </summary>
    public virtual Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets the date and time the entity was created.
    /// </summary>
    public virtual DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the date and time the entity was last updated.
    /// </summary>
    public virtual DateTime? UpdatedAt { get; set; }
}
