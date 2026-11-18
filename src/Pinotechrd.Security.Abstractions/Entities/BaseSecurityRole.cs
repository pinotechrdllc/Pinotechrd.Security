using Microsoft.AspNetCore.Identity;

namespace Pinotechrd.Security.Entities;

/// <summary>
/// Base role entity for Pinotechrd Security infrastructure.
/// </summary>
public class BaseSecurityRole : IdentityRole<Guid>
{
    /// <summary>
    /// Creates an empty role instance.
    /// </summary>
    public BaseSecurityRole() : base() { }

    /// <summary>
    /// Creates a role with a predefined name.
    /// </summary>
    public BaseSecurityRole(string roleName) : base(roleName) { }

    /// <summary>
    /// Human-readable role description.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// UTC date when the role was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
