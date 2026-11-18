using Microsoft.AspNetCore.Identity;

namespace Pinotechrd.Security.Entities;

/// <summary>
/// Base user entity for Pinotechrd Security infrastructure.
/// </summary>
public class BaseSecurityUser : IdentityUser<Guid>
{
    /// <summary>
    /// UTC date when the user was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// UTC date of the last profile update.
    /// </summary>
    public DateTime? UpdatedAt { get; set; }

    /// <summary>
    /// Indicates whether the user account is active.
    /// </summary>
    public bool IsActive { get; set; } = true;
}
