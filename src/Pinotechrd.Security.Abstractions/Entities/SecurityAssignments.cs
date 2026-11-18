using Pinotechrd.Security.Enums;

namespace Pinotechrd.Security.Entities;

/// <summary>
/// Mapping between roles and permissions.
/// Mapped to the tenant schema.
/// </summary>
public class RolePermission : BaseSecurityEntity
{
    /// <summary>
    /// Identifier of the role receiving the permission.
    /// </summary>
    public virtual Guid RoleId { get; set; }

    /// <summary>
    /// Identifier of the granted permission.
    /// </summary>
    public virtual Guid PermissionId { get; set; }

    /// <summary>
    /// Navigation property to the granted permission.
    /// </summary>
    public virtual SecurityPermission Permission { get; set; } = null!;

    /// <summary>
    /// Creates an empty assignment instance for ORM materialization.
    /// </summary>
    public RolePermission() { }

    /// <summary>
    /// Creates a new role-permission assignment.
    /// </summary>
    public static RolePermission Create(Guid roleId, Guid permissionId)
    {
        if (roleId == Guid.Empty) throw new ArgumentException("RoleId is required.");

        return new RolePermission
        {
            Id = Guid.NewGuid(),
            RoleId = roleId,
            PermissionId = permissionId,
            CreatedAt = DateTime.UtcNow
        };
    }
}

/// <summary>
/// Direct mapping between users and specific permission overrides (Allow/Deny).
/// Mapped to the tenant schema.
/// </summary>
public class UserModulePermission : BaseSecurityEntity
{
    /// <summary>
    /// Identifier of the user receiving the override.
    /// </summary>
    public virtual Guid UserId { get; set; }

    /// <summary>
    /// Identifier of the permission being overridden.
    /// </summary>
    public virtual Guid PermissionId { get; set; }

    /// <summary>
    /// Allow or deny mode for this override.
    /// </summary>
    public virtual PermissionAccessType AccessType { get; set; }

    /// <summary>
    /// Navigation property to the overridden permission.
    /// </summary>
    public virtual SecurityPermission Permission { get; set; } = null!;

    /// <summary>
    /// Creates an empty assignment instance for ORM materialization.
    /// </summary>
    public UserModulePermission() { }

    /// <summary>
    /// Creates a user-permission override with an explicit access type.
    /// </summary>
    protected static UserModulePermission Create(Guid userId, Guid permissionId, PermissionAccessType accessType)
    {
        if (userId == Guid.Empty) throw new ArgumentException("UserId is required.");

        return new UserModulePermission
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            PermissionId = permissionId,
            AccessType = accessType,
            CreatedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Creates an allow override for a user permission.
    /// </summary>
    public static UserModulePermission CreateAllow(Guid userId, Guid permissionId) => Create(userId, permissionId, PermissionAccessType.Allow);

    /// <summary>
    /// Creates a deny override for a user permission.
    /// </summary>
    public static UserModulePermission CreateDeny(Guid userId, Guid permissionId) => Create(userId, permissionId, PermissionAccessType.Deny);
}
