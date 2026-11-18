namespace Pinotechrd.Security.Entities;

/// <summary>
/// Represents a system module that groups permissions.
/// Mapped to the tenant schema.
/// </summary>
public class SecurityModule : BaseSecurityEntity
{
    /// <summary>
    /// Display name of the module.
    /// </summary>
    public virtual string Name { get; set; } = string.Empty;

    /// <summary>
    /// Stable module code used for checks and policy names.
    /// </summary>
    public virtual string Code { get; set; } = string.Empty;

    /// <summary>
    /// Optional module description.
    /// </summary>
    public virtual string? Description { get; set; }

    /// <summary>
    /// Indicates whether the module is active.
    /// </summary>
    public virtual bool IsActive { get; set; } = true;

    /// <summary>
    /// Relative ordering used for menus and listings.
    /// </summary>
    public virtual int DisplayOrder { get; set; }

    /// <summary>
    /// Permissions associated with this module.
    /// </summary>
    public virtual ICollection<SecurityPermission> Permissions { get; set; } = new List<SecurityPermission>();

    /// <summary>
    /// Subscription plans that include this module.
    /// </summary>
    public virtual ICollection<SubscriptionPlanModule> PlanModules { get; set; } = new List<SubscriptionPlanModule>();

    /// <summary>
    /// Creates an empty module instance for ORM materialization.
    /// </summary>
    public SecurityModule() { }

    /// <summary>
    /// Creates a new security module.
    /// </summary>
    public static SecurityModule Create(string name, string code, string? description = null, int displayOrder = 0)
    {
        return new SecurityModule
        {
            Id = Guid.NewGuid(),
            Name = name,
            Code = code.ToUpperInvariant(),
            Description = description,
            DisplayOrder = displayOrder,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Updates mutable module metadata.
    /// </summary>
    public void Update(string name, string? description, int displayOrder)
    {
        Name = name;
        Description = description;
        DisplayOrder = displayOrder;
        UpdatedAt = DateTime.UtcNow;
    }
}

/// <summary>
/// Represents a specific permission within a module.
/// Mapped to the tenant schema.
/// </summary>
public class SecurityPermission : BaseSecurityEntity
{
    /// <summary>
    /// Parent module identifier.
    /// </summary>
    public virtual Guid ModuleId { get; set; }

    /// <summary>
    /// Display name of the permission.
    /// </summary>
    public virtual string Name { get; set; } = string.Empty;

    /// <summary>
    /// Stable permission code used in authorization checks.
    /// </summary>
    public virtual string Code { get; set; } = string.Empty;

    /// <summary>
    /// Optional permission description.
    /// </summary>
    public virtual string? Description { get; set; }

    /// <summary>
    /// Optional grouping key for UI organization.
    /// </summary>
    public virtual string? Group { get; set; }

    /// <summary>
    /// Indicates whether the permission is currently active.
    /// </summary>
    public virtual bool IsActive { get; set; } = true;

    /// <summary>
    /// Navigation property to the parent module.
    /// </summary>
    public virtual SecurityModule Module { get; set; } = null!;

    /// <summary>
    /// Role assignments that include this permission.
    /// </summary>
    public virtual ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();

    /// <summary>
    /// Creates an empty permission instance for ORM materialization.
    /// </summary>
    public SecurityPermission() { }

    /// <summary>
    /// Creates a new security permission.
    /// </summary>
    public static SecurityPermission Create(Guid moduleId, string name, string code, string? description = null, string? group = null)
    {
        return new SecurityPermission
        {
            Id = Guid.NewGuid(),
            ModuleId = moduleId,
            Name = name,
            Code = code.ToUpperInvariant(),
            Description = description,
            Group = group,
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };
    }
}
