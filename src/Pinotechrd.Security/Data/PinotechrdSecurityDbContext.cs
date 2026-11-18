using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Data;

/// <summary>
/// Base database context for Pinotechrd Security infrastructure.
/// Handles multi-schema routing: 
/// - "public" for global catalog.
/// - Dynamic for tenant-specific identity and security.
/// </summary>
/// <typeparam name="TUser">The type of the user entity.</typeparam>
/// <typeparam name="TRole">The type of the role entity.</typeparam>
public abstract class PinotechrdSecurityDbContext<TUser, TRole> : IdentityDbContext<TUser, TRole, Guid>, ISecurityDbContext, ISchemaAwareContext
    where TUser : BaseSecurityUser
    where TRole : BaseSecurityRole
{
    private readonly ISchemaProvider _schemaProvider;

    /// <summary>
    /// Initializes the security DbContext with schema provider support.
    /// </summary>
    protected PinotechrdSecurityDbContext(DbContextOptions options, ISchemaProvider schemaProvider) : base(options)
    {
        _schemaProvider = schemaProvider;
    }

    /// <summary>
    /// Gets the dynamic schema name resolved for the current context.
    /// </summary>
    public string SchemaName => _schemaProvider.GetSchemaName();

    // Catalog Entities (Static Global Schema: "public")
    /// <summary>
    /// Catalog tenants.
    /// </summary>
    public virtual DbSet<Tenant> Tenants { get; set; } = null!;

    /// <summary>
    /// Catalog subscription plans.
    /// </summary>
    public virtual DbSet<SubscriptionPlan> SubscriptionPlans { get; set; } = null!;

    /// <summary>
    /// Catalog system subscriptions.
    /// </summary>
    public virtual DbSet<SystemSubscription> SystemSubscriptions { get; set; } = null!;

    /// <summary>
    /// Catalog plan-module mappings.
    /// </summary>
    public virtual DbSet<SubscriptionPlanModule> SubscriptionPlanModules { get; set; } = null!;

    /// <summary>
    /// Catalog plan features.
    /// </summary>
    public virtual DbSet<SubscriptionPlanFeature> SubscriptionPlanFeatures { get; set; } = null!;

    // Security Entities (Dynamic Tenant Schema)
    /// <summary>
    /// Tenant-scoped security modules.
    /// </summary>
    public virtual DbSet<SecurityModule> SecurityModules { get; set; } = null!;

    /// <summary>
    /// Tenant-scoped security permissions.
    /// </summary>
    public virtual DbSet<SecurityPermission> SecurityPermissions { get; set; } = null!;

    /// <summary>
    /// Tenant-scoped role-permission assignments.
    /// </summary>
    public virtual DbSet<RolePermission> RolePermissions { get; set; } = null!;

    /// <summary>
    /// Tenant-scoped user permission overrides.
    /// </summary>
    public virtual DbSet<UserModulePermission> UserModulePermissions { get; set; } = null!;

    // ISecurityDbContext implementation
    IQueryable<SecurityPermission> ISecurityDbContext.Permissions => SecurityPermissions;
    IQueryable<SecurityModule> ISecurityDbContext.Modules => SecurityModules;
    IQueryable<SystemSubscription> ISecurityDbContext.SystemSubscriptions => SystemSubscriptions;
    IQueryable<RolePermission> ISecurityDbContext.RolePermissions => RolePermissions;
    IQueryable<UserModulePermission> ISecurityDbContext.UserModulePermissions => UserModulePermissions;
    IQueryable<SubscriptionPlanModule> ISecurityDbContext.SubscriptionPlanModules => SubscriptionPlanModules;

    /// <summary>
    /// Configures entity mappings for catalog and tenant-scoped schemas.
    /// </summary>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // 1. Catalog Mapping (Global "public" schema)
        string catalogSchema = "public";
        
        modelBuilder.Entity<Tenant>(entity => 
        {
            entity.ToTable("tenants", catalogSchema);
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Identifier).HasMaxLength(100).IsRequired();
            entity.HasIndex(e => e.Identifier).IsUnique();
            entity.HasOne(e => e.Subscription).WithMany(s => s.Tenants).HasForeignKey(e => e.SubscriptionId);
        });

        modelBuilder.Entity<SubscriptionPlan>(entity => 
        {
            entity.ToTable("subscription_plans", catalogSchema);
            entity.Property(e => e.Name).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Code).HasMaxLength(50).IsRequired();
            entity.Property(e => e.MonthlyPrice).HasPrecision(18, 2);
            entity.HasIndex(e => e.Code).IsUnique();
        });

        modelBuilder.Entity<SystemSubscription>(entity => 
        {
            entity.ToTable("system_subscriptions", catalogSchema);
            entity.HasOne(e => e.Plan).WithMany(p => p.SystemSubscriptions).HasForeignKey(e => e.PlanId);
        });

        modelBuilder.Entity<SubscriptionPlanModule>(entity => 
        {
            entity.ToTable("subscription_plan_modules", catalogSchema);
            entity.HasOne(e => e.Plan).WithMany(p => p.PlanModules).HasForeignKey(e => e.PlanId);
            entity.HasOne(e => e.Module).WithMany(m => m.PlanModules).HasForeignKey(e => e.ModuleId);
        });

        modelBuilder.Entity<SubscriptionPlanFeature>(entity => 
        {
            entity.ToTable("subscription_plan_features", catalogSchema);
            entity.Property(e => e.Code).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Value).HasMaxLength(500);
            entity.Property(e => e.Description).HasMaxLength(500);
            entity.HasOne(e => e.Plan).WithMany(p => p.PlanFeatures).HasForeignKey(e => e.PlanId);
        });

        // 2. Tenant Identity & Security Mapping (Dynamic schema)
        string dynamicSchema = SchemaName;
        modelBuilder.HasDefaultSchema(dynamicSchema);

        // Identity Table Mapping
        modelBuilder.Entity<TUser>(entity => entity.ToTable("users", dynamicSchema));
        modelBuilder.Entity<TRole>(entity => entity.ToTable("roles", dynamicSchema));
        modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityUserClaim<Guid>>(entity => entity.ToTable("user_claims", dynamicSchema));
        modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityUserRole<Guid>>(entity => entity.ToTable("user_roles", dynamicSchema));
        modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityUserLogin<Guid>>(entity => entity.ToTable("user_logins", dynamicSchema));
        modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityRoleClaim<Guid>>(entity => entity.ToTable("role_claims", dynamicSchema));
        modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityUserToken<Guid>>(entity => entity.ToTable("user_tokens", dynamicSchema));

        // Security Entities Mapping
        modelBuilder.Entity<SecurityModule>(entity => 
        {
            entity.ToTable("security_modules", dynamicSchema);
            entity.Property(e => e.Name).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Code).HasMaxLength(50).IsRequired();
            entity.HasIndex(e => e.Code).IsUnique();
        });

        modelBuilder.Entity<SecurityPermission>(entity => 
        {
            entity.ToTable("security_permissions", dynamicSchema);
            entity.Property(e => e.Name).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Code).HasMaxLength(100).IsRequired();
            entity.HasIndex(e => e.Code).IsUnique();
            entity.HasOne(e => e.Module).WithMany(m => m.Permissions).HasForeignKey(e => e.ModuleId);
        });

        modelBuilder.Entity<RolePermission>(entity => 
        {
            entity.ToTable("role_permissions", dynamicSchema);
            entity.HasOne(e => e.Permission).WithMany(p => p.RolePermissions).HasForeignKey(e => e.PermissionId);
        });

        modelBuilder.Entity<UserModulePermission>(entity => 
        {
            entity.ToTable("user_permissions", dynamicSchema);
            entity.HasOne(e => e.Permission).WithMany().HasForeignKey(e => e.PermissionId);
        });
    }
}
