using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Data;

/// <summary>
/// Base database context for Pinotechrd Security infrastructure.
/// Handles multi-schema routing:
/// - A constant catalog schema (<see cref="PinotechrdSecurityModelOptions.CatalogSchema"/>, default "public").
/// - Tenant-specific identity and security tables, in the tenant's schema (see <see cref="TenantSchemaMode"/>).
/// </summary>
/// <remarks>
/// Configure the options with <see cref="PinotechrdSecurityDbContextOptionsExtensions.UsePinotechrdSecurity(DbContextOptionsBuilder, Action{PinotechrdSecurityModelOptions}?)"/>.
/// In <see cref="TenantSchemaMode.SchemaPerTenantInModel"/> (the default) the context refuses to build its model
/// unless <see cref="ModelSchemaCacheKeyFactory"/> is the model cache key factory, because EF Core would otherwise
/// reuse the first tenant's model, and schema, for every tenant.
/// The catalog table that maps plans to modules has no foreign key to the tenant's module table: modules live in
/// each tenant schema, the plan mapping lives once in the catalog, and they are matched by module id.
/// </remarks>
/// <typeparam name="TUser">The type of the user entity.</typeparam>
/// <typeparam name="TRole">The type of the role entity.</typeparam>
public abstract class PinotechrdSecurityDbContext<TUser, TRole> : IdentityDbContext<TUser, TRole, Guid>, ISecurityDbContext, ISchemaAwareContext, ISearchPathTenantSource
    where TUser : BaseSecurityUser
    where TRole : BaseSecurityRole
{
    private readonly ISchemaProvider _schemaProvider;
    private readonly PinotechrdSecurityModelSettings _settings;

    /// <summary>
    /// Initializes the security DbContext with schema provider support.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// A pre-built or compiled model is supplied (<c>UseModel</c>) in <see cref="TenantSchemaMode.SchemaPerTenantInModel"/>,
    /// or <see cref="TenantSchemaMode.SearchPath"/> is used without the library's <c>search_path</c> interceptors and
    /// without <see cref="PinotechrdSecurityModelOptions.ApplicationTakesResponsibilityForSearchPath"/>.
    /// </exception>
    protected PinotechrdSecurityDbContext(DbContextOptions options, ISchemaProvider schemaProvider) : base(options)
    {
        _schemaProvider = schemaProvider;
        _settings = options.FindExtension<PinotechrdSecurityDbContextOptionsExtension>()?.Settings
                    ?? PinotechrdSecurityModelSettings.Default;

        RefuseSharedSchemaFallback(_settings, schemaProvider, GetType().Name);

        var core = options.FindExtension<CoreOptionsExtension>();
        if (_settings.TenantSchemaMode == TenantSchemaMode.SchemaPerTenantInModel && core?.Model != null)
        {
            // A supplied model (UseModel, compiled models) holds one schema and bypasses the per-schema model cache.
            throw new InvalidOperationException(
                $"{GetType().Name} cannot use a pre-built or compiled model (UseModel) with TenantSchemaMode.SchemaPerTenantInModel: " +
                "the model holds one tenant's schema. Remove UseModel, or use TenantSchemaMode.SearchPath.");
        }

        if (_settings.TenantSchemaMode == TenantSchemaMode.SearchPath
            && !_settings.ApplicationTakesResponsibilityForSearchPath
            && core?.Interceptors?.Contains(SearchPathConnectionInterceptor.Instance) != true)
        {
            throw new InvalidOperationException(
                $"{GetType().Name} uses TenantSchemaMode.SearchPath without the search_path interceptors, so its queries " +
                "would reach the connection's default schema. Configure it only through UsePinotechrdSecurity(), or set " +
                "ApplicationTakesResponsibilityForSearchPath if the application binds every connection itself.");
        }
    }

    string ISearchPathTenantSource.ResolveSearchPathSchema() => _schemaProvider.GetSchemaName();

    /// <summary>
    /// In <see cref="TenantSchemaMode.SearchPath"/> a connection must only ever be bound to a resolved tenant's schema.
    /// The shared-schema fallback would bind a request without a tenant to the shared <c>identity</c> schema, where the
    /// tenant tables do not live, so that combination is refused.
    /// </summary>
    private static void RefuseSharedSchemaFallback(PinotechrdSecurityModelSettings settings, ISchemaProvider schemaProvider, string contextName)
    {
        if (settings.TenantSchemaMode == TenantSchemaMode.SearchPath
            && schemaProvider is Tenancy.DbSchemaProvider { SharedSchemaFallbackEnabled: true })
        {
            throw new InvalidOperationException(
                $"{contextName} uses TenantSchemaMode.SearchPath with TenantResolutionOptions.UseSharedSchemaWhenNoTenant: a request " +
                "without a tenant would be bound to the shared schema. Turn the fallback off; in SearchPath mode a connection " +
                "without a resolved tenant is refused, and design-time tooling does not need it because the model has no tenant schema.");
        }
    }

    /// <summary>
    /// Gets the tenant schema written into the model, or <see langword="null"/> in
    /// <see cref="TenantSchemaMode.SearchPath"/>, where the model has no tenant schema.
    /// </summary>
    public string? SchemaName => _settings.TenantSchemaMode == TenantSchemaMode.SearchPath
        ? null
        : _schemaProvider.GetSchemaName();

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
        // Fail instead of serving one tenant's model (and schema) to every tenant.
        if (_settings.TenantSchemaMode == TenantSchemaMode.SchemaPerTenantInModel
            && this.GetService<IModelCacheKeyFactory>() is not ModelSchemaCacheKeyFactory)
        {
            throw new InvalidOperationException(
                $"{GetType().Name} writes the tenant schema into its model, but the model cache is not keyed by schema, " +
                "so every tenant would get the first tenant's model. Call options.UsePinotechrdSecurity() where the " +
                "context options are built (AddDbContext and any design-time factory), or use TenantSchemaMode.SearchPath.");
        }

        base.OnModelCreating(modelBuilder);

        // 1. Catalog Mapping (constant schema)
        string? catalogSchema = _settings.CatalogSchema;
        var excludeCatalog = _settings.ExcludeCatalogFromMigrations;

        modelBuilder.Entity<Tenant>(entity =>
        {
            entity.ToTable("tenants", catalogSchema, t => t.ExcludeFromMigrations(excludeCatalog));
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Identifier).HasMaxLength(100).IsRequired();
            entity.HasIndex(e => e.Identifier).IsUnique();
            entity.HasOne(e => e.Subscription).WithMany(s => s.Tenants).HasForeignKey(e => e.SubscriptionId);
        });

        modelBuilder.Entity<SubscriptionPlan>(entity => 
        {
            entity.ToTable("subscription_plans", catalogSchema, t => t.ExcludeFromMigrations(excludeCatalog));
            entity.Property(e => e.Name).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Code).HasMaxLength(50).IsRequired();
            entity.Property(e => e.MonthlyPrice).HasPrecision(18, 2);
            entity.HasIndex(e => e.Code).IsUnique();
        });

        modelBuilder.Entity<SystemSubscription>(entity => 
        {
            entity.ToTable("system_subscriptions", catalogSchema, t => t.ExcludeFromMigrations(excludeCatalog));
            entity.HasOne(e => e.Plan).WithMany(p => p.SystemSubscriptions).HasForeignKey(e => e.PlanId);
        });

        modelBuilder.Entity<SubscriptionPlanModule>(entity => 
        {
            entity.ToTable("subscription_plan_modules", catalogSchema, t => t.ExcludeFromMigrations(excludeCatalog));
            entity.HasOne(e => e.Plan).WithMany(p => p.PlanModules).HasForeignKey(e => e.PlanId);
            // No foreign key from the catalog to a tenant table: ModuleId is matched to the tenant's module by value.
            entity.Ignore(e => e.Module);
            entity.HasIndex(e => e.ModuleId);
        });

        modelBuilder.Entity<SecurityModule>().Ignore(m => m.PlanModules);

        modelBuilder.Entity<SubscriptionPlanFeature>(entity =>
        {
            entity.ToTable("subscription_plan_features", catalogSchema, t => t.ExcludeFromMigrations(excludeCatalog));
            entity.Property(e => e.Code).HasMaxLength(100).IsRequired();
            entity.Property(e => e.Value).HasMaxLength(500);
            entity.Property(e => e.Description).HasMaxLength(500);
            entity.HasOne(e => e.Plan).WithMany(p => p.PlanFeatures).HasForeignKey(e => e.PlanId);
        });

        // 2. Tenant Identity & Security Mapping (tenant schema, or none in search_path mode)
        string? dynamicSchema = SchemaName;
        if (dynamicSchema != null)
        {
            modelBuilder.HasDefaultSchema(dynamicSchema);
        }

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

        // Persistent refresh token store (opt-in): tenant schema only, so another tenant's token is not even visible.
        if (_settings.MapRefreshTokens)
        {
            AuthStoreModel.MapRefreshTokens(modelBuilder, dynamicSchema);
        }

        // Persistent two-factor attempt store (opt-in): tenant schema only, like the refresh tokens.
        if (_settings.MapTwoFactorAttempts)
        {
            AuthStoreModel.MapTwoFactorAttempts(modelBuilder, dynamicSchema);
        }
    }
}
