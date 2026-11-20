using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// What the <see cref="CatalogTenantStore"/> reads: the catalog schema, and the options of its context, built once from
/// the application's delegate. The context is not registered in the container, so EF Core tools find only the
/// application's own context.
/// </summary>
internal sealed class CatalogTenantStoreSettings(string? schema, Action<DbContextOptionsBuilder> configure)
{
    private readonly Lazy<DbContextOptions<CatalogTenantDbContext>> _options = new(() =>
    {
        var builder = new DbContextOptionsBuilder<CatalogTenantDbContext>();
        configure(builder);
        builder.ReplaceService<IModelCacheKeyFactory, CatalogTenantModelCacheKeyFactory>();
        return builder.Options;
    });

    public string? Schema { get; } = schema;

    public DbContextOptions<CatalogTenantDbContext> Options => _options.Value;
}

/// <summary>
/// A context that maps only the catalog's <c>tenants</c> table, for <see cref="CatalogTenantStore"/>. It is not the
/// tenant-scoped context: the tenant middleware asks the store before any tenant is set.
/// </summary>
internal sealed class CatalogTenantDbContext : DbContext
{
    private readonly CatalogTenantStoreSettings _settings;

    /// <summary>The catalog schema this context's model maps.</summary>
    internal string? Schema => _settings.Schema;

    public CatalogTenantDbContext(DbContextOptions<CatalogTenantDbContext> options, CatalogTenantStoreSettings settings) : base(options)
    {
        _settings = settings;
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Tenant>(entity =>
        {
            entity.ToTable("tenants", _settings.Schema, t => t.ExcludeFromMigrations());
            entity.HasKey(e => e.Id);
            entity.Ignore(e => e.Subscription);
        });
    }
}

/// <summary>
/// An <see cref="ITenantStore"/> over the catalog's <c>tenants</c> table: a tenant exists when its row has the identifier
/// and is <see cref="TenantStatus.Active"/>. Registered by <c>AddPinotechrdCatalogTenantStore</c>.
/// </summary>
internal sealed class CatalogTenantStore : ITenantStore
{
    private readonly CatalogTenantStoreSettings _settings;

    public CatalogTenantStore(CatalogTenantStoreSettings settings)
    {
        _settings = settings;
    }

    public async Task<bool> TenantExistsAsync(string tenantId, CancellationToken cancellationToken = default)
    {
        await using var db = new CatalogTenantDbContext(_settings.Options, _settings);
        return await db.Set<Tenant>()
            .AsNoTracking()
            .TagWith("Pinotechrd.CatalogTenantStore")
            .AnyAsync(t => t.Identifier == tenantId && t.Status == TenantStatus.Active, cancellationToken);
    }
}

/// <summary>Keys the catalog context's model by schema, so two catalog schemas in one process get their own models.</summary>
internal sealed class CatalogTenantModelCacheKeyFactory : IModelCacheKeyFactory
{
    public object Create(DbContext context, bool designTime) =>
        (context.GetType(), (context as CatalogTenantDbContext)?.Schema, designTime);
}
