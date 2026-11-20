using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Extensions;

/// <summary>
/// Registration of the catalog-backed <see cref="ITenantStore"/>.
/// </summary>
public static class CatalogTenantStoreExtensions
{
    /// <summary>
    /// Replaces any <see cref="ITenantStore"/> with one that reads the catalog's <c>tenants</c> table: a tenant exists
    /// when its row has the identifier and is active.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The store uses a context of its own that maps only that table, configured by <paramref name="configureCatalog"/>
    /// (for example <c>o =&gt; o.UseNpgsql(catalogConnectionString)</c>), never the tenant-scoped context: the tenant
    /// middleware asks the store before any tenant is set. Give it a connection that can read the catalog only; it never
    /// writes. It is asked on every request that names a tenant, with no cache (one round trip per request), so a
    /// suspended tenant is refused at once. The context is not registered in the container, so <c>dotnet ef</c> still
    /// finds only the application's context.
    /// </para>
    /// <para>
    /// The store maps <c>Identifier</c> and <c>Status</c> (an integer) with EF Core's default naming, as the library's own
    /// context does. If the application's context renames the catalog's columns (a naming convention, a value
    /// conversion of <c>Status</c>), apply the same in <paramref name="configureCatalog"/>, or every tenant is refused.
    /// </para>
    /// <para>
    /// <paramref name="catalogSchema"/> must be the <c>CatalogSchema</c> of the application's context ("public" by default).
    /// Registered as scoped, like the tenant middleware's use of it.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="configureCatalog">Configures the provider and connection the store reads the catalog with.</param>
    /// <param name="catalogSchema">The schema of the catalog tables.</param>
    /// <returns>The same service collection.</returns>
    public static IServiceCollection AddPinotechrdCatalogTenantStore(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder> configureCatalog,
        string? catalogSchema = "public")
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureCatalog);

        services.RemoveAll<CatalogTenantStoreSettings>();
        services.AddSingleton(new CatalogTenantStoreSettings(catalogSchema, configureCatalog));
        services.RemoveAll<ITenantStore>();
        services.AddScoped<ITenantStore, CatalogTenantStore>();
        return services;
    }
}
