using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Pinotechrd.Security.Data;

/// <summary>
/// How the tenant tables of <see cref="PinotechrdSecurityDbContext{TUser, TRole}"/> find their schema.
/// </summary>
public enum TenantSchemaMode
{
    /// <summary>
    /// The schema of the resolved tenant (from <c>ISchemaProvider</c>) is written into the EF Core model, so each
    /// tenant has its own model. Requires <see cref="PinotechrdSecurityDbContextOptionsExtensions.UsePinotechrdSecurity(DbContextOptionsBuilder, Action{PinotechrdSecurityModelOptions}?)"/>,
    /// which keys the model cache by schema; without it the context refuses to build its model.
    /// </summary>
    SchemaPerTenantInModel = 0,

    /// <summary>
    /// The tenant tables have no schema in the model; PostgreSQL resolves them through <c>search_path</c>.
    /// The model is the same for every tenant. <c>UsePinotechrdSecurity</c> adds interceptors that bind every
    /// connection EF Core opens to the resolved tenant's schema, refuse to open without a tenant or inside an
    /// ambient transaction, and refuse every command on a connection not bound to the current tenant. They also
    /// refuse connection strings with <c>Multiplexing</c>, <c>No Reset On Close</c>, <c>Search Path</c> or
    /// <c>Options</c> setting <c>search_path</c>, and EF Core commands that change <c>search_path</c>, the role or the
    /// session state. PostgreSQL only, with session-level pooling: a connection pooler is detected when a connection is
    /// bound and refused unless <see cref="PinotechrdSecurityModelOptions.ConnectionPoolerUsesSessionMode"/> says it runs in
    /// session mode (transaction or statement mode would share one tenant's session with another).
    /// </summary>
    SearchPath = 1
}

/// <summary>
/// Model settings of <see cref="PinotechrdSecurityDbContext{TUser, TRole}"/>, set through
/// <see cref="PinotechrdSecurityDbContextOptionsExtensions.UsePinotechrdSecurity(DbContextOptionsBuilder, Action{PinotechrdSecurityModelOptions}?)"/>.
/// Keep them the same for every instance of one context type.
/// </summary>
public sealed class PinotechrdSecurityModelOptions
{
    /// <summary>
    /// How tenant tables find their schema. Default: <see cref="TenantSchemaMode.SchemaPerTenantInModel"/>.
    /// </summary>
    public TenantSchemaMode TenantSchemaMode { get; set; } = TenantSchemaMode.SchemaPerTenantInModel;

    /// <summary>
    /// Schema of the catalog tables (tenants, plans, subscriptions). Default <c>public</c>.
    /// <see langword="null"/> leaves them without a schema, resolved by <c>search_path</c>.
    /// </summary>
    public string? CatalogSchema { get; set; } = "public";

    /// <summary>
    /// When <see langword="true"/>, the catalog tables are excluded from this context's migrations, so a
    /// tenant context does not try to create them. Default <see langword="false"/>.
    /// </summary>
    public bool ExcludeCatalogFromMigrations { get; set; }

    /// <summary>
    /// <see cref="TenantSchemaMode.SearchPath"/> only. When <see langword="true"/>, the library does not add its
    /// <c>search_path</c> interceptors and the application takes full responsibility for binding every connection
    /// to the resolved tenant's schema, and for never letting a rollback or a pooled connection restore another
    /// path. Without the interceptors and without this flag, the context refuses to start. Default <see langword="false"/>.
    /// </summary>
    public bool ApplicationTakesResponsibilityForSearchPath { get; set; }

    /// <summary>
    /// <see cref="TenantSchemaMode.SearchPath"/> only. Set it to <see langword="true"/> when the application connects
    /// through a connection pooler (PgBouncer, Odyssey, PgCat, a cloud proxy) that runs in <b>session</b> mode, where a
    /// client keeps one server session until it disconnects. Default <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// When a connection is bound, the library compares the server's <c>pg_backend_pid()</c> with the process id the
    /// client was given; a pooler gives its own, so they differ. Unless this option is on, binding is then refused:
    /// in transaction or statement mode the pooler hands the same server session, with the <c>search_path</c> one tenant
    /// set, to another client between statements, so one tenant's commands can run on another tenant's schema. Turn it
    /// on only for session mode. <see cref="TenantSchemaMode.SchemaPerTenantInModel"/> works with every pooler mode,
    /// because each query names its schema.
    /// The detection is best effort (a pooler that forwards the server's process id is not seen), and this option is a
    /// declaration the library cannot verify: declared for a pooler that actually runs in transaction or statement mode
    /// (including a per-database or per-user override, or a pooler without a session mode such as AWS RDS Proxy),
    /// tenants' sessions are shared without an error.
    /// </remarks>
    public bool ConnectionPoolerUsesSessionMode { get; set; }

    /// <summary>
    /// When <see langword="true"/>, the model maps the tables of the persistent refresh token store
    /// (<c>refresh_tokens</c> and <c>refresh_token_families</c>) in the tenant schema, never the catalog schema.
    /// Required by <c>AddPinotechrdEfRefreshTokenStore</c>. Turning it on changes the model: add a migration.
    /// Default <see langword="false"/>, which leaves the model unchanged.
    /// </summary>
    public bool MapRefreshTokens { get; set; }

    /// <summary>
    /// When <see langword="true"/>, the model maps the table of the persistent two-factor attempt store
    /// (<c>two_factor_attempts</c>) in the tenant schema, never the catalog schema.
    /// Required by <c>AddPinotechrdEfTwoFactorAttemptStore</c>. Turning it on changes the model: add a migration.
    /// Default <see langword="false"/>, which leaves the model unchanged.
    /// </summary>
    public bool MapTwoFactorAttempts { get; set; }
}

/// <summary>
/// Registers <see cref="PinotechrdSecurityDbContext{TUser, TRole}"/> model settings and the per-schema model cache.
/// </summary>
public static class PinotechrdSecurityDbContextOptionsExtensions
{
    /// <summary>
    /// Configures the security model and replaces EF Core's model cache key factory with
    /// <see cref="ModelSchemaCacheKeyFactory"/>, so each tenant schema gets its own model.
    /// Call it wherever the context's options are built, including design-time factories.
    /// </summary>
    /// <param name="builder">Options builder of the security context.</param>
    /// <param name="configure">Optional model settings.</param>
    /// <returns>The same builder.</returns>
    public static DbContextOptionsBuilder UsePinotechrdSecurity(
        this DbContextOptionsBuilder builder,
        Action<PinotechrdSecurityModelOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new PinotechrdSecurityModelOptions();
        configure?.Invoke(options);

        var extension = new PinotechrdSecurityDbContextOptionsExtension(new PinotechrdSecurityModelSettings(
            options.TenantSchemaMode,
            options.CatalogSchema,
            options.ExcludeCatalogFromMigrations,
            options.ApplicationTakesResponsibilityForSearchPath,
            options.MapRefreshTokens,
            options.MapTwoFactorAttempts,
            options.ConnectionPoolerUsesSessionMode));

        ((IDbContextOptionsBuilderInfrastructure)builder).AddOrUpdateExtension(extension);
        builder.ReplaceService<IModelCacheKeyFactory, ModelSchemaCacheKeyFactory>();

        if (options.TenantSchemaMode == TenantSchemaMode.SearchPath && !options.ApplicationTakesResponsibilityForSearchPath)
        {
            var interceptors = builder.Options.FindExtension<CoreOptionsExtension>()?.Interceptors ?? [];
            if (!interceptors.Contains(SearchPathConnectionInterceptor.Instance))
            {
                builder.AddInterceptors(SearchPathConnectionInterceptor.Instance, SearchPathCommandInterceptor.Instance);
            }
        }

        return builder;
    }
}

/// <summary>
/// Immutable snapshot of <see cref="PinotechrdSecurityModelOptions"/>; part of the model cache key.
/// </summary>
internal sealed record PinotechrdSecurityModelSettings(
    TenantSchemaMode TenantSchemaMode,
    string? CatalogSchema,
    bool ExcludeCatalogFromMigrations,
    bool ApplicationTakesResponsibilityForSearchPath,
    bool MapRefreshTokens = false,
    bool MapTwoFactorAttempts = false,
    bool ConnectionPoolerUsesSessionMode = false)
{
    public static readonly PinotechrdSecurityModelSettings Default = new(TenantSchemaMode.SchemaPerTenantInModel, "public", false, false);
}

/// <summary>
/// EF Core options extension carrying <see cref="PinotechrdSecurityModelSettings"/>.
/// </summary>
internal sealed class PinotechrdSecurityDbContextOptionsExtension : IDbContextOptionsExtension
{
    private DbContextOptionsExtensionInfo? _info;

    public PinotechrdSecurityDbContextOptionsExtension(PinotechrdSecurityModelSettings settings)
    {
        Settings = settings;
    }

    public PinotechrdSecurityModelSettings Settings { get; }

    public DbContextOptionsExtensionInfo Info => _info ??= new ExtensionInfo(this);

    public void ApplyServices(Microsoft.Extensions.DependencyInjection.IServiceCollection services)
    {
    }

    public void Validate(IDbContextOptions options)
    {
    }

    private sealed class ExtensionInfo : DbContextOptionsExtensionInfo
    {
        public ExtensionInfo(IDbContextOptionsExtension extension) : base(extension)
        {
        }

        private new PinotechrdSecurityDbContextOptionsExtension Extension => (PinotechrdSecurityDbContextOptionsExtension)base.Extension;

        public override bool IsDatabaseProvider => false;

        public override string LogFragment => $"PinotechrdSecurity:{Extension.Settings.TenantSchemaMode} ";

        // The settings change the model, not the internal services.
        public override int GetServiceProviderHashCode() => 0;

        public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other) => other is ExtensionInfo;

        public override void PopulateDebugInfo(IDictionary<string, string> debugInfo)
        {
            debugInfo["PinotechrdSecurity:TenantSchemaMode"] = Extension.Settings.TenantSchemaMode.ToString();
        }
    }
}
