using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Pinotechrd.Security.Authorization;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Extensions;

/// <summary>
/// Extension methods for registering Pinotechrd Security services.
/// </summary>
public static class SecurityExtensions
{
    /// <summary>
    /// Registers Pinotechrd Security infrastructure including multi-tenancy, granular authorization, and identity management.
    /// </summary>
    /// <typeparam name="TContext">Security-aware EF Core DbContext type.</typeparam>
    /// <typeparam name="TUser">Identity user type.</typeparam>
    /// <typeparam name="TRole">Identity role type.</typeparam>
    /// <param name="services">Service collection to configure.</param>
    /// <param name="configure">Optional options delegate for security settings.</param>
    /// <returns>The same service collection for chaining.</returns>
    /// <remarks>
    /// <para>
    /// The JWT settings are not checked here. They are validated when the host starts, and the host fails to
    /// start with an <see cref="OptionsValidationException"/> that names each missing or weak setting.
    /// </para>
    /// <para>
    /// Tenant membership is also checked when the host starts and when the options are first read: unless
    /// <typeparamref name="TContext"/> derives from <see cref="Data.PinotechrdSecurityDbContext{TUser, TRole}"/>, its
    /// registered options use <c>UsePinotechrdSecurity()</c> and, in <see cref="Data.TenantSchemaMode.SearchPath"/>,
    /// <c>ApplicationTakesResponsibilityForSearchPath</c> is off, an <see cref="IIdentityValidator{TUser}"/> must be
    /// registered or <see cref="PinotechrdSecurityOptions.AllowUnverifiedTenantMembership"/> set to
    /// <see langword="true"/>.
    /// </para>
    /// <para>
    /// Bearer options: in a <c>PostConfigure</c> step, which runs after every <c>Configure</c>, the library sets on
    /// the final <see cref="TokenValidationParameters"/> (creating it if the application set it to null):
    /// issuer, audience, lifetime and signing-key validation on; signed tokens and expiration required; the
    /// configured issuer, audience and key; HMAC-SHA256 as the only algorithm. Every other property the
    /// application configures, even by replacing the whole object, is kept. Only a <c>PostConfigure</c>
    /// registered after this call could change these settings.
    /// </para>
    /// <para>
    /// Tenant resolution: <c>UseTenantResolution</c> also checks, right before each endpoint runs, that an
    /// authenticated user's tenant claim equals the resolved tenant, wherever routing sits in the pipeline.
    /// Place it after <c>UseAuthentication</c>.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddPinotechrdSecurity<TContext, TUser, TRole>(
        this IServiceCollection services,
        Action<PinotechrdSecurityOptions>? configure = null)
        where TContext : DbContext
        where TUser : BaseSecurityUser, new()
        where TRole : BaseSecurityRole, new()
    {
        var options = new PinotechrdSecurityOptions();
        configure?.Invoke(options);

        // JWT settings are validated when the host starts (or on first use), not here, so tools that build
        // the host without configuration (for example OpenAPI generation at build time) still work.
        services.AddOptions<PinotechrdSecurityOptions>()
            .Configure(o =>
            {
                o.Jwt = options.Jwt;
                o.AllowUnverifiedTenantMembership = options.AllowUnverifiedTenantMembership;
                // Keep IOptions<PinotechrdSecurityOptions>.Value.Tenancy equal to the registered TenantResolutionOptions.
                var tenancy = o.Tenancy;
                tenancy.HeaderName = options.Tenancy.HeaderName;
                tenancy.ClaimType = options.Tenancy.ClaimType;
                tenancy.Sources = options.Tenancy.Sources;
                tenancy.OnMissingTenant = options.Tenancy.OnMissingTenant;
                tenancy.RequiredPathPrefix = options.Tenancy.RequiredPathPrefix;
                tenancy.SkipPaths = options.Tenancy.SkipPaths;
                tenancy.UseSharedSchemaWhenNoTenant = options.Tenancy.UseSharedSchemaWhenNoTenant;
            })
            .ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<PinotechrdSecurityOptions>, PinotechrdSecurityOptionsValidator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<PinotechrdSecurityOptions>, TenantMembershipValidator<TContext, TUser>>());

        services.AddScoped<TenantContext>();
        services.AddSingleton(options.Tenancy);

        services.AddMemoryCache();

        services.AddScoped<DbSecurityStore>();
        services.AddScoped<ISecurityStore>(sp => 
        {
            var dbStore = sp.GetRequiredService<DbSecurityStore>();
            var cache = sp.GetRequiredService<IMemoryCache>();
            return new TenantCacheStore(dbStore, cache);
        });

        services.AddScoped<ISecurityEngine, SecurityEngine>();
        services.AddScoped<SecuritySeeder>();

        services.AddIdentity<TUser, TRole>(idOptions =>
        {
            idOptions.Password.RequireDigit = true;
            idOptions.Password.RequiredLength = 8;
            idOptions.User.RequireUniqueEmail = true;

            idOptions.SignIn.RequireConfirmedAccount = false;
            idOptions.SignIn.RequireConfirmedEmail = false;
            idOptions.SignIn.RequireConfirmedPhoneNumber = false;
        })
        .AddEntityFrameworkStores<TContext>()
        .AddDefaultTokenProviders();

        services.AddScoped<ITokenProvider, JwtTokenProvider>();
        // TryAdd: a store registered before this call (for example a persistent one) is kept, so the order of the
        // registrations cannot silently fall back to the in-memory default.
        services.TryAddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        services.TryAddSingleton<ITwoFactorAttemptStore, InMemoryTwoFactorAttemptStore>();
        // Two-factor tokens need Data Protection keys shared by every instance: warn when they are not persisted.
        services.AddHostedService<DataProtectionKeyCheck>();
        services.AddScoped<IPinotechrdAuthManager<TUser>, PinotechrdAuthManager<TUser>>();
        services.AddScoped<ISecurityDbContext>(sp => sp.GetRequiredService<TContext>() as ISecurityDbContext ?? throw new InvalidOperationException("DbContext does not implement ISecurityDbContext"));
        services.AddScoped<IPinotechrdSecurityManager<TUser, TRole>, PinotechrdSecurityManager<TUser, TRole>>();

        services.AddAuthentication(auth =>
        {
            auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer();

        // Applied from the validated options in a PostConfigure step, which runs after every Configure, so an
        // application that changes or replaces TokenValidationParameters keeps its other settings but cannot
        // drop what the library guarantees.
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .PostConfigure<IOptions<PinotechrdSecurityOptions>, TenantResolutionOptions>((jwt, security, tenancy) =>
            {
                // The tenant claim must arrive under its own name: inbound claim mapping would rename, for example,
                // "tid" to http://schemas.microsoft.com/identity/claims/tenantid, and every request would then be
                // tenant_invalid. Only that claim type is exempted, on this scheme's handler instances; every other
                // claim keeps the default mapping (sub stays ClaimTypes.NameIdentifier).
                TenantClaimMapping.Exempt(jwt, tenancy.ClaimType);

                var settings = security.Value.Jwt;
                var parameters = jwt.TokenValidationParameters ??= new TokenValidationParameters();
                parameters.ValidateIssuer = true;
                parameters.ValidateAudience = true;
                parameters.ValidateLifetime = true;
                parameters.ValidateIssuerSigningKey = true;
                parameters.RequireSignedTokens = true;
                parameters.RequireExpirationTime = true;
                parameters.ValidIssuer = settings.Issuer;
                parameters.ValidAudience = settings.Audience;
                parameters.ValidAlgorithms = [SecurityAlgorithms.HmacSha256];
                parameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(settings.Secret));
            });

        services.AddAuthorization();
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();

        return services;
    }

    /// <summary>
    /// Adds the tenant resolution middleware to the pipeline.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Order: after <c>UseAuthentication()</c>, before <c>UseAuthorization()</c> and <c>UseOutputCache()</c>.
    /// The middleware also installs an endpoint feature that wraps every endpoint set on the request, by routing
    /// before or after it or by a re-execution, so that after authorization and before the endpoint runs an
    /// authenticated user's tenant claim must equal the resolved tenant (<c>400 tenant_invalid</c> otherwise). This
    /// covers minimal APIs, MVC, Razor Pages and fallback endpoints, including endpoints that authenticate with
    /// their own schemes, and does not depend on where <c>UseRouting()</c> is. Skip paths are not checked.
    /// </para>
    /// <para>
    /// Not covered: code that calls <c>AuthenticateAsync</c> itself inside an endpoint, and long-lived
    /// connections (for example SignalR), which are checked only when they connect.
    /// </para>
    /// </remarks>
    /// <param name="app">Application pipeline builder.</param>
    /// <returns>The same application builder for chaining.</returns>
    public static IApplicationBuilder UseTenantResolution(this IApplicationBuilder app)
    {
        return app.UseMiddleware<TenantResolutionMiddleware>();
    }
}
