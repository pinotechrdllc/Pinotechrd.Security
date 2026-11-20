using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
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
    /// configured issuer, audience and key; HMAC-SHA256 as the only algorithm; a <c>ClockSkew</c> no larger than
    /// <see cref="JwtSettings.MaximumClockSkew"/> (a larger one is lowered to it). It also clears what would widen
    /// those checks: <c>ValidIssuers</c>, <c>ValidAudiences</c>, the issuer, audience, lifetime and algorithm
    /// validator delegates, and every other source of keys or signature validation. Every other property the
    /// application configures, even by replacing the whole object, is kept.
    /// </para>
    /// <para>
    /// The final bearer options are then validated against that policy, after every <c>Configure</c> and
    /// <c>PostConfigure</c>: a <c>PostConfigure</c> registered after this call that changes any of these settings or sets a
    /// <c>ClockSkew</c> above <see cref="JwtSettings.MaximumClockSkew"/>, fails the host at start with an <see cref="OptionsValidationException"/>
    /// that names the setting. So do custom token handlers, a <see cref="TokenValidationParameters"/> subclass, a token
    /// reader or pre-signature transform, and forwarding the bearer scheme's authentication to another scheme. The check
    /// covers the options as configured; code the application runs during authentication (for example event handlers
    /// that set a result) and other authentication schemes are the application's responsibility.
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
                o.TenantCacheExpiration = options.TenantCacheExpiration;
                o.SetDefaultAuthenticationSchemes = options.SetDefaultAuthenticationSchemes;
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

        // TryAdd inside: an IDistributedCache registered before this call is kept, and the usual providers (Redis,
        // SQL Server) use Add, so one registered after it wins too. The in-memory default is per instance.
        services.AddDistributedMemoryCache();

        services.AddScoped<DbSecurityStore>();
        services.AddScoped(sp => new TenantCacheStore(
            sp.GetRequiredService<DbSecurityStore>(),
            sp.GetRequiredService<IDistributedCache>(),
            sp.GetRequiredService<IOptions<PinotechrdSecurityOptions>>()));
        services.AddScoped<ISecurityStore>(sp => sp.GetRequiredService<TenantCacheStore>());
        services.AddScoped<ISecurityCacheInvalidator>(sp => sp.GetRequiredService<TenantCacheStore>());

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

        // The defaults are applied from the configured PinotechrdSecurityOptions, so the flag is honoured however and
        // whenever the application sets it. Registered here, after AddIdentity (whose defaults it may clear), so a host
        // Configure<AuthenticationOptions> after this call still wins, as before.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<AuthenticationOptions>, DefaultAuthenticationSchemesSetup>());
        services.AddAuthentication()
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
                // A smaller skew the application chose is kept; a larger one (the framework default is 5 minutes) is
                // lowered, so an expired token is not accepted for longer than the configured maximum.
                if (parameters.ClockSkew > settings.MaximumClockSkew)
                {
                    parameters.ClockSkew = settings.MaximumClockSkew;
                }

                // Every other way to widen what those settings accept is cleared: an issuer or audience list (accepted
                // in addition to the single value), and validator delegates, which replace the built-in issuer,
                // audience, lifetime and algorithm checks instead of adding to them.
                parameters.ValidIssuers = null;
                parameters.ValidAudiences = null;
                parameters.IssuerValidator = null;
                parameters.IssuerValidatorUsingConfiguration = null;
                parameters.AudienceValidator = null;
                parameters.LifetimeValidator = null;
                parameters.AlgorithmValidator = null;
                // Only the configured secrets are accepted: the current one first, then the previous ones
                // (validation only). Every other way to supply a key or skip the signature check is cleared: a key,
                // resolver or signature validator the application set, and keys from OpenID Connect metadata
                // (Authority, MetadataAddress, Configuration, ConfigurationManager), which the handler then never
                // fetches.
                parameters.IssuerSigningKey = null;
                parameters.IssuerSigningKeys = JwtSigningKeys.ValidationKeys(settings);
                parameters.IssuerSigningKeyResolver = null;
                parameters.IssuerSigningKeyResolverUsingConfiguration = null;
                parameters.SignatureValidator = null;
                parameters.SignatureValidatorUsingConfiguration = null;
                parameters.ConfigurationManager = null;
                jwt.Configuration = null;
                jwt.ConfigurationManager = null;
            });

        // The PostConfigure above runs after every Configure, but a PostConfigure registered after this call runs after
        // it. Validation runs once all of them have run: it checks the final options, so a later change that weakens
        // the policy fails the host at start (and the first use of the options) instead of accepting tokens.
        // Checked at start by a hosted service rather than ValidateOnStart: hosted services start after the options
        // marked ValidateOnStart are validated, so invalid security options still fail with their own single error.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<JwtBearerOptions>, JwtBearerPolicyValidator>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, JwtBearerPolicyStartupCheck>());

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

    /// <summary>
    /// Sets JWT bearer as the default authenticate and challenge scheme unless
    /// <see cref="PinotechrdSecurityOptions.SetDefaultAuthenticationSchemes"/> is <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// When the flag is <see langword="false"/>, the defaults that <c>AddIdentity</c> sets (authenticate and
    /// challenge to <see cref="IdentityConstants.ApplicationScheme"/>, sign-in to
    /// <see cref="IdentityConstants.ExternalScheme"/>) are cleared, but only while they still hold Identity's values,
    /// so the host's <c>DefaultScheme</c> applies and a value the host set explicitly is kept. Registered after
    /// <c>AddIdentity</c>, so its values are already in place when this runs.
    /// </remarks>
    private sealed class DefaultAuthenticationSchemesSetup : IConfigureOptions<AuthenticationOptions>
    {
        private readonly IOptions<PinotechrdSecurityOptions> _security;

        public DefaultAuthenticationSchemesSetup(IOptions<PinotechrdSecurityOptions> security)
        {
            _security = security;
        }

        private bool ReadSetDefaultAuthenticationSchemes()
        {
            try
            {
                return _security.Value.SetDefaultAuthenticationSchemes;
            }
            catch (OptionsValidationException)
            {
                // The authentication options are also built by tools that resolve the scheme provider without
                // configuration (for example OpenAPI generation at build time), which must keep working. Falling back
                // to the flag's default is safe: an invalid configuration still fails the host at start
                // (ValidateOnStart), and every other read of these options throws the same exception.
                return true;
            }
        }

        public void Configure(AuthenticationOptions options)
        {
            if (ReadSetDefaultAuthenticationSchemes())
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                return;
            }

            if (options.DefaultAuthenticateScheme == IdentityConstants.ApplicationScheme)
            {
                options.DefaultAuthenticateScheme = null;
            }

            if (options.DefaultChallengeScheme == IdentityConstants.ApplicationScheme)
            {
                options.DefaultChallengeScheme = null;
            }

            if (options.DefaultSignInScheme == IdentityConstants.ExternalScheme)
            {
                options.DefaultSignInScheme = null;
            }
        }
    }
}
