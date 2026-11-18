using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
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
    public static IServiceCollection AddPinotechrdSecurity<TContext, TUser, TRole>(
        this IServiceCollection services,
        Action<PinotechrdSecurityOptions>? configure = null)
        where TContext : DbContext
        where TUser : BaseSecurityUser, new()
        where TRole : BaseSecurityRole, new()
    {
        var options = new PinotechrdSecurityOptions();
        configure?.Invoke(options);

        services.Configure<PinotechrdSecurityOptions>(o => 
        {
            o.Jwt = options.Jwt;
        });

        if (string.IsNullOrWhiteSpace(options.Jwt.Secret))
        {
            throw new InvalidOperationException("PinotechrdSecurity requires a non-empty JWT secret.");
        }

        if (options.Jwt.Secret.Length < options.Jwt.MinimumSecretLength)
        {
            throw new InvalidOperationException($"JWT secret must be at least {options.Jwt.MinimumSecretLength} characters.");
        }

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
        services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        services.AddScoped<IPinotechrdAuthManager<TUser>, PinotechrdAuthManager<TUser>>();
        services.AddScoped<ISecurityDbContext>(sp => sp.GetRequiredService<TContext>() as ISecurityDbContext ?? throw new InvalidOperationException("DbContext does not implement ISecurityDbContext"));
        services.AddScoped<IPinotechrdSecurityManager<TUser, TRole>, PinotechrdSecurityManager<TUser, TRole>>();

        services.AddAuthentication(auth =>
        {
            auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(jwt =>
        {
            jwt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = !string.IsNullOrEmpty(options.Jwt.Issuer),
                ValidateAudience = !string.IsNullOrEmpty(options.Jwt.Audience),
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = options.Jwt.Issuer,
                ValidAudience = options.Jwt.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Jwt.Secret))
            };
        });

        services.AddAuthorization();
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();

        return services;
    }

    /// <summary>
    /// Adds the tenant resolution middleware to the pipeline.
    /// </summary>
    /// <param name="app">Application pipeline builder.</param>
    /// <returns>The same application builder for chaining.</returns>
    public static IApplicationBuilder UseTenantResolution(this IApplicationBuilder app)
    {
        return app.UseMiddleware<TenantResolutionMiddleware>();
    }
}
