using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.OutputCaching;
using Microsoft.Extensions.DependencyInjection;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Output cache policy that keys cached responses by the tenant resolved for the request.
/// </summary>
/// <remarks>
/// <para>
/// The key uses <see cref="TenantContext.TenantId"/>, the tenant after resolution and validation, never the raw
/// header. Caching is turned off for the request (no lookup, no storage) when:
/// </para>
/// <list type="bullet">
/// <item><description>tenant resolution has not run for the request: <c>UseOutputCache()</c> is placed before
/// <c>UseTenantResolution()</c>, or the path is one of <see cref="TenantResolutionOptions.SkipPaths"/>;</description></item>
/// <item><description>authorization has not run for the request: <c>UseOutputCache()</c> is placed before
/// <c>UseAuthorization()</c>, where a user authenticated only by an endpoint's own scheme still looks anonymous, so
/// a per-user response could be stored under the tenant key;</description></item>
/// <item><description>the path requires a tenant (<see cref="TenantResolutionOptions.RequiredPathPrefix"/>) and none was resolved.</description></item>
/// </list>
/// <para>
/// Add it to a policy that keeps ASP.NET Core's defaults (only GET and HEAD, no authenticated requests); see
/// <see cref="TenantOutputCacheExtensions.CacheOutputPerTenant{TBuilder}"/>. Response caching (<c>UseResponseCaching</c>,
/// <c>Vary</c> headers) and caches in front of the application (CDN, reverse proxy) are not covered.
/// </para>
/// </remarks>
public sealed class TenantOutputCachePolicy : IOutputCachePolicy
{
    /// <summary>Name of the vary-by value that holds the tenant.</summary>
    public const string VaryByKey = "pinotechrd-tenant";

    // Set by ASP.NET Core's authorization middleware on every request with an endpoint.
    private const string AuthorizationRanKey = "__AuthorizationMiddlewareWithEndpointInvoked";

    /// <inheritdoc />
    public ValueTask CacheRequestAsync(OutputCacheContext context, CancellationToken cancellation)
    {
        var http = context.HttpContext;
        if (!http.Items.ContainsKey(TenantResolutionMiddleware.TenantResolutionRanKey)
            || !http.Items.ContainsKey(AuthorizationRanKey))
        {
            Refuse(context);
            return ValueTask.CompletedTask;
        }

        var tenant = http.RequestServices.GetService<TenantContext>()?.TenantId;
        if (tenant == null)
        {
            var options = http.RequestServices.GetService<TenantResolutionOptions>() ?? new TenantResolutionOptions();
            if (TenantResolutionMiddleware.MatchesPrefix(http.Request.Path, options.RequiredPathPrefix))
            {
                Refuse(context);
                return ValueTask.CompletedTask;
            }
        }

        // An empty value keeps "no tenant" apart from every real tenant id (ids are never empty).
        context.CacheVaryByRules.VaryByValues[VaryByKey] = tenant ?? string.Empty;
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask ServeFromCacheAsync(OutputCacheContext context, CancellationToken cancellation) => ValueTask.CompletedTask;

    /// <inheritdoc />
    public ValueTask ServeResponseAsync(OutputCacheContext context, CancellationToken cancellation) => ValueTask.CompletedTask;

    private static void Refuse(OutputCacheContext context)
    {
        context.AllowCacheLookup = false;
        context.AllowCacheStorage = false;
    }
}

/// <summary>
/// Endpoint helpers for tenant-aware output caching.
/// </summary>
public static class TenantOutputCacheExtensions
{
    /// <summary>
    /// Caches the endpoint's output per resolved tenant: ASP.NET Core's default output cache policy, your settings,
    /// then <see cref="TenantOutputCachePolicy"/>. Requires <c>UseOutputCache()</c> after <c>UseTenantResolution()</c> and <c>UseAuthorization()</c>.
    /// </summary>
    /// <typeparam name="TBuilder">Endpoint convention builder.</typeparam>
    /// <param name="builder">The endpoint (or group) to cache.</param>
    /// <param name="configure">Optional extra settings, such as expiry or tags.</param>
    /// <returns>The same builder.</returns>
    public static TBuilder CacheOutputPerTenant<TBuilder>(this TBuilder builder, Action<OutputCachePolicyBuilder>? configure = null)
        where TBuilder : IEndpointConventionBuilder
    {
        return builder.CacheOutput(policy =>
        {
            configure?.Invoke(policy);
            policy.AddPolicy<TenantOutputCachePolicy>();
        });
    }
}
