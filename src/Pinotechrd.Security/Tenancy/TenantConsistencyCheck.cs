using System.Runtime.CompilerServices;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Pinotechrd.Security.Core;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Wraps the routed endpoint so that, right before it executes, the final principal is checked against the
/// resolved tenant.
/// </summary>
/// <remarks>
/// The authorization middleware runs between <c>UseTenantResolution</c> and the endpoint and merges the
/// principals of the endpoint's own authentication schemes into <see cref="HttpContext.User"/>. So when the
/// wrapped endpoint starts, <see cref="HttpContext.User"/> is final. If any identity is authenticated, the
/// tenant claim of the authenticated identities must exist, be a single value, and equal
/// <see cref="TenantContext.TenantId"/>; otherwise the request gets the <c>tenant_invalid</c> rejection and
/// the endpoint does not run. Then the access tokens of the library must still belong to a live session
/// (<see cref="IAccessTokenSessionCheck"/>), or the request gets <c>401 session_revoked</c>; an endpoint that allows
/// anonymous access (sign-in, refresh) runs instead as anonymous, so a client still sending its ended token can sign in
/// again. The wrapper keeps the endpoint's route pattern, order, metadata and name.
/// </remarks>
internal sealed class TenantConsistencyCheck
{
    private readonly TenantResolutionOptions _options;
    private readonly ILogger _logger;
    private readonly ConditionalWeakTable<Endpoint, Endpoint> _wrapped = new();

    public TenantConsistencyCheck(TenantResolutionOptions options, ILogger logger)
    {
        _options = options;
        _logger = logger;
    }

    public Endpoint Wrap(Endpoint endpoint)
    {
        if (endpoint.RequestDelegate == null || _wrappers.TryGetValue(endpoint, out _)) return endpoint;
        return _wrapped.GetValue(endpoint, original =>
        {
            var wrapper = Create(original);
            _wrappers.AddOrUpdate(wrapper, Marker);
            return wrapper;
        });
    }

    private static readonly object Marker = new();
    private readonly ConditionalWeakTable<Endpoint, object> _wrappers = new();

    private Endpoint Create(Endpoint endpoint)
    {
        var original = endpoint.RequestDelegate!;
        RequestDelegate checkedDelegate = async context =>
        {
            if (await IsConsistentOrRejectAsync(context))
            {
                await original(context);
            }
        };

        return endpoint is RouteEndpoint route
            ? new RouteEndpoint(checkedDelegate, route.RoutePattern, route.Order, route.Metadata, route.DisplayName)
            : new Endpoint(checkedDelegate, endpoint.Metadata, endpoint.DisplayName);
    }

    private async Task<bool> IsConsistentOrRejectAsync(HttpContext context)
    {
        var status = TenantClaims.Read(context.User, _options.ClaimType, out var claimTenant);
        if (status == TenantClaimStatus.NotAuthenticated) return true;

        var resolved = context.RequestServices?.GetService<TenantContext>()?.TenantId;
        if (status == TenantClaimStatus.Single
            && resolved != null
            && string.Equals(resolved, claimTenant, StringComparison.Ordinal))
        {
            var sessions = context.RequestServices?.GetService<IAccessTokenSessionCheck>();
            if (sessions == null || await sessions.IsCurrentAsync(context, resolved, context.RequestAborted)) return true;

            SecurityLog.AccessTokenSessionEnded(Events(context), resolved);

            if (context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() != null)
            {
                // The ended session's identity is dropped: the endpoint sees an anonymous request.
                context.User = new ClaimsPrincipal(new ClaimsIdentity());
                return true;
            }

            context.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
            await TenantResolutionMiddleware.RejectAsync(
                context, _logger, TenantResolutionErrorCodes.SessionRevoked, "Session revoked", "Session revoked.", StatusCodes.Status401Unauthorized);
            return false;
        }

        SecurityLog.TenantMismatch(Events(context), TenantResolutionErrorCodes.TenantInvalid);
        await TenantResolutionMiddleware.RejectAsync(
            context, _logger, TenantResolutionErrorCodes.TenantInvalid, "Invalid tenant", $"Invalid {_options.HeaderName}.");
        return false;
    }

    private static ILogger? Events(HttpContext context) => SecurityLog.Create(context.RequestServices?.GetService<ILoggerFactory>());
}
