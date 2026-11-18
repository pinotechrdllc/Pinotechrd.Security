using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Interfaces;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Request sources the tenant resolution middleware may read the tenant identifier from.
/// </summary>
/// <remarks>
/// For an authenticated principal the verified claim is the only source, whatever these flags say:
/// <see cref="Claim"/> is always in effect and cannot be turned off. The flags only decide what an
/// anonymous request may use: with <see cref="Header"/> it may name its tenant in the header; without it,
/// an anonymous request has no tenant. <c>Header</c> alone therefore behaves like <c>Claim | Header</c>.
/// </remarks>
[Flags]
public enum TenantSources
{
    /// <summary>
    /// Anonymous requests have no tenant. Authenticated requests still use the claim.
    /// </summary>
    None = 0,

    /// <summary>
    /// The claim named by <see cref="TenantResolutionOptions.ClaimType"/> on an authenticated principal.
    /// The only verified source. Always in effect for authenticated principals.
    /// </summary>
    Claim = 1,

    /// <summary>
    /// The request header named by <see cref="TenantResolutionOptions.HeaderName"/>. Unverified: read only for
    /// anonymous requests, never for an authenticated principal.
    /// </summary>
    Header = 2
}

/// <summary>
/// What the tenant resolution middleware does when an anonymous request that requires a tenant has none.
/// </summary>
public enum MissingTenantBehavior
{
    /// <summary>
    /// Answer <c>400 Bad Request</c> with the code <see cref="TenantResolutionErrorCodes.TenantRequired"/>.
    /// </summary>
    Reject = 0,

    /// <summary>
    /// Continue without a tenant, so authentication, authorization or the endpoint decide.
    /// An anonymous request to a protected endpoint then gets <c>401</c> from authorization.
    /// </summary>
    Continue = 1
}

/// <summary>
/// Stable machine-readable codes written in the <c>code</c> member of the problem details
/// returned by the tenant resolution middleware.
/// </summary>
public static class TenantResolutionErrorCodes
{
    /// <summary>
    /// The request requires a tenant and none was resolved.
    /// </summary>
    public const string TenantRequired = "tenant_required";

    /// <summary>
    /// The tenant identifier is malformed, unknown or not active, or an authenticated principal has no tenant
    /// claim. All these cases return this same code.
    /// </summary>
    public const string TenantInvalid = "tenant_invalid";
}

/// <summary>
/// Options for configuring tenant resolution.
/// </summary>
public class TenantResolutionOptions
{
    /// <summary>
    /// Header name used to resolve tenant identifier.
    /// </summary>
    public string HeaderName { get; set; } = "TenantId";

    /// <summary>
    /// Claim type used to resolve tenant identifier from authenticated principals.
    /// </summary>
    public string ClaimType { get; set; } = "tenant_id";

    /// <summary>
    /// Sources anonymous requests may use. Default: <see cref="TenantSources.Claim"/> and <see cref="TenantSources.Header"/>.
    /// </summary>
    /// <remarks>
    /// An authenticated principal is resolved from its claim only; the header is never read for it, so a header
    /// naming another tenant is ignored and causes no rejection. An authenticated principal without the claim
    /// gets <see cref="TenantResolutionErrorCodes.TenantInvalid"/> on a path that requires a tenant. The claim
    /// comes from a token whose signature was validated, while the header is caller-supplied; RFC 9700 and
    /// OWASP ASVS treat the validated token as the only authority for the caller's context. The header only
    /// serves anonymous requests, such as login, and the tenant it names is checked against
    /// <see cref="ITenantStore"/> before it is used.
    /// </remarks>
    public TenantSources Sources { get; set; } = TenantSources.Claim | TenantSources.Header;

    /// <summary>
    /// What happens when an anonymous request that requires a tenant has none. Default: <see cref="MissingTenantBehavior.Reject"/>.
    /// A tenant identifier that is present but malformed, unknown or inactive is always rejected, and so is an
    /// authenticated principal without the tenant claim.
    /// </summary>
    public MissingTenantBehavior OnMissingTenant { get; set; } = MissingTenantBehavior.Reject;

    /// <summary>
    /// Requests whose path starts with this prefix require a tenant. Default: <c>/api</c>.
    /// Matching is by whole path segments, ignoring case: <c>/api</c> matches <c>/api</c> and <c>/api/x</c>,
    /// not <c>/apix</c>. Use <c>/</c> to require a tenant on every path, or <see langword="null"/> or empty to require it on none.
    /// </summary>
    public string? RequiredPathPrefix { get; set; } = "/api";

    /// <summary>
    /// Request path prefixes that bypass tenant resolution. Matched by whole path segments, ignoring case.
    /// </summary>
    public List<string> SkipPaths { get; set; } = new();

    /// <summary>
    /// When <see langword="true"/>, <see cref="DbSchemaProvider"/> returns the shared schema when no tenant is
    /// resolved. Default <see langword="false"/>: it throws instead. Set it only where no tenant is expected,
    /// such as design-time tooling.
    /// </summary>
    public bool UseSharedSchemaWhenNoTenant { get; set; }
}

/// <summary>
/// Middleware to resolve the current tenant from the authenticated claim or, for anonymous requests, a header.
/// </summary>
/// <remarks>
/// Rejections are written through <see cref="IProblemDetailsService"/> when one is registered
/// (<c>application/problem+json</c>, RFC 9457) with a <c>code</c> member from
/// <see cref="TenantResolutionErrorCodes"/>; otherwise a plain-text body is written.
/// A malformed, unknown or inactive tenant gets the same status and body: the identifier is checked against
/// <see cref="TenantIdentifier"/> first, then <see cref="ITenantStore.TenantExistsAsync"/>, which answers both
/// unknown and inactive with <see langword="false"/>.
/// When authentication is configured, the middleware must run after <c>UseAuthentication()</c>; otherwise it
/// throws <see cref="InvalidOperationException"/> instead of trusting the header of a request whose principal
/// was never read. Hosts without any authentication scheme are not affected.
/// Tenant identifiers and header values are never written to logs.
/// </remarks>
public class TenantResolutionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly TenantResolutionOptions _options;
    private readonly ILogger<TenantResolutionMiddleware> _logger;

    /// <summary>
    /// Initializes the tenant resolution middleware.
    /// </summary>
    public TenantResolutionMiddleware(
        RequestDelegate next,
        TenantResolutionOptions options,
        ILogger<TenantResolutionMiddleware> logger)
    {
        _next = next;
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Resolves tenant context from the configured sources and validates tenant existence.
    /// </summary>
    /// <exception cref="InvalidOperationException">Authentication is configured but has not run before this middleware.</exception>
    public async Task InvokeAsync(HttpContext context, TenantContext tenantContext, ITenantStore tenantStore)
    {
        var path = context.Request.Path;

        // Skip resolution for specific paths
        if (_options.SkipPaths.Any(p => MatchesPrefix(path, p)))
        {
            await _next(context);
            return;
        }

        var required = MatchesPrefix(path, _options.RequiredPathPrefix);
        string? tenantId = null;

        if (context.User?.Identity?.IsAuthenticated == true)
        {
            // 1. Authenticated principal: the verified claim is the only source.
            tenantId = context.User.FindFirstValue(_options.ClaimType);
            if (string.IsNullOrEmpty(tenantId))
            {
                if (required)
                {
                    await RejectAsync(context, TenantResolutionErrorCodes.TenantInvalid, "Invalid tenant", $"Invalid {_options.HeaderName}.");
                    return;
                }

                await _next(context);
                return;
            }
        }
        else if (_options.Sources.HasFlag(TenantSources.Header))
        {
            // 2. Anonymous request: the header, only once authentication has had its chance to run.
            await EnsureAuthenticationRanAsync(context);

            if (context.Request.Headers.TryGetValue(_options.HeaderName, out var headerValue))
            {
                tenantId = headerValue.FirstOrDefault();
            }
        }

        // 3. Validation: format first, so a malformed value never reaches the store.
        if (!string.IsNullOrEmpty(tenantId))
        {
            if (TenantIdentifier.IsValid(tenantId) && await tenantStore.TenantExistsAsync(tenantId))
            {
                tenantContext.SetTenant(tenantId);
                await _next(context);
                return;
            }

            await RejectAsync(context, TenantResolutionErrorCodes.TenantInvalid, "Invalid tenant", $"Invalid {_options.HeaderName}.");
            return;
        }

        if (required && _options.OnMissingTenant == MissingTenantBehavior.Reject)
        {
            await RejectAsync(context, TenantResolutionErrorCodes.TenantRequired, "Tenant required", $"{_options.HeaderName} is required.");
            return;
        }

        await _next(context);
    }

    private static bool MatchesPrefix(PathString path, string? prefix)
    {
        if (string.IsNullOrEmpty(prefix)) return false;

        var normalized = (prefix[0] == '/' ? prefix : "/" + prefix).TrimEnd('/');
        if (normalized.Length == 0) return true; // "/" means every path

        return path.StartsWithSegments(new PathString(normalized), StringComparison.OrdinalIgnoreCase);
    }

    private static async Task EnsureAuthenticationRanAsync(HttpContext context)
    {
        // The authentication middleware sets IAuthenticationFeature on every request, anonymous or not.
        if (context.Features.Get<IAuthenticationFeature>() != null) return;

        var schemes = context.RequestServices?.GetService<IAuthenticationSchemeProvider>();
        if (schemes == null || await schemes.GetDefaultAuthenticateSchemeAsync() == null) return;

        throw new InvalidOperationException(
            "UseTenantResolution() runs before UseAuthentication(). Call app.UseAuthentication() before " +
            "app.UseTenantResolution(), so the tenant of an authenticated user comes from its verified claim.");
    }

    private async Task RejectAsync(HttpContext context, string code, string title, string plainTextMessage)
    {
        _logger.LogDebug("Tenant resolution rejected the request with code {Code}.", code);

        context.Response.StatusCode = StatusCodes.Status400BadRequest;

        var problemDetailsService = context.RequestServices?.GetService<IProblemDetailsService>();
        if (problemDetailsService != null)
        {
            var problem = new ProblemDetails
            {
                Status = StatusCodes.Status400BadRequest,
                Title = title
            };
            problem.Extensions["code"] = code;

            var written = await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
            {
                HttpContext = context,
                ProblemDetails = problem
            });

            if (written)
            {
                return;
            }
        }

        await context.Response.WriteAsync(plainTextMessage);
    }
}
