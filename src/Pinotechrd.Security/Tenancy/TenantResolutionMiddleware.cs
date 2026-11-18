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
/// The precedence is fixed and does not follow the order of the flags: the claim of an
/// authenticated user is always read first, then the header. A configurable order would let an
/// unverified source override the verified claim.
/// </remarks>
[Flags]
public enum TenantSources
{
    /// <summary>
    /// No source. Every request is treated as having no tenant.
    /// </summary>
    None = 0,

    /// <summary>
    /// The claim named by <see cref="TenantResolutionOptions.ClaimType"/> on an authenticated principal.
    /// This is the only verified source.
    /// </summary>
    Claim = 1,

    /// <summary>
    /// The request header named by <see cref="TenantResolutionOptions.HeaderName"/>. Unverified:
    /// read only when the claim source did not produce a value.
    /// </summary>
    Header = 2
}

/// <summary>
/// What the tenant resolution middleware does when a request that requires a tenant has none.
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
    /// The resolved tenant identifier is unknown or not active. Both cases return this same code.
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
    /// Sources the tenant identifier may be read from. Default: <see cref="TenantSources.Claim"/>
    /// and <see cref="TenantSources.Header"/>.
    /// </summary>
    /// <remarks>
    /// The claim of an authenticated user always wins. When an authenticated user carries the claim,
    /// the header is not read at all, so a header with a different value neither overrides the claim
    /// nor causes a rejection. The claim comes from a token whose signature was validated, while the
    /// header is caller-supplied; RFC 9700 and OWASP ASVS treat the validated token as the authority
    /// for the caller's context. Rejecting a mismatch would add no protection, because the header is
    /// never used when the claim is present. Use <see cref="TenantSources.Claim"/> alone to accept
    /// only the verified source; the header is then not available to anonymous requests such as login.
    /// An authenticated principal without the claim falls through to the header.
    /// </remarks>
    public TenantSources Sources { get; set; } = TenantSources.Claim | TenantSources.Header;

    /// <summary>
    /// What happens when a request that requires a tenant has none. Default: <see cref="MissingTenantBehavior.Reject"/>.
    /// A tenant identifier that is present but unknown or inactive is always rejected.
    /// </summary>
    public MissingTenantBehavior OnMissingTenant { get; set; } = MissingTenantBehavior.Reject;

    /// <summary>
    /// Requests whose path starts with this prefix (case-insensitive) require a tenant. Default: <c>/api</c>.
    /// Use <c>/</c> to require a tenant on every path, or <see langword="null"/> or empty to require it on none.
    /// </summary>
    public string? RequiredPathPrefix { get; set; } = "/api";

    /// <summary>
    /// Request path prefixes that bypass tenant resolution.
    /// </summary>
    public List<string> SkipPaths { get; set; } = new();
}

/// <summary>
/// Middleware to resolve the current tenant from the authenticated claim or a request header.
/// </summary>
/// <remarks>
/// Rejections are written through <see cref="IProblemDetailsService"/> when one is registered
/// (<c>application/problem+json</c>, RFC 9457) with a <c>code</c> member from
/// <see cref="TenantResolutionErrorCodes"/>; otherwise a plain-text body is written.
/// An unknown tenant and an inactive tenant get the same status and body, because
/// <see cref="ITenantStore.TenantExistsAsync"/> answers both with <see langword="false"/>.
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
    public async Task InvokeAsync(HttpContext context, TenantContext tenantContext, ITenantStore tenantStore)
    {
        var path = context.Request.Path.Value?.ToLowerInvariant();

        // Skip resolution for specific paths
        if (_options.SkipPaths.Any(p => path != null && path.StartsWith(p.ToLowerInvariant())))
        {
            await _next(context);
            return;
        }

        string? tenantId = null;

        // 1. Authenticated principal claim (verified source). When present, no other source is read.
        if (_options.Sources.HasFlag(TenantSources.Claim) && context.User?.Identity?.IsAuthenticated == true)
        {
            tenantId = context.User.FindFirstValue(_options.ClaimType);
        }

        // 2. HTTP header (unverified source), only when the claim gave no value.
        if (string.IsNullOrEmpty(tenantId) &&
            _options.Sources.HasFlag(TenantSources.Header) &&
            context.Request.Headers.TryGetValue(_options.HeaderName, out var headerValue))
        {
            tenantId = headerValue.FirstOrDefault();
        }

        // 3. Validation
        if (!string.IsNullOrEmpty(tenantId))
        {
            if (await tenantStore.TenantExistsAsync(tenantId))
            {
                tenantContext.SetTenant(tenantId);
                await _next(context);
                return;
            }

            await RejectAsync(context, TenantResolutionErrorCodes.TenantInvalid, "Invalid tenant", $"Invalid {_options.HeaderName}.");
            return;
        }

        var prefix = _options.RequiredPathPrefix;
        if (_options.OnMissingTenant == MissingTenantBehavior.Reject &&
            !string.IsNullOrEmpty(prefix) &&
            path != null &&
            path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            await RejectAsync(context, TenantResolutionErrorCodes.TenantRequired, "Tenant required", $"{_options.HeaderName} is required.");
            return;
        }

        await _next(context);
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
