using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
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
/// "Authenticated" means by the default authenticate scheme when the middleware runs: with
/// <see cref="Options.PinotechrdSecurityOptions.SetDefaultAuthenticationSchemes"/> set to <see langword="false"/> and
/// a default other than JWT bearer, a request carrying only a bearer token is anonymous here and must send the tenant
/// header, unless the default is a policy scheme that forwards to JWT bearer when an <c>Authorization: Bearer</c>
/// header is present.
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

    /// <summary>
    /// The access token's user signed out, had its sessions revoked, changed or reset its password, was deactivated or
    /// no longer exists in the tenant (<see cref="Options.JwtSettings.ValidateSecurityStamp"/>). Returned with status
    /// <c>401</c>; sign in again.
    /// </summary>
    public const string SessionRevoked = "session_revoked";
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
    /// <para>
    /// An authenticated principal is resolved from its claim only; the header is never read for it, so a header
    /// naming another tenant is ignored and causes no rejection. An authenticated principal without the claim
    /// gets <see cref="TenantResolutionErrorCodes.TenantInvalid"/> on a path that requires a tenant. With the
    /// library's JWT bearer scheme the claim comes from a token whose signature was validated, while the header is
    /// caller-supplied; RFC 9700 and OWASP ASVS treat the validated token as the only authority for the caller's
    /// context. For any other scheme (for example cookies or OpenID Connect when
    /// <see cref="Options.PinotechrdSecurityOptions.SetDefaultAuthenticationSchemes"/> is <see langword="false"/>), the
    /// host is responsible for a tenant claim whose membership was verified and for exempting it from inbound claim
    /// mapping. The middleware reads the principal of the default authenticate scheme, so with a default other than
    /// JWT bearer a request carrying only a bearer token is anonymous here and must send the header, unless the
    /// default is a policy scheme that forwards to JWT bearer when an <c>Authorization: Bearer</c> header is present.
    /// The header serves
    /// requests whose principal is not authenticated when the middleware runs, such as login and refresh, and
    /// the tenant it names is checked against <see cref="ITenantStore"/> before it is used.
    /// </para>
    /// <para>
    /// Exact rule: the tenant claim is read from authenticated identities only (a claim on an unauthenticated
    /// identity is ignored); if two authenticated identities carry different tenants, the request is rejected
    /// with <see cref="TenantResolutionErrorCodes.TenantInvalid"/>. If no identity is authenticated when the
    /// middleware runs, the request may name its tenant in the header, whatever other headers it carries (an
    /// expired bearer token, or a gateway's <c>Authorization: Basic</c>).
    /// </para>
    /// <para>
    /// An endpoint can authenticate with its own schemes after this middleware has run. So, before any endpoint of
    /// the request runs (after authorization), an authenticated user must carry exactly one tenant claim equal to
    /// the resolved tenant; otherwise the request gets <c>400</c> <see cref="TenantResolutionErrorCodes.TenantInvalid"/>.
    /// This also applies to an authenticated user without the claim on a path that does not require a tenant. Then
    /// the library's access token must still belong to a live session, or the request gets <c>401</c>
    /// <see cref="TenantResolutionErrorCodes.SessionRevoked"/> (see <c>JwtSettings.ValidateSecurityStamp</c>).
    /// Skip paths are not checked.
    /// </para>
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
/// Middleware to resolve the current tenant from the authenticated claim or, for requests not authenticated
/// when it runs, a header (see <see cref="TenantResolutionOptions.Sources"/> for the exact rule).
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
    private readonly TenantConsistencyCheck _consistency;

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
        _consistency = new TenantConsistencyCheck(options, logger);
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

        // Every endpoint this request runs gets the tenant consistency check, whether routing ran before this
        // middleware or runs after it: the endpoint feature wraps any endpoint set on the request from now on.
        context.Features.Set<IEndpointFeature>(new ConsistencyEndpointFeature(context.Features.Get<IEndpointFeature>(), _consistency));
        context.Items[TenantResolutionRanKey] = true;

        await ResolveAsync(context, tenantContext, tenantStore, path);
    }

    /// <summary>Key of the <see cref="HttpContext.Items"/> entry set once this middleware has resolved the request.</summary>
    internal const string TenantResolutionRanKey = "Pinotechrd.Security.TenantResolutionRan";

    /// <summary>
    /// Endpoint feature that hands out only wrapped endpoints. Routing and re-execution (exception handler, status
    /// code pages) set the endpoint through <see cref="IEndpointFeature"/>, and the endpoint middleware reads it from
    /// there, so no endpoint of this request can run without the check.
    /// </summary>
    private sealed class ConsistencyEndpointFeature : IEndpointFeature
    {
        private readonly TenantConsistencyCheck _check;
        private Endpoint? _endpoint;

        public ConsistencyEndpointFeature(IEndpointFeature? previous, TenantConsistencyCheck check)
        {
            _check = check;
            _endpoint = previous?.Endpoint is { } current ? check.Wrap(current) : null;
        }

        public Endpoint? Endpoint
        {
            get => _endpoint;
            set => _endpoint = value == null ? null : _check.Wrap(value);
        }
    }

    private async Task ResolveAsync(HttpContext context, TenantContext tenantContext, ITenantStore tenantStore, PathString path)
    {
        var required = MatchesPrefix(path, _options.RequiredPathPrefix);
        string? tenantId = null;

        var claimStatus = TenantClaims.Read(context.User, _options.ClaimType, out var claimTenant);
        if (claimStatus == TenantClaimStatus.Conflict)
        {
            // Two authenticated identities name different tenants: neither can be trusted.
            await RejectAsync(context, _logger, TenantResolutionErrorCodes.TenantInvalid, "Invalid tenant", $"Invalid {_options.HeaderName}.");
            return;
        }

        if (claimStatus != TenantClaimStatus.NotAuthenticated)
        {
            // 1. Authenticated principal: the verified claim of its authenticated identities is the only source.
            tenantId = claimTenant;
            if (string.IsNullOrEmpty(tenantId))
            {
                if (required)
                {
                    await RejectAsync(context, _logger, TenantResolutionErrorCodes.TenantInvalid, "Invalid tenant", $"Invalid {_options.HeaderName}.");
                    return;
                }

                await _next(context);
                return;
            }
        }
        else
        {
            // 2. Not authenticated when this middleware runs: the header, once authentication has had its chance.
            //    Endpoint-specific schemes that authenticate later are checked by the consistency step.
            var useHeader = _options.Sources.HasFlag(TenantSources.Header);
            if (useHeader || context.Request.Headers.ContainsKey("Authorization"))
            {
                await EnsureAuthenticationRanAsync(context);
            }

            if (useHeader && context.Request.Headers.TryGetValue(_options.HeaderName, out var headerValue))
            {
                tenantId = headerValue.FirstOrDefault();
            }
        }

        // 3. Validation: format first, so a malformed value never reaches the store.
        //    The store is asked before any tenant-scoped context or model exists.
        if (!string.IsNullOrEmpty(tenantId))
        {
            if (TenantIdentifier.IsValid(tenantId) && await tenantStore.TenantExistsAsync(tenantId, context.RequestAborted))
            {
                tenantContext.SetTenant(tenantId);
                await _next(context);
                return;
            }

            await RejectAsync(context, _logger, TenantResolutionErrorCodes.TenantInvalid, "Invalid tenant", $"Invalid {_options.HeaderName}.");
            return;
        }

        if (required && _options.OnMissingTenant == MissingTenantBehavior.Reject)
        {
            await RejectAsync(context, _logger, TenantResolutionErrorCodes.TenantRequired, "Tenant required", $"{_options.HeaderName} is required.");
            return;
        }

        await _next(context);
    }

    internal static bool MatchesPrefix(PathString path, string? prefix)
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

        // Either scheme is enough: the JWT bearer scheme that AddPinotechrdSecurity always registers, even when the
        // host keeps its own defaults (SetDefaultAuthenticationSchemes = false), or any default authenticate scheme
        // (for example cookies), whose principal also feeds the tenant claim.
        var schemes = context.RequestServices?.GetService<IAuthenticationSchemeProvider>();
        if (schemes == null) return;
        if (await schemes.GetSchemeAsync(JwtBearerDefaults.AuthenticationScheme) == null
            && await schemes.GetDefaultAuthenticateSchemeAsync() == null) return;

        throw new InvalidOperationException(
            "UseTenantResolution() runs before UseAuthentication(). Call app.UseAuthentication() before " +
            "app.UseTenantResolution(), so the tenant of an authenticated user comes from its verified claim.");
    }

    internal static async Task RejectAsync(
        HttpContext context, ILogger logger, string code, string title, string plainTextMessage, int status = StatusCodes.Status400BadRequest)
    {
        logger.LogDebug("Tenant resolution rejected the request with code {Code}.", code);

        context.Response.StatusCode = status;

        var problemDetailsService = context.RequestServices?.GetService<IProblemDetailsService>();
        if (problemDetailsService != null)
        {
            var problem = new ProblemDetails
            {
                Status = status,
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
