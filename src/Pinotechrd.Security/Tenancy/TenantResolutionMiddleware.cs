using Microsoft.AspNetCore.Http;
using Pinotechrd.Security.Interfaces;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace Pinotechrd.Security.Tenancy;

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
    /// JSON property name used when resolving tenant from request body.
    /// </summary>
    public string JsonProperty { get; set; } = "tenantId";

    /// <summary>
    /// Query string parameter used for tenant resolution fallback.
    /// </summary>
    public string QueryParameter { get; set; } = "tenantId";

    /// <summary>
    /// Request path prefixes that bypass tenant resolution.
    /// </summary>
    public List<string> SkipPaths { get; set; } = new();
}

/// <summary>
/// Middleware to resolve the current tenant from multiple sources.
/// </summary>
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
    /// Resolves tenant context from claims or request inputs and validates tenant existence.
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

        // 1. Authenticated principal claim (trusted source)
        if (context.User?.Identity?.IsAuthenticated == true)
        {
            tenantId = context.User.FindFirstValue(_options.ClaimType);
        }

        // 2. HTTP Header
        if (string.IsNullOrEmpty(tenantId) && context.Request.Headers.TryGetValue(_options.HeaderName, out var headerValue))
        {
            tenantId = headerValue.FirstOrDefault();
        }

        // 3. Request Body (JSON)
        if (string.IsNullOrEmpty(tenantId) &&
            context.Request.ContentLength > 0 && 
            context.Request.ContentType != null &&
            context.Request.ContentType.Contains("application/json"))
        {
            try
            {
                context.Request.EnableBuffering();
                using var reader = new StreamReader(
                    context.Request.Body,
                    encoding: System.Text.Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    bufferSize: 1024,
                    leaveOpen: true);

                var body = await reader.ReadToEndAsync();
                context.Request.Body.Position = 0;

                if (!string.IsNullOrWhiteSpace(body))
                {
                    using var jsonDoc = JsonDocument.Parse(body);
                    if (jsonDoc.RootElement.TryGetProperty(_options.JsonProperty, out var tenantElement))
                    {
                        tenantId = tenantElement.GetString();
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to extract tenant from request body.");
            }
        }

        // 4. Query String
        if (string.IsNullOrEmpty(tenantId) && context.Request.Query.ContainsKey(_options.QueryParameter))
        {
            tenantId = context.Request.Query[_options.QueryParameter];
        }

        // 5. Validation
        if (!string.IsNullOrEmpty(tenantId))
        {
            if (await tenantStore.TenantExistsAsync(tenantId))
            {
                tenantContext.SetTenant(tenantId);
                await _next(context);
                return;
            }
            
            context.Response.StatusCode = 400; 
            await context.Response.WriteAsync($"Invalid {_options.HeaderName}.");
            return;
        }

        // If not found and not a skip path, block API requests
        if (path != null && path.StartsWith("/api"))
        {
             context.Response.StatusCode = 400;
             await context.Response.WriteAsync($"{_options.HeaderName} is required.");
             return;
        }

        await _next(context);
    }
}
