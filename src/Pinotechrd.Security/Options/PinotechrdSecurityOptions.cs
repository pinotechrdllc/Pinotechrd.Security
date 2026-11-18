using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Options;

/// <summary>
/// Configuration options for Pinotechrd Security.
/// </summary>
public class PinotechrdSecurityOptions
{
    /// <summary>
    /// Multi-tenancy settings.
    /// </summary>
    public TenantResolutionOptions Tenancy { get; } = new();

    /// <summary>
    /// JWT Authentication settings.
    /// </summary>
    public JwtSettings Jwt { get; set; } = new();
}

/// <summary>
/// Settings for JWT token generation and validation.
/// </summary>
public class JwtSettings
{
    /// <summary>
    /// Symmetric secret used to sign and validate JWT access tokens.
    /// </summary>
    public string Secret { get; set; } = string.Empty;

    /// <summary>
    /// Minimum accepted length for <see cref="Secret"/>.
    /// </summary>
    public int MinimumSecretLength { get; set; } = 32;

    /// <summary>
    /// Optional expected issuer for JWT validation.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// Optional expected audience for JWT validation.
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>
    /// Access token lifetime in minutes.
    /// </summary>
    public int ExpiryMinutes { get; set; } = 60;

    /// <summary>
    /// Refresh token lifetime in days.
    /// </summary>
    public int RefreshTokenExpiryDays { get; set; } = 7;
}
