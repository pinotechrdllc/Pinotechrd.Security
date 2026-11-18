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
    /// Minimum accepted length of <see cref="Secret"/>, in UTF-8 bytes. Values below 32 are ignored:
    /// the floor is 32 bytes and cannot be lowered.
    /// </summary>
    public int MinimumSecretLength { get; set; } = 32;

    /// <summary>
    /// Expected issuer. Required: the host fails to start without it.
    /// </summary>
    public string? Issuer { get; set; }

    /// <summary>
    /// Expected audience. Required: the host fails to start without it.
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
