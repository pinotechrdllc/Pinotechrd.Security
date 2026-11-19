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

    /// <summary>
    /// Lets the host start when nothing proves that a user belongs to the tenant it signs in to. Default
    /// <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library relies on membership only when all three hold for the context passed to
    /// <c>AddPinotechrdSecurity</c>: it derives from <see cref="Data.PinotechrdSecurityDbContext{TUser, TRole}"/>, its
    /// registered options were built with <c>UsePinotechrdSecurity()</c>, and in
    /// <see cref="Data.TenantSchemaMode.SearchPath"/> <c>ApplicationTakesResponsibilityForSearchPath</c> is off.
    /// Otherwise, with no <see cref="Interfaces.IIdentityValidator{TUser}"/> registered, options validation fails when
    /// the host starts or when the options are first read.
    /// </para>
    /// <para>
    /// The check cannot see the database provider: one that ignores schemas (for example SQLite or InMemory on a
    /// single shared database) puts every tenant's users in the same tables unless each tenant has its own database.
    /// Set this to <see langword="true"/> only when the application checks membership in another way; otherwise a
    /// user of one tenant can obtain a token for another tenant. The value is shared by every
    /// <c>AddPinotechrdSecurity</c> call, and binding these options from configuration lets configuration set it.
    /// </para>
    /// </remarks>
    public bool AllowUnverifiedTenantMembership { get; set; }
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
