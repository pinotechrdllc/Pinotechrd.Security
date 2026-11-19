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

    /// <summary>
    /// How long a tenant's subscription state and active module codes stay in the distributed cache. Default
    /// 5 minutes. Must be positive.
    /// </summary>
    /// <remarks>
    /// After a change, call <see cref="Interfaces.ISecurityCacheInvalidator.InvalidateTenantAsync"/> for the next check
    /// to see it. This expiration bounds how long a change that is not followed by an invalidation (a subscription
    /// reaching its end date, an edit made directly in the database) keeps the old answer.
    /// </remarks>
    public TimeSpan TenantCacheExpiration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Makes JWT bearer the default authenticate and challenge scheme. Default <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <see langword="true"/>, <c>AddPinotechrdSecurity</c> sets
    /// <c>AuthenticationOptions.DefaultAuthenticateScheme</c> and <c>DefaultChallengeScheme</c> to
    /// <c>JwtBearerDefaults.AuthenticationScheme</c>, which take precedence over a <c>DefaultScheme</c> the host set.
    /// </para>
    /// <para>
    /// Set it to <see langword="false"/> when the host keeps its own defaults (for example cookies or OpenID
    /// Connect). The JWT bearer scheme and the settings the library enforces on it are still registered, the
    /// library sets no default, and it clears the defaults that ASP.NET Core Identity sets
    /// (<c>DefaultAuthenticateScheme</c> and <c>DefaultChallengeScheme</c> equal to
    /// <c>IdentityConstants.ApplicationScheme</c>, <c>DefaultSignInScheme</c> equal to
    /// <c>IdentityConstants.ExternalScheme</c>) while they still hold those values, so the host's <c>DefaultScheme</c>
    /// applies; a value the host set explicitly is kept. JWT endpoints must then select the scheme themselves (for
    /// example <c>[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]</c>).
    /// </para>
    /// <para>
    /// With <see langword="false"/>, the tenant middleware reads the principal of the host's default scheme: a request
    /// that carries only a bearer token is anonymous there and must send the tenant header, unless the default is a
    /// policy scheme (<c>ForwardDefaultSelector</c>) that picks JWT bearer when an <c>Authorization: Bearer</c>
    /// header is present. For schemes other than the library's JWT bearer, the host is responsible for issuing a
    /// tenant claim whose membership was verified and for exempting it from inbound claim mapping.
    /// </para>
    /// <para>
    /// The value is read from <c>IOptions&lt;PinotechrdSecurityOptions&gt;</c>, so a later
    /// <c>Configure&lt;PinotechrdSecurityOptions&gt;</c> or configuration binding is honoured.
    /// </para>
    /// </remarks>
    public bool SetDefaultAuthenticationSchemes { get; set; } = true;
}

/// <summary>
/// Settings for JWT token generation and validation.
/// </summary>
public class JwtSettings
{
    /// <summary>
    /// Symmetric secret used to sign and validate JWT access tokens. Issued tokens carry its key id in the
    /// <c>kid</c> header: the first 16 lowercase hex characters of SHA-256 over the secret's UTF-8 bytes.
    /// </summary>
    public string Secret { get; set; } = string.Empty;

    /// <summary>
    /// Earlier secrets still accepted when validating tokens, never used to sign. Default empty.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Rolling rotation across several instances: (1) add the new secret here on every instance, so all of them
    /// accept it before any signs with it; (2) make it <see cref="Secret"/> and move the old one here, everywhere;
    /// (3) once the old secret's tokens are no longer needed (access tokens expired and the refresh window over),
    /// remove it. The library enforces no time limit: a secret here is accepted until it is removed.
    /// </para>
    /// <para>
    /// Never keep a leaked secret here: whoever holds it can forge tokens, and <c>GetPrincipalFromExpiredToken</c>
    /// accepts them at any age. Remove it and rotate at once. Keys are read once, when the host starts: a change
    /// takes effect only after a restart.
    /// </para>
    /// <para>
    /// Each entry must meet the same minimum length as <see cref="Secret"/>, and must not be empty, equal to
    /// <see cref="Secret"/>, or repeated.
    /// </para>
    /// </remarks>
    public IList<string> PreviousSecrets { get; set; } = new List<string>();

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
