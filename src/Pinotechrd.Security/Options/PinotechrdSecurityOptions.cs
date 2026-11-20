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
    /// Lets the host start outside Development with the in-memory <c>IRefreshTokenStore</c> or
    /// <c>ITwoFactorAttemptStore</c>. Default <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// The in-memory stores are per instance and lost on restart: refresh tokens stop working, replay detection forgets
    /// used tokens, and every instance counts its own two-factor attempts. Outside Development the host fails to start
    /// with them unless this is set; use <c>AddPinotechrdEfRefreshTokenStore</c> and
    /// <c>AddPinotechrdEfTwoFactorAttemptStore</c>, or register your own stores. Set it only for a single instance whose
    /// sessions may be lost; a warning is then logged at start (event <c>4102</c>).
    /// The stores are recognised from the service registrations: a factory, decorator or keyed registration, or a store
    /// registered in another container, is trusted as the application's own. Once set to <see langword="true"/> (in the
    /// <c>AddPinotechrdSecurity</c> delegate, a <c>Configure</c> or configuration binding), another
    /// <c>AddPinotechrdSecurity</c> call does not reset it.
    /// </remarks>
    public bool AllowInMemoryStores { get; set; }

    /// <summary>
    /// Lets the host start outside Development when no Data Protection key repository is configured. Default
    /// <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// Two-factor tokens are protected with Data Protection. Without a key repository shared by every instance
    /// (<c>AddDataProtection().PersistKeysTo...()</c>), a token issued by one instance cannot be read by another or after
    /// a restart that loses the key folder. Outside Development the host fails to start in that case unless this is set;
    /// with it set, a warning is logged (event <c>4101</c>). Set it when the default key folder is already shared (for
    /// example Azure App Service) or for a single instance whose key folder survives restarts. Once set to
    /// <see langword="true"/>, another <c>AddPinotechrdSecurity</c> call does not reset it.
    /// </remarks>
    public bool AllowUnpersistedDataProtectionKeys { get; set; }

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
    /// Access token lifetime in minutes. Default 15; accepted range 1 to 60.
    /// </summary>
    /// <remarks>
    /// An access token is accepted until it expires, plus at most <see cref="MaximumClockSkew"/>. With
    /// <see cref="ValidateSecurityStamp"/> off, signing out, changing the password or deactivating the user does not
    /// reach a token already issued, and this lifetime is the longest time such a change takes to apply. Clients renew
    /// with the refresh token.
    /// </remarks>
    public int ExpiryMinutes { get; set; } = 15;

    /// <summary>
    /// Refresh token lifetime in days. Default 7; accepted range 1 to 90.
    /// </summary>
    public int RefreshTokenExpiryDays { get; set; } = 7;

    /// <summary>
    /// Largest clock skew the bearer scheme tolerates when it checks a token's lifetime. Default 1 minute; accepted
    /// range zero to 5 minutes.
    /// </summary>
    /// <remarks>
    /// A <c>TokenValidationParameters.ClockSkew</c> the application sets on the bearer scheme is kept when it is not
    /// larger; a larger one, including the framework default of 5 minutes, is lowered to this value. The final bearer
    /// options must not exceed it, or the host fails to start.
    /// </remarks>
    public TimeSpan MaximumClockSkew { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Refuses an access token whose user signed out, had its sessions revoked, changed or reset its password, or was
    /// deactivated after the token was issued. Default <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Access tokens carry a hash of the user's security stamp (claim <c>sstamp</c>; the stamp itself is not in the
    /// token). Right before each endpoint, <c>UseTenantResolution</c> checks every identity whose claims were issued by
    /// <see cref="Issuer"/>: its user must exist in the resolved tenant, be active, and have the same stamp, or the
    /// request gets <c>401</c> with the code <c>session_revoked</c>. This costs a user lookup per request unless
    /// <see cref="SecurityStampValidationInterval"/> is above zero.
    /// </para>
    /// <para>
    /// A token without the claim is refused when the user store keeps security stamps, so tokens issued with
    /// <c>ITokenProvider.GenerateAccessToken</c> outside the library's sign-in must be issued through the library's sign-in instead, or this check turned off.
    /// With a user store that keeps no security stamps, only deactivation and deletion are detected.
    /// </para>
    /// <para>
    /// The check runs right before the endpoint, after authorization: a revoked token that lacks a required permission
    /// gets <c>403</c> from authorization first. An endpoint that allows anonymous access runs as anonymous instead of
    /// being refused, so a client that still sends its ended token can sign in again. Not checked: skip paths of the
    /// tenant middleware, requests that run no endpoint (terminal middleware, output-cache hits), long-lived
    /// connections after they connect, and hosts that do not call <c>UseTenantResolution</c>.
    /// </para>
    /// <para>
    /// The checked token is recorded by the bearer scheme's <c>OnTokenValidated</c> event, before claims
    /// transformations. An application that replaces <c>JwtBearerOptions.Events</c> after the library or sets
    /// <c>EventsType</c> loses that record; the check then falls back to identities whose claims keep the issuer
    /// <see cref="Issuer"/>, which a claims transformation that re-creates claims does not.
    /// </para>
    /// <para>
    /// With it off, a change reaches access tokens only when they expire (<see cref="ExpiryMinutes"/>).
    /// </para>
    /// </remarks>
    public bool ValidateSecurityStamp { get; set; } = true;

    /// <summary>
    /// How long the result of the security-stamp check is reused for a tenant and user. Default zero: the user store is
    /// read on every request. Accepted range zero to 5 minutes.
    /// </summary>
    /// <remarks>
    /// Above zero, the result is kept in <c>IDistributedCache</c>, so a sign-out, revocation, password change or
    /// deactivation takes up to this long to reach access tokens already issued. The default distributed cache is in
    /// memory and per instance; register a shared one (for example Redis) when several instances serve the API.
    /// </remarks>
    public TimeSpan SecurityStampValidationInterval { get; set; } = TimeSpan.Zero;
}
