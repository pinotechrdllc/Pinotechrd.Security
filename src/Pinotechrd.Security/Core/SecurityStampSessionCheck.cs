using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Core;

/// <summary>
/// The claim that binds an access token to the user's security stamp at the time it was issued.
/// </summary>
internal static class SecurityStampClaim
{
    /// <summary>Claim type in issued access tokens.</summary>
    public const string Type = "sstamp";

    /// <summary>Claim type of the user id in issued access tokens.</summary>
    public const string UserIdType = "id";

    /// <summary>
    /// The first 16 bytes of SHA-256 over the stamp, base64url encoded (22 characters); empty for a missing stamp. The
    /// stamp itself never leaves the server: a token is readable by its holder.
    /// </summary>
    public static string Hash(string? stamp)
    {
        if (string.IsNullOrEmpty(stamp)) return string.Empty;
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(stamp), digest);
        return Base64Url.EncodeToString(digest[..16]);
    }
}

/// <summary>
/// The user id and stamp claims of an access token the library's bearer scheme validated on this request, recorded
/// from the handler's own principal before any claims transformation or event handler of the application can change it.
/// </summary>
internal sealed record ValidatedAccessToken(IReadOnlyList<string> UserIds, IReadOnlyList<string> Stamps)
{
    private static readonly object Key = new();

    public static ValidatedAccessToken? Capture(ClaimsPrincipal? principal) =>
        principal == null
            ? null
            : new ValidatedAccessToken(
                principal.FindAll(SecurityStampClaim.UserIdType).Select(c => c.Value).ToList(),
                principal.FindAll(SecurityStampClaim.Type).Select(c => c.Value).ToList());

    public static void Store(HttpContext context, ValidatedAccessToken token) => context.Items[Key] = token;

    public static void Record(HttpContext context, ClaimsPrincipal? principal)
    {
        if (Capture(principal) is { } token) Store(context, token);
    }

    public static ValidatedAccessToken? Read(HttpContext context) =>
        context.Items.TryGetValue(Key, out var value) ? value as ValidatedAccessToken : null;

    public static ValidatedAccessToken From(ClaimsIdentity identity) => new(
        identity.FindAll(SecurityStampClaim.UserIdType).Select(c => c.Value).ToList(),
        identity.FindAll(SecurityStampClaim.Type).Select(c => c.Value).ToList());

    /// <summary>The user id and stamp claims of <paramref name="identity"/> that <paramref name="issuer"/> issued.</summary>
    public static ValidatedAccessToken From(ClaimsIdentity identity, string issuer) => new(
        IssuedBy(identity, SecurityStampClaim.UserIdType, issuer),
        IssuedBy(identity, SecurityStampClaim.Type, issuer));

    public static List<string> IssuedBy(ClaimsIdentity identity, string type, string issuer) =>
        identity.FindAll(c => string.Equals(c.Type, type, StringComparison.Ordinal) && string.Equals(c.Issuer, issuer, StringComparison.Ordinal))
            .Select(c => c.Value)
            .ToList();
}

/// <summary>
/// Decides whether the access tokens of a request still belong to a live session. Resolved per request by the tenant
/// consistency check, after the tenant is resolved, so the user store reads the tenant's own tables.
/// </summary>
internal interface IAccessTokenSessionCheck
{
    Task<bool> IsCurrentAsync(HttpContext context, string tenantId, CancellationToken cancellationToken);
}

/// <summary>
/// Accepts an access token issued by the library only while its user exists in the resolved tenant, is active, and
/// has the security stamp the token was issued with. Sign-out, session revocation, deactivation and password changes
/// renew the stamp, so they reach access tokens already issued.
/// </summary>
/// <remarks>
/// The token checked is the one the library's bearer scheme recorded when it validated it
/// (<see cref="ValidatedAccessToken"/>), so a claims transformation that rebuilds the principal does not hide it. When
/// nothing was recorded (the application replaced the bearer events), every authenticated identity with a claim issued
/// by <see cref="JwtSettings.Issuer"/> is checked instead. With <see cref="JwtSettings.SecurityStampValidationInterval"/>
/// above zero, the answer for a tenant and user is kept in <see cref="IDistributedCache"/> for that long.
/// <see cref="IsSessionActiveAsync"/> is the public form of the same check, for hosts without <c>UseTenantResolution</c>.
/// </remarks>
internal sealed class SecurityStampSessionCheck<TUser> : IAccessTokenSessionCheck, IAccessTokenSessionValidator
    where TUser : BaseSecurityUser
{
    private const string CachePrefix = "pinotechrd:session:";
    private const string NoSession = "0";
    private const string Session = "1";

    private readonly UserManager<TUser> _userManager;
    private readonly IDistributedCache _cache;
    private readonly IOptions<PinotechrdSecurityOptions> _options;
    private readonly TenantContext? _tenantContext;

    public SecurityStampSessionCheck(
        UserManager<TUser> userManager,
        IDistributedCache cache,
        IOptions<PinotechrdSecurityOptions> options,
        TenantContext? tenantContext = null)
    {
        _userManager = userManager;
        _cache = cache;
        _options = options;
        _tenantContext = tenantContext;
    }

    public async Task<bool> IsCurrentAsync(HttpContext context, string tenantId, CancellationToken cancellationToken)
    {
        var settings = _options.Value.Jwt;
        if (!settings.ValidateSecurityStamp) return true;

        foreach (var token in TokensOf(context, settings.Issuer))
        {
            if (!await IsCurrentAsync(token, tenantId, settings.SecurityStampValidationInterval, cancellationToken)) return false;
        }

        return true;
    }

    /// <inheritdoc />
    public async Task<bool> IsSessionActiveAsync(ClaimsPrincipal principal, string tenantId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);
        if (string.IsNullOrEmpty(tenantId)) return false;
        // The user is read through the scoped context, which follows TenantContext: when it names another tenant, the
        // answer would come from that tenant's tables and be cached under tenantId.
        if (_tenantContext?.TenantId is { } resolved && !string.Equals(resolved, tenantId, StringComparison.Ordinal)) return false;

        var options = _options.Value;
        var issuer = options.Jwt.Issuer;
        if (string.IsNullOrEmpty(issuer)) return false;
        var tenantClaimType = options.Tenancy.ClaimType;
        var checkedAny = false;
        foreach (var identity in principal.Identities)
        {
            if (!IsLibraryIdentity(identity, issuer)) continue;
            checkedAny = true;

            // Only the library's own claims count, so a claims transformation that adds an id or tenant claim of its
            // own does not change the answer.
            var tenants = ValidatedAccessToken.IssuedBy(identity, tenantClaimType, issuer);
            if (tenants.Count != 1 || !string.Equals(tenants[0], tenantId, StringComparison.Ordinal)) return false;
            if (!await IsCurrentAsync(ValidatedAccessToken.From(identity, issuer), tenantId, options.Jwt.SecurityStampValidationInterval, cancellationToken))
                return false;
        }

        return checkedAny;
    }

    private static bool IsLibraryIdentity(ClaimsIdentity identity, string? issuer) =>
        identity.IsAuthenticated
        && !string.IsNullOrEmpty(issuer)
        && identity.Claims.Any(c => string.Equals(c.Issuer, issuer, StringComparison.Ordinal));

    private static IEnumerable<ValidatedAccessToken> TokensOf(HttpContext context, string? issuer)
    {
        if (ValidatedAccessToken.Read(context) is { } recorded)
        {
            yield return recorded;
            yield break;
        }

        foreach (var identity in context.User.Identities)
        {
            if (IsLibraryIdentity(identity, issuer))
            {
                yield return ValidatedAccessToken.From(identity);
            }
        }
    }

    private async Task<bool> IsCurrentAsync(ValidatedAccessToken token, string tenantId, TimeSpan interval, CancellationToken cancellationToken)
    {
        if (token.UserIds.Count != 1 || token.Stamps.Count > 1) return false;

        var current = await CurrentStampAsync(tenantId, token.UserIds[0], interval, cancellationToken);
        if (current == null) return false;

        var presented = token.Stamps.Count == 1 ? token.Stamps[0] : string.Empty;
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(current), Encoding.UTF8.GetBytes(presented));
    }

    /// <summary>
    /// The stamp hash of an active user of the tenant (empty when the store keeps no stamps), or <see langword="null"/>
    /// when there is no such user.
    /// </summary>
    private async Task<string?> CurrentStampAsync(string tenantId, string userId, TimeSpan interval, CancellationToken cancellationToken)
    {
        if (interval <= TimeSpan.Zero) return await LoadAsync(userId, cancellationToken);

        // Length-prefixed, so no tenant and user pair can produce the key of another pair.
        var key = $"{CachePrefix}{tenantId.Length}:{tenantId}:{userId}";
        var cached = await _cache.GetStringAsync(key, cancellationToken);
        if (cached != null) return cached.StartsWith(Session, StringComparison.Ordinal) ? cached[1..] : null;

        var loaded = await LoadAsync(userId, cancellationToken);
        await _cache.SetStringAsync(
            key,
            loaded == null ? NoSession : Session + loaded,
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = interval },
            cancellationToken);
        return loaded;
    }

    private async Task<string?> LoadAsync(string userId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TUser? user;
        try
        {
            user = await _userManager.FindByIdAsync(userId);
        }
        catch (Exception e) when (e is FormatException or NotSupportedException or ArgumentException)
        {
            // An id the store cannot parse names no user.
            return null;
        }

        if (user is not { IsActive: true }) return null;
        return _userManager.SupportsUserSecurityStamp
            ? SecurityStampClaim.Hash(await _userManager.GetSecurityStampAsync(user))
            : string.Empty;
    }
}
