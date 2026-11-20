using Microsoft.Extensions.Logging;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Stable event ids of the security events the library logs, all under the logger category
/// <see cref="Category"/>, so operators can route and alert on them.
/// </summary>
/// <remarks>
/// <para>
/// Events carry the resolved tenant id and the user id when known, and a reason. They never carry an email, a user
/// name, a password, a token, a token hash, a security stamp or a two-factor code. The user id is the user store's key
/// (a <see cref="Guid"/> for <c>BaseSecurityUser</c>); a user type keyed by its email would put the email in the
/// events, so do not key users by personal data. A user id is still pseudonymous personal data: apply your retention
/// policy. Outside a request (a background job) the tenant id is empty. Responses to clients stay generic: the reason
/// is only in the log.
/// </para>
/// <para>
/// Ids 4101 and 4102 are startup warnings (see <c>AllowUnpersistedDataProtectionKeys</c> and
/// <c>AllowInMemoryStores</c>), logged under their own categories.
/// </para>
/// </remarks>
public static class SecurityEvents
{
    /// <summary>The logger category of every security event.</summary>
    public const string Category = "Pinotechrd.Security.Events";

    /// <summary>A sign-in with a password failed (Information). Properties: <c>TenantId</c>, <c>UserId</c> (empty for an
    /// unknown user), <c>Reason</c>: <c>TenantMismatch</c>, <c>UnknownUser</c>, <c>Inactive</c>, <c>WrongPassword</c>,
    /// <c>LockedOut</c>, <c>NotAllowed</c>, <c>NoPassword</c> or <c>ValidatorRefused</c>.</summary>
    public static readonly EventId SignInFailed = new(4201, nameof(SignInFailed));

    /// <summary>Tokens were issued (Information). Properties: <c>TenantId</c>, <c>UserId</c>, <c>Method</c>:
    /// <c>Password</c>, <c>TwoFactor</c> or <c>Refresh</c>.</summary>
    public static readonly EventId TokensIssued = new(4202, nameof(TokensIssued));

    /// <summary>A wrong password or two-factor code locked the account out (Warning). Properties: <c>TenantId</c>,
    /// <c>UserId</c>.</summary>
    public static readonly EventId AccountLockedOut = new(4203, nameof(AccountLockedOut));

    /// <summary>A refresh token that was already used was presented again; its whole family was revoked (Warning).
    /// Properties: <c>TenantId</c>, <c>UserId</c> and <c>FamilyId</c> (when the store reports them).</summary>
    public static readonly EventId RefreshTokenReused = new(4204, nameof(RefreshTokenReused));

    /// <summary>A refresh token of another tenant was presented (Warning). Properties: <c>TenantId</c> (the resolved
    /// tenant). Only a store that sees every tenant's tokens can tell this case; with the EF Core store, whose tables are
    /// per tenant, another tenant's token is not found and logs <see cref="RefreshRefused"/> with <c>NotFound</c>.</summary>
    public static readonly EventId RefreshTokenTenantMismatch = new(4205, nameof(RefreshTokenTenantMismatch));

    /// <summary>A refresh was refused for another reason (Information). Properties: <c>TenantId</c>, <c>UserId</c>
    /// (when known), <c>Reason</c>: <c>NotFound</c>, <c>Expired</c>, <c>Revoked</c>, <c>UnknownUser</c>,
    /// <c>Inactive</c>, <c>LockedOut</c>, <c>NotAllowed</c>, <c>StampChanged</c>, <c>ValidatorRefused</c> or
    /// <c>InvalidStoreResult</c> (a store reported a consumed token without a user).</summary>
    public static readonly EventId RefreshRefused = new(4206, nameof(RefreshRefused));

    /// <summary>A wrong two-factor code was entered (Warning). Properties: <c>TenantId</c>, <c>UserId</c>.</summary>
    public static readonly EventId TwoFactorCodeFailed = new(4207, nameof(TwoFactorCodeFailed));

    /// <summary>A two-factor challenge ran out: the wrong code that used its last attempt, every attempt past the
    /// limit, or a failure that could not be recorded and spent it (Warning). Logged at least once per exhausted
    /// challenge, possibly more. Properties: <c>TenantId</c>, <c>UserId</c>.</summary>
    public static readonly EventId TwoFactorChallengeExhausted = new(4208, nameof(TwoFactorChallengeExhausted));

    /// <summary>Every session of a user was ended (Information). Properties: <c>TenantId</c>, <c>UserId</c>,
    /// <c>Trigger</c>: <c>SignOut</c>, <c>Revoked</c>, <c>Deactivated</c> or <c>Deleted</c>.</summary>
    public static readonly EventId SessionsEnded = new(4209, nameof(SessionsEnded));

    /// <summary>An access token was refused because its session ended (Information: a client that keeps sending a
    /// stale token logs it on every request). Properties: <c>TenantId</c>.</summary>
    public static readonly EventId AccessTokenSessionEnded = new(4210, nameof(AccessTokenSessionEnded));

    /// <summary>An authenticated request named a tenant other than its token's, or carried conflicting tenant claims
    /// (Warning). Properties: <c>Code</c>: <c>tenant_invalid</c> (the claim differs from the resolved tenant, checked
    /// before the endpoint) or <c>conflicting_tenant_claims</c> (the identities from authentication name different
    /// tenants). The tenant values are not logged.</summary>
    public static readonly EventId TenantMismatch = new(4211, nameof(TenantMismatch));

    /// <summary>A tenant's cached subscription and module data was invalidated (Information). Properties:
    /// <c>TenantId</c>.</summary>
    public static readonly EventId TenantCacheInvalidated = new(4212, nameof(TenantCacheInvalidated));
}

/// <summary>
/// The logging calls behind <see cref="SecurityEvents"/>.
/// </summary>
internal static class SecurityLog
{
    private static readonly Action<ILogger, string, string, string, Exception?> s_signInFailed =
        LoggerMessage.Define<string, string, string>(LogLevel.Information, SecurityEvents.SignInFailed,
            "Sign-in failed in tenant {TenantId} for user {UserId}: {Reason}.");

    private static readonly Action<ILogger, string, string, string, Exception?> s_tokensIssued =
        LoggerMessage.Define<string, string, string>(LogLevel.Information, SecurityEvents.TokensIssued,
            "Tokens issued in tenant {TenantId} for user {UserId} by {Method}.");

    private static readonly Action<ILogger, string, string, Exception?> s_lockedOut =
        LoggerMessage.Define<string, string>(LogLevel.Warning, SecurityEvents.AccountLockedOut,
            "Account locked out in tenant {TenantId} for user {UserId}.");

    private static readonly Action<ILogger, string, string, string, Exception?> s_reused =
        LoggerMessage.Define<string, string, string>(LogLevel.Warning, SecurityEvents.RefreshTokenReused,
            "A used refresh token was presented again in tenant {TenantId} for user {UserId}; family {FamilyId} was revoked.");

    private static readonly Action<ILogger, string, Exception?> s_refreshTenantMismatch =
        LoggerMessage.Define<string>(LogLevel.Warning, SecurityEvents.RefreshTokenTenantMismatch,
            "A refresh token of another tenant was presented in tenant {TenantId}.");

    private static readonly Action<ILogger, string, string, string, Exception?> s_refreshRefused =
        LoggerMessage.Define<string, string, string>(LogLevel.Information, SecurityEvents.RefreshRefused,
            "Refresh refused in tenant {TenantId} for user {UserId}: {Reason}.");

    private static readonly Action<ILogger, string, string, Exception?> s_twoFactorFailed =
        LoggerMessage.Define<string, string>(LogLevel.Warning, SecurityEvents.TwoFactorCodeFailed,
            "Wrong two-factor code in tenant {TenantId} for user {UserId}.");

    private static readonly Action<ILogger, string, string, Exception?> s_twoFactorExhausted =
        LoggerMessage.Define<string, string>(LogLevel.Warning, SecurityEvents.TwoFactorChallengeExhausted,
            "Two-factor challenge exhausted in tenant {TenantId} for user {UserId}.");

    private static readonly Action<ILogger, string, string, string, Exception?> s_sessionsEnded =
        LoggerMessage.Define<string, string, string>(LogLevel.Information, SecurityEvents.SessionsEnded,
            "Every session ended in tenant {TenantId} for user {UserId}: {Trigger}.");

    private static readonly Action<ILogger, string, Exception?> s_accessTokenSessionEnded =
        LoggerMessage.Define<string>(LogLevel.Information, SecurityEvents.AccessTokenSessionEnded,
            "An access token whose session ended was refused in tenant {TenantId}.");

    private static readonly Action<ILogger, string, Exception?> s_tenantMismatch =
        LoggerMessage.Define<string>(LogLevel.Warning, SecurityEvents.TenantMismatch,
            "An authenticated request was refused: {Code}.");

    private static readonly Action<ILogger, string, Exception?> s_cacheInvalidated =
        LoggerMessage.Define<string>(LogLevel.Information, SecurityEvents.TenantCacheInvalidated,
            "Cached subscription and module data invalidated for tenant {TenantId}.");

    public static void SignInFailed(ILogger? logger, string? tenantId, string? userId, string reason)
    {
        if (logger != null) s_signInFailed(logger, tenantId ?? string.Empty, userId ?? string.Empty, reason, null);
    }

    public static void TokensIssued(ILogger? logger, string tenantId, string userId, string method)
    {
        if (logger != null) s_tokensIssued(logger, tenantId, userId, method, null);
    }

    public static void AccountLockedOut(ILogger? logger, string tenantId, string userId)
    {
        if (logger != null) s_lockedOut(logger, tenantId, userId, null);
    }

    public static void RefreshTokenReused(ILogger? logger, string tenantId, string? userId, string? familyId)
    {
        if (logger != null) s_reused(logger, tenantId, userId ?? string.Empty, familyId ?? string.Empty, null);
    }

    public static void RefreshTokenTenantMismatch(ILogger? logger, string tenantId)
    {
        if (logger != null) s_refreshTenantMismatch(logger, tenantId, null);
    }

    public static void RefreshRefused(ILogger? logger, string tenantId, string? userId, string reason)
    {
        if (logger != null) s_refreshRefused(logger, tenantId, userId ?? string.Empty, reason, null);
    }

    public static void TwoFactorCodeFailed(ILogger? logger, string tenantId, string userId)
    {
        if (logger != null) s_twoFactorFailed(logger, tenantId, userId, null);
    }

    public static void TwoFactorChallengeExhausted(ILogger? logger, string tenantId, string userId)
    {
        if (logger != null) s_twoFactorExhausted(logger, tenantId, userId, null);
    }

    public static void SessionsEnded(ILogger? logger, string? tenantId, string userId, string trigger)
    {
        if (logger != null) s_sessionsEnded(logger, tenantId ?? string.Empty, userId, trigger, null);
    }

    public static void AccessTokenSessionEnded(ILogger? logger, string tenantId)
    {
        if (logger != null) s_accessTokenSessionEnded(logger, tenantId, null);
    }

    public static void TenantMismatch(ILogger? logger, string code)
    {
        if (logger != null) s_tenantMismatch(logger, code, null);
    }

    public static void TenantCacheInvalidated(ILogger? logger, string tenantId)
    {
        if (logger != null) s_cacheInvalidated(logger, tenantId, null);
    }

    /// <summary>The security event logger, or <see langword="null"/> without a logger factory.</summary>
    public static ILogger? Create(ILoggerFactory? factory) => factory?.CreateLogger(SecurityEvents.Category);
}
