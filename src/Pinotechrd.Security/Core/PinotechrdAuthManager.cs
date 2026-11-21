using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Implementation of the Pinotechrd Authentication Manager.
/// Handles the integration between ASP.NET Identity and Pinotechrd Security Engine.
/// </summary>
/// <remarks>
/// <para>
/// Tenant binding: every token is issued for the tenant the request was resolved for
/// (<see cref="TenantContext"/>). Login, two-factor completion and refresh fail with the generic error when
/// no tenant is resolved or when the tenant passed in differs from it.
/// </para>
/// <para>
/// Membership: this class does not check that the user belongs to the tenant. Finding the user proves
/// membership only when the user store reads the tenant's own tables. <c>AddPinotechrdSecurity</c> relies on that only
/// when all three hold: the context derives from <see cref="Data.PinotechrdSecurityDbContext{TUser, TRole}"/>, its
/// registered options were built with <c>UsePinotechrdSecurity()</c>, and in <see cref="Data.TenantSchemaMode.SearchPath"/>
/// <c>ApplicationTakesResponsibilityForSearchPath</c> is off. Otherwise an <see cref="IIdentityValidator{TUser}"/> must
/// be registered to check membership, or <see cref="PinotechrdSecurityOptions.AllowUnverifiedTenantMembership"/> set;
/// the check fails the host start, and also the first read of the options, which this class does in its constructor.
/// The check cannot see the database provider: one that ignores schemas (for example SQLite or InMemory on a single
/// shared database) puts every tenant's users in the same tables unless each tenant has its own database.
/// </para>
/// <para>
/// Login failures for an unknown user, an inactive user (<see cref="BaseSecurityUser.IsActive"/>), a wrong
/// password, a user without a password, a locked-out account, an account that Identity does not allow to
/// sign in and a tenant mismatch all return the same <see cref="AuthResult"/> with the error
/// <c>Invalid credentials</c>. On every path where Identity does not hash the password against a stored
/// hash, the password is verified against a dummy hash made once per hasher type with the same
/// <see cref="IPasswordHasher{TUser}"/>, so these paths pay the hashing cost too. This narrows the timing
/// difference between existing and unknown accounts; it is not constant time. The user lookups, the lockout
/// bookkeeping and the database writes for an existing account still take different time.
/// </para>
/// <para>
/// Two-factor sign-in: when the user has two-factor enabled, <see cref="LoginAsync"/> returns
/// <see cref="AuthResult.TwoFactorRequired"/> with an opaque token protected by ASP.NET Core Data
/// Protection. The token is bound to the user, the tenant and the user's security stamp, and expires
/// after five minutes. Each token allows five code attempts, counted through
/// <see cref="ITwoFactorAttemptStore"/> before the code is checked, so concurrent guesses are counted too.
/// Wrong codes also count toward the Identity lockout: a count lost to a concurrent update is retried after
/// reloading the user, and a count that still cannot be recorded spends the token's remaining attempts.
/// A successful verification renews the security
/// stamp, which invalidates the token and the code just used.
/// </para>
/// <para>
/// Refresh: the presented token is consumed atomically through <see cref="IRefreshTokenStore.ConsumeAsync"/>.
/// A token of another tenant is refused without being consumed, and so is the token of a locked-out user (read first
/// with <see cref="IRefreshTokenStore.ValidateAsync"/>), so a lockout does not end the session: the token works again
/// once the lockout ends. To disable an account, deactivate it or end its sessions instead of only locking it out.
/// Reusing a consumed token revokes its family.
/// The user must still exist, be active, not locked out, allowed to sign in, and have the security stamp
/// captured when the token was issued. Every refresh failure returns <c>Invalid token</c>.
/// </para>
/// </remarks>
public class PinotechrdAuthManager<TUser> : IPinotechrdAuthManager<TUser> where TUser : class, new()
{
    private const string InvalidCredentials = "Invalid credentials";
    private const string InvalidSession = "Invalid session";
    private const string InvalidCode = "Invalid or expired code";
    private const string InvalidRefreshToken = "Invalid token";
    private const string TwoFactorProtectorPurpose = "Pinotechrd.Security.TwoFactor.v2";
    private const int MaxTwoFactorAttemptsPerToken = 5;
    private static readonly TimeSpan TwoFactorTokenLifetime = TimeSpan.FromMinutes(5);
    private static readonly ConcurrentDictionary<Type, string> s_dummyPasswordHashes = new();

    private readonly UserManager<TUser> _userManager;
    private readonly SignInManager<TUser> _signInManager;
    private readonly ISecurityEngine _securityEngine;
    private readonly ITokenProvider _tokenProvider;
    private readonly IRefreshTokenStore _refreshTokenStore;
    private readonly PinotechrdSecurityOptions _options;
    private readonly IIdentityValidator<TUser>? _customValidator;
    private readonly IPinotechrdMessageService? _messageService;
    private readonly IDataProtector? _twoFactorProtector;
    private readonly TenantContext? _tenantContext;
    private readonly ITwoFactorAttemptStore? _twoFactorAttempts;
    private readonly TimeProvider _timeProvider;
    private readonly ISecurityDbContext? _securityDbContext;
    private readonly string _tenantClaimType;
    private readonly ISecurityDataProvider? _dataProvider;
    private readonly ILogger? _events;
    private readonly IUserStore<TUser>? _userStore;
    private const int MaxFailedCountRetries = 10;
    // Every concurrent failure but one loses each round, so this bounds how many parallel failures all count.
    private const int MaxFailedAttemptRetries = 100;
    private const string ByPassword = "Password";
    private const string ByTwoFactor = "TwoFactor";
    private const string ByRefresh = "Refresh";

    /// <summary>
    /// Initializes the authentication manager.
    /// </summary>
    /// <remarks>
    /// Without <paramref name="tenantContext"/> every login, two-factor completion and refresh fails, because
    /// the tenant of the request cannot be checked. Without <paramref name="dataProtectionProvider"/> or
    /// <paramref name="twoFactorAttemptStore"/> two-factor sign-in fails closed: a user with two-factor enabled
    /// cannot log in and every two-factor method fails. <c>AddPinotechrdSecurity</c> registers all three.
    /// Without <paramref name="dataProvider"/> (the application registers it) the self-service methods
    /// <see cref="SignOutCurrentUserAsync"/> and <see cref="ChangeOwnPasswordAsync"/> find no authenticated user.
    /// Without <paramref name="loggerFactory"/> no security events (<see cref="SecurityEvents"/>) are logged. With
    /// <paramref name="userStore"/> (the store <paramref name="userManager"/> uses), the security stamp renewal of
    /// <see cref="SignOutCurrentUserAsync"/> cannot be cancelled by the request once the revocation started.
    /// </remarks>
    public PinotechrdAuthManager(
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        ISecurityEngine securityEngine,
        ITokenProvider tokenProvider,
        IRefreshTokenStore refreshTokenStore,
        IOptions<PinotechrdSecurityOptions> options,
        IIdentityValidator<TUser>? customValidator = null,
        IPinotechrdMessageService? messageService = null,
        IDataProtectionProvider? dataProtectionProvider = null,
        TenantContext? tenantContext = null,
        ITwoFactorAttemptStore? twoFactorAttemptStore = null,
        TimeProvider? timeProvider = null,
        ISecurityDbContext? securityDbContext = null,
        TenantResolutionOptions? tenantOptions = null,
        ISecurityDataProvider? dataProvider = null,
        ILoggerFactory? loggerFactory = null,
        IUserStore<TUser>? userStore = null)
    {
        _userManager = userManager;
        _userStore = userStore;
        _signInManager = signInManager;
        _events = SecurityLog.Create(loggerFactory);
        _securityEngine = securityEngine;
        _tokenProvider = tokenProvider;
        _refreshTokenStore = refreshTokenStore;
        _options = options.Value;
        _customValidator = customValidator;
        _messageService = messageService;
        _twoFactorProtector = dataProtectionProvider?.CreateProtector(TwoFactorProtectorPurpose);
        _tenantContext = tenantContext;
        _twoFactorAttempts = twoFactorAttemptStore;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _securityDbContext = securityDbContext;
        // One source of truth for the claim name: the TenantResolutionOptions singleton that the middleware, the
        // permission handler, the engine and the consistency check read.
        _tenantClaimType = tenantOptions?.ClaimType ?? _options.Tenancy.ClaimType;
        _dataProvider = dataProvider;
    }

    /// <inheritdoc />
    public async Task<AuthResult> LoginAsync(string emailOrUsername, string password, string tenantId, CancellationToken cancellationToken = default)
    {
        EnsureTenantMembershipIsProven();
        // 0. The token can only be issued for the tenant this request was resolved for.
        if (!IsCurrentTenant(tenantId))
        {
            VerifyAgainstDummyHash(password);
            SecurityLog.SignInFailed(_events, _tenantContext?.TenantId, null, "TenantMismatch");
            return AuthResult.Failure(InvalidCredentials);
        }

        cancellationToken.ThrowIfCancellationRequested();
        // 1. Hybrid lookup: Try Email, then UserName
        var user = await _userManager.FindByEmailAsync(emailOrUsername)
                   ?? await _userManager.FindByNameAsync(emailOrUsername);

        if (user == null || IsInactive(user))
        {
            VerifyAgainstDummyHash(password);
            SecurityLog.SignInFailed(_events, tenantId, user == null ? null : await _userManager.GetUserIdAsync(user), user == null ? "UnknownUser" : "Inactive");
            return AuthResult.Failure(InvalidCredentials);
        }

        cancellationToken.ThrowIfCancellationRequested();
        // Read from the loaded entity (no query), so the lockout this attempt causes can be told from an earlier one.
        var wasLockedOut = _userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user);
        // 2. Check password. The failure is counted here rather than by Identity (lockoutOnFailure), which drops the
        // count when a concurrent failure updated the user first: parallel wrong passwords would then never lock it.
        var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: false);
        if (!result.Succeeded && !result.IsLockedOut && !result.IsNotAllowed && _userManager.SupportsUserLockout)
        {
            var recorded = await RecordFailedAttemptAsync(user);
            if (recorded != null && await _userManager.IsLockedOutAsync(recorded)) result = SignInResult.LockedOut;
        }

        if (!result.Succeeded)
        {
            // Identity refuses locked-out and not-allowed accounts, and users without a password,
            // before it hashes anything.
            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (result.IsLockedOut || result.IsNotAllowed || !hasPassword)
                VerifyAgainstDummyHash(password);

            var userId = await _userManager.GetUserIdAsync(user);
            var reason = result.IsLockedOut ? (wasLockedOut ? "LockedOut" : "WrongPassword")
                : result.IsNotAllowed ? "NotAllowed"
                : !hasPassword ? "NoPassword"
                : "WrongPassword";
            SecurityLog.SignInFailed(_events, tenantId, userId, reason);
            if (result.IsLockedOut && !wasLockedOut) SecurityLog.AccountLockedOut(_events, tenantId, userId);
            return AuthResult.Failure(InvalidCredentials);
        }

        cancellationToken.ThrowIfCancellationRequested();
        // 3. Second factor. CheckPasswordSignInAsync never reports RequiresTwoFactor, so ask Identity directly.
        if (_userManager.SupportsUserTwoFactor && await _userManager.GetTwoFactorEnabledAsync(user))
        {
            if (_twoFactorProtector == null || _twoFactorAttempts == null)
                return AuthResult.Failure("Two-factor sign-in is not available");

            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            var twoFactorToken = await CreateTwoFactorTokenAsync(user, tenantId);
            return AuthResult.TwoFactorRequired(providers.ToList(), twoFactorToken);
        }

        return await BuildAuthenticatedResultAsync(user, tenantId, null, ByPassword, cancellationToken);
    }

    /// <summary>
    /// Refuses to start a sign-in, two-factor completion or refresh when the setup does not prove that the user found
    /// belongs to the request's tenant, unless the application checks membership itself (an
    /// <see cref="IIdentityValidator{TUser}"/>) or allows it unverified. The host start makes the same check, but cannot
    /// when the context's options depend on the request's tenant; this one also covers options that differ per tenant.
    /// It runs before anything is read or changed, so a refused call consumes no refresh token and renews no stamp.
    /// </summary>
    /// <exception cref="InvalidOperationException">The setup does not prove membership: a configuration error, not a
    /// failed sign-in.</exception>
    private void EnsureTenantMembershipIsProven()
    {
        if (_options.AllowUnverifiedTenantMembership || _customValidator != null) return;

        // The context that matters is the one the users are read from: the user store's, not ISecurityDbContext, which
        // the application can replace. A manager built by hand, with neither, is not checked.
        var context = UserStoreContext(_userStore) ?? _securityDbContext as DbContext;
        if (context != null)
        {
            Options.TenantMembership.ThrowIfNotProven(context, typeof(TUser).Name);
        }
        else if (_userStore != null || _securityDbContext != null)
        {
            throw new InvalidOperationException(
                $"Tenant membership cannot be verified: neither the user store nor ISecurityDbContext is an EF Core context. " +
                $"Register an IIdentityValidator<{typeof(TUser).Name}> that checks membership, or set " +
                "PinotechrdSecurityOptions.AllowUnverifiedTenantMembership to true if the application checks it elsewhere.");
        }
    }

    /// <summary>The EF Core context behind an Identity EF store (its public <c>Context</c> property), if it is one.</summary>
    private static DbContext? UserStoreContext(IUserStore<TUser>? store) =>
        store?.GetType().GetProperty("Context")?.GetValue(store) as DbContext;

    private async Task<AuthResult> BuildAuthenticatedResultAsync(TUser user, string tenantId, string? familyId, string method, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Fetch user basic info
        var userId = await _userManager.GetUserIdAsync(user);
        var email = await _userManager.GetEmailAsync(user) ?? string.Empty;

        // 1. External Domain Validation (for example, an employees table owned by the host application)
        string fullName = email;
        var additionalClaims = new List<Claim>();

        if (_customValidator != null)
        {
            var validationResult = await _customValidator.ValidateAsync(user, tenantId, cancellationToken);
            if (!validationResult.Succeeded)
            {
                if (method == ByRefresh) SecurityLog.RefreshRefused(_events, tenantId, userId, "ValidatorRefused");
                else SecurityLog.SignInFailed(_events, tenantId, userId, "ValidatorRefused");
                return AuthResult.Failure(validationResult.ErrorMessage ?? "Validation failed");
            }

            fullName = validationResult.FullName ?? fullName;
            if (validationResult.AdditionalClaims != null)
                additionalClaims.AddRange(validationResult.AdditionalClaims);
        }

        // 2. Fetch Permissions via Engine
        var permissions = (await _securityEngine.GetPermissionsAsync(userId, cancellationToken)).ToList();

        // 3. Build Claims
        var claims = new List<Claim>
        {
            new Claim("id", userId),
            new Claim("name", fullName),
            new Claim(_tenantClaimType, tenantId),
            new Claim(ClaimTypes.Email, email)
        };

        // The user id and stamp claims are the library's: a validator cannot supply or duplicate them.
        claims.AddRange(additionalClaims.Where(c =>
            !string.Equals(c.Type, SecurityStampClaim.Type, StringComparison.Ordinal)
            && !string.Equals(c.Type, SecurityStampClaim.UserIdType, StringComparison.Ordinal)));
        foreach (var p in permissions)
        {
            claims.Add(new Claim("permission", p));
        }

        var securityStamp = _userManager.SupportsUserSecurityStamp
            ? await _userManager.GetSecurityStampAsync(user)
            : null;
        // Binds the access token to this stamp, so renewing it (sign-out, revocation, password change, deactivation)
        // reaches the token before it expires (JwtSettings.ValidateSecurityStamp).
        var stampHash = SecurityStampClaim.Hash(securityStamp);
        if (stampHash.Length > 0)
        {
            claims.Add(new Claim(SecurityStampClaim.Type, stampHash));
        }

        // 4. Generate Tokens
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var accessToken = _tokenProvider.GenerateAccessToken(claims);
        var refreshToken = _tokenProvider.GenerateRefreshToken();
        var expiresAt = now.AddMinutes(_options.Jwt.ExpiryMinutes);
        var refreshTokenExpiresAt = now.AddDays(_options.Jwt.RefreshTokenExpiryDays);

        await _refreshTokenStore.SaveAsync(
            userId,
            tenantId,
            refreshToken,
            refreshTokenExpiresAt,
            familyId ?? Guid.NewGuid().ToString("N"),
            securityStamp,
            cancellationToken);

        SecurityLog.TokensIssued(_events, tenantId, userId, method);
        return AuthResult.Success(
            new AuthToken(accessToken, refreshToken, expiresAt),
            userId,
            fullName,
            permissions,
            user);
    }

    /// <inheritdoc />
    public async Task<IList<string>> GetTwoFactorProvidersAsync(string twoFactorToken, CancellationToken cancellationToken = default)
    {
        var ticket = await ReadTwoFactorTokenAsync(twoFactorToken, cancellationToken);
        if (ticket == null) return new List<string>();

        cancellationToken.ThrowIfCancellationRequested();
        return await _userManager.GetValidTwoFactorProvidersAsync(ticket.User);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Only providers returned by <see cref="UserManager{TUser}.GetValidTwoFactorProvidersAsync"/> are accepted,
    /// and locked-out users are refused. This method sends a message every time it succeeds: callers must
    /// rate limit it (for example per token and per client address).
    /// </remarks>
    public async Task<AuthResult> SendTwoFactorCodeAsync(string twoFactorToken, string provider, CancellationToken cancellationToken = default)
    {
        var ticket = await ReadTwoFactorTokenAsync(twoFactorToken, cancellationToken);
        if (ticket == null) return AuthResult.Failure(InvalidSession);
        var user = ticket.User;

        if (_messageService == null)
            return AuthResult.Failure("Messaging service not configured for MFA");

        if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
            return AuthResult.Failure(InvalidSession);

        if (!await IsValidProviderAsync(user, provider))
            return AuthResult.Failure("Invalid two-factor provider");

        cancellationToken.ThrowIfCancellationRequested();
        var code = await _userManager.GenerateTwoFactorTokenAsync(user, provider);

        // Destination lookup
        string destination = "";
        if (provider == "Email") destination = await _userManager.GetEmailAsync(user) ?? "";
        else if (provider == "Phone") destination = await _userManager.GetPhoneNumberAsync(user) ?? "";
        // If it's a custom provider, the implementation of IPinotechrdMessageService should handle it
        // Or we could pass more metadata.

        await _messageService.SendCodeAsync(destination, code, SecurityCodeType.TwoFactor, cancellationToken);

        return AuthResult.Success(new AuthToken("", "", DateTime.MinValue), "", "", []);
    }

    /// <inheritdoc />
    public async Task<AuthResult> VerifyTwoFactorCodeAsync(string twoFactorToken, string provider, string code, string tenantId, CancellationToken cancellationToken = default)
    {
        EnsureTenantMembershipIsProven();
        var ticket = await ReadTwoFactorTokenAsync(twoFactorToken, cancellationToken);
        if (ticket == null || !string.Equals(ticket.TenantId, tenantId, StringComparison.Ordinal))
            return AuthResult.Failure(InvalidSession);

        var user = ticket.User;
        if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
            return AuthResult.Failure(InvalidCode);

        if (!await IsValidProviderAsync(user, provider))
            return AuthResult.Failure(InvalidCode);

        // Count the attempt before checking the code, so concurrent guesses cannot all slip under the limit.
        var attempts = await _twoFactorAttempts!.RegisterAttemptAsync(ticket.ChallengeId, ticket.ExpiresAt, cancellationToken);
        if (attempts > MaxTwoFactorAttemptsPerToken)
        {
            // Every attempt past the limit is logged: with concurrent attempts no single one is sure to see the exact
            // count at which the challenge ran out.
            SecurityLog.TwoFactorChallengeExhausted(_events, ticket.TenantId, await _userManager.GetUserIdAsync(user));
            return AuthResult.Failure(InvalidCode);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var valid = await _userManager.VerifyTwoFactorTokenAsync(user, provider, code);
        if (!valid)
        {
            // The per-token count above already holds this failure, even if this update fails.
            // If the failure cannot be recorded (for example a concurrency conflict that survives the retries),
            // the challenge is spent: no further code is accepted for this token.
            var userId = await _userManager.GetUserIdAsync(user);
            SecurityLog.TwoFactorCodeFailed(_events, ticket.TenantId, userId);
            var exhausted = attempts >= MaxTwoFactorAttemptsPerToken;
            if (_userManager.SupportsUserLockout)
            {
                var recorded = await RecordFailedAttemptAsync(user);
                if (recorded == null)
                {
                    await _twoFactorAttempts!.ExhaustAsync(ticket.ChallengeId, ticket.ExpiresAt, CancellationToken.None);
                    exhausted = true;
                }
                else if (await _userManager.IsLockedOutAsync(recorded))
                {
                    // Wrong codes count toward the Identity lockout too.
                    SecurityLog.AccountLockedOut(_events, ticket.TenantId, userId);
                }
            }

            if (exhausted) SecurityLog.TwoFactorChallengeExhausted(_events, ticket.TenantId, userId);
            return AuthResult.Failure(InvalidCode);
        }

        // A concurrent failure may have locked the account after the first check.
        if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
            return AuthResult.Failure(InvalidCode);

        // Single use: a new security stamp invalidates this token and the code just used. It is renewed first;
        // a concurrency conflict is retried only while the stored stamp is still the token's, so of two
        // concurrent verifications of one token only one can renew it.
        if (_userManager.SupportsUserSecurityStamp)
        {
            var renewed = await RetryOnConcurrencyAsync(
                user,
                u => _userManager.UpdateSecurityStampAsync(u),
                async u => string.Equals(await _userManager.GetSecurityStampAsync(u) ?? string.Empty, ticket.Stamp, StringComparison.Ordinal));
            if (renewed == null) return AuthResult.Failure(InvalidSession);
            user = renewed;
        }

        if (_userManager.SupportsUserLockout)
        {
            var reset = await RetryOnConcurrencyAsync(user, u => _userManager.ResetAccessFailedCountAsync(u));
            if (reset == null) return AuthResult.Failure(InvalidSession);
            user = reset;
        }

        return await BuildAuthenticatedResultAsync(user, ticket.TenantId, null, ByTwoFactor, cancellationToken);
    }

    private sealed record TwoFactorTicket(TUser User, string TenantId, string ChallengeId, DateTimeOffset ExpiresAt, string Stamp);

    private async Task<string> CreateTwoFactorTokenAsync(TUser user, string tenantId)
    {
        var userId = await _userManager.GetUserIdAsync(user);
        var stamp = _userManager.SupportsUserSecurityStamp
            ? await _userManager.GetSecurityStampAsync(user) ?? string.Empty
            : string.Empty;
        var challengeId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var expiresAt = _timeProvider.GetUtcNow().Add(TwoFactorTokenLifetime).ToUnixTimeMilliseconds();

        var payload = JsonSerializer.Serialize(new[]
        {
            userId, tenantId, stamp, challengeId, expiresAt.ToString(CultureInfo.InvariantCulture)
        });
        return _twoFactorProtector!.Protect(payload);
    }

    private async Task<TwoFactorTicket?> ReadTwoFactorTokenAsync(string twoFactorToken, CancellationToken cancellationToken)
    {
        if (_twoFactorProtector == null || _twoFactorAttempts == null || string.IsNullOrEmpty(twoFactorToken)) return null;

        string?[]? parts;
        try
        {
            var payload = _twoFactorProtector.Unprotect(twoFactorToken);
            parts = JsonSerializer.Deserialize<string?[]>(payload);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        {
            return null;
        }

        if (parts is not { Length: 5 }
            || string.IsNullOrEmpty(parts[0])
            || parts[1] is not { } tenantId
            || string.IsNullOrEmpty(parts[3])
            || !long.TryParse(parts[4], NumberStyles.None, CultureInfo.InvariantCulture, out var expiresAtMs))
        {
            return null;
        }

        var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(expiresAtMs);
        if (_timeProvider.GetUtcNow() >= expiresAt || !IsCurrentTenant(tenantId)) return null;

        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(parts[0]!);
        if (user == null || IsInactive(user)) return null;

        if (_userManager.SupportsUserSecurityStamp)
        {
            var stamp = await _userManager.GetSecurityStampAsync(user) ?? string.Empty;
            if (!string.Equals(stamp, parts[2] ?? string.Empty, StringComparison.Ordinal)) return null;
        }

        return new TwoFactorTicket(user, tenantId, parts[3]!, expiresAt, parts[2] ?? string.Empty);
    }

    /// <summary>
    /// Increments the Identity failed-access count (and locks the account at the limit). Concurrent wrong passwords or
    /// codes make the update fail on the concurrency stamp; the user is then reloaded and the increment retried after
    /// a short random delay, up to <see cref="MaxFailedAttemptRetries"/> times, so every failure counts. Once a
    /// concurrent failure has locked the account, the lockout already applies and nothing more is written.
    /// </summary>
    /// <returns>The (possibly reloaded) user once the failure is recorded or the account is locked out;
    /// <see langword="null"/> when it could not be recorded.</returns>
    private async Task<TUser?> RecordFailedAttemptAsync(TUser user)
    {
        for (var attempt = 0; attempt < MaxFailedAttemptRetries; attempt++)
        {
            var result = await _userManager.AccessFailedAsync(user);
            if (result?.Succeeded == true) return user;
            if (!IsConcurrencyFailure(result)) return null;

            await Task.Delay(Random.Shared.Next(1, 2 + Math.Min(attempt, 20) * 2));
            var reloaded = await ReloadUserAsync(user);
            if (reloaded == null) return null;
            user = reloaded;
            if (await _userManager.IsLockedOutAsync(user)) return user;
        }

        return null;
    }

    private static bool IsConcurrencyFailure(IdentityResult? result) =>
        result?.Errors.Any(e => e.Code == nameof(IdentityErrorDescriber.ConcurrencyFailure)) == true;

    /// <summary>
    /// Runs a user update; on a concurrency conflict, reloads the user and, if <paramref name="stillValid"/>
    /// allows, retries, up to <see cref="MaxFailedCountRetries"/> times.
    /// </summary>
    /// <returns>The (possibly reloaded) user when the update succeeded; otherwise <see langword="null"/>.</returns>
    private async Task<TUser?> RetryOnConcurrencyAsync(
        TUser user,
        Func<TUser, Task<IdentityResult>> update,
        Func<TUser, Task<bool>>? stillValid = null)
    {
        for (var attempt = 0; attempt < MaxFailedCountRetries; attempt++)
        {
            var result = await update(user);
            if (result?.Succeeded == true) return user;

            if (!IsConcurrencyFailure(result)) return null;

            var reloaded = await ReloadUserAsync(user);
            if (reloaded == null) return null;
            if (stillValid != null && !await stillValid(reloaded)) return null;
            user = reloaded;
        }

        return null;
    }

    private async Task<TUser?> ReloadUserAsync(TUser user)
    {
        // An EF Core store keeps returning the tracked (stale) instance from FindByIdAsync, so reload the entry, in the
        // context the users are read from.
        if ((UserStoreContext(_userStore) ?? _securityDbContext as DbContext) is { } context)
        {
            var entry = context.Entry(user);
            if (entry.State != EntityState.Detached)
            {
                await entry.ReloadAsync();
                return entry.State == EntityState.Detached ? null : user;
            }
        }

        return await _userManager.FindByIdAsync(await _userManager.GetUserIdAsync(user));
    }

    private async Task<bool> IsValidProviderAsync(TUser user, string provider)
    {
        if (string.IsNullOrEmpty(provider)) return false;
        var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
        return providers.Contains(provider, StringComparer.Ordinal);
    }

    private bool IsCurrentTenant(string? tenantId) =>
        !string.IsNullOrEmpty(tenantId)
        && _tenantContext?.TenantId is { } current
        && string.Equals(current, tenantId, StringComparison.Ordinal);

    private static bool IsInactive(TUser user) => user is BaseSecurityUser { IsActive: false };

    private void VerifyAgainstDummyHash(string password)
    {
        var hasher = _userManager.PasswordHasher;
        // Cached per hasher type: Identity registers the hasher as scoped, so a per-instance cache would hash
        // on every request and make this path slower than a real verification.
        if (!s_dummyPasswordHashes.TryGetValue(hasher.GetType(), out var hash))
        {
            var created = hasher.HashPassword(new TUser(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
            // An empty value is not cached, so it is not reused for later calls.
            if (!string.IsNullOrEmpty(created))
                created = s_dummyPasswordHashes.GetOrAdd(hasher.GetType(), created);
            hash = created ?? string.Empty;
        }

        hasher.VerifyHashedPassword(new TUser(), hash, password ?? string.Empty);
    }

    /// <inheritdoc />
    public async Task<AuthResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        EnsureTenantMembershipIsProven();
        var tenantId = _tenantContext?.TenantId;
        if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(refreshToken))
            return AuthResult.Failure(InvalidRefreshToken);

        // A locked-out user is refused before the token is consumed, so the session survives the lockout. Wrong
        // passwords typed by anyone who knows the user name lock the account, and must not end the user's sessions.
        if (_userManager.SupportsUserLockout && await LockedOutOwnerAsync(refreshToken, tenantId, cancellationToken) is { } lockedOutId)
            return RefreshRefused(lockedOutId, "LockedOut");

        // Atomic: of two concurrent refreshes with one token, only one gets past this line.
        var consumed = await _refreshTokenStore.ConsumeAsync(refreshToken, tenantId, cancellationToken);
        if (consumed is not { Succeeded: true } || string.IsNullOrEmpty(consumed.UserId))
        {
            switch (consumed?.Status)
            {
                case RefreshTokenConsumeStatus.Reused:
                    SecurityLog.RefreshTokenReused(_events, tenantId, consumed.UserId, consumed.FamilyId);
                    break;
                case RefreshTokenConsumeStatus.TenantMismatch:
                    SecurityLog.RefreshTokenTenantMismatch(_events, tenantId);
                    break;
                case RefreshTokenConsumeStatus.Consumed:
                    // A store that consumed the token but reported no user: the token is spent and nothing is issued.
                    SecurityLog.RefreshRefused(_events, tenantId, null, "InvalidStoreResult");
                    break;
                default:
                    SecurityLog.RefreshRefused(_events, tenantId, null, consumed?.Status.ToString() ?? "NotFound");
                    break;
            }

            return AuthResult.Failure(InvalidRefreshToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByIdAsync(consumed.UserId);
        if (user == null || IsInactive(user))
            return RefreshRefused(consumed.UserId, user == null ? "UnknownUser" : "Inactive");

        // A lockout that started after the check above: the token is spent.
        if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
            return RefreshRefused(consumed.UserId, "LockedOut");

        if (!await _signInManager.CanSignInAsync(user))
            return RefreshRefused(consumed.UserId, "NotAllowed");

        if (_userManager.SupportsUserSecurityStamp)
        {
            var stamp = await _userManager.GetSecurityStampAsync(user);
            if (consumed.SecurityStamp == null || !string.Equals(stamp, consumed.SecurityStamp, StringComparison.Ordinal))
                return RefreshRefused(consumed.UserId, "StampChanged");
        }

        var refreshed = await BuildAuthenticatedResultAsync(user, tenantId, consumed.FamilyId, ByRefresh, cancellationToken);
        // A failing IIdentityValidator is reported like every other refresh failure.
        return refreshed.Succeeded ? refreshed : AuthResult.Failure(InvalidRefreshToken);

        AuthResult RefreshRefused(string userId, string reason)
        {
            SecurityLog.RefreshRefused(_events, tenantId, userId, reason);
            return AuthResult.Failure(InvalidRefreshToken);
        }
    }

    /// <summary>
    /// The user id of a live refresh token of <paramref name="tenantId"/> whose user is locked out, read without
    /// consuming the token (<see cref="IRefreshTokenStore.ValidateAsync"/>); otherwise <see langword="null"/>, and the
    /// consume decides as usual.
    /// </summary>
    private async Task<string?> LockedOutOwnerAsync(string refreshToken, string tenantId, CancellationToken cancellationToken)
    {
        RefreshTokenValidationResult? peek;
        try
        {
            peek = await _refreshTokenStore.ValidateAsync(refreshToken, cancellationToken);
        }
        catch (Exception e) when (e is NotImplementedException or NotSupportedException)
        {
            // A store without a lookup: the consume below decides, and a lockout spends the token as before.
            return null;
        }

        if (peek is not { IsValid: true, UserId: { Length: > 0 } userId }
            || !string.Equals(peek.TenantId, tenantId, StringComparison.Ordinal))
        {
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        TUser? owner;
        try
        {
            owner = await _userManager.FindByIdAsync(userId);
        }
        catch (Exception e) when (e is FormatException or NotSupportedException or ArgumentException)
        {
            return null;
        }

        return owner != null && await _userManager.IsLockedOutAsync(owner) ? userId : null;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Revokes every refresh token of the authenticated user, in every session, and renews the security stamp.
    /// Access tokens already issued, including the one of this request, stop working at once with
    /// <see cref="JwtSettings.ValidateSecurityStamp"/> on (the default) and a user store that keeps security stamps;
    /// otherwise they stay valid until they expire (<see cref="JwtSettings.ExpiryMinutes"/>, plus at most
    /// <see cref="JwtSettings.MaximumClockSkew"/>). Returns <see langword="false"/>
    /// when no <see cref="ISecurityDataProvider"/> was supplied to the constructor, and, with the tokens already
    /// revoked, when renewing the security stamp fails. A user store without security stamps only has its tokens revoked.
    /// </remarks>
    public async Task<bool> SignOutCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        var user = await FindCurrentUserAsync(cancellationToken);
        if (user == null) return false;

        // Revoke under the stored id: tokens are saved under GetUserIdAsync.
        // Last cancellation point: the revocation and the stamp renewal then run to the end.
        cancellationToken.ThrowIfCancellationRequested();
        var signedOutId = await _userManager.GetUserIdAsync(user);
        await _refreshTokenStore.RevokeAllForUserAsync(signedOutId, CancellationToken.None);
        SecurityLog.SessionsEnded(_events, _tenantContext?.TenantId, signedOutId, "SignOut");
        if (!_userManager.SupportsUserSecurityStamp) return true;

        var stampResult = await UncancellableUserWrites.RenewSecurityStampAsync(_userManager, _userStore, user, _securityDbContext as DbContext);
        return stampResult.Succeeded;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Fails with <c>User not found</c> when there is no authenticated user, the user is not found, or no
    /// <see cref="ISecurityDataProvider"/> was supplied to the constructor.
    /// </remarks>
    public async Task<AuthResult> ChangeOwnPasswordAsync(string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        var user = await FindCurrentUserAsync(cancellationToken);
        if (user == null) return AuthResult.Failure("User not found");

        cancellationToken.ThrowIfCancellationRequested();
        var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
        if (!result.Succeeded)
            return AuthResult.Failure(string.Join(", ", result.Errors.Select(e => e.Description)));

        var userId = await _userManager.GetUserIdAsync(user);
        return AuthResult.Success(new AuthToken("", "", DateTime.MinValue), userId, "", []);
    }

    /// <summary>
    /// The authenticated user of the request, as reported by <see cref="ISecurityDataProvider.GetCurrentUserId"/>,
    /// or <see langword="null"/> when there is none or it does not exist.
    /// </summary>
    private async Task<TUser?> FindCurrentUserAsync(CancellationToken cancellationToken)
    {
        var userId = _dataProvider?.GetCurrentUserId();
        if (string.IsNullOrEmpty(userId)) return null;
        cancellationToken.ThrowIfCancellationRequested();
        return await _userManager.FindByIdAsync(userId);
    }

    /// <inheritdoc />
    public async Task<string?> GeneratePasswordResetTokenAsync(string email, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return null;
        cancellationToken.ThrowIfCancellationRequested();
        return await _userManager.GeneratePasswordResetTokenAsync(user);
    }

    /// <inheritdoc />
    /// <remarks>
    /// An unknown e-mail gets the same failure as an invalid reset token (Identity's <c>InvalidToken</c> description).
    /// </remarks>
    public async Task<AuthResult> ResetPasswordAsync(string email, string token, string newPassword, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return AuthResult.Failure(_userManager.ErrorDescriber.InvalidToken().Description);

        cancellationToken.ThrowIfCancellationRequested();
        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (!result.Succeeded)
            return AuthResult.Failure(string.Join(", ", result.Errors.Select(e => e.Description)));

        return AuthResult.Success(new AuthToken("", "", DateTime.MinValue), "", "", []);
    }
}
