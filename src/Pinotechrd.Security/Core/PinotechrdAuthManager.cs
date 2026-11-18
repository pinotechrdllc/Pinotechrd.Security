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
/// no tenant is resolved or when the tenant passed in differs from it. In the schema-per-tenant model the
/// user is looked up through the tenant's schema, so finding the user is what proves membership; with a
/// shared schema, use <see cref="IIdentityValidator{TUser}"/> to check membership.
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
/// Wrong codes also count toward the Identity lockout. A successful verification renews the security
/// stamp, which invalidates the token and the code just used.
/// </para>
/// <para>
/// Refresh: the presented token is consumed atomically through <see cref="IRefreshTokenStore.ConsumeAsync"/>.
/// A token of another tenant is refused without being consumed. Reusing a consumed token revokes its family.
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

    /// <summary>
    /// Initializes the authentication manager.
    /// </summary>
    /// <remarks>
    /// Without <paramref name="tenantContext"/> every login, two-factor completion and refresh fails, because
    /// the tenant of the request cannot be checked. Without <paramref name="dataProtectionProvider"/> or
    /// <paramref name="twoFactorAttemptStore"/> two-factor sign-in fails closed: a user with two-factor enabled
    /// cannot log in and every two-factor method fails. <c>AddPinotechrdSecurity</c> registers all three.
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
        TimeProvider? timeProvider = null)
    {
        _userManager = userManager;
        _signInManager = signInManager;
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
    }

    /// <inheritdoc />
    public async Task<AuthResult> LoginAsync(string emailOrUsername, string password, string tenantId)
    {
        // 0. The token can only be issued for the tenant this request was resolved for.
        if (!IsCurrentTenant(tenantId))
        {
            VerifyAgainstDummyHash(password);
            return AuthResult.Failure(InvalidCredentials);
        }

        // 1. Hybrid lookup: Try Email, then UserName
        var user = await _userManager.FindByEmailAsync(emailOrUsername)
                   ?? await _userManager.FindByNameAsync(emailOrUsername);

        if (user == null || IsInactive(user))
        {
            VerifyAgainstDummyHash(password);
            return AuthResult.Failure(InvalidCredentials);
        }

        // 2. Check password (lockout semantics are Identity's: lockoutOnFailure stays on)
        var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            // Identity refuses locked-out and not-allowed accounts, and users without a password,
            // before it hashes anything.
            if (result.IsLockedOut || result.IsNotAllowed || !await _userManager.HasPasswordAsync(user))
                VerifyAgainstDummyHash(password);
            return AuthResult.Failure(InvalidCredentials);
        }

        // 3. Second factor. CheckPasswordSignInAsync never reports RequiresTwoFactor, so ask Identity directly.
        if (_userManager.SupportsUserTwoFactor && await _userManager.GetTwoFactorEnabledAsync(user))
        {
            if (_twoFactorProtector == null || _twoFactorAttempts == null)
                return AuthResult.Failure("Two-factor sign-in is not available");

            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            var twoFactorToken = await CreateTwoFactorTokenAsync(user, tenantId);
            return AuthResult.TwoFactorRequired(providers.ToList(), twoFactorToken);
        }

        return await BuildAuthenticatedResultAsync(user, tenantId);
    }

    private async Task<AuthResult> BuildAuthenticatedResultAsync(TUser user, string tenantId, string? familyId = null)
    {
        // Fetch user basic info
        var userId = await _userManager.GetUserIdAsync(user);
        var email = await _userManager.GetEmailAsync(user) ?? string.Empty;

        // 1. External Domain Validation (for example, an employees table owned by the host application)
        string fullName = email;
        var additionalClaims = new List<Claim>();

        if (_customValidator != null)
        {
            var validationResult = await _customValidator.ValidateAsync(user, tenantId);
            if (!validationResult.Succeeded)
                return AuthResult.Failure(validationResult.ErrorMessage ?? "Validation failed");

            fullName = validationResult.FullName ?? fullName;
            if (validationResult.AdditionalClaims != null)
                additionalClaims.AddRange(validationResult.AdditionalClaims);
        }

        // 2. Fetch Permissions via Engine
        var permissions = (await _securityEngine.GetPermissionsAsync(userId)).ToList();

        // 3. Build Claims
        var claims = new List<Claim>
        {
            new Claim("id", userId),
            new Claim("name", fullName),
            new Claim("tenant_id", tenantId),
            new Claim(ClaimTypes.Email, email)
        };

        claims.AddRange(additionalClaims);
        foreach (var p in permissions)
        {
            claims.Add(new Claim("permission", p));
        }

        // 4. Generate Tokens
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var accessToken = _tokenProvider.GenerateAccessToken(claims);
        var refreshToken = _tokenProvider.GenerateRefreshToken();
        var expiresAt = now.AddMinutes(_options.Jwt.ExpiryMinutes);
        var refreshTokenExpiresAt = now.AddDays(_options.Jwt.RefreshTokenExpiryDays);
        var securityStamp = _userManager.SupportsUserSecurityStamp
            ? await _userManager.GetSecurityStampAsync(user)
            : null;

        await _refreshTokenStore.SaveAsync(
            userId,
            tenantId,
            refreshToken,
            refreshTokenExpiresAt,
            familyId ?? Guid.NewGuid().ToString("N"),
            securityStamp);

        return AuthResult.Success(
            new AuthToken(accessToken, refreshToken, expiresAt),
            userId,
            fullName,
            permissions,
            user);
    }

    /// <inheritdoc />
    public async Task<IList<string>> GetTwoFactorProvidersAsync(string twoFactorToken)
    {
        var ticket = await ReadTwoFactorTokenAsync(twoFactorToken);
        if (ticket == null) return new List<string>();

        return await _userManager.GetValidTwoFactorProvidersAsync(ticket.User);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Only providers returned by <see cref="UserManager{TUser}.GetValidTwoFactorProvidersAsync"/> are accepted,
    /// and locked-out users are refused. This method sends a message every time it succeeds: callers must
    /// rate limit it (for example per token and per client address).
    /// </remarks>
    public async Task<AuthResult> SendTwoFactorCodeAsync(string twoFactorToken, string provider)
    {
        var ticket = await ReadTwoFactorTokenAsync(twoFactorToken);
        if (ticket == null) return AuthResult.Failure(InvalidSession);
        var user = ticket.User;

        if (_messageService == null)
            return AuthResult.Failure("Messaging service not configured for MFA");

        if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
            return AuthResult.Failure(InvalidSession);

        if (!await IsValidProviderAsync(user, provider))
            return AuthResult.Failure("Invalid two-factor provider");

        var code = await _userManager.GenerateTwoFactorTokenAsync(user, provider);

        // Destination lookup
        string destination = "";
        if (provider == "Email") destination = await _userManager.GetEmailAsync(user) ?? "";
        else if (provider == "Phone") destination = await _userManager.GetPhoneNumberAsync(user) ?? "";
        // If it's a custom provider, the implementation of IPinotechrdMessageService should handle it
        // Or we could pass more metadata.

        await _messageService.SendCodeAsync(destination, code, SecurityCodeType.TwoFactor);

        return AuthResult.Success(new AuthToken("", "", DateTime.MinValue), "", "", []);
    }

    /// <inheritdoc />
    public async Task<AuthResult> VerifyTwoFactorCodeAsync(string twoFactorToken, string provider, string code, string tenantId)
    {
        var ticket = await ReadTwoFactorTokenAsync(twoFactorToken);
        if (ticket == null || !string.Equals(ticket.TenantId, tenantId, StringComparison.Ordinal))
            return AuthResult.Failure(InvalidSession);

        var user = ticket.User;
        if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
            return AuthResult.Failure(InvalidCode);

        if (!await IsValidProviderAsync(user, provider))
            return AuthResult.Failure(InvalidCode);

        // Count the attempt before checking the code, so concurrent guesses cannot all slip under the limit.
        var attempts = await _twoFactorAttempts!.RegisterAttemptAsync(ticket.ChallengeId, ticket.ExpiresAt);
        if (attempts > MaxTwoFactorAttemptsPerToken)
            return AuthResult.Failure(InvalidCode);

        var valid = await _userManager.VerifyTwoFactorTokenAsync(user, provider, code);
        if (!valid)
        {
            // The per-token count above already holds this failure, even if this update fails.
            if (_userManager.SupportsUserLockout) await _userManager.AccessFailedAsync(user);
            return AuthResult.Failure(InvalidCode);
        }

        // A concurrent failure may have locked the account after the first check.
        if (_userManager.SupportsUserLockout)
        {
            if (await _userManager.IsLockedOutAsync(user)) return AuthResult.Failure(InvalidCode);
            await _userManager.ResetAccessFailedCountAsync(user);
        }

        // Single use: a new security stamp invalidates this token and the code just used.
        if (_userManager.SupportsUserSecurityStamp)
        {
            var stampResult = await _userManager.UpdateSecurityStampAsync(user);
            if (!stampResult.Succeeded) return AuthResult.Failure(InvalidSession);
        }

        return await BuildAuthenticatedResultAsync(user, ticket.TenantId);
    }

    private sealed record TwoFactorTicket(TUser User, string TenantId, string ChallengeId, DateTimeOffset ExpiresAt);

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

    private async Task<TwoFactorTicket?> ReadTwoFactorTokenAsync(string twoFactorToken)
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

        var user = await _userManager.FindByIdAsync(parts[0]!);
        if (user == null || IsInactive(user)) return null;

        if (_userManager.SupportsUserSecurityStamp)
        {
            var stamp = await _userManager.GetSecurityStampAsync(user) ?? string.Empty;
            if (!string.Equals(stamp, parts[2] ?? string.Empty, StringComparison.Ordinal)) return null;
        }

        return new TwoFactorTicket(user, tenantId, parts[3]!, expiresAt);
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
    public async Task<AuthResult> RefreshAsync(string refreshToken)
    {
        var tenantId = _tenantContext?.TenantId;
        if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(refreshToken))
            return AuthResult.Failure(InvalidRefreshToken);

        // Atomic: of two concurrent refreshes with one token, only one gets past this line.
        var consumed = await _refreshTokenStore.ConsumeAsync(refreshToken, tenantId);
        if (consumed is not { Succeeded: true } || string.IsNullOrEmpty(consumed.UserId))
            return AuthResult.Failure(InvalidRefreshToken);

        var user = await _userManager.FindByIdAsync(consumed.UserId);
        if (user == null || IsInactive(user)) return AuthResult.Failure(InvalidRefreshToken);

        if (_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(user))
            return AuthResult.Failure(InvalidRefreshToken);

        if (!await _signInManager.CanSignInAsync(user))
            return AuthResult.Failure(InvalidRefreshToken);

        if (_userManager.SupportsUserSecurityStamp)
        {
            var stamp = await _userManager.GetSecurityStampAsync(user);
            if (consumed.SecurityStamp == null || !string.Equals(stamp, consumed.SecurityStamp, StringComparison.Ordinal))
                return AuthResult.Failure(InvalidRefreshToken);
        }

        return await BuildAuthenticatedResultAsync(user, tenantId, consumed.FamilyId);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Revokes every refresh token of the user, in every session, and renews the security stamp.
    /// Access tokens already issued stay valid until they expire (<see cref="JwtSettings.ExpiryMinutes"/>,
    /// 60 minutes by default), because JWT validation does not consult the server.
    /// </remarks>
    public async Task SignOutAsync(string userId)
    {
        await _refreshTokenStore.RevokeAllForUserAsync(userId);

        var user = await _userManager.FindByIdAsync(userId);
        if (user != null)
        {
            await _userManager.UpdateSecurityStampAsync(user);
        }
    }

    /// <inheritdoc />
    public async Task<AuthResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return AuthResult.Failure("User not found");

        var result = await _userManager.ChangePasswordAsync(user, currentPassword, newPassword);
        if (!result.Succeeded)
            return AuthResult.Failure(string.Join(", ", result.Errors.Select(e => e.Description)));

        return AuthResult.Success(new AuthToken("", "", DateTime.MinValue), userId, "", []);
    }

    /// <inheritdoc />
    public async Task<string?> GeneratePasswordResetTokenAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return null;
        return await _userManager.GeneratePasswordResetTokenAsync(user);
    }

    /// <inheritdoc />
    /// <remarks>
    /// An unknown e-mail gets the same failure as an invalid reset token (Identity's <c>InvalidToken</c> description).
    /// </remarks>
    public async Task<AuthResult> ResetPasswordAsync(string email, string token, string newPassword)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return AuthResult.Failure(_userManager.ErrorDescriber.InvalidToken().Description);

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (!result.Succeeded)
            return AuthResult.Failure(string.Join(", ", result.Errors.Select(e => e.Description)));

        return AuthResult.Success(new AuthToken("", "", DateTime.MinValue), "", "", []);
    }
}
