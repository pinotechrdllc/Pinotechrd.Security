using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Pinotechrd.Security.Options;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Implementation of the Pinotechrd Authentication Manager.
/// Handles the integration between ASP.NET Identity and Pinotechrd Security Engine.
/// </summary>
/// <remarks>
/// <para>
/// Login failures for an unknown user, a wrong password, a locked-out account and an account that
/// Identity does not allow to sign in all return the same <see cref="AuthResult"/> with the error
/// <c>Invalid credentials</c>. When no password hash is checked against a real user (unknown user,
/// locked out, not allowed), the password is verified against a fixed dummy hash made once with the
/// same <see cref="IPasswordHasher{TUser}"/>, so these paths pay the hashing cost too. This narrows the
/// timing difference between existing and unknown accounts; it is not constant time. The user lookups,
/// the lockout bookkeeping and the database writes for an existing account still take different time.
/// </para>
/// <para>
/// Two-factor sign-in: when the user has two-factor enabled, <see cref="LoginAsync"/> returns
/// <see cref="AuthResult.TwoFactorRequired"/> with an opaque token protected by ASP.NET Core Data
/// Protection. The token is bound to the user, the tenant and the user's security stamp, and expires
/// after five minutes. A successful verification renews the security stamp, which invalidates the
/// token and the code just used. Failed codes count toward the Identity lockout.
/// </para>
/// </remarks>
public class PinotechrdAuthManager<TUser> : IPinotechrdAuthManager<TUser> where TUser : class, new()
{
    private const string InvalidCredentials = "Invalid credentials";
    private const string InvalidSession = "Invalid session";
    private const string InvalidCode = "Invalid or expired code";
    private const string TwoFactorProtectorPurpose = "Pinotechrd.Security.TwoFactor.v1";
    private static readonly TimeSpan TwoFactorTokenLifetime = TimeSpan.FromMinutes(5);
    private static string? s_dummyPasswordHash;

    private readonly UserManager<TUser> _userManager;
    private readonly SignInManager<TUser> _signInManager;
    private readonly ISecurityEngine _securityEngine;
    private readonly ITokenProvider _tokenProvider;
    private readonly IRefreshTokenStore _refreshTokenStore;
    private readonly PinotechrdSecurityOptions _options;
    private readonly IIdentityValidator<TUser>? _customValidator;
    private readonly IPinotechrdMessageService? _messageService;
    private readonly ITimeLimitedDataProtector? _twoFactorProtector;

    /// <summary>
    /// Initializes the authentication manager.
    /// </summary>
    /// <remarks>
    /// Without <paramref name="dataProtectionProvider"/> two-factor sign-in fails closed: a user with
    /// two-factor enabled cannot log in and every two-factor method fails. <c>AddPinotechrdSecurity</c>
    /// registers Data Protection through ASP.NET Core Identity.
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
        IDataProtectionProvider? dataProtectionProvider = null)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _securityEngine = securityEngine;
        _tokenProvider = tokenProvider;
        _refreshTokenStore = refreshTokenStore;
        _options = options.Value;
        _customValidator = customValidator;
        _messageService = messageService;
        _twoFactorProtector = dataProtectionProvider?
            .CreateProtector(TwoFactorProtectorPurpose)
            .ToTimeLimitedDataProtector();
    }

    /// <inheritdoc />
    public async Task<AuthResult> LoginAsync(string emailOrUsername, string password, string tenantId)
    {
        // 1. Hybrid lookup: Try Email, then UserName
        var user = await _userManager.FindByEmailAsync(emailOrUsername) 
                   ?? await _userManager.FindByNameAsync(emailOrUsername);

        if (user == null)
        {
            VerifyAgainstDummyHash(password);
            return AuthResult.Failure(InvalidCredentials);
        }

        // 2. Check password (lockout semantics are Identity's: lockoutOnFailure stays on)
        var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            // Identity refuses locked-out and not-allowed accounts before it hashes the password.
            if (result.IsLockedOut || result.IsNotAllowed) VerifyAgainstDummyHash(password);
            return AuthResult.Failure(InvalidCredentials);
        }

        // 3. Second factor. CheckPasswordSignInAsync never reports RequiresTwoFactor, so ask Identity directly.
        if (_userManager.SupportsUserTwoFactor && await _userManager.GetTwoFactorEnabledAsync(user))
        {
            if (_twoFactorProtector == null)
                return AuthResult.Failure("Two-factor sign-in is not available");

            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            var twoFactorToken = await CreateTwoFactorTokenAsync(user, tenantId);
            return AuthResult.TwoFactorRequired(providers.ToList(), twoFactorToken);
        }

        return await BuildAuthenticatedResultAsync(user, tenantId);
    }

    private async Task<AuthResult> BuildAuthenticatedResultAsync(TUser user, string tenantId)
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
        var accessToken = _tokenProvider.GenerateAccessToken(claims);
        var refreshToken = _tokenProvider.GenerateRefreshToken();
        var expiresAt = DateTime.UtcNow.AddMinutes(_options.Jwt.ExpiryMinutes);
        var refreshTokenExpiresAt = DateTime.UtcNow.AddDays(_options.Jwt.RefreshTokenExpiryDays);

        await _refreshTokenStore.SaveAsync(userId, tenantId, refreshToken, refreshTokenExpiresAt);

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
    public async Task<AuthResult> SendTwoFactorCodeAsync(string twoFactorToken, string provider)
    {
        var ticket = await ReadTwoFactorTokenAsync(twoFactorToken);
        if (ticket == null) return AuthResult.Failure(InvalidSession);
        var user = ticket.User;

        if (_messageService == null)
            return AuthResult.Failure("Messaging service not configured for MFA");

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

        var valid = await _userManager.VerifyTwoFactorTokenAsync(user, provider, code);
        if (!valid)
        {
            if (_userManager.SupportsUserLockout) await _userManager.AccessFailedAsync(user);
            return AuthResult.Failure(InvalidCode);
        }

        if (_userManager.SupportsUserLockout) await _userManager.ResetAccessFailedCountAsync(user);

        // Single use: a new security stamp invalidates this token and the code just used.
        if (_userManager.SupportsUserSecurityStamp)
        {
            var stampResult = await _userManager.UpdateSecurityStampAsync(user);
            if (!stampResult.Succeeded) return AuthResult.Failure(InvalidSession);
        }

        return await BuildAuthenticatedResultAsync(user, ticket.TenantId);
    }

    private sealed record TwoFactorTicket(TUser User, string TenantId);

    private async Task<string> CreateTwoFactorTokenAsync(TUser user, string tenantId)
    {
        var userId = await _userManager.GetUserIdAsync(user);
        var stamp = _userManager.SupportsUserSecurityStamp
            ? await _userManager.GetSecurityStampAsync(user)
            : string.Empty;

        var payload = JsonSerializer.Serialize(new[] { userId, tenantId, stamp });
        return _twoFactorProtector!.Protect(payload, TwoFactorTokenLifetime);
    }

    private async Task<TwoFactorTicket?> ReadTwoFactorTokenAsync(string twoFactorToken)
    {
        if (_twoFactorProtector == null || string.IsNullOrEmpty(twoFactorToken)) return null;

        string?[]? parts;
        try
        {
            var payload = _twoFactorProtector.Unprotect(twoFactorToken, out _);
            parts = JsonSerializer.Deserialize<string?[]>(payload);
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        {
            return null;
        }

        if (parts is not { Length: 3 } || string.IsNullOrEmpty(parts[0]) || parts[1] is not { } tenantId) return null;

        var user = await _userManager.FindByIdAsync(parts[0]!);
        if (user == null) return null;

        if (_userManager.SupportsUserSecurityStamp)
        {
            var stamp = await _userManager.GetSecurityStampAsync(user);
            if (!string.Equals(stamp, parts[2] ?? string.Empty, StringComparison.Ordinal)) return null;
        }

        return new TwoFactorTicket(user, tenantId);
    }

    private void VerifyAgainstDummyHash(string password)
    {
        var hasher = _userManager.PasswordHasher;
        var hash = Volatile.Read(ref s_dummyPasswordHash);
        if (hash == null)
        {
            var created = hasher.HashPassword(new TUser(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
            // An empty value is not cached, so it is not reused for later calls.
            if (!string.IsNullOrEmpty(created))
                Interlocked.CompareExchange(ref s_dummyPasswordHash, created, null);
            hash = created ?? string.Empty;
        }

        hasher.VerifyHashedPassword(new TUser(), hash, password ?? string.Empty);
    }

    /// <inheritdoc />
    public async Task<AuthResult> RefreshAsync(string refreshToken)
    {
        var validation = await _refreshTokenStore.ValidateAsync(refreshToken);
        if (!validation.IsValid)
        {
            return AuthResult.Failure(validation.Reason ?? "Invalid token");
        }

        var userId = validation.UserId;
        var tenantId = validation.TenantId ?? string.Empty;

        if (string.IsNullOrEmpty(userId)) return AuthResult.Failure("Invalid token");

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return AuthResult.Failure("User not found");

        await _refreshTokenStore.RevokeAsync(refreshToken);

        return await BuildAuthenticatedResultAsync(user, tenantId);
    }

    /// <inheritdoc />
    public async Task SignOutAsync(string userId)
    {
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
    public async Task<AuthResult> ResetPasswordAsync(string email, string token, string newPassword)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null) return AuthResult.Failure("User not found");

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (!result.Succeeded)
            return AuthResult.Failure(string.Join(", ", result.Errors.Select(e => e.Description)));

        return AuthResult.Success(new AuthToken("", "", DateTime.MinValue), "", "", []);
    }
}
