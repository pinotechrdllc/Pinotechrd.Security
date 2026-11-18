using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
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
public class PinotechrdAuthManager<TUser> : IPinotechrdAuthManager<TUser> where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly SignInManager<TUser> _signInManager;
    private readonly ISecurityEngine _securityEngine;
    private readonly ITokenProvider _tokenProvider;
    private readonly IRefreshTokenStore _refreshTokenStore;
    private readonly PinotechrdSecurityOptions _options;
    private readonly IIdentityValidator<TUser>? _customValidator;
    private readonly IPinotechrdMessageService? _messageService;

    /// <summary>
    /// Initializes the authentication manager.
    /// </summary>
    public PinotechrdAuthManager(
        UserManager<TUser> userManager,
        SignInManager<TUser> signInManager,
        ISecurityEngine securityEngine,
        ITokenProvider tokenProvider,
        IRefreshTokenStore refreshTokenStore,
        IOptions<PinotechrdSecurityOptions> options,
        IIdentityValidator<TUser>? customValidator = null,
        IPinotechrdMessageService? messageService = null)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _securityEngine = securityEngine;
        _tokenProvider = tokenProvider;
        _refreshTokenStore = refreshTokenStore;
        _options = options.Value;
        _customValidator = customValidator;
        _messageService = messageService;
    }

    /// <inheritdoc />
    public async Task<AuthResult> LoginAsync(string emailOrUsername, string password, string tenantId)
    {
        // 1. Hybrid lookup: Try Email, then UserName
        var user = await _userManager.FindByEmailAsync(emailOrUsername) 
                   ?? await _userManager.FindByNameAsync(emailOrUsername);

        if (user == null) return AuthResult.Failure("Invalid credentials");

        // 2. Check password
        var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        
        if (result.RequiresTwoFactor)
        {
            var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
            var userId = await _userManager.GetUserIdAsync(user);
            return AuthResult.TwoFactorRequired(providers.ToList(), userId);
        }

        if (!result.Succeeded)
        {
            if (result.IsLockedOut) return AuthResult.Failure("Account locked out");
            return AuthResult.Failure("Invalid credentials");
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
        var user = await _userManager.FindByIdAsync(twoFactorToken);
        if (user == null) return new List<string>();

        return await _userManager.GetValidTwoFactorProvidersAsync(user);
    }

    /// <inheritdoc />
    public async Task<AuthResult> SendTwoFactorCodeAsync(string twoFactorToken, string provider)
    {
        var user = await _userManager.FindByIdAsync(twoFactorToken);
        if (user == null) return AuthResult.Failure("Invalid session");

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
        var user = await _userManager.FindByIdAsync(twoFactorToken);
        if (user == null) return AuthResult.Failure("Invalid session");

        var valid = await _userManager.VerifyTwoFactorTokenAsync(user, provider, code);
        if (!valid) return AuthResult.Failure("Invalid or expired code");

        return await BuildAuthenticatedResultAsync(user, tenantId);
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
