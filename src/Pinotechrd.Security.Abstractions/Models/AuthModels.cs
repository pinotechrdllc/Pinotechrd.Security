using System.Collections.Generic;

namespace Pinotechrd.Security.Models;

/// <summary>
/// Represents the result of an authentication attempt.
/// </summary>
/// <param name="Succeeded">Indicates whether authentication succeeded.</param>
/// <param name="ErrorMessage">Human-readable error for failed authentication attempts.</param>
/// <param name="Token">Issued access and refresh tokens when successful.</param>
/// <param name="UserId">Authenticated user identifier.</param>
/// <param name="FullName">Display name for the authenticated user.</param>
/// <param name="Permissions">Flattened permission list for the authenticated user.</param>
/// <param name="RequiresTwoFactor">Indicates whether a second factor is required to continue.</param>
/// <param name="TwoFactorProviders">Available 2FA providers when second factor is required.</param>
/// <param name="TwoFactorToken">Temporary token used to continue a 2FA flow.</param>
/// <param name="User">Optional user projection returned by the authentication flow.</param>
public record AuthResult(
    bool Succeeded,
    string? ErrorMessage = null,
    AuthToken? Token = null,
    string? UserId = null,
    string? FullName = null,
    IEnumerable<string>? Permissions = null,
    bool RequiresTwoFactor = false,
    IEnumerable<string>? TwoFactorProviders = null,
    string? TwoFactorToken = null,
    object? User = null)
{
    /// <summary>
    /// Creates a successful authentication result.
    /// </summary>
    public static AuthResult Success(AuthToken token, string userId, string fullName, IEnumerable<string> permissions, object? user = null) 
        => new(true, null, token, userId, fullName, permissions, false, null, null, user);

    /// <summary>
    /// Creates a failed authentication result.
    /// </summary>
    public static AuthResult Failure(string errorMessage) 
        => new(false, errorMessage);

    /// <summary>
    /// Creates a result that indicates the sign-in requires two-factor verification.
    /// </summary>
    public static AuthResult TwoFactorRequired(IEnumerable<string> providers, string twoFactorToken)
        => new(false, null, null, null, null, null, true, providers, twoFactorToken);
}

/// <summary>
/// Represents a security token response.
/// </summary>
/// <param name="AccessToken">Short-lived JWT access token.</param>
/// <param name="RefreshToken">Long-lived refresh token used to renew access.</param>
/// <param name="ExpiresAt">UTC expiration instant for the access token.</param>
public record AuthToken(
    string AccessToken,
    string RefreshToken,
    DateTime ExpiresAt);
