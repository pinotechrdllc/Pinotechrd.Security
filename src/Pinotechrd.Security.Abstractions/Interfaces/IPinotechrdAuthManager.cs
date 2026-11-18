using System.Collections.Generic;
using System.Threading.Tasks;
using Pinotechrd.Security.Models;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Orchestrates high-level authentication and identity operations.
/// </summary>
/// <typeparam name="TUser">The identity user type.</typeparam>
public interface IPinotechrdAuthManager<TUser> where TUser : class
{
    /// <summary>
    /// Authenticates a user by credentials and generates tokens.
    /// </summary>
    Task<AuthResult> LoginAsync(string email, string password, string tenantId);

    /// <summary>
    /// Refreshes an expired access token using a refresh token.
    /// </summary>
    Task<AuthResult> RefreshAsync(string refreshToken);

    /// <summary>
    /// Invalidates the user's current session.
    /// </summary>
    Task SignOutAsync(string userId);

    /// <summary>
    /// Changes the user's password.
    /// </summary>
    Task<AuthResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword);

    /// <summary>
    /// Initiates a password reset flow.
    /// </summary>
    Task<string?> GeneratePasswordResetTokenAsync(string email);

    /// <summary>
    /// Completes the password reset process.
    /// </summary>
    Task<AuthResult> ResetPasswordAsync(string email, string token, string newPassword);

    /// <summary>
    /// Gets the list of available 2FA providers for the user (Email, Phone, etc).
    /// </summary>
    /// <param name="twoFactorToken">The temporary token obtained during login.</param>
    Task<IList<string>> GetTwoFactorProvidersAsync(string twoFactorToken);

    /// <summary>
    /// Sends a 2FA code to the specified provider.
    /// </summary>
    /// <param name="twoFactorToken">The temporary token.</param>
    /// <param name="provider">The selected provider name.</param>
    Task<AuthResult> SendTwoFactorCodeAsync(string twoFactorToken, string provider);

    /// <summary>
    /// Verifies the 2FA code and completes authentication.
    /// </summary>
    /// <param name="twoFactorToken">The temporary token.</param>
    /// <param name="provider">The provider used.</param>
    /// <param name="code">The verification code.</param>
    /// <param name="tenantId">The target tenant ID.</param>
    Task<AuthResult> VerifyTwoFactorCodeAsync(string twoFactorToken, string provider, string code, string tenantId);
}
