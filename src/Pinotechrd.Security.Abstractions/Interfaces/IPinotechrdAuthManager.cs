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
    /// Authenticates a user by credentials and generates tokens for <paramref name="tenantId"/>,
    /// which must be the tenant resolved for the current request.
    /// </summary>
    Task<AuthResult> LoginAsync(string email, string password, string tenantId);

    /// <summary>
    /// Refreshes an expired access token using a refresh token.
    /// </summary>
    Task<AuthResult> RefreshAsync(string refreshToken);

    /// <summary>
    /// Signs the authenticated user out of every session: revokes all of its refresh tokens.
    /// Access tokens already issued stay valid until they expire.
    /// </summary>
    /// <remarks>
    /// Self-service: the user is the authenticated user of the request (<see cref="ISecurityDataProvider.GetCurrentUserId"/>),
    /// never an identifier supplied by the caller. To sign out another user, use
    /// <see cref="IPinotechrdSecurityManager{TUser, TRole}.RevokeUserSessionsAsync"/>.
    /// </remarks>
    /// <returns><see langword="false"/>, with nothing changed, when there is no authenticated user or the user is not
    /// found; <see langword="false"/>, with the tokens already revoked, when renewing the security stamp fails;
    /// otherwise <see langword="true"/>.</returns>
    Task<bool> SignOutCurrentUserAsync();

    /// <summary>
    /// Changes the authenticated user's password, validating <paramref name="currentPassword"/>.
    /// </summary>
    /// <remarks>
    /// Self-service: the user is the authenticated user of the request (<see cref="ISecurityDataProvider.GetCurrentUserId"/>),
    /// never an identifier supplied by the caller. To change another user's password, use
    /// <see cref="IPinotechrdSecurityManager{TUser, TRole}.ChangeUserPasswordAsync"/>.
    /// </remarks>
    /// <returns>A failed <see cref="AuthResult"/>, with nothing changed, when there is no authenticated user, the user is
    /// not found, or Identity refuses the change.</returns>
    Task<AuthResult> ChangeOwnPasswordAsync(string currentPassword, string newPassword);

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
    /// <param name="twoFactorToken">The temporary token obtained during login (<see cref="AuthResult.TwoFactorToken"/>).
    /// It is an opaque, short-lived value bound to the user and the tenant, not the user identifier.</param>
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
    /// <param name="tenantId">The target tenant ID. It must be the tenant the token was issued for.</param>
    Task<AuthResult> VerifyTwoFactorCodeAsync(string twoFactorToken, string provider, string code, string tenantId);
}
