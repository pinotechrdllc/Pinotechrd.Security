using System.Security.Claims;
using System.Threading;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Tells whether the access tokens of a principal still belong to a live session. <c>UseTenantResolution</c> runs this
/// check before each endpoint; a host that resolves the tenant another way calls it itself, after authentication and
/// once the request's data access reads the tenant's own tables.
/// </summary>
/// <remarks>
/// <para>
/// <c>AddPinotechrdSecurity</c> registers it as a scoped service. A session ends, and this method returns
/// <see langword="false"/> for every access token already issued for it, when:
/// </para>
/// <list type="bullet">
/// <item><description>the user signs out (<c>IPinotechrdAuthManager.SignOutCurrentUserAsync</c>);</description></item>
/// <item><description>an administrator ends the user's sessions (<c>IPinotechrdSecurityManager.RevokeUserSessionsAsync</c>);</description></item>
/// <item><description>the password changes or is reset (<c>ChangeOwnPasswordAsync</c>, <c>ResetPasswordAsync</c>,
/// <c>IPinotechrdSecurityManager.ResetUserPasswordAsync</c>);</description></item>
/// <item><description>the user is deactivated (<c>SetUserActiveStatusAsync(id, false)</c>, or <c>UpdateUserAsync</c>
/// with <c>IsActive = false</c>) or deleted;</description></item>
/// <item><description>Identity renews the user's security stamp for another reason (for example a change of email,
/// user name, phone number, two-factor setting or authenticator key, or a two-factor sign-in on another device).</description></item>
/// </list>
/// <para>
/// The check reads the user from the tenant's tables on every call, or, with
/// <c>JwtSettings.SecurityStampValidationInterval</c> above zero, reuses the answer for that long through
/// <c>IDistributedCache</c>, so a session ended meanwhile can still be reported active until it expires. It needs a user
/// store that keeps security stamps; with one that does not, only the user's existence and active flag are checked.
/// How a token carries its session is an implementation detail: do not read or compare the token's claims yourself.
/// </para>
/// <para>
/// Resolve it per request (from <c>HttpContext.RequestServices</c> or an endpoint parameter), never in a singleton: it
/// reads through the request's scoped user store.
/// </para>
/// </remarks>
public interface IAccessTokenSessionValidator
{
    /// <summary>
    /// Returns <see langword="true"/> when every access token of the library in <paramref name="principal"/> belongs
    /// to a live session in <paramref name="tenantId"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library's access tokens are the authenticated identities of <paramref name="principal"/> with claims issued
    /// by <c>JwtSettings.Issuer</c>, and only claims with that issuer are read; identities of other schemes are ignored.
    /// The result is <see langword="false"/> (fails closed) when:
    /// </para>
    /// <list type="bullet">
    /// <item><description><paramref name="principal"/> has no such identity, or <paramref name="tenantId"/> is empty;</description></item>
    /// <item><description>the request's <c>TenantContext</c> is set to another tenant than <paramref name="tenantId"/>;</description></item>
    /// <item><description>an identity does not carry exactly one user id and exactly one tenant claim equal to
    /// <paramref name="tenantId"/>;</description></item>
    /// <item><description>its user does not exist in the tenant, is inactive, or its session ended (see the list on
    /// <see cref="IAccessTokenSessionValidator"/>), including tokens issued before the library carried the session in
    /// them and tokens a host built itself with <c>ITokenProvider.GenerateAccessToken</c> (with a user store that keeps
    /// no security stamps such tokens cannot be told apart, and pass while their user exists and is active).</description></item>
    /// </list>
    /// <para>
    /// Call it after authentication and after the scoped data access has been pointed at <paramref name="tenantId"/>:
    /// the user is read through the request's user store. It always checks, whatever
    /// <c>JwtSettings.ValidateSecurityStamp</c> says; that option only turns the check of <c>UseTenantResolution</c>
    /// off. Answer a <see langword="false"/> with <c>401</c>, as <c>UseTenantResolution</c> does.
    /// </para>
    /// </remarks>
    /// <param name="principal">The authenticated principal of the request, for example <c>HttpContext.User</c>.</param>
    /// <param name="tenantId">The tenant the host resolved for the request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> IsSessionActiveAsync(ClaimsPrincipal principal, string tenantId, CancellationToken cancellationToken = default);
}
