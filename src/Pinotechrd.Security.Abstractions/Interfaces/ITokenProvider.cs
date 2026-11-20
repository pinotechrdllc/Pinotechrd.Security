using System.Collections.Generic;
using System.Security.Claims;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Issues access tokens and opaque refresh token values.
/// </summary>
public interface ITokenProvider
{
    /// <summary>
    /// Generates a new access token with the specified claims.
    /// </summary>
    string GenerateAccessToken(IEnumerable<Claim> claims);

    /// <summary>
    /// Generates a secure random refresh token.
    /// </summary>
    string GenerateRefreshToken();
}
