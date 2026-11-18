using System.Collections.Generic;
using System.Security.Claims;

namespace Pinotechrd.Security.Interfaces;

/// <summary>
/// Defines the contract for generating and validating security tokens.
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

    /// <summary>
    /// Resolves the principal from an expired token for refresh flows.
    /// </summary>
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
}
