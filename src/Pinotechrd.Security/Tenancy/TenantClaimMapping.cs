using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Pinotechrd.Security.Tenancy;

/// <summary>
/// Exempts the tenant claim type from inbound claim mapping, so a token's tenant claim is read under the name the
/// library writes and the middleware looks for.
/// </summary>
/// <remarks>
/// Only the per-instance maps of the handlers are changed (<see cref="JsonWebTokenHandler.InboundClaimTypeMap"/>, used by
/// default, and <see cref="JwtSecurityTokenHandler.InboundClaimTypeMap"/>, used when the application turns on
/// <c>UseSecurityTokenValidators</c>); the process-wide default maps and every other claim mapping are left alone.
/// </remarks>
internal static class TenantClaimMapping
{
    public static void Exempt(JwtBearerOptions options, string claimType)
    {
        foreach (var handler in options.TokenHandlers)
        {
            switch (handler)
            {
                case JsonWebTokenHandler json:
                    json.InboundClaimTypeMap.Remove(claimType);
                    break;
                case JwtSecurityTokenHandler legacy:
                    legacy.InboundClaimTypeMap.Remove(claimType);
                    break;
            }
        }

#pragma warning disable CS0618 // SecurityTokenValidators is obsolete, but still active with UseSecurityTokenValidators.
        foreach (var validator in options.SecurityTokenValidators)
        {
            if (validator is JwtSecurityTokenHandler legacy) legacy.InboundClaimTypeMap.Remove(claimType);
        }
#pragma warning restore CS0618
    }

    /// <summary>A legacy handler whose inbound map does not rename <paramref name="claimType"/>.</summary>
    public static JwtSecurityTokenHandler LegacyHandler(string claimType)
    {
        var handler = new JwtSecurityTokenHandler();
        handler.InboundClaimTypeMap.Remove(claimType);
        return handler;
    }
}
