using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Implements JWT token generation and validation.
/// </summary>
public class JwtTokenProvider : ITokenProvider
{
    private readonly JwtSettings _settings;
    private readonly string _tenantClaimType;

    /// <summary>
    /// Initializes the token provider using configured JWT settings.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The secret is missing or shorter than 32 UTF-8 bytes (or <see cref="JwtSettings.MinimumSecretLength"/> if higher),
    /// or the issuer or audience is missing.
    /// </exception>
    public JwtTokenProvider(IOptions<PinotechrdSecurityOptions> options)
    {
        _settings = options.Value.Jwt;
        _tenantClaimType = options.Value.Tenancy.ClaimType;
        JwtSettingsRules.ThrowIfInvalid(_settings);
    }

    /// <inheritdoc />
    public string GenerateAccessToken(IEnumerable<Claim> claims)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _settings.Issuer,
            audience: _settings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_settings.ExpiryMinutes),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <inheritdoc />
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    /// <inheritdoc />
    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _settings.Issuer,
            ValidAudience = _settings.Audience,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Secret)),
            ValidateLifetime = false 
        };

        // Same claim names as the bearer handler: the tenant claim type is exempt from inbound mapping.
        var tokenHandler = Tenancy.TenantClaimMapping.LegacyHandler(_tenantClaimType);
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        
        if (securityToken is not JwtSecurityToken jwtSecurityToken || 
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }
}
