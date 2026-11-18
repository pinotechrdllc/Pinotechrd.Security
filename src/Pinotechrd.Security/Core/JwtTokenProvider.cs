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

    /// <summary>
    /// Initializes the token provider using configured JWT settings.
    /// </summary>
    public JwtTokenProvider(IOptions<PinotechrdSecurityOptions> options)
    {
        _settings = options.Value.Jwt;

        if (string.IsNullOrWhiteSpace(_settings.Secret))
        {
            throw new InvalidOperationException("JWT secret is required.");
        }

        if (_settings.Secret.Length < _settings.MinimumSecretLength)
        {
            throw new InvalidOperationException($"JWT secret must be at least {_settings.MinimumSecretLength} characters.");
        }
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
        var validateIssuer = !string.IsNullOrWhiteSpace(_settings.Issuer);
        var validateAudience = !string.IsNullOrWhiteSpace(_settings.Audience);

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = validateAudience,
            ValidateIssuer = validateIssuer,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _settings.Issuer,
            ValidAudience = _settings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Secret)),
            ValidateLifetime = false 
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        
        if (securityToken is not JwtSecurityToken jwtSecurityToken || 
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }
}
