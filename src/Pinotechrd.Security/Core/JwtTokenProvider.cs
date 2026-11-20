using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;

namespace Pinotechrd.Security.Core;

/// <summary>
/// Issues JWT access tokens and opaque refresh token values.
/// </summary>
public class JwtTokenProvider : ITokenProvider
{
    private readonly JwtSettings _settings;

    /// <summary>
    /// Initializes the token provider using configured JWT settings.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// A <see cref="JwtSettings"/> value fails validation: the secret is missing or shorter than 32 UTF-8 bytes (or
    /// <see cref="JwtSettings.MinimumSecretLength"/> if higher), a previous secret is invalid, the issuer or audience is
    /// missing, or <see cref="JwtSettings.ExpiryMinutes"/>, <see cref="JwtSettings.RefreshTokenExpiryDays"/> or
    /// <see cref="JwtSettings.MaximumClockSkew"/> is out of range.
    /// </exception>
    public JwtTokenProvider(IOptions<PinotechrdSecurityOptions> options)
    {
        _settings = options.Value.Jwt;
        JwtSettingsRules.ThrowIfInvalid(_settings);
    }

    /// <inheritdoc />
    public string GenerateAccessToken(IEnumerable<Claim> claims)
    {
        // Signed with the current secret only; the header carries its kid.
        var creds = JwtSigningKeys.CreateSigningCredentials(_settings);

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
}
