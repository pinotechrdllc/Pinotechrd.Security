using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Options;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class JwtTokenProviderTests
{
    private static JwtTokenProvider CreateProvider()
    {
        var options = new PinotechrdSecurityOptions
        {
            Jwt = new JwtSettings
            {
                Secret = "super-secret-key-with-minimum-length-32",
                Issuer = "pinotechrd-tests",
                Audience = "pinotechrd-clients",
                ExpiryMinutes = 5
            }
        };

        return new JwtTokenProvider(Microsoft.Extensions.Options.Options.Create(options));
    }

    [Fact]
    public void GenerateAccessToken_ShouldIncludeProvidedClaims()
    {
        var provider = CreateProvider();
        var claims = new[]
        {
            new Claim("id", "user-123"),
            new Claim("tenant_id", "tenant-a")
        };

        var token = provider.GenerateAccessToken(claims);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        jwt.Claims.Should().Contain(c => c.Type == "id" && c.Value == "user-123");
        jwt.Claims.Should().Contain(c => c.Type == "tenant_id" && c.Value == "tenant-a");
    }

    [Fact]
    public void GenerateRefreshToken_ShouldReturnDifferentValues()
    {
        var provider = CreateProvider();

        var first = provider.GenerateRefreshToken();
        var second = provider.GenerateRefreshToken();

        first.Should().NotBeNullOrWhiteSpace();
        second.Should().NotBeNullOrWhiteSpace();
        first.Should().NotBe(second);
    }

    [Fact]
    public void GenerateAccessToken_ShouldBeValidOnlyForTheConfiguredIssuerAudienceAndSecret()
    {
        var token = CreateProvider().GenerateAccessToken([new Claim("id", "user-123"), new Claim("tenant_id", "tenant-a")]);

        Validate(token, "pinotechrd-tests", "pinotechrd-clients", "super-secret-key-with-minimum-length-32")
            .FindFirst("id")?.Value.Should().Be("user-123");
        ((Action)(() => Validate(token, "different-issuer", "pinotechrd-clients", "super-secret-key-with-minimum-length-32")))
            .Should().Throw<SecurityTokenException>();
        ((Action)(() => Validate(token, "pinotechrd-tests", "different-audience", "super-secret-key-with-minimum-length-32")))
            .Should().Throw<SecurityTokenException>();
        ((Action)(() => Validate(token, "pinotechrd-tests", "pinotechrd-clients", "another-secret-key-with-minimum-length-32")))
            .Should().Throw<SecurityTokenException>();
    }

    [Fact]
    public void ITokenProvider_ShouldNotOfferToReadExpiredTokens()
    {
        // Sessions are renewed with opaque refresh tokens; reading an expired access token at any age bypassed revocation.
        typeof(Pinotechrd.Security.Interfaces.ITokenProvider).GetMethod("GetPrincipalFromExpiredToken").Should().BeNull();
        typeof(JwtTokenProvider).GetMethod("GetPrincipalFromExpiredToken").Should().BeNull();
    }

    private static ClaimsPrincipal Validate(string token, string issuer, string audience, string secret) =>
        new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(secret)),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        }, out _);
}
