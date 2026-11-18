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
    public void GetPrincipalFromExpiredToken_ShouldReturnPrincipalFromValidSignedToken()
    {
        var provider = CreateProvider();
        var token = provider.GenerateAccessToken(new[]
        {
            new Claim("id", "user-123"),
            new Claim("tenant_id", "tenant-a")
        });

        var principal = provider.GetPrincipalFromExpiredToken(token);

        principal.FindFirst("id")?.Value.Should().Be("user-123");
        principal.FindFirst("tenant_id")?.Value.Should().Be("tenant-a");
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_ShouldThrow_WhenIssuerDoesNotMatch()
    {
        var sourceProvider = CreateProvider();
        var token = sourceProvider.GenerateAccessToken(new[]
        {
            new Claim("id", "user-123"),
            new Claim("tenant_id", "tenant-a")
        });

        var options = new PinotechrdSecurityOptions
        {
            Jwt = new JwtSettings
            {
                Secret = "super-secret-key-with-minimum-length-32",
                Issuer = "different-issuer",
                Audience = "pinotechrd-clients",
                ExpiryMinutes = 5
            }
        };

        var provider = new JwtTokenProvider(Microsoft.Extensions.Options.Options.Create(options));

        var act = () => provider.GetPrincipalFromExpiredToken(token);

        act.Should().Throw<SecurityTokenException>();
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_ShouldThrow_WhenAudienceDoesNotMatch()
    {
        var sourceProvider = CreateProvider();
        var token = sourceProvider.GenerateAccessToken(new[]
        {
            new Claim("id", "user-123"),
            new Claim("tenant_id", "tenant-a")
        });

        var options = new PinotechrdSecurityOptions
        {
            Jwt = new JwtSettings
            {
                Secret = "super-secret-key-with-minimum-length-32",
                Issuer = "pinotechrd-tests",
                Audience = "different-audience",
                ExpiryMinutes = 5
            }
        };

        var provider = new JwtTokenProvider(Microsoft.Extensions.Options.Options.Create(options));

        var act = () => provider.GetPrincipalFromExpiredToken(token);

        act.Should().Throw<SecurityTokenException>();
    }
}
