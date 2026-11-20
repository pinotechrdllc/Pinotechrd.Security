using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>JWT signing key rotation: <c>PreviousSecrets</c> validate only, <c>kid</c> identifies the signing key.</summary>
public class JwtKeyRotationTests
{
    private static readonly string Current = new('c', 40);
    private static readonly string Previous = new('p', 40);
    private static readonly string Previous2 = new('q', 40);
    private static readonly string Unknown = new('u', 40);
    private const string Issuer = "rotation-issuer";
    private const string Audience = "rotation-audience";

    private static string ExpectedKid(string secret) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)))[..16].ToLowerInvariant();

    private static void Configure(PinotechrdSecurityOptions o, params string[] previous)
    {
        o.Jwt.Secret = Current;
        o.Jwt.Issuer = Issuer;
        o.Jwt.Audience = Audience;
        foreach (var p in previous) o.Jwt.PreviousSecrets.Add(p);
        o.AllowUnverifiedTenantMembership = true;
    }

    private static JwtTokenProvider Provider(params string[] previous)
    {
        var options = new PinotechrdSecurityOptions();
        Configure(options, previous);
        return new JwtTokenProvider(Microsoft.Extensions.Options.Options.Create(options));
    }

    private static string Sign(string secret, bool withKid, DateTime? expires = null)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        if (withKid) key.KeyId = ExpectedKid(secret);
        var exp = expires ?? DateTime.UtcNow.AddMinutes(5);
        var token = new JwtSecurityToken(
            Issuer, Audience, [new Claim("id", "user-1")],
            notBefore: exp.AddMinutes(-10), expires: exp,
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static async Task StartAndStopAsync(Action<PinotechrdSecurityOptions> configure)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Services.AllowEphemeralSecurityState();
        builder.Logging.ClearProviders();
        var databaseName = Guid.NewGuid().ToString();
        builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
        builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(configure);
        using var host = builder.Build();
        await host.StartAsync();
        await host.StopAsync();
    }

    private static async Task<string> StartAndGetMessageAsync(Action<PinotechrdSecurityOptions> configure)
    {
        var act = () => StartAndStopAsync(configure);
        return (await act.Should().ThrowAsync<OptionsValidationException>()).Which.Message;
    }

    private static bool IsSignatureFailure(Exception e) =>
        e is SecurityTokenSignatureKeyNotFoundException or SecurityTokenInvalidSignatureException;

    // ---- kid and signing ---------------------------------------------------------------------

    [Fact]
    public void GenerateAccessToken_ShouldCarryKidOfTheCurrentSecret()
    {
        var token = Provider(Previous).GenerateAccessToken([new Claim("id", "u")]);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        jwt.Header.Kid.Should().Be(ExpectedKid(Current));
        jwt.Header.Kid.Should().MatchRegex("^[0-9a-f]{16}$");
    }

    [Fact]
    public void GenerateAccessToken_ShouldNeverSignWithAPreviousSecret()
    {
        var token = Provider(Previous, Previous2).GenerateAccessToken([new Claim("id", "u")]);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        jwt.Header.Kid.Should().NotBe(ExpectedKid(Previous)).And.NotBe(ExpectedKid(Previous2));
        // The current secret alone validates it; the previous ones do not.
        ValidateWith(Current, token).FindFirst("id")!.Value.Should().Be("u");
        ((Action)(() => ValidateWith(Previous, token))).Should().Throw<SecurityTokenException>().Where(e => IsSignatureFailure(e));
        ((Action)(() => ValidateWith(Previous2, token))).Should().Throw<SecurityTokenException>().Where(e => IsSignatureFailure(e));
    }

    private static ClaimsPrincipal ValidateWith(string secret, string token) =>
        new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
        {
            ValidIssuer = Issuer,
            ValidAudience = Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        }, out _);

    // ---- The real JwtBearer handler ----------------------------------------------------------

    private static Task<InProcessHost> StartHostAsync(bool replaceParameters, params string[] previous) =>
        StartHostAsync(replaceParameters, null, previous);

    private static Task<InProcessHost> StartHostAsync(
        bool replaceParameters, Action<JwtBearerOptions>? appConfigure, params string[] previous) =>
        InProcessHost.StartAsync(
            builder =>
            {
                var databaseName = Guid.NewGuid().ToString();
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
                builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o => Configure(o, previous));
                builder.Services.AddHostStubs();
                if (appConfigure is not null)
                {
                    builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, appConfigure);
                }

                if (replaceParameters)
                {
                    builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, o =>
                        o.TokenValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Unknown))
                        });
                }
            },
            app =>
            {
                app.UseAuthentication();
                app.UseAuthorization();
                app.MapGet("/secured", [Authorize] () => Results.Ok());
            });

    private static async Task<HttpStatusCode> CallAsync(InProcessHost host, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/secured");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return (await host.Client.SendAsync(request)).StatusCode;
    }

    [Fact]
    public async Task BearerHandler_ShouldAcceptTokensSignedWithCurrentOrPreviousSecrets_WithOrWithoutKid()
    {
        await using var host = await StartHostAsync(false, Previous, Previous2);

        (await CallAsync(host, Sign(Current, true))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, Sign(Current, false))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, Sign(Previous, true))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, Sign(Previous2, true))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, Sign(Previous2, false))).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task BearerHandler_ShouldRejectAnUnknownSecret_AndAPreviousSecretNotConfigured()
    {
        await using var host = await StartHostAsync(false, Previous);

        (await CallAsync(host, Sign(Unknown, true))).Should().Be(HttpStatusCode.Unauthorized);
        (await CallAsync(host, Sign(Unknown, false))).Should().Be(HttpStatusCode.Unauthorized);
        (await CallAsync(host, Sign(Previous2, true))).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task BearerHandler_ShouldRejectAPreviousSecretToken_WhenThereAreNoPreviousSecrets()
    {
        await using var host = await StartHostAsync(false);

        (await CallAsync(host, Sign(Previous, true))).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task BearerHandler_ShouldRejectAnExpiredPreviousSecretToken()
    {
        await using var host = await StartHostAsync(false, Previous);

        (await CallAsync(host, Sign(Previous, true, DateTime.UtcNow.AddMinutes(-30)))).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task BearerHandler_ShouldValidateAgainstTheConfiguredKeys_WhenTheApplicationReplacedTheParameters()
    {
        await using var host = await StartHostAsync(true, Previous);

        (await CallAsync(host, Sign(Current, true))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, Sign(Previous, true))).Should().Be(HttpStatusCode.OK);
        // The key the application put in its own parameters must not survive.
        (await CallAsync(host, Sign(Unknown, true))).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task BearerHandler_ShouldRejectAForeignKey_WhenTheApplicationSetsAnIssuerSigningKeyResolver()
    {
        var attacker = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Unknown));
        await using var host = await StartHostAsync(false, o =>
            o.TokenValidationParameters.IssuerSigningKeyResolver = (_, _, _, _) => [attacker], Previous);

        (await CallAsync(host, Sign(Unknown, true))).Should().Be(HttpStatusCode.Unauthorized);
        (await CallAsync(host, Sign(Unknown, false))).Should().Be(HttpStatusCode.Unauthorized);
        (await CallAsync(host, Sign(Current, true))).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task BearerHandler_ShouldRejectAForeignKey_WhenTheApplicationSetsASignatureValidatorThatAcceptsAnything()
    {
        await using var host = await StartHostAsync(false, o =>
            o.TokenValidationParameters.SignatureValidator = (token, _) => new JwtSecurityToken(token), Previous);

        (await CallAsync(host, Sign(Unknown, true))).Should().Be(HttpStatusCode.Unauthorized);
        (await CallAsync(host, Sign(Current, true))).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task BearerHandler_ShouldRejectAForeignKey_WhenTheApplicationSetsAnOpenIdConnectConfigurationWithAnExtraKey()
    {
        var attacker = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Unknown));
        await using var host = await StartHostAsync(false, o =>
        {
            var configuration = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration();
            configuration.SigningKeys.Add(attacker);
            o.Configuration = configuration;
        }, Previous);

        (await CallAsync(host, Sign(Unknown, true))).Should().Be(HttpStatusCode.Unauthorized);
        (await CallAsync(host, Sign(Current, true))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, Sign(Previous, true))).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task BearerHandler_ShouldStartAndFetchNothing_WhenTheApplicationSetsAuthorityAndMetadataAddress()
    {
        await using var host = await StartHostAsync(false, o =>
        {
            o.Authority = "https://authority.invalid/";
            o.MetadataAddress = "https://authority.invalid/.well-known/openid-configuration";
            o.RequireHttpsMetadata = true;
        }, Previous);

        (await CallAsync(host, Sign(Current, true))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, Sign(Previous, true))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, Sign(Unknown, true))).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task BearerHandler_ShouldRejectAnUnknownSecret_EvenWhenItsKidClaimsTheCurrentKey()
    {
        await using var host = await StartHostAsync(false, Previous);
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Unknown)) { KeyId = ExpectedKid(Current) };
        var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            Issuer, Audience, [new Claim("id", "x")], expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)));

        (await CallAsync(host, token)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public void PostConfigure_ShouldForceTheKeysCurrentFirstThenPrevious_AfterTheApplicationReplacedTheParameters()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o => Configure(o, Previous, Previous2));
        services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, o =>
            o.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Unknown))
            });
        using var provider = services.BuildServiceProvider();

        var parameters = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;

        parameters.IssuerSigningKey.Should().BeNull();
        parameters.IssuerSigningKeys.Select(k => k.KeyId).Should()
            .Equal(ExpectedKid(Current), ExpectedKid(Previous), ExpectedKid(Previous2));
    }

    // ---- Startup validation ------------------------------------------------------------------

    [Fact]
    public async Task HostStart_ShouldAcceptValidPreviousSecrets()
    {
        var act = () => StartAndStopAsync(o => Configure(o, Previous, Previous2));

        await act.Should().NotThrowAsync();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task HostStart_ShouldRejectAnEmptyPreviousSecret(string empty)
    {
        var message = await StartAndGetMessageAsync(o => Configure(o, Previous, empty));

        message.Should().Contain("PinotechrdSecurityOptions.Jwt.PreviousSecrets[1] must not be empty.");
    }

    [Fact]
    public async Task HostStart_ShouldRejectAPreviousSecretShorterThan32Bytes()
    {
        var message = await StartAndGetMessageAsync(o => Configure(o, new string('s', 31)));

        message.Should().Contain("PinotechrdSecurityOptions.Jwt.PreviousSecrets[0] must be at least 32 bytes in UTF-8.");
    }

    [Fact]
    public async Task HostStart_ShouldAcceptAPreviousSecretOfExactly32Bytes()
    {
        var act = () => StartAndStopAsync(o => Configure(o, new string('s', 32)));

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task HostStart_ShouldUseTheRaisedMinimumLengthForPreviousSecrets()
    {
        var message = await StartAndGetMessageAsync(o =>
        {
            Configure(o, new string('s', 40));
            o.Jwt.Secret = new string('c', 64);
            o.Jwt.MinimumSecretLength = 64;
        });

        message.Should().Contain("PinotechrdSecurityOptions.Jwt.PreviousSecrets[0] must be at least 64 bytes in UTF-8.");
    }

    [Fact]
    public async Task HostStart_ShouldRejectAPreviousSecretEqualToTheCurrentSecret()
    {
        var message = await StartAndGetMessageAsync(o => Configure(o, Previous, Current));

        message.Should().Contain("PinotechrdSecurityOptions.Jwt.PreviousSecrets[1] must not equal PinotechrdSecurityOptions.Jwt.Secret.");
        message.Should().NotContain("PreviousSecrets[0]");
    }

    [Fact]
    public async Task HostStart_ShouldRejectOnlyTheLaterCopyOfADuplicatePreviousSecret()
    {
        var message = await StartAndGetMessageAsync(o => Configure(o, Previous, Previous2, Previous));

        message.Should().Contain("PinotechrdSecurityOptions.Jwt.PreviousSecrets[2] duplicates an earlier entry of PinotechrdSecurityOptions.Jwt.PreviousSecrets.");
        message.Should().NotContain("PreviousSecrets[0]").And.NotContain("PreviousSecrets[1]");
    }

    [Fact]
    public async Task HostStart_ShouldNeverPutAPreviousSecretValueInTheErrorMessage()
    {
        const string weak = "weak-previous-VALUE-do-not-leak";

        var message = await StartAndGetMessageAsync(o => Configure(o, weak));

        message.Should().Contain("PreviousSecrets[0]").And.NotContain(weak);
    }
}
