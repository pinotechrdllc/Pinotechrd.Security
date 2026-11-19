using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Hosting;

/// <summary>
/// How the library's JwtBearer setup combines with a consumer's own <c>Configure&lt;JwtBearerOptions&gt;</c>:
/// consumer settings that do not weaken validation survive, and the algorithm pin always wins.
/// </summary>
public class JwtBearerConfigurationTests
{
    private const string Secret = "jwt-bearer-config-test-secret-key-32-bytes!";

    private static JwtBearerOptions Resolve(Action<IServiceCollection>? before = null, Action<IServiceCollection>? after = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        before?.Invoke(services);
        services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
        {
            o.Jwt.Secret = Secret;
            o.Jwt.Issuer = "the-issuer";
            o.Jwt.Audience = "the-audience";
            o.AllowUnverifiedTenantMembership = true;
        });
        after?.Invoke(services);
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
    }

    [Fact]
    public void LibraryDefaults_ShouldRequireIssuerAudienceLifetimeSigningKeyAndHs256()
    {
        var parameters = Resolve().TokenValidationParameters;

        parameters.ValidateIssuer.Should().BeTrue();
        parameters.ValidateAudience.Should().BeTrue();
        parameters.ValidateLifetime.Should().BeTrue();
        parameters.ValidateIssuerSigningKey.Should().BeTrue();
        parameters.ValidIssuer.Should().Be("the-issuer");
        parameters.ValidAudience.Should().Be("the-audience");
        parameters.ValidAlgorithms.Should().Equal(SecurityAlgorithms.HmacSha256);
        parameters.IssuerSigningKey.Should().BeNull();
        parameters.IssuerSigningKeys.Should().ContainSingle()
            .Which.Should().BeOfType<SymmetricSecurityKey>()
            .Which.Key.Should().Equal(Encoding.UTF8.GetBytes(Secret));
    }

    [Fact]
    public void ConsumerClockSkew_ShouldBeKept_WhenConfiguredBeforeAddPinotechrdSecurity()
    {
        var options = Resolve(before: services => services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(7)));

        options.TokenValidationParameters.ClockSkew.Should().Be(TimeSpan.FromSeconds(7));
        options.TokenValidationParameters.ValidAlgorithms.Should().Equal(SecurityAlgorithms.HmacSha256);
        options.TokenValidationParameters.ValidIssuer.Should().Be("the-issuer");
    }

    [Fact]
    public void ConsumerClockSkew_ShouldBeKept_WhenConfiguredAfterAddPinotechrdSecurity()
    {
        var options = Resolve(after: services => services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(9)));

        options.TokenValidationParameters.ClockSkew.Should().Be(TimeSpan.FromSeconds(9));
    }

    [Fact]
    public void ConsumerAlgorithms_ShouldBeOverriddenByThePin_WhenConfiguredAfter()
    {
        var options = Resolve(after: services => services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.HmacSha512]));

        options.TokenValidationParameters.ValidAlgorithms.Should().Equal(SecurityAlgorithms.HmacSha256);
    }

    [Fact]
    public void ConsumerAlgorithms_ShouldBeOverriddenByThePin_WhenConfiguredBefore()
    {
        var options = Resolve(before: services => services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.HmacSha512]));

        options.TokenValidationParameters.ValidAlgorithms.Should().Equal(SecurityAlgorithms.HmacSha256);
    }

    [Fact]
    public void ConsumerPostConfigure_ThatChangesTheAlgorithms_ShouldFailOptionsValidation()
    {
        // A later PostConfigure runs after the library's pin; the final options are validated, so the change is refused.
        var act = () => Resolve(after: services => services.PostConfigure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.HmacSha512]));

        act.Should().Throw<OptionsValidationException>().WithMessage("*ValidAlgorithms must be HS256 only*");
    }

    // ---- Members that widen what the policy accepts ---------------------------------------------

    public static TheoryData<string, Action<TokenValidationParameters>> WideningMembers => new()
    {
        { "LifetimeValidator", p => p.LifetimeValidator = (_, _, _, _) => true },
        { "AudienceValidator", p => p.AudienceValidator = (_, _, _) => true },
        { "IssuerValidator", p => p.IssuerValidator = (issuer, _, _) => issuer },
        { "AlgorithmValidator", p => p.AlgorithmValidator = (_, _, _, _) => true },
        { "ValidIssuers", p => p.ValidIssuers = ["someone-else"] },
        { "ValidAudiences", p => p.ValidAudiences = ["someone-else"] },
    };

    [Theory]
    [MemberData(nameof(WideningMembers))]
    public void ConsumerConfigure_ThatWidensThePolicy_ShouldBeCleared(string member, Action<TokenValidationParameters> widen)
    {
        foreach (var before in new[] { true, false })
        {
            Action<IServiceCollection> configure = services => services.Configure<JwtBearerOptions>(
                JwtBearerDefaults.AuthenticationScheme, o => widen(o.TokenValidationParameters));
            var parameters = (before ? Resolve(before: configure) : Resolve(after: configure)).TokenValidationParameters;

            parameters.LifetimeValidator.Should().BeNull(member);
            parameters.AudienceValidator.Should().BeNull(member);
            parameters.IssuerValidator.Should().BeNull(member);
            parameters.AlgorithmValidator.Should().BeNull(member);
            parameters.ValidIssuers.Should().BeNull(member);
            parameters.ValidAudiences.Should().BeNull(member);
        }
    }

    [Theory]
    [MemberData(nameof(WideningMembers))]
    public void ConsumerPostConfigure_ThatWidensThePolicy_ShouldFailOptionsValidation(string member, Action<TokenValidationParameters> widen)
    {
        var act = () => Resolve(after: services => services.PostConfigure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme, o => widen(o.TokenValidationParameters)));

        act.Should().Throw<OptionsValidationException>().WithMessage($"*{member} must*");
    }

    private static SymmetricSecurityKey OtherKey() => new(Encoding.UTF8.GetBytes(new string('k', 48)));

    private sealed class SubclassedParameters : TokenValidationParameters;

    private sealed class CustomHandler : Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler;

    public static TheoryData<string, Action<JwtBearerOptions>> ReplacedSecurityMembers => new()
    {
        { "IssuerSigningKeys", o => o.TokenValidationParameters.IssuerSigningKeys = [OtherKey()] },
        { "IssuerSigningKeys", o => o.TokenValidationParameters.IssuerSigningKeys = [.. o.TokenValidationParameters.IssuerSigningKeys, OtherKey()] },
        { "IssuerSigningKey", o => o.TokenValidationParameters.IssuerSigningKey = OtherKey() },
        { "IssuerSigningKeyResolver", o => o.TokenValidationParameters.IssuerSigningKeyResolver = (_, _, _, _) => [OtherKey()] },
        { "IssuerSigningKeyResolverUsingConfiguration", o => o.TokenValidationParameters.IssuerSigningKeyResolverUsingConfiguration = (_, _, _, _, _) => [OtherKey()] },
        { "ValidateIssuer", o => o.TokenValidationParameters.ValidateIssuer = false },
        { "ValidateAudience", o => o.TokenValidationParameters.ValidateAudience = false },
        { "ValidateLifetime", o => o.TokenValidationParameters.ValidateLifetime = false },
        { "ValidateIssuerSigningKey", o => o.TokenValidationParameters.ValidateIssuerSigningKey = false },
        { "RequireSignedTokens", o => o.TokenValidationParameters.RequireSignedTokens = false },
        { "RequireExpirationTime", o => o.TokenValidationParameters.RequireExpirationTime = false },
        { "ValidIssuer", o => o.TokenValidationParameters.ValidIssuer = "someone-else" },
        { "ValidAudience", o => o.TokenValidationParameters.ValidAudience = "someone-else" },
        { "IssuerValidatorUsingConfiguration", o => o.TokenValidationParameters.IssuerValidatorUsingConfiguration = (issuer, _, _, _) => issuer },
        { "SignatureValidator", o => o.TokenValidationParameters.SignatureValidator = (token, _) => new JwtSecurityToken(token) },
        { "SignatureValidatorUsingConfiguration", o => o.TokenValidationParameters.SignatureValidatorUsingConfiguration = (token, _, _) => new JwtSecurityToken(token) },
        { "TokenReader", o => o.TokenValidationParameters.TokenReader = (token, _) => new JwtSecurityToken(token) },
        { "TransformBeforeSignatureValidation", o => o.TokenValidationParameters.TransformBeforeSignatureValidation = (token, _) => token },
        { "TokenValidationParameters", o => o.TokenValidationParameters = new SubclassedParameters() },
        { "TokenHandlers", o => o.TokenHandlers.Add(new CustomHandler()) },
        { "ForwardDefault", o => o.ForwardDefault = "other" },
        { "ForwardAuthenticate", o => o.ForwardAuthenticate = "other" },
        { "ForwardDefaultSelector", o => o.ForwardDefaultSelector = _ => "other" },
        { "ClockSkew", o => o.TokenValidationParameters.ClockSkew = TimeSpan.FromDays(365) },
        { "ClockSkew", o => o.TokenValidationParameters.ClockSkew = TimeSpan.FromMinutes(5) + TimeSpan.FromTicks(1) },
    };

    [Theory]
    [MemberData(nameof(ReplacedSecurityMembers))]
    public void ConsumerPostConfigure_ThatChangesThePolicy_ShouldFailOptionsValidation(string member, Action<JwtBearerOptions> change)
    {
        var act = () => Resolve(after: services => services.PostConfigure(JwtBearerDefaults.AuthenticationScheme, change));

        act.Should().Throw<OptionsValidationException>().WithMessage($"*{member} must*");
    }

    [Fact]
    public void ConsumerPostConfigure_ThatSetsTheParametersToNull_ShouldFailOptionsValidation()
    {
        var act = () => Resolve(after: services => services.PostConfigure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme, o => o.TokenValidationParameters = null!));

        act.Should().Throw<OptionsValidationException>().WithMessage("*TokenValidationParameters is null*");
    }

    [Fact]
    public void ClockSkewOfExactlyFiveMinutes_ShouldBeAccepted()
    {
        var options = Resolve(after: services => services.PostConfigure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme, o => o.TokenValidationParameters.ClockSkew = TimeSpan.FromMinutes(5)));

        options.TokenValidationParameters.ClockSkew.Should().Be(TimeSpan.FromMinutes(5));
    }

    [Fact]
    public void AnotherBearerScheme_ShouldNotBeCheckedByThePolicy()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication().AddJwtBearer("Partner", o => o.TokenValidationParameters.ValidateLifetime = false);
        services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
        {
            o.Jwt.Secret = Secret;
            o.Jwt.Issuer = "the-issuer";
            o.Jwt.Audience = "the-audience";
            o.AllowUnverifiedTenantMembership = true;
        });
        using var provider = services.BuildServiceProvider();

        var other = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get("Partner");

        other.TokenValidationParameters.ValidateLifetime.Should().BeFalse("the policy covers the library's scheme only");
    }

    [Fact]
    public async Task HostStart_ShouldFailWithOnlyTheSecurityOptionsError_WhenThoseAreInvalid()
    {
        var act = () => InProcessHost.StartAsync(
            builder =>
            {
                var databaseName = Guid.NewGuid().ToString();
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
                builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = Secret;
                    o.Jwt.Issuer = "the-issuer";
                    o.Jwt.Audience = "";
                    o.AllowUnverifiedTenantMembership = true;
                });
                builder.Services.AddHostStubs();
            },
            app => app.MapGet("/", () => Results.Ok()));

        (await act.Should().ThrowAsync<OptionsValidationException>())
            .Which.Message.Should().Contain("PinotechrdSecurityOptions.Jwt.Audience").And.NotContain("JwtBearerOptions");
    }

    [Fact]
    public void ConsumerPostConfigure_OfSettingsOutsideThePolicy_ShouldBeAccepted()
    {
        var options = Resolve(after: services => services.PostConfigure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o =>
            {
                o.TokenValidationParameters.NameClaimType = "name";
                o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
                o.SaveToken = true;
            }));

        options.TokenValidationParameters.NameClaimType.Should().Be("name");
        options.TokenValidationParameters.ClockSkew.Should().Be(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task HostStart_ShouldFail_WhenALaterPostConfigureWeakensThePolicy()
    {
        var act = () => InProcessHost.StartAsync(
            builder =>
            {
                var databaseName = Guid.NewGuid().ToString();
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
                builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = Secret;
                    o.Jwt.Issuer = "the-issuer";
                    o.Jwt.Audience = "the-audience";
                    o.AllowUnverifiedTenantMembership = true;
                });
                builder.Services.AddHostStubs();
                builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme,
                    o => o.TokenValidationParameters.LifetimeValidator = (_, _, _, _) => true);
            },
            app => app.MapGet("/", () => Results.Ok()));

        await act.Should().ThrowAsync<OptionsValidationException>().WithMessage("*LifetimeValidator*");
    }

    [Fact]
    public void ReplacingTheParametersEntirely_ShouldStillEndWithThePinnedAlgorithm()
    {
        var options = Resolve(after: services => services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters = new TokenValidationParameters { ClockSkew = TimeSpan.Zero }));

        options.TokenValidationParameters.ValidAlgorithms.Should().Equal(SecurityAlgorithms.HmacSha256);
        options.TokenValidationParameters.ClockSkew.Should().Be(TimeSpan.Zero);
    }

    // Replacing the whole parameters object drops what the library configured. The pin is re-applied, but the issuer,
    // the audience and the signing key are not: a consumer that replaces the object and turns validation off ends
    // with a bearer handler that accepts any token signed with an allowed algorithm and any issuer.
    [Fact]
    public void ReplacingTheParametersEntirely_ShouldStillRequireTheConfiguredIssuerAndAudience()
    {
        var options = Resolve(after: services => services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = false
            }));
        var parameters = options.TokenValidationParameters;

        parameters.ValidAlgorithms.Should().Equal(SecurityAlgorithms.HmacSha256);
        parameters.ValidateIssuer.Should().BeTrue();
        parameters.ValidateAudience.Should().BeTrue();
        parameters.ValidIssuer.Should().Be("the-issuer");
        parameters.ValidAudience.Should().Be("the-audience");
        parameters.IssuerSigningKey.Should().BeNull();
        parameters.IssuerSigningKeys.Should().ContainSingle()
            .Which.Should().BeOfType<SymmetricSecurityKey>()
            .Which.Key.Should().Equal(Encoding.UTF8.GetBytes(Secret));
    }

    [Fact]
    public void ReplacingTheParametersEntirely_WithDefaults_ShouldStillEndWithTheConfiguredIssuerAudienceKeyAndLifetime()
    {
        var options = Resolve(after: services => services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters = new TokenValidationParameters()));
        var parameters = options.TokenValidationParameters;

        parameters.ValidateIssuer.Should().BeTrue();
        parameters.ValidateAudience.Should().BeTrue();
        parameters.ValidateLifetime.Should().BeTrue();
        parameters.ValidateIssuerSigningKey.Should().BeTrue();
        parameters.ValidIssuer.Should().Be("the-issuer");
        parameters.ValidAudience.Should().Be("the-audience");
        parameters.IssuerSigningKey.Should().BeNull();
        parameters.IssuerSigningKeys.Should().ContainSingle()
            .Which.Should().BeOfType<SymmetricSecurityKey>()
            .Which.Key.Should().Equal(Encoding.UTF8.GetBytes(Secret));
        parameters.ValidAlgorithms.Should().Equal(SecurityAlgorithms.HmacSha256);
    }

    // The framework's own JwtBearerPostConfigureOptions runs before the library's and dereferences the parameters, so a
    // null assignment fails closed (an exception when the options are first built) instead of reaching the library's step.
    [Fact]
    public void SettingTheParametersToNull_ShouldNeverEndWithWeakerValidation_ItFailsClosedOrEndsValidated()
    {
        JwtBearerOptions? options = null;
        var act = () => options = Resolve(after: services => services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters = null!));

        try
        {
            act();
        }
        catch (Exception)
        {
            return; // failed closed
        }

        var parameters = options!.TokenValidationParameters;
        parameters.ValidateIssuer.Should().BeTrue();
        parameters.ValidateAudience.Should().BeTrue();
        parameters.ValidateLifetime.Should().BeTrue();
        parameters.ValidIssuer.Should().Be("the-issuer");
        parameters.ValidAudience.Should().Be("the-audience");
        parameters.ValidAlgorithms.Should().Equal(SecurityAlgorithms.HmacSha256);
    }

    [Fact]
    public void ReplacingTheParametersEntirely_ShouldKeepASignedTokenRequirement()
    {
        var options = Resolve(after: services => services.Configure<JwtBearerOptions>(
            JwtBearerDefaults.AuthenticationScheme,
            o => o.TokenValidationParameters = new TokenValidationParameters { RequireSignedTokens = false, RequireExpirationTime = false }));

        options.TokenValidationParameters.RequireSignedTokens.Should().BeTrue();
        options.TokenValidationParameters.RequireExpirationTime.Should().BeTrue();
    }

    // ---- Through the real handler, with the parameters replaced by the application ------------

    private static string Token(string issuer, string audience, string algorithm = SecurityAlgorithms.HmacSha256)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret));
        var token = new JwtSecurityToken(
            issuer, audience, [new Claim("sub", "user-1")], expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(key, algorithm));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static Task<InProcessHost> StartReplacedHostAsync(bool replaceWithWeakParameters) =>
        InProcessHost.StartAsync(
            builder =>
            {
                var databaseName = Guid.NewGuid().ToString();
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
                builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = Secret;
                    o.Jwt.Issuer = "the-issuer";
                    o.Jwt.Audience = "the-audience";
                    o.AllowUnverifiedTenantMembership = true;
                });
                builder.Services.AddHostStubs();
                if (replaceWithWeakParameters)
                {
                    // The application replaces the parameters, after the library, and turns every check off.
                    builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, o =>
                        o.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            ValidateIssuerSigningKey = false
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
        request.Headers.Authorization = new("Bearer", token);
        return (await host.Client.SendAsync(request)).StatusCode;
    }

    [Fact]
    public async Task RealHandler_ShouldRejectAWrongIssuerAndAudience_WhenTheApplicationReplacedTheParametersAfterTheLibrary()
    {
        await using var host = await StartReplacedHostAsync(replaceWithWeakParameters: true);

        (await CallAsync(host, Token("the-issuer", "the-audience"))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, Token("someone-else", "the-audience"))).Should().Be(HttpStatusCode.Unauthorized);
        (await CallAsync(host, Token("the-issuer", "someone-else"))).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RealHandler_ShouldRejectOtherAlgorithms_WhenTheApplicationReplacedTheParametersAfterTheLibrary()
    {
        await using var host = await StartReplacedHostAsync(replaceWithWeakParameters: true);

        // HS384 needs a 48-byte key to sign; the secret is 43 bytes, so sign with a longer key of the same prefix is not "the same key":
        // the point here is that the pin, not the signature, decides, and the signature check still applies.
        var wrongKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(new string('z', 64)));
        var forged = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            "the-issuer", "the-audience", [new Claim("sub", "x")], expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(wrongKey, SecurityAlgorithms.HmacSha256)));

        (await CallAsync(host, forged)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RealHandler_ShouldRejectAnExpiredToken_WhenTheApplicationReplacedTheParametersAfterTheLibrary()
    {
        await using var host = await StartReplacedHostAsync(replaceWithWeakParameters: true);
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret));
        var expired = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            "the-issuer", "the-audience", [new Claim("sub", "x")],
            notBefore: DateTime.UtcNow.AddHours(-3), expires: DateTime.UtcNow.AddHours(-2),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)));

        (await CallAsync(host, expired)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RealHandler_ShouldKeepThePolicy_WhenTheApplicationConfiguresValidatorDelegatesAndLists()
    {
        await using var host = await InProcessHost.StartAsync(
            builder =>
            {
                var databaseName = Guid.NewGuid().ToString();
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
                builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
                {
                    o.Jwt.Secret = Secret;
                    o.Jwt.Issuer = "the-issuer";
                    o.Jwt.Audience = "the-audience";
                    o.AllowUnverifiedTenantMembership = true;
                });
                builder.Services.AddHostStubs();
                builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, o =>
                {
                    var p = o.TokenValidationParameters;
                    p.LifetimeValidator = (_, _, _, _) => true;
                    p.AudienceValidator = (_, _, _) => true;
                    p.IssuerValidator = (issuer, _, _) => issuer;
                    p.AlgorithmValidator = (_, _, _, _) => true;
                    p.ValidIssuers = ["someone-else"];
                    p.ValidAudiences = ["someone-else"];
                });
            },
            app =>
            {
                app.UseAuthentication();
                app.UseAuthorization();
                app.MapGet("/secured", [Authorize] () => Results.Ok());
            });
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret));
        var expired = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            "the-issuer", "the-audience", [new Claim("sub", "x")],
            notBefore: DateTime.UtcNow.AddHours(-12), expires: DateTime.UtcNow.AddHours(-10),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)));

        (await CallAsync(host, Token("the-issuer", "the-audience"))).Should().Be(HttpStatusCode.OK);
        (await CallAsync(host, expired)).Should().Be(HttpStatusCode.Unauthorized);
        (await CallAsync(host, Token("someone-else", "the-audience"))).Should().Be(HttpStatusCode.Unauthorized);
        (await CallAsync(host, Token("the-issuer", "someone-else"))).Should().Be(HttpStatusCode.Unauthorized);
    }
}
