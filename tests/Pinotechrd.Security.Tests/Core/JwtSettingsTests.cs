using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using FluentAssertions;
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

/// <summary>JWT settings validation (at host start) and algorithm, issuer and audience pinning.</summary>
public class JwtSettingsTests
{
    // 64 bytes, so the tests can also sign with HS512 using the very same key.
    private static readonly string Secret = new string((char)107, 64);
    private const string Issuer = "pinotechrd-tests";
    private const string Audience = "pinotechrd-clients";

    private static void ConfigureValid(PinotechrdSecurityOptions o)
    {
        o.Jwt.Secret = Secret;
        o.Jwt.Issuer = Issuer;
        o.Jwt.Audience = Audience;
        o.AllowUnverifiedTenantMembership = true;
    }

    private static async Task StartGenericHostAsync(Action<PinotechrdSecurityOptions>? configure)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        var databaseName = Guid.NewGuid().ToString();
        builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
        builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
        {
            configure?.Invoke(o);
            o.AllowUnverifiedTenantMembership = true;
        });
        using var host = builder.Build();
        await host.StartAsync();
        await host.StopAsync();
    }

    // ---- Validation moved to host start ------------------------------------------------------

    [Fact]
    public void AddPinotechrdSecurity_ShouldNotThrow_WhenTheJwtSettingsAreEmpty()
    {
        var services = new ServiceCollection();
        services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));

        var act = () => services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>();

        act.Should().NotThrow();
    }

    [Fact]
    public async Task HostStart_ShouldFailWithOptionsValidationExceptionNamingEverySetting_WhenNothingIsConfigured()
    {
        var act = () => StartGenericHostAsync(null);

        var thrown = (await act.Should().ThrowAsync<OptionsValidationException>()).Which;
        thrown.Message.Should().Contain("Jwt.Secret").And.Contain("Jwt.Issuer").And.Contain("Jwt.Audience");
    }

    [Fact]
    public async Task HostStart_ShouldNameOnlyTheMissingSetting()
    {
        var act = () => StartGenericHostAsync(o =>
        {
            ConfigureValid(o);
            o.Jwt.Issuer = null;
        });

        var message = (await act.Should().ThrowAsync<OptionsValidationException>()).Which.Message;
        message.Should().Contain("Jwt.Issuer");
        message.Should().NotContain("Jwt.Secret").And.NotContain("Jwt.Audience");
    }

    [Fact]
    public async Task HostStart_ShouldRejectABlankAudience()
    {
        var act = () => StartGenericHostAsync(o =>
        {
            ConfigureValid(o);
            o.Jwt.Audience = "   ";
        });

        (await act.Should().ThrowAsync<OptionsValidationException>()).Which.Message.Should().Contain("Jwt.Audience");
    }

    [Fact]
    public async Task HostStart_ShouldSucceed_WhenTheSettingsAreValid()
    {
        var act = () => StartGenericHostAsync(ConfigureValid);

        await act.Should().NotThrowAsync();
    }

    // ---- Lifetimes and clock skew ----------------------------------------------------------------

    [Fact]
    public void Defaults_ShouldBeAFifteenMinuteAccessToken_SevenDayRefreshToken_AndOneMinuteSkew()
    {
        var settings = new JwtSettings();

        settings.ExpiryMinutes.Should().Be(15);
        settings.RefreshTokenExpiryDays.Should().Be(7);
        settings.MaximumClockSkew.Should().Be(TimeSpan.FromMinutes(1));
    }

    [Theory]
    [InlineData(int.MinValue, false)]
    [InlineData(-1, false)]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(60, true)]
    [InlineData(61, false)]
    [InlineData(int.MaxValue, false)]
    public async Task HostStart_ShouldAcceptExpiryMinutesOnlyFromOneToSixty(int minutes, bool accepted)
    {
        var act = () => StartGenericHostAsync(o => { ConfigureValid(o); o.Jwt.ExpiryMinutes = minutes; });

        if (accepted) await act.Should().NotThrowAsync();
        else await act.Should().ThrowAsync<OptionsValidationException>().WithMessage("*Jwt.ExpiryMinutes must be between 1 and 60*");
    }

    [Theory]
    [InlineData(-1, false)]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(90, true)]
    [InlineData(91, false)]
    public async Task HostStart_ShouldAcceptRefreshTokenExpiryDaysOnlyFromOneToNinety(int days, bool accepted)
    {
        var act = () => StartGenericHostAsync(o => { ConfigureValid(o); o.Jwt.RefreshTokenExpiryDays = days; });

        if (accepted) await act.Should().NotThrowAsync();
        else await act.Should().ThrowAsync<OptionsValidationException>().WithMessage("*Jwt.RefreshTokenExpiryDays must be between 1 and 90*");
    }

    public static TheoryData<TimeSpan, bool> SkewBounds => new()
    {
        { TimeSpan.FromTicks(-1), false },
        { TimeSpan.Zero, true },
        { TimeSpan.FromMinutes(5), true },
        { TimeSpan.FromMinutes(5) + TimeSpan.FromTicks(1), false },
        { TimeSpan.MaxValue, false },
    };

    [Theory]
    [MemberData(nameof(SkewBounds))]
    public async Task HostStart_ShouldAcceptMaximumClockSkewOnlyFromZeroToFiveMinutes(TimeSpan skew, bool accepted)
    {
        var act = () => StartGenericHostAsync(o => { ConfigureValid(o); o.Jwt.MaximumClockSkew = skew; });

        if (accepted) await act.Should().NotThrowAsync();
        else (await act.Should().ThrowAsync<OptionsValidationException>().WithMessage("*Jwt.MaximumClockSkew must be between zero and 5 minutes*"))
            .Which.Message.Should().NotContain("JwtBearerOptions", "the bearer policy check skips while the security options are invalid");
    }

    [Fact]
    public void JwtTokenProvider_ShouldRefuseAnOutOfRangeLifetime()
    {
        var options = new PinotechrdSecurityOptions();
        ConfigureValid(options);
        options.Jwt.ExpiryMinutes = 0;

        var act = () => new JwtTokenProvider(Microsoft.Extensions.Options.Options.Create(options));

        act.Should().Throw<InvalidOperationException>().WithMessage("*Jwt.ExpiryMinutes*");
    }

    [Fact]
    public async Task HostStart_ShouldNeverPutTheSecretValueInTheErrorMessage()
    {
        const string weak = "weak-secret-VALUE-do-not-leak";

        var act = () => StartGenericHostAsync(o =>
        {
            ConfigureValid(o);
            o.Jwt.Secret = weak;
        });

        var thrown = (await act.Should().ThrowAsync<OptionsValidationException>()).Which;
        thrown.Message.Should().Contain("Jwt.Secret").And.NotContain(weak);
        thrown.ToString().Should().NotContain(weak);
    }

    [Theory]
    [InlineData(31, false)]
    [InlineData(32, true)]
    [InlineData(33, true)]
    public async Task HostStart_ShouldCountSecretLengthInBytes(int length, bool accepted)
    {
        var secret = new string('k', length);
        var act = () => StartGenericHostAsync(o =>
        {
            ConfigureValid(o);
            o.Jwt.Secret = secret;
        });

        if (accepted) await act.Should().NotThrowAsync();
        else (await act.Should().ThrowAsync<OptionsValidationException>()).Which.Message.Should().Contain("Jwt.Secret");
    }

    [Fact]
    public async Task HostStart_ShouldAcceptSixteenTwoByteCharacters_BecauseTheyAre32Bytes()
    {
        var secret = new string('é', 16);
        Encoding.UTF8.GetByteCount(secret).Should().Be(32);

        var act = () => StartGenericHostAsync(o =>
        {
            ConfigureValid(o);
            o.Jwt.Secret = secret;
        });

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task HostStart_ShouldRejectFifteenTwoByteCharactersPlusOneAscii_BecauseTheyAre31Bytes()
    {
        var secret = new string('é', 15) + "a";

        var act = () => StartGenericHostAsync(o =>
        {
            ConfigureValid(o);
            o.Jwt.Secret = secret;
        });

        await act.Should().ThrowAsync<OptionsValidationException>();
    }

    [Fact]
    public async Task HostStart_ShouldStillRequire32Bytes_WhenMinimumSecretLengthIsLoweredTo8()
    {
        var act = () => StartGenericHostAsync(o =>
        {
            ConfigureValid(o);
            o.Jwt.MinimumSecretLength = 8;
            o.Jwt.Secret = new string('k', 20);
        });

        await act.Should().ThrowAsync<OptionsValidationException>();
    }

    [Theory]
    [InlineData(40, false)]
    [InlineData(64, true)]
    public async Task HostStart_ShouldHonorAHigherMinimumSecretLength(int length, bool accepted)
    {
        var act = () => StartGenericHostAsync(o =>
        {
            ConfigureValid(o);
            o.Jwt.MinimumSecretLength = 64;
            o.Jwt.Secret = new string('k', length);
        });

        if (accepted) await act.Should().NotThrowAsync();
        else await act.Should().ThrowAsync<OptionsValidationException>();
    }

    [Theory]
    [InlineData(31, false)]
    [InlineData(32, true)]
    public void JwtTokenProvider_ShouldCountSecretLengthInBytes(int length, bool accepted)
    {
        var options = Microsoft.Extensions.Options.Options.Create(new PinotechrdSecurityOptions
        {
            Jwt = new JwtSettings { Secret = new string('k', length), Issuer = Issuer, Audience = Audience }
        });

        var act = () => new JwtTokenProvider(options);

        if (accepted) act.Should().NotThrow();
        else act.Should().Throw<InvalidOperationException>();
    }

    // ---- Algorithm, issuer and audience pinning ----------------------------------------------

    private static string Base64Url(string text) => Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(text));

    private static string Sign(string algorithm, string issuer = Issuer, string audience = Audience, DateTime? expires = null)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret));
        var token = new JwtSecurityToken(
            issuer,
            audience,
            [new Claim("id", "user-1"), new Claim("tenant_id", "tenant-a")],
            notBefore: (expires ?? DateTime.UtcNow.AddMinutes(5)).AddMinutes(-10),
            expires: expires ?? DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(key, algorithm));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string UnsignedNoneToken() =>
        Base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "."
        + Base64Url($"{{\"id\":\"user-1\",\"tenant_id\":\"tenant-a\",\"iss\":\"{Issuer}\",\"aud\":\"{Audience}\",\"exp\":{DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()}}}")
        + ".";

    private static JwtTokenProvider Provider() =>
        new(Microsoft.Extensions.Options.Options.Create(new PinotechrdSecurityOptions
        {
            Jwt = new JwtSettings { Secret = Secret, Issuer = Issuer, Audience = Audience }
        }));

    public static TheoryData<string, string> RejectedTokens() => new()
    {
        { "HS512 with the same key", Sign(SecurityAlgorithms.HmacSha512) },
        { "HS384 with the same key", Sign(SecurityAlgorithms.HmacSha384) },
        { "alg none", UnsignedNoneToken() },
        { "wrong issuer", Sign(SecurityAlgorithms.HmacSha256, issuer: "someone-else") },
        { "wrong audience", Sign(SecurityAlgorithms.HmacSha256, audience: "someone-else") }
    };

    [Theory]
    [MemberData(nameof(RejectedTokens))]
    public void GetPrincipalFromExpiredToken_ShouldReject(string name, string token)
    {
        var act = () => Provider().GetPrincipalFromExpiredToken(token);

        act.Should().Throw<Exception>(name);
    }

    [Fact]
    public void GetPrincipalFromExpiredToken_ShouldAcceptAnExpiredHs256Token_ForTheRightIssuerAndAudience()
    {
        var token = Sign(SecurityAlgorithms.HmacSha256, expires: DateTime.UtcNow.AddMinutes(-30));

        var principal = Provider().GetPrincipalFromExpiredToken(token);

        principal.FindFirst("id")?.Value.Should().Be("user-1");
    }

    [Theory]
    [MemberData(nameof(RejectedTokens))]
    public async Task BearerHandler_ShouldRejectWith401(string name, string token)
    {
        await using var host = await StartSecuredHostAsync();

        var response = await host.Client.SendAsync(Secured(token));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized, name);
    }

    [Fact]
    public async Task BearerHandler_ShouldAcceptAValidHs256Token_AndRejectAnExpiredOne()
    {
        await using var host = await StartSecuredHostAsync();

        var ok = await host.Client.SendAsync(Secured(Sign(SecurityAlgorithms.HmacSha256)));
        var expired = await host.Client.SendAsync(Secured(Sign(SecurityAlgorithms.HmacSha256, expires: DateTime.UtcNow.AddMinutes(-30))));

        ok.StatusCode.Should().Be(HttpStatusCode.OK);
        expired.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task BearerHandler_ShouldApplyTheOneMinuteDefaultSkew_NotTheFrameworksFiveMinutes()
    {
        await using var host = await StartSecuredHostAsync();

        var withinSkew = await host.Client.SendAsync(Secured(Sign(SecurityAlgorithms.HmacSha256, expires: DateTime.UtcNow.AddSeconds(-20))));
        var beyondSkew = await host.Client.SendAsync(Secured(Sign(SecurityAlgorithms.HmacSha256, expires: DateTime.UtcNow.AddMinutes(-2))));

        withinSkew.StatusCode.Should().Be(HttpStatusCode.OK);
        beyondSkew.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "two minutes past expiry is inside the framework's 5-minute default");
    }

    [Fact]
    public async Task BearerHandler_ShouldApplyAConfiguredZeroSkew()
    {
        await using var host = await StartSecuredHostAsync(o => o.Jwt.MaximumClockSkew = TimeSpan.Zero);

        var expired = await host.Client.SendAsync(Secured(Sign(SecurityAlgorithms.HmacSha256, expires: DateTime.UtcNow.AddSeconds(-20))));

        expired.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    private static HttpRequestMessage Secured(string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/secured");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private static Task<InProcessHost> StartSecuredHostAsync(Action<PinotechrdSecurityOptions>? adjust = null) =>
        InProcessHost.StartAsync(
            builder =>
            {
                var databaseName = Guid.NewGuid().ToString();
                builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(databaseName));
                builder.Services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
                {
                    ConfigureValid(o);
                    adjust?.Invoke(o);
                });
                builder.Services.AddHostStubs();
            },
            app =>
            {
                app.UseAuthentication();
                app.UseAuthorization();
                app.MapGet("/secured", [Authorize] () => Results.Ok());
            });
}
