using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class PinotechrdAuthManagerTests
{
    [Fact]
    public async Task RefreshAsync_ShouldFail_WhenRefreshTokenIsUnknownOrRevoked()
    {
        var userManager = CreateUserManager();
        var signInManager = CreateSignInManager(userManager);
        var engine = Substitute.For<ISecurityEngine>();
        var tokenProvider = Substitute.For<ITokenProvider>();
        var refreshStore = Substitute.For<IRefreshTokenStore>();
        refreshStore.ValidateAsync("bad-refresh").Returns(new RefreshTokenValidationResult(false, Reason: "Refresh token revoked"));

        var manager = CreateManager(userManager, signInManager, engine, tokenProvider, refreshStore);

        var result = await manager.RefreshAsync("bad-refresh");

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be("Refresh token revoked");
        await refreshStore.DidNotReceive().RevokeAsync(Arg.Any<string>());
    }

    [Fact]
    public async Task RefreshAsync_ShouldRotateRefreshToken_WhenRefreshTokenIsValid()
    {
        var user = new TestUser { Id = Guid.NewGuid(), UserName = "alice", Email = "alice@pinotechrd.test" };

        var userManager = CreateUserManager();
        userManager.FindByIdAsync("user-1").Returns(user);
        userManager.GetUserIdAsync(user).Returns("user-1");
        userManager.GetEmailAsync(user).Returns("alice@pinotechrd.test");

        var signInManager = CreateSignInManager(userManager);
        var engine = Substitute.For<ISecurityEngine>();
        engine.GetPermissionsAsync("user-1").Returns(new[] { "permissions.read" });

        var tokenProvider = Substitute.For<ITokenProvider>();
        tokenProvider.GenerateAccessToken(Arg.Any<IEnumerable<System.Security.Claims.Claim>>()).Returns("access-2");
        tokenProvider.GenerateRefreshToken().Returns("refresh-2");

        var refreshStore = Substitute.For<IRefreshTokenStore>();
        refreshStore.ValidateAsync("refresh-1")
            .Returns(new RefreshTokenValidationResult(true, "user-1", "tenant-a"));

        var manager = CreateManager(userManager, signInManager, engine, tokenProvider, refreshStore);

        var result = await manager.RefreshAsync("refresh-1");

        result.Succeeded.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Token!.AccessToken.Should().Be("access-2");
        result.Token.RefreshToken.Should().Be("refresh-2");

        await refreshStore.Received(1).RevokeAsync("refresh-1");
        await refreshStore.Received(1).SaveAsync("user-1", "tenant-a", "refresh-2", Arg.Any<DateTime>());
    }

    private static PinotechrdAuthManager<TestUser> CreateManager(
        UserManager<TestUser> userManager,
        SignInManager<TestUser> signInManager,
        ISecurityEngine engine,
        ITokenProvider tokenProvider,
        IRefreshTokenStore refreshStore)
    {
        var options = Microsoft.Extensions.Options.Options.Create(new PinotechrdSecurityOptions
        {
            Jwt = new JwtSettings
            {
                Secret = "super-secret-key-with-minimum-length-32",
                MinimumSecretLength = 32,
                ExpiryMinutes = 60,
                RefreshTokenExpiryDays = 7,
                Issuer = "pinotechrd-tests",
                Audience = "pinotechrd-tests"
            }
        });

        return new PinotechrdAuthManager<TestUser>(
            userManager,
            signInManager,
            engine,
            tokenProvider,
            refreshStore,
            options);
    }

    private static UserManager<TestUser> CreateUserManager()
    {
        var store = Substitute.For<IUserStore<TestUser>>();
        var options = Microsoft.Extensions.Options.Options.Create(new IdentityOptions());
        var passwordHasher = Substitute.For<IPasswordHasher<TestUser>>();
        var userValidators = new List<IUserValidator<TestUser>>();
        var passwordValidators = new List<IPasswordValidator<TestUser>>();
        var keyNormalizer = Substitute.For<ILookupNormalizer>();
        var errors = new IdentityErrorDescriber();
        var services = Substitute.For<IServiceProvider>();
        var logger = Substitute.For<ILogger<UserManager<TestUser>>>();

        return Substitute.For<UserManager<TestUser>>(
            store,
            options,
            passwordHasher,
            userValidators,
            passwordValidators,
            keyNormalizer,
            errors,
            services,
            logger);
    }

    private static SignInManager<TestUser> CreateSignInManager(UserManager<TestUser> userManager)
    {
        var contextAccessor = Substitute.For<IHttpContextAccessor>();
        var claimsFactory = Substitute.For<IUserClaimsPrincipalFactory<TestUser>>();
        var options = Microsoft.Extensions.Options.Options.Create(new IdentityOptions());
        var logger = Substitute.For<ILogger<SignInManager<TestUser>>>();
        var schemes = Substitute.For<IAuthenticationSchemeProvider>();
        var confirmation = Substitute.For<IUserConfirmation<TestUser>>();

        return Substitute.For<SignInManager<TestUser>>(
            userManager,
            contextAccessor,
            claimsFactory,
            options,
            logger,
            schemes,
            confirmation);
    }

    public sealed class TestUser : BaseSecurityUser
    {
    }
}
