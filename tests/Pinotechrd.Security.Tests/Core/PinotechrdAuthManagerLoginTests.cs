using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using NSubstitute;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Models;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>
/// Login failure uniformity and the dummy password hash. The dummy hash cache is static per user type,
/// so each test that depends on it uses its own user type.
/// </summary>
public class PinotechrdAuthManagerLoginTests
{
    private const string Invalid = "Invalid credentials";

    public sealed class UnknownUser : BaseSecurityUser;

    public sealed class ManyUnknownUsers : BaseSecurityUser;

    public sealed class WrongPasswordUser : BaseSecurityUser;

    public sealed class LockedUser : BaseSecurityUser;

    public sealed class NotAllowedUser : BaseSecurityUser;

    public sealed class EqualityUser : BaseSecurityUser;

    public sealed class LockoutRequestUser : BaseSecurityUser;

    public sealed class ConcurrentUser : BaseSecurityUser;

    public sealed class HappyUser : BaseSecurityUser;

    public sealed class NameLookupUser : BaseSecurityUser;

    [Fact]
    public async Task LoginAsync_ShouldFailWithInvalidCredentialsAndVerifyOnceAgainstDummyHash_WhenUserIsUnknown()
    {
        var kit = new AuthManagerTestKit<UnknownUser>();

        var result = await kit.Manager.LoginAsync("nobody@x.test", "whatever", "tenant-a");

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(Invalid);
        kit.Hasher.Verifications.Should().ContainSingle().Which.Password.Should().Be("whatever");
        kit.Hasher.Verifications.Single().Hash.Should().NotBeNullOrEmpty();
        await kit.SignInManager.DidNotReceiveWithAnyArgs().CheckPasswordSignInAsync(default!, default!, default);
    }

    [Fact]
    public async Task LoginAsync_ShouldCreateTheDummyHashAtMostOnce_AcrossManyUnknownUserCalls()
    {
        var kit = new AuthManagerTestKit<ManyUnknownUsers>();

        for (var i = 0; i < 25; i++)
        {
            await kit.Manager.LoginAsync($"nobody{i}@x.test", "pw", "tenant-a");
        }

        kit.Hasher.HashCalls.Should().Be(1);
        kit.Hasher.Verifications.Should().HaveCount(25);
        kit.Hasher.Verifications.Select(v => v.Hash).Distinct().Should().ContainSingle();
    }

    [Fact]
    public async Task LoginAsync_ShouldFailWithSameErrorAndNotUseDummyHash_WhenPasswordIsWrong()
    {
        var kit = new AuthManagerTestKit<WrongPasswordUser>();
        kit.AddUser("alice@x.test");

        var result = await kit.Manager.LoginAsync("alice@x.test", "wrong", "tenant-a");

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(Invalid);
        kit.Hasher.HashCalls.Should().Be(0);
        kit.Hasher.Verifications.Should().BeEmpty();
    }

    [Fact]
    public async Task LoginAsync_ShouldFailWithSameErrorAndRunDummyVerify_WhenUserIsLockedOut()
    {
        var kit = new AuthManagerTestKit<LockedUser>();
        var user = kit.AddUser("alice@x.test");
        kit.LockOut(user);

        var result = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<LockedUser>.Password, "tenant-a");

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(Invalid);
        kit.Hasher.Verifications.Should().ContainSingle();
    }

    [Fact]
    public async Task LoginAsync_ShouldFailWithSameErrorAndRunDummyVerify_WhenUserIsNotAllowedToSignIn()
    {
        var kit = new AuthManagerTestKit<NotAllowedUser>();
        var user = kit.AddUser("alice@x.test");
        kit.SignInManager.CheckPasswordSignInAsync(user, Arg.Any<string>(), Arg.Any<bool>())
            .Returns(Task.FromResult(Microsoft.AspNetCore.Identity.SignInResult.NotAllowed));

        var result = await kit.Manager.LoginAsync("alice@x.test", "pw", "tenant-a");

        result.Succeeded.Should().BeFalse();
        result.ErrorMessage.Should().Be(Invalid);
        kit.Hasher.Verifications.Should().ContainSingle();
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnEqualResults_ForUnknownWrongLockedAndNotAllowed()
    {
        var kit = new AuthManagerTestKit<EqualityUser>();
        var existing = kit.AddUser("alice@x.test");
        var locked = kit.AddUser("locked@x.test");
        kit.LockOut(locked);
        var notAllowed = kit.AddUser("blocked@x.test");
        kit.SignInManager.CheckPasswordSignInAsync(notAllowed, Arg.Any<string>(), Arg.Any<bool>())
            .Returns(Task.FromResult(Microsoft.AspNetCore.Identity.SignInResult.NotAllowed));

        var results = new[]
        {
            await kit.Manager.LoginAsync("nobody@x.test", "pw", "tenant-a"),
            await kit.Manager.LoginAsync(existing.Email!, "wrong", "tenant-a"),
            await kit.Manager.LoginAsync("locked@x.test", "pw", "tenant-a"),
            await kit.Manager.LoginAsync("blocked@x.test", "pw", "tenant-a")
        };

        results.Should().AllSatisfy(r => r.Should().Be(AuthResult.Failure(Invalid)));
    }

    [Fact]
    public async Task LoginAsync_ShouldRequestLockoutOnFailure_WhenCheckingThePassword()
    {
        var kit = new AuthManagerTestKit<LockoutRequestUser>();
        var user = kit.AddUser("alice@x.test");

        await kit.Manager.LoginAsync("alice@x.test", "wrong", "tenant-a");

        await kit.SignInManager.Received(1).CheckPasswordSignInAsync(user, "wrong", true);
        await kit.SignInManager.DidNotReceive().CheckPasswordSignInAsync(user, Arg.Any<string>(), false);
    }

    [Fact]
    public async Task LoginAsync_ShouldNotThrowAndEndWithOneUsableCachedHash_WhenFirstCallsRunConcurrently()
    {
        var kit = new AuthManagerTestKit<ConcurrentUser>();
        kit.Hasher.HashDelay = TimeSpan.FromMilliseconds(20);

        var calls = Enumerable.Range(0, 32)
            .Select(i => Task.Run(() => kit.Manager.LoginAsync($"nobody{i}@x.test", "pw", "tenant-a")));
        var results = await Task.WhenAll(calls);

        results.Should().AllSatisfy(r => r.ErrorMessage.Should().Be(Invalid));

        var hashesBefore = kit.Hasher.HashCalls;
        var verificationsBefore = kit.Hasher.Verifications.Count;
        for (var i = 0; i < 5; i++) await kit.Manager.LoginAsync("later@x.test", "pw", "tenant-a");

        kit.Hasher.HashCalls.Should().Be(hashesBefore, "once the race is over the cached hash is reused");
        var later = kit.Hasher.Verifications.Skip(verificationsBefore).Select(v => v.Hash).ToList();
        later.Should().HaveCount(5).And.OnlyContain(h => !string.IsNullOrEmpty(h));
        later.Distinct().Should().ContainSingle();
    }

    [Fact]
    public async Task LoginAsync_ShouldSucceedAndIssueTokensWithTheLoginTenant_WhenCredentialsAreValidAndTwoFactorIsOff()
    {
        var kit = new AuthManagerTestKit<HappyUser>();
        var user = kit.AddUser("alice@x.test");

        var result = await kit.Manager.LoginAsync("alice@x.test", AuthManagerTestKit<HappyUser>.Password, "tenant-a");

        result.Succeeded.Should().BeTrue();
        result.RequiresTwoFactor.Should().BeFalse();
        result.Token!.AccessToken.Should().Be("access-token");
        await kit.RefreshStore.Received(1).SaveAsync(user.Id.ToString(), "tenant-a", "refresh-token", Arg.Any<DateTime>());
        kit.Hasher.Verifications.Should().BeEmpty();
    }

    [Fact]
    public async Task LoginAsync_ShouldFindTheUserByUserName_WhenEmailLookupFindsNothing()
    {
        var kit = new AuthManagerTestKit<NameLookupUser>();
        var user = kit.AddUser("alice@x.test");
        kit.UserManager.FindByEmailAsync("alice").Returns(Task.FromResult<NameLookupUser?>(null));
        kit.UserManager.FindByNameAsync("alice").Returns(Task.FromResult<NameLookupUser?>(user));

        var result = await kit.Manager.LoginAsync("alice", AuthManagerTestKit<NameLookupUser>.Password, "tenant-a");

        result.Succeeded.Should().BeTrue();
    }
}
