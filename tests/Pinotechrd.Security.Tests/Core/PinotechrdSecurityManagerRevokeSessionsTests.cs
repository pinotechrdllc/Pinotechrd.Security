using FluentAssertions;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>Administrative session revocation: the user is named by the caller, not taken from the request.</summary>
public class PinotechrdSecurityManagerRevokeSessionsTests
{
    public sealed class SessionUser : BaseSecurityUser;

    private static (PinotechrdSecurityManager<SessionUser, BaseSecurityRole> Manager, AuthManagerTestKit<SessionUser> Kit, SessionUser A, SessionUser B, IRefreshTokenStore Store)
        Setup(bool withStore = true)
    {
        var kit = new AuthManagerTestKit<SessionUser>();
        var a = kit.AddUser("a@x.test");
        var b = kit.AddUser("b@x.test");
        var store = Substitute.For<IRefreshTokenStore>();
        var manager = new PinotechrdSecurityManager<SessionUser, BaseSecurityRole>(kit.UserManager, null!, null!, withStore ? store : null);
        return (manager, kit, a, b, store);
    }

    [Fact]
    public async Task RevokeUserSessionsAsync_ShouldRevokeTheTargetsTokensAndRenewItsStampOnly()
    {
        var (manager, kit, a, b, store) = Setup();
        var (stampA, stampB) = (kit.StampOf(a), kit.StampOf(b));

        var ok = await manager.RevokeUserSessionsAsync(a.Id.ToString());

        ok.Should().BeTrue();
        await store.Received(1).RevokeAllForUserAsync(a.Id.ToString(), Arg.Any<CancellationToken>());
        await store.DidNotReceive().RevokeAllForUserAsync(b.Id.ToString(), Arg.Any<CancellationToken>());
        kit.StampOf(a).Should().NotBe(stampA);
        kit.StampOf(b).Should().Be(stampB);
    }

    [Fact]
    public async Task RevokeUserSessionsAsync_ShouldLeaveOtherUsersRefreshTokensUsable_WithTheRealStore()
    {
        var kit = new AuthManagerTestKit<SessionUser>();
        var a = kit.AddUser("a@x.test");
        var b = kit.AddUser("b@x.test");
        var store = new InMemoryRefreshTokenStore();
        var manager = new PinotechrdSecurityManager<SessionUser, BaseSecurityRole>(kit.UserManager, null!, null!, store);
        var expires = DateTime.UtcNow.AddMinutes(10);
        await store.SaveAsync(a.Id.ToString(), "tenant-a", "token-a", expires);
        await store.SaveAsync(b.Id.ToString(), "tenant-a", "token-b", expires);

        (await manager.RevokeUserSessionsAsync(a.Id.ToString())).Should().BeTrue();

        (await store.ValidateAsync("token-a")).IsValid.Should().BeFalse();
        (await store.ValidateAsync("token-b")).IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task RevokeUserSessionsAsync_ShouldReturnFalseAndRevokeNothing_WhenTheUserIsUnknown()
    {
        var (manager, kit, a, _, store) = Setup();
        var stamp = kit.StampOf(a);

        var ok = await manager.RevokeUserSessionsAsync(Guid.NewGuid().ToString());

        ok.Should().BeFalse();
        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        kit.StampOf(a).Should().Be(stamp);
    }

    [Fact]
    public async Task RevokeUserSessionsAsync_ShouldReturnFalseAndLeaveTheStamp_WhenNoRefreshTokenStoreIsRegistered()
    {
        var (manager, kit, a, _, _) = Setup(withStore: false);
        var stamp = kit.StampOf(a);

        var ok = await manager.RevokeUserSessionsAsync(a.Id.ToString());

        ok.Should().BeFalse();
        kit.StampOf(a).Should().Be(stamp);
    }

    [Fact]
    public async Task RevokeUserSessionsAsync_ShouldReturnFalseButKeepTheTokensRevoked_WhenTheStampCannotBeRenewed()
    {
        var (manager, kit, a, _, store) = Setup();
        kit.MakeStampUpdateFail(a);

        var ok = await manager.RevokeUserSessionsAsync(a.Id.ToString());

        ok.Should().BeFalse();
        await store.Received(1).RevokeAllForUserAsync(a.Id.ToString(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RevokeUserSessionsAsync_ShouldReturnTrueAndRevokeTokensWithoutTouchingTheStamp_WhenTheStoreHasNoSecurityStamps()
    {
        var (manager, kit, a, _, store) = Setup();
        kit.UserManager.SupportsUserSecurityStamp.Returns(false);

        var ok = await manager.RevokeUserSessionsAsync(a.Id.ToString());

        ok.Should().BeTrue();
        await store.Received(1).RevokeAllForUserAsync(a.Id.ToString(), Arg.Any<CancellationToken>());
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
    }

    [Fact]
    public async Task RevokeUserSessionsAsync_ShouldRevokeUnderTheStoredId_WhenTheLookupMatchedAnotherSpellingOfTheId()
    {
        var (manager, kit, a, _, store) = Setup();
        var upper = a.Id.ToString().ToUpperInvariant();
        upper.Should().NotBe(a.Id.ToString());
        kit.UserManager.FindByIdAsync(upper).Returns(Task.FromResult<SessionUser?>(a));

        var ok = await manager.RevokeUserSessionsAsync(upper);

        ok.Should().BeTrue();
        await store.Received(1).RevokeAllForUserAsync(a.Id.ToString(), Arg.Any<CancellationToken>());
        await store.DidNotReceive().RevokeAllForUserAsync(upper, Arg.Any<CancellationToken>());
    }
}
