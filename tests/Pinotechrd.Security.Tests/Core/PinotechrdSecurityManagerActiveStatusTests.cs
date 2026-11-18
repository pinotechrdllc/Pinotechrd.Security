using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class PinotechrdSecurityManagerActiveStatusTests
{
    public sealed class StatusUser : BaseSecurityUser;

    private static (PinotechrdSecurityManager<StatusUser, BaseSecurityRole> Manager, AuthManagerTestKit<StatusUser> Kit, StatusUser User, IRefreshTokenStore Store)
        Setup(bool updateSucceeds = true)
    {
        var kit = new AuthManagerTestKit<StatusUser>();
        var user = kit.AddUser("alice@x.test");
        kit.UserManager.UpdateAsync(user).Returns(Task.FromResult(updateSucceeds ? IdentityResult.Success : IdentityResult.Failed()));
        var store = Substitute.For<IRefreshTokenStore>();
        var manager = new PinotechrdSecurityManager<StatusUser, BaseSecurityRole>(kit.UserManager, null!, null!, store);
        return (manager, kit, user, store);
    }

    [Fact]
    public async Task SetUserActiveStatusAsync_ShouldRevokeAllRefreshTokensAndRenewTheStamp_WhenDeactivating()
    {
        var (manager, kit, user, store) = Setup();
        var stamp = kit.StampOf(user);

        var ok = await manager.SetUserActiveStatusAsync(user.Id.ToString(), false);

        ok.Should().BeTrue();
        user.IsActive.Should().BeFalse();
        await store.Received(1).RevokeAllForUserAsync(user.Id.ToString(), Arg.Any<CancellationToken>());
        kit.StampOf(user).Should().NotBe(stamp);
    }

    [Fact]
    public async Task SetUserActiveStatusAsync_ShouldNeitherRevokeNorRenewTheStamp_WhenActivating()
    {
        var (manager, kit, user, store) = Setup();
        user.IsActive = false;
        var stamp = kit.StampOf(user);

        var ok = await manager.SetUserActiveStatusAsync(user.Id.ToString(), true);

        ok.Should().BeTrue();
        user.IsActive.Should().BeTrue();
        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        kit.StampOf(user).Should().Be(stamp);
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
    }

    [Fact]
    public async Task SetUserActiveStatusAsync_ShouldReturnFalseAndRevokeNothing_WhenTheUpdateFails()
    {
        var (manager, _, user, store) = Setup(updateSucceeds: false);

        var ok = await manager.SetUserActiveStatusAsync(user.Id.ToString(), false);

        ok.Should().BeFalse();
        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
    }

    [Fact]
    public async Task SetUserActiveStatusAsync_ShouldReturnFalse_WhenTheUserIsUnknown()
    {
        var (manager, _, _, store) = Setup();

        var ok = await manager.SetUserActiveStatusAsync(Guid.NewGuid().ToString(), false);

        ok.Should().BeFalse();
        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
    }

    [Fact]
    public async Task SetUserActiveStatusAsync_ShouldReturnFalse_WhenTheStampCannotBeRenewed()
    {
        var (manager, kit, user, _) = Setup();
        kit.MakeStampUpdateFail(user);

        var ok = await manager.SetUserActiveStatusAsync(user.Id.ToString(), false);

        ok.Should().BeFalse();
    }
}
