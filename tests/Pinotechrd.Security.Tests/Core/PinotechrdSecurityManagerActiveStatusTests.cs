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

    // ---- UpdateUserAsync ------------------------------------------------------------------------

    [Fact]
    public async Task UpdateUserAsync_ShouldEndTheSessions_WhenItStoresTheUserInactive()
    {
        var (manager, kit, user, store) = Setup();
        var stamp = kit.StampOf(user);
        user.IsActive = false;

        (await manager.UpdateUserAsync(user)).Should().BeTrue();

        await store.Received(1).RevokeAllForUserAsync(user.Id.ToString(), CancellationToken.None);
        kit.StampOf(user).Should().NotBe(stamp);
    }

    [Fact]
    public async Task UpdateUserAsync_ShouldNeitherRevokeNorRenew_ForAnActiveUser()
    {
        var (manager, kit, user, store) = Setup();
        var stamp = kit.StampOf(user);

        (await manager.UpdateUserAsync(user)).Should().BeTrue();

        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        await kit.UserManager.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(default!);
        kit.StampOf(user).Should().Be(stamp);
    }

    [Fact]
    public async Task UpdateUserAsync_ShouldReturnFalseAndRevokeNothing_WhenTheUpdateFails()
    {
        var (manager, _, user, store) = Setup(updateSucceeds: false);
        user.IsActive = false;

        (await manager.UpdateUserAsync(user)).Should().BeFalse();

        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
    }

    [Fact]
    public async Task UpdateUserAsync_ShouldReturnFalse_WithTheTokensRevoked_WhenTheStampRenewalFails()
    {
        var (manager, kit, user, store) = Setup();
        kit.MakeStampUpdateFail(user);
        user.IsActive = false;

        (await manager.UpdateUserAsync(user)).Should().BeFalse();

        await store.Received(1).RevokeAllForUserAsync(user.Id.ToString(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UpdateUserAsync_ShouldRenewTheStamp_WithoutARefreshTokenStore()
    {
        var kit = new AuthManagerTestKit<StatusUser>();
        var user = kit.AddUser("bob@x.test");
        kit.UserManager.UpdateAsync(user).Returns(Task.FromResult(IdentityResult.Success));
        var manager = new PinotechrdSecurityManager<StatusUser, BaseSecurityRole>(kit.UserManager, null!, null!);
        var stamp = kit.StampOf(user);
        user.IsActive = false;

        (await manager.UpdateUserAsync(user)).Should().BeTrue();

        kit.StampOf(user).Should().NotBe(stamp);
    }

    [Fact]
    public async Task UpdateUserAsync_ShouldFinishTheRevocation_WhenTheRequestIsCancelledDuringTheUpdate()
    {
        var (manager, kit, user, store) = Setup();
        using var cts = new CancellationTokenSource();
        kit.UserManager.UpdateAsync(user).Returns(_ =>
        {
            cts.Cancel();
            return Task.FromResult(IdentityResult.Success);
        });
        user.IsActive = false;

        (await manager.UpdateUserAsync(user, cts.Token)).Should().BeTrue();

        await store.Received(1).RevokeAllForUserAsync(user.Id.ToString(), CancellationToken.None);
    }

    [Fact]
    public async Task UpdateUserAsync_ShouldLogSessionsEndedDeactivated()
    {
        var logs = new Pinotechrd.Security.Tests.Hosting.CapturedLogs();
        var kit = new AuthManagerTestKit<StatusUser>();
        var user = kit.AddUser("carol@x.test");
        kit.UserManager.UpdateAsync(user).Returns(Task.FromResult(IdentityResult.Success));
        var manager = new PinotechrdSecurityManager<StatusUser, BaseSecurityRole>(
            kit.UserManager, null!, null!, Substitute.For<IRefreshTokenStore>(), logs);
        user.IsActive = false;

        await manager.UpdateUserAsync(user);

        logs.Events(SecurityEvents.SessionsEnded.Id).Should().ContainSingle().Which.Property("Trigger").Should().Be("Deactivated");
    }
}
