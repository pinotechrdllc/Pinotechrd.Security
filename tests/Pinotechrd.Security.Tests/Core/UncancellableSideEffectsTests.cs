using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>
/// Once a security side effect has started it runs to the end: a token cancelled while it runs does not stop it.
/// The token is cancelled from inside the operation (by the store or the user manager) and the outcome is observed.
/// </summary>
public class UncancellableSideEffectsTests
{
    private const string Tenant = "tenant-a";

    public sealed class SideUser : BaseSecurityUser;

    /// <summary>A refresh token store whose revocation cancels <paramref name="cts"/> and records the token it was given.</summary>
    private static IRefreshTokenStore CancellingStore(CancellationTokenSource cts, List<CancellationToken> seen)
    {
        var store = Substitute.For<IRefreshTokenStore>();
        store.RevokeAllForUserAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(call =>
        {
            seen.Add(call.ArgAt<CancellationToken>(1));
            cts.Cancel();
            return Task.CompletedTask;
        });
        return store;
    }

    private static CancellationToken Cancelled() => new(canceled: true);

    // ---- SignOutCurrentUserAsync -------------------------------------------------------------

    private static (AuthManagerTestKit<SideUser> Kit, SideUser User) SignOutKit(IRefreshTokenStore store)
    {
        var provider = Substitute.For<ISecurityDataProvider>();
        var kit = new AuthManagerTestKit<SideUser>(tenant: Tenant, refreshStore: store, dataProvider: provider);
        var user = kit.AddUser("alice@x.test");
        provider.GetCurrentUserId().Returns(user.Id.ToString());
        return (kit, user);
    }

    [Fact]
    public async Task SignOutCurrentUserAsync_ShouldRevokeWithAnUncancellableTokenAndRenewTheStamp_WhenCancelledDuringRevocation()
    {
        using var cts = new CancellationTokenSource();
        var seen = new List<CancellationToken>();
        var (kit, user) = SignOutKit(CancellingStore(cts, seen));
        var stamp = kit.StampOf(user);

        var ok = await kit.Manager.SignOutCurrentUserAsync(cts.Token);

        ok.Should().BeTrue();
        cts.IsCancellationRequested.Should().BeTrue("the revocation did cancel the request token");
        seen.Should().ContainSingle().Which.CanBeCanceled.Should().BeFalse();
        kit.StampOf(user).Should().NotBe(stamp);
    }

    [Fact]
    public async Task SignOutCurrentUserAsync_ShouldThrowOperationCanceledAndRevokeNothing_WhenTheTokenIsAlreadyCancelled()
    {
        var store = Substitute.For<IRefreshTokenStore>();
        var (kit, user) = SignOutKit(store);
        var stamp = kit.StampOf(user);

        var act = () => kit.Manager.SignOutCurrentUserAsync(Cancelled());

        await act.Should().ThrowAsync<OperationCanceledException>();
        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        kit.StampOf(user).Should().Be(stamp);
    }

    // ---- RevokeUserSessionsAsync -------------------------------------------------------------

    private static (PinotechrdSecurityManager<SideUser, BaseSecurityRole> Manager, AuthManagerTestKit<SideUser> Kit, SideUser User) ManagerOver(IRefreshTokenStore store)
    {
        var kit = new AuthManagerTestKit<SideUser>();
        var user = kit.AddUser("alice@x.test");
        return (new PinotechrdSecurityManager<SideUser, BaseSecurityRole>(kit.UserManager, null!, null!, store), kit, user);
    }

    [Fact]
    public async Task RevokeUserSessionsAsync_ShouldRevokeWithAnUncancellableTokenAndRenewTheStamp_WhenCancelledDuringRevocation()
    {
        using var cts = new CancellationTokenSource();
        var seen = new List<CancellationToken>();
        var (manager, kit, user) = ManagerOver(CancellingStore(cts, seen));
        var stamp = kit.StampOf(user);

        var ok = await manager.RevokeUserSessionsAsync(user.Id.ToString(), cts.Token);

        ok.Should().BeTrue();
        cts.IsCancellationRequested.Should().BeTrue();
        seen.Should().ContainSingle().Which.CanBeCanceled.Should().BeFalse();
        kit.StampOf(user).Should().NotBe(stamp);
    }

    [Fact]
    public async Task RevokeUserSessionsAsync_ShouldThrowOperationCanceledAndRevokeNothing_WhenTheTokenIsAlreadyCancelled()
    {
        var store = Substitute.For<IRefreshTokenStore>();
        var (manager, kit, user) = ManagerOver(store);
        var stamp = kit.StampOf(user);

        var act = () => manager.RevokeUserSessionsAsync(user.Id.ToString(), Cancelled());

        await act.Should().ThrowAsync<OperationCanceledException>();
        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        kit.StampOf(user).Should().Be(stamp);
    }

    // ---- DeleteUserAsync ---------------------------------------------------------------------

    [Fact]
    public async Task DeleteUserAsync_ShouldRevokeUncancellablyAndStillDelete_WhenCancelledDuringRevocation()
    {
        using var cts = new CancellationTokenSource();
        var seen = new List<CancellationToken>();
        var (manager, kit, user) = ManagerOver(CancellingStore(cts, seen));
        kit.UserManager.DeleteAsync(Arg.Any<SideUser>()).Returns(Task.FromResult(IdentityResult.Success));

        var ok = await manager.DeleteUserAsync(user.Id.ToString(), cts.Token);

        ok.Should().BeTrue();
        seen.Should().ContainSingle().Which.CanBeCanceled.Should().BeFalse();
        await kit.UserManager.Received(1).DeleteAsync(user);
    }

    [Fact]
    public async Task DeleteUserAsync_ShouldThrowOperationCanceledAndRevokeAndDeleteNothing_WhenTheTokenIsAlreadyCancelled()
    {
        var store = Substitute.For<IRefreshTokenStore>();
        var (manager, kit, user) = ManagerOver(store);

        var act = () => manager.DeleteUserAsync(user.Id.ToString(), Cancelled());

        await act.Should().ThrowAsync<OperationCanceledException>();
        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        await kit.UserManager.DidNotReceiveWithAnyArgs().DeleteAsync(default!);
    }

    // ---- CreateUserAsync without a rollback --------------------------------------------------

    [Fact]
    public async Task CreateUserAsync_ShouldStillAssignTheRoles_WhenCancelledAfterTheUserWasCreated_AndNothingCanRollBack()
    {
        using var cts = new CancellationTokenSource();
        var kit = new AuthManagerTestKit<SideUser>();
        var roles = Substitute.For<RoleManager<BaseSecurityRole>>(
            Substitute.For<IRoleStore<BaseSecurityRole>>(), null, null, null, null);
        roles.RoleExistsAsync("clerk").Returns(true);
        var user = new SideUser { Id = Guid.NewGuid(), UserName = "new@x.test", Email = "new@x.test" };
        kit.UserManager.CreateAsync(user, "pw").Returns(_ =>
        {
            cts.Cancel();
            return Task.FromResult(IdentityResult.Success);
        });
        kit.UserManager.AddToRolesAsync(user, Arg.Any<IEnumerable<string>>()).Returns(Task.FromResult(IdentityResult.Success));
        // A null security context is not a relational DbContext: there is no transaction to roll the user back with.
        var manager = new PinotechrdSecurityManager<SideUser, BaseSecurityRole>(kit.UserManager, roles, null!);

        var ok = await manager.CreateUserAsync(user, "pw", ["clerk"], cts.Token);

        ok.Should().BeTrue();
        await kit.UserManager.Received(1).AddToRolesAsync(user, Arg.Is<IEnumerable<string>>(r => r.Single() == "clerk"));
    }

    [Fact]
    public async Task CreateUserAsync_ShouldThrowOperationCanceledAndCreateNoUser_WhenTheTokenIsAlreadyCancelled_AndNothingCanRollBack()
    {
        var kit = new AuthManagerTestKit<SideUser>();
        var roles = Substitute.For<RoleManager<BaseSecurityRole>>(
            Substitute.For<IRoleStore<BaseSecurityRole>>(), null, null, null, null);
        roles.RoleExistsAsync("clerk").Returns(true);
        var user = new SideUser { Id = Guid.NewGuid(), UserName = "new@x.test", Email = "new@x.test" };
        var manager = new PinotechrdSecurityManager<SideUser, BaseSecurityRole>(kit.UserManager, roles, null!);

        var act = () => manager.CreateUserAsync(user, "pw", ["clerk"], Cancelled());

        await act.Should().ThrowAsync<OperationCanceledException>();
        await kit.UserManager.DidNotReceiveWithAnyArgs().CreateAsync(default!, default!);
    }
}
