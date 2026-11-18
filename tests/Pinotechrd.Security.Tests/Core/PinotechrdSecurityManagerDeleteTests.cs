using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class PinotechrdSecurityManagerDeleteTests
{
    private const string Tenant = "tenant-a";

    public sealed class DeleteUser : BaseSecurityUser;

    private static (PinotechrdSecurityManager<DeleteUser, BaseSecurityRole> Manager, AuthManagerTestKit<DeleteUser> Kit, DeleteUser User)
        Setup(IRefreshTokenStore store, bool deleteSucceeds = true)
    {
        var kit = new AuthManagerTestKit<DeleteUser>();
        var user = kit.AddUser("alice@x.test");
        kit.UserManager.DeleteAsync(Arg.Any<DeleteUser>())
            .Returns(Task.FromResult(deleteSucceeds ? IdentityResult.Success : IdentityResult.Failed()));
        var manager = new PinotechrdSecurityManager<DeleteUser, BaseSecurityRole>(kit.UserManager, null!, null!, store);
        return (manager, kit, user);
    }

    private static Task SaveAsync(IRefreshTokenStore store, string userId, string token, string tenant = Tenant) =>
        store.SaveAsync(userId, tenant, token, DateTime.UtcNow.AddDays(1));

    [Fact]
    public async Task DeleteUserAsync_ShouldInvalidateEveryRefreshTokenOfTheUser_WhenTheDeleteSucceeds()
    {
        var store = new InMemoryRefreshTokenStore();
        var (manager, _, user) = Setup(store);
        var id = user.Id.ToString();
        await SaveAsync(store, id, "t1");
        await SaveAsync(store, id, "t2");
        await SaveAsync(store, id, "t3", "tenant-b");

        var ok = await manager.DeleteUserAsync(id);

        ok.Should().BeTrue();
        foreach (var token in new[] { "t1", "t2", "t3" })
            (await store.ValidateAsync(token)).IsValid.Should().BeFalse(token);
        (await store.ConsumeAsync("t1", Tenant)).Succeeded.Should().BeFalse();
        (await store.ConsumeAsync("t2", Tenant)).Succeeded.Should().BeFalse();
        (await store.ConsumeAsync("t3", "tenant-b")).Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task DeleteUserAsync_ShouldRevokeTokensBeforeDeletingTheUser()
    {
        var store = Substitute.For<IRefreshTokenStore>();
        var (manager, kit, user) = Setup(store);
        var id = user.Id.ToString();

        await manager.DeleteUserAsync(id);

        Received.InOrder(() =>
        {
            store.RevokeAllForUserAsync(id, Arg.Any<CancellationToken>());
            kit.UserManager.DeleteAsync(user);
        });
    }

    [Fact]
    public async Task DeleteUserAsync_ShouldPropagateAndNotDelete_WhenRevocationThrows()
    {
        var store = Substitute.For<IRefreshTokenStore>();
        store.RevokeAllForUserAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("store down"));
        var (manager, kit, user) = Setup(store);

        var act = () => manager.DeleteUserAsync(user.Id.ToString());

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("store down");
        await kit.UserManager.DidNotReceiveWithAnyArgs().DeleteAsync(default!);
    }

    [Fact]
    public async Task DeleteUserAsync_ShouldReturnFalseAndKeepTokensRevoked_WhenTheDeleteFails()
    {
        var store = new InMemoryRefreshTokenStore();
        var (manager, _, user) = Setup(store, deleteSucceeds: false);
        var id = user.Id.ToString();
        await SaveAsync(store, id, "t1");

        var ok = await manager.DeleteUserAsync(id);

        ok.Should().BeFalse();
        (await store.ValidateAsync("t1")).IsValid.Should().BeFalse();
        (await store.ConsumeAsync("t1", Tenant)).Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task DeleteUserAsync_ShouldReturnFalseAndRevokeNothing_WhenTheUserIsUnknown()
    {
        var store = Substitute.For<IRefreshTokenStore>();
        var (manager, kit, _) = Setup(store);

        var ok = await manager.DeleteUserAsync(Guid.NewGuid().ToString());

        ok.Should().BeFalse();
        await store.DidNotReceiveWithAnyArgs().RevokeAllForUserAsync(default!);
        await kit.UserManager.DidNotReceiveWithAnyArgs().DeleteAsync(default!);
    }

    [Fact]
    public async Task DeleteUserAsync_ShouldLeaveTokensOfOtherUsersValid()
    {
        var store = new InMemoryRefreshTokenStore();
        var (manager, kit, user) = Setup(store);
        var other = kit.AddUser("bob@x.test");
        await SaveAsync(store, user.Id.ToString(), "mine");
        await SaveAsync(store, other.Id.ToString(), "theirs");

        await manager.DeleteUserAsync(user.Id.ToString());

        var validation = await store.ValidateAsync("theirs");
        validation.IsValid.Should().BeTrue();
        validation.UserId.Should().Be(other.Id.ToString());
        (await store.ConsumeAsync("theirs", Tenant)).Succeeded.Should().BeTrue();
    }
}
