using FluentAssertions;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Models;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>A token that is already cancelled stops reads and writes before they touch the database.</summary>
public class DbSecurityStoreCancellationTests
{
    private static CancellationToken Cancelled() => new(canceled: true);

    [Fact]
    public async Task GetUserOverridesAsync_ShouldThrowOperationCanceled_WhenTheTokenIsAlreadyCancelled()
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();
        var store = new DbSecurityStore(rig.Db);

        var act = () => store.GetUserOverridesAsync(rig.UserId.ToString(), Cancelled());

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task GetActiveCatalogAsync_ShouldThrowOperationCanceled_WhenTheTokenIsAlreadyCancelled()
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();
        var store = new DbSecurityStore(rig.Db);

        var act = () => store.GetActiveCatalogAsync("a", Cancelled());

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task IsSubscriptionActiveAsync_ShouldThrowOperationCanceled_WhenTheTokenIsAlreadyCancelled()
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();
        var store = new DbSecurityStore(rig.Db);

        var act = () => store.IsSubscriptionActiveAsync("a", Cancelled());

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task GetUserOverridesAsync_ShouldStillReturnRows_WhenTheTokenIsNotCancelled()
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();
        (await rig.Manager.ReplaceUserOverridesAsync(rig.UserId.ToString(),
            [new UserPermissionOverride("SALES.VIEW", PermissionAccessType.Allow)])).Should().BeTrue();
        var store = new DbSecurityStore(rig.Db);

        var rows = await store.GetUserOverridesAsync(rig.UserId.ToString(), new CancellationTokenSource().Token);

        rows.Should().ContainSingle().Which.Code.Should().Be("SALES.VIEW");
    }

    [Fact]
    public async Task GetUsersAsync_ShouldThrowOperationCanceled_WhenTheTokenIsAlreadyCancelled()
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();

        var act = () => rig.Manager.GetUsersAsync(Cancelled());

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldThrowOperationCanceledAndKeepThePreviousOverrides_WhenTheTokenIsAlreadyCancelled()
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();
        (await rig.Manager.ReplaceUserOverridesAsync(rig.UserId.ToString(),
            [new UserPermissionOverride("SALES.VIEW", PermissionAccessType.Allow)])).Should().BeTrue();

        var act = () => rig.Manager.ReplaceUserOverridesAsync(rig.UserId.ToString(),
            [new UserPermissionOverride("SALES.EDIT", PermissionAccessType.Deny)], Cancelled());

        await act.Should().ThrowAsync<OperationCanceledException>();
        (await rig.UserOverridesAsync()).Should().Equal("SALES.VIEW:" + PermissionAccessType.Allow);
    }
}
