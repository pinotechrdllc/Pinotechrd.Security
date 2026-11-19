using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Models;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>
/// Contract of <c>AssignPermissionsToRoleAsync</c> and <c>ReplaceUserOverridesAsync</c> that does not need PostgreSQL:
/// validation, atomicity, error propagation and behaviour inside a caller's transaction. SQLite is relational, so
/// transactions and set-based deletes work.
/// </summary>
public sealed class PinotechrdSecurityManagerReplaceTests : IAsyncLifetime
{
    private SqliteSecurityManagerRig _rig = null!;

    public async Task InitializeAsync() => _rig = await SqliteSecurityManagerRig.CreateAsync();

    public async Task DisposeAsync() => await _rig.DisposeAsync();

    private Task<bool> Assign(IEnumerable<string> codes) => _rig.Manager.AssignPermissionsToRoleAsync(_rig.RoleId.ToString(), codes);

    private Task<bool> Replace(params UserPermissionOverride[] overrides) => _rig.Manager.ReplaceUserOverridesAsync(_rig.UserId.ToString(), overrides);

    private static UserPermissionOverride Allow(string code) => new(code, PermissionAccessType.Allow);

    private static UserPermissionOverride Deny(string code) => new(code, PermissionAccessType.Deny);

    // ---- Role: validation changes nothing ----------------------------------------------------

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldReturnFalse_WhenTheRoleIdIsNotAGuid()
    {
        (await _rig.Manager.AssignPermissionsToRoleAsync("not-a-guid", ["SALES.VIEW"])).Should().BeFalse();
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldReturnFalseAndChangeNothing_WhenTheRoleDoesNotExist()
    {
        (await _rig.Manager.AssignPermissionsToRoleAsync(Guid.NewGuid().ToString(), ["SALES.VIEW"])).Should().BeFalse();

        _rig.Db.ChangeTracker.Clear();
        (await _rig.Db.RolePermissions.CountAsync()).Should().Be(0);
    }

    [Theory]
    [InlineData("SALES VIEW")]
    [InlineData("SALES.MISSING")]
    public async Task AssignPermissionsToRoleAsync_ShouldReturnFalseAndKeepThePreviousSet_WhenACodeIsInvalidOrUnknown(string bad)
    {
        await Assign(["SALES.VIEW"]);

        (await Assign(["SALES.EDIT", bad])).Should().BeFalse();

        (await _rig.RoleCodesAsync()).Should().Equal("SALES.VIEW");
    }

    // ---- User: validation changes nothing ----------------------------------------------------

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldReturnFalseAndChangeNothing_WhenTheUserDoesNotExist()
    {
        var ok = await _rig.Manager.ReplaceUserOverridesAsync(Guid.NewGuid().ToString(), [Allow("SALES.VIEW")]);

        ok.Should().BeFalse();
        _rig.Db.ChangeTracker.Clear();
        (await _rig.Db.UserModulePermissions.CountAsync()).Should().Be(0);
    }

    [Theory]
    [InlineData("SALES VIEW")]
    [InlineData("SALES.MISSING")]
    public async Task ReplaceUserOverridesAsync_ShouldReturnFalseAndKeepThePreviousOverrides_WhenACodeIsInvalidOrUnknown(string bad)
    {
        await Replace(Allow("SALES.VIEW"));

        (await Replace(Deny("SALES.EDIT"), Allow(bad))).Should().BeFalse();

        (await _rig.UserOverridesAsync()).Should().Equal("SALES.VIEW:Allow");
    }

    // ---- Atomicity and error propagation -----------------------------------------------------

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldKeepThePreviousSetAndPropagate_WhenTheInsertFailsMidReplace()
    {
        await Assign(["SALES.VIEW", "SALES.EDIT"]);
        _rig.Fault.Remaining = 1;

        var act = () => Assign(["SALES.DELETE"]);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("boom");
        (await _rig.RoleCodesAsync()).Should().Equal("SALES.EDIT", "SALES.VIEW");
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldKeepThePreviousOverridesAndPropagate_WhenTheInsertFailsMidReplace()
    {
        await Replace(Allow("SALES.VIEW"), Deny("SALES.EDIT"));
        _rig.Fault.Remaining = 1;

        var act = () => Replace(Allow("SALES.DELETE"));

        await act.Should().ThrowAsync<InvalidOperationException>();
        (await _rig.UserOverridesAsync()).Should().Equal("SALES.EDIT:Deny", "SALES.VIEW:Allow");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldNotRetry_WhenTheErrorIsNotADbUpdateException()
    {
        _rig.Fault.Remaining = 100;
        var before = _rig.Fault.Calls;

        var act = () => Assign(["SALES.VIEW"]);

        await act.Should().ThrowAsync<InvalidOperationException>();
        (_rig.Fault.Calls - before).Should().Be(1);
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldSucceedAfterARetry_WhenTheFirstAttemptsFailWithADbUpdateException()
    {
        await Assign(["SALES.VIEW"]);
        _rig.Fault.Make = () => new DbUpdateException("conflict");
        _rig.Fault.Remaining = 2;

        (await Assign(["SALES.EDIT"])).Should().BeTrue();

        (await _rig.RoleCodesAsync()).Should().Equal("SALES.EDIT");
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldSucceedAfterARetry_WhenTheFirstAttemptsFailWithADbUpdateException()
    {
        await Replace(Allow("SALES.VIEW"));
        _rig.Fault.Make = () => new DbUpdateException("conflict");
        _rig.Fault.Remaining = 4;

        (await Replace(Deny("SALES.EDIT"))).Should().BeTrue();

        (await _rig.UserOverridesAsync()).Should().Equal("SALES.EDIT:Deny");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldGiveUpAfterFiveAttempts_AndKeepThePreviousSet()
    {
        await Assign(["SALES.VIEW"]);
        _rig.Fault.Make = () => new DbUpdateException("conflict");
        _rig.Fault.Remaining = 100;
        var before = _rig.Fault.Calls;

        var act = () => Assign(["SALES.EDIT"]);

        await act.Should().ThrowAsync<DbUpdateException>();
        (_rig.Fault.Calls - before).Should().Be(5);
        _rig.Fault.Remaining = 0;
        (await _rig.RoleCodesAsync()).Should().Equal("SALES.VIEW");
    }

    // ---- Inside a caller's transaction -------------------------------------------------------

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldRunInsideTheCallersTransaction_AndBeGoneAfterRollback()
    {
        await Assign(["SALES.VIEW"]);
        await using var transaction = await _rig.Db.Database.BeginTransactionAsync();

        (await Assign(["SALES.EDIT", "SALES.DELETE"])).Should().BeTrue();

        _rig.Db.Database.CurrentTransaction.Should().BeSameAs(transaction, "the call must neither commit nor replace the caller's transaction");
        (await _rig.RoleCodesAsync()).Should().Equal("SALES.DELETE", "SALES.EDIT");
        await transaction.RollbackAsync();
        (await _rig.RoleCodesAsync()).Should().Equal("SALES.VIEW");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldPersistWhenTheCallersTransactionCommits()
    {
        await using (var transaction = await _rig.Db.Database.BeginTransactionAsync())
        {
            (await Assign(["SALES.EDIT"])).Should().BeTrue();
            await transaction.CommitAsync();
        }

        (await _rig.RoleCodesAsync()).Should().Equal("SALES.EDIT");
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldRunInsideTheCallersTransaction_AndBeGoneAfterRollback()
    {
        await Replace(Allow("SALES.VIEW"));
        await using var transaction = await _rig.Db.Database.BeginTransactionAsync();

        (await Replace(Deny("SALES.EDIT"))).Should().BeTrue();

        _rig.Db.Database.CurrentTransaction.Should().BeSameAs(transaction);
        (await _rig.UserOverridesAsync()).Should().Equal("SALES.EDIT:Deny");
        await transaction.RollbackAsync();
        (await _rig.UserOverridesAsync()).Should().Equal("SALES.VIEW:Allow");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldLeaveTheCallersTransactionOpen_WhenTheRoleDoesNotExist()
    {
        await using var transaction = await _rig.Db.Database.BeginTransactionAsync();

        (await _rig.Manager.AssignPermissionsToRoleAsync(Guid.NewGuid().ToString(), ["SALES.VIEW"])).Should().BeFalse();

        _rig.Db.Database.CurrentTransaction.Should().BeSameAs(transaction);
        await transaction.RollbackAsync();
    }

    // ---- Savepoint inside the caller transaction ---------------------------------------------

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldKeepThePreviousRowsAfterTheCallerCommits_WhenTheInsertFailsAfterTheDelete()
    {
        await Assign(["SALES.VIEW", "SALES.EDIT"]);
        await using var transaction = await _rig.Db.Database.BeginTransactionAsync();
        _rig.Fault.Remaining = 1;

        var act = () => Assign(["SALES.DELETE"]);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("boom");
        await transaction.CommitAsync();
        (await _rig.RoleCodesAsync()).Should().Equal("SALES.EDIT", "SALES.VIEW");
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldKeepThePreviousRowsAfterTheCallerCommits_WhenTheInsertFailsAfterTheDelete()
    {
        await Replace(Allow("SALES.VIEW"), Deny("SALES.EDIT"));
        await using var transaction = await _rig.Db.Database.BeginTransactionAsync();
        _rig.Fault.Remaining = 1;

        var act = () => Replace(Allow("SALES.DELETE"));

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("boom");
        await transaction.CommitAsync();
        (await _rig.UserOverridesAsync()).Should().Equal("SALES.EDIT:Deny", "SALES.VIEW:Allow");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldKeepThePreviousRowsAfterTheCallerCommits_WhenTheResultIsFalse()
    {
        await Assign(["SALES.VIEW"]);
        await using var transaction = await _rig.Db.Database.BeginTransactionAsync();

        (await Assign(["SALES.EDIT", "SALES.MISSING"])).Should().BeFalse();

        await transaction.CommitAsync();
        (await _rig.RoleCodesAsync()).Should().Equal("SALES.VIEW");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldKeepTheTransactionUsable_ForTwoSuccessfulCalls()
    {
        await using var transaction = await _rig.Db.Database.BeginTransactionAsync();

        (await Assign(["SALES.VIEW"])).Should().BeTrue();
        (await Assign(["SALES.EDIT"])).Should().BeTrue();
        await transaction.CommitAsync();

        (await _rig.RoleCodesAsync()).Should().Equal("SALES.EDIT");
    }

    // ---- A permission deleted after the request was validated --------------------------------

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldReturnFalseAndKeepThePreviousSet_WhenAPermissionIsDeletedAfterTheLock()
    {
        await Assign(["SALES.VIEW"]);
        _rig.DeleteAfterLock.Code = "SALES.EDIT";

        (await Assign(["SALES.EDIT"])).Should().BeFalse();

        (await _rig.RoleCodesAsync()).Should().Equal("SALES.VIEW");
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldReturnFalseAndKeepThePreviousOverrides_WhenAPermissionIsDeletedAfterTheLock()
    {
        await Replace(Allow("SALES.VIEW"));
        _rig.DeleteAfterLock.Code = "SALES.EDIT";

        (await Replace(Deny("SALES.EDIT"))).Should().BeFalse();

        (await _rig.UserOverridesAsync()).Should().Equal("SALES.VIEW:Allow");
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldReturnFalseAndKeepThePreviousSetAfterCommit_WhenAPermissionIsDeletedAfterTheLockInsideACallerTransaction()
    {
        await Assign(["SALES.VIEW"]);
        await using var transaction = await _rig.Db.Database.BeginTransactionAsync();
        _rig.DeleteAfterLock.Code = "SALES.EDIT";

        (await Assign(["SALES.EDIT"])).Should().BeFalse();

        await transaction.CommitAsync();
        (await _rig.RoleCodesAsync()).Should().Equal("SALES.VIEW");
    }

    // ---- Pending changes ---------------------------------------------------------------------

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldThrowAndChangeNothing_WhenTheContextHasPendingChanges()
    {
        await Assign(["SALES.VIEW"]);
        _rig.Db.Roles.Add(new Pinotechrd.Security.Tests.Hosting.HostRole { Name = "pending", NormalizedName = "PENDING" });

        var act = () => Assign(["SALES.EDIT"]);

        await act.Should().ThrowAsync<InvalidOperationException>();
        _rig.Db.ChangeTracker.Clear();
        (await _rig.RoleCodesAsync()).Should().Equal("SALES.VIEW");
        (await _rig.Db.Roles.CountAsync(r => r.Name == "pending")).Should().Be(0, "the pending role was never saved");
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldThrowAndChangeNothing_WhenTheContextHasPendingChanges()
    {
        await Replace(Allow("SALES.VIEW"));
        _rig.Db.Roles.Add(new Pinotechrd.Security.Tests.Hosting.HostRole { Name = "pending", NormalizedName = "PENDING" });

        var act = () => Replace(Deny("SALES.EDIT"));

        await act.Should().ThrowAsync<InvalidOperationException>();
        _rig.Db.ChangeTracker.Clear();
        (await _rig.UserOverridesAsync()).Should().Equal("SALES.VIEW:Allow");
        (await _rig.Db.Roles.CountAsync(r => r.Name == "pending")).Should().Be(0);
    }
}
