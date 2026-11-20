using FluentAssertions;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class PinotechrdSecurityManagerOverrideTests
{
    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldReturnFalse_WhenUserIdIsNotAGuid()
    {
        await using var db = NewDb();
        var manager = new PinotechrdSecurityManager<TestUser, TestRole>(null!, null!, db);

        var replaced = await manager.ReplaceUserOverridesAsync("not-a-guid", []);

        replaced.Should().BeFalse();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task ReplaceUserOverridesAsync_ShouldRefuseAnEmptyCode_AndKeepTheStoredOverrides(string? code)
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();
        var userId = rig.UserId.ToString();
        (await rig.Manager.ReplaceUserOverridesAsync(userId, [new UserPermissionOverride("SALES.EDIT", PermissionAccessType.Deny)]))
            .Should().BeTrue();

        var replaced = await rig.Manager.ReplaceUserOverridesAsync(userId, [
            new UserPermissionOverride("SALES.VIEW", PermissionAccessType.Allow),
            new UserPermissionOverride(code!, PermissionAccessType.Deny)
        ]);

        replaced.Should().BeFalse("an empty code is invalid; skipping it would report a Deny as written");
        (await rig.UserOverridesAsync()).Should().Equal("SALES.EDIT:Deny");
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldReturnFalse_ForANullItem()
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();

        var replaced = await rig.Manager.ReplaceUserOverridesAsync(rig.UserId.ToString(), [null!]);

        replaced.Should().BeFalse();
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldKeepDenyWhenBothAreSent_AndClearOnAnEmptyList()
    {
        await using var rig = await SqliteSecurityManagerRig.CreateAsync();
        var db = rig.Db;
        var manager = rig.Manager;
        var userId = rig.UserId.ToString();

        var replaced = await manager.ReplaceUserOverridesAsync(userId, [
            new UserPermissionOverride("sales.view", PermissionAccessType.Allow),
            new UserPermissionOverride("SALES.VIEW", PermissionAccessType.Deny)
        ]);

        replaced.Should().BeTrue();
        db.ChangeTracker.Clear();
        var stored = await db.UserModulePermissions.SingleAsync();
        stored.AccessType.Should().Be(PermissionAccessType.Deny);

        var unknown = await manager.ReplaceUserOverridesAsync(userId, [
            new UserPermissionOverride("MISSING.CODE", PermissionAccessType.Allow)
        ]);
        unknown.Should().BeFalse();
        (await db.UserModulePermissions.CountAsync()).Should().Be(1);

        var cleared = await manager.ReplaceUserOverridesAsync(userId, []);
        cleared.Should().BeTrue();
        (await db.UserModulePermissions.CountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task AssignPermissionsToRoleAsync_ShouldThrow_WhenTheProviderIsNotRelational()
    {
        await using var db = NewDb();
        var manager = new PinotechrdSecurityManager<TestUser, TestRole>(null!, null!, db);

        var act = () => manager.AssignPermissionsToRoleAsync(Guid.NewGuid().ToString(), []);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*relational*");
    }

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldThrow_WhenTheProviderIsNotRelational()
    {
        await using var db = NewDb();
        var manager = new PinotechrdSecurityManager<TestUser, TestRole>(null!, null!, db);

        var act = () => manager.ReplaceUserOverridesAsync(Guid.NewGuid().ToString(), []);

        await act.Should().ThrowAsync<InvalidOperationException>().WithMessage("*relational*");
    }

    private static OverrideDb NewDb()
    {
        var options = new DbContextOptionsBuilder<OverrideDb>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new OverrideDb(options);
    }

    private sealed class TestUser : BaseSecurityUser
    {
    }

    private sealed class TestRole : BaseSecurityRole
    {
    }

    private sealed class OverrideDb : IdentityDbContext<TestUser, TestRole, Guid>, ISecurityDbContext
    {
        public OverrideDb(DbContextOptions<OverrideDb> options) : base(options)
        {
        }

        public DbSet<SecurityPermission> PermissionRows { get; set; } = null!;
        public DbSet<UserModulePermission> OverrideRows { get; set; } = null!;

        public IQueryable<SecurityPermission> Permissions => PermissionRows;
        public IQueryable<SecurityModule> Modules => Set<SecurityModule>();
        public IQueryable<SystemSubscription> SystemSubscriptions => Set<SystemSubscription>();
        public IQueryable<RolePermission> RolePermissions => Set<RolePermission>();
        public IQueryable<UserModulePermission> UserModulePermissions => OverrideRows;
        public IQueryable<SubscriptionPlanModule> SubscriptionPlanModules => Set<SubscriptionPlanModule>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<SecurityPermission>().Ignore(permission => permission.Module);
            modelBuilder.Entity<SecurityPermission>().Ignore(permission => permission.RolePermissions);
            modelBuilder.Entity<UserModulePermission>().Ignore(row => row.Permission);
        }
    }
}
