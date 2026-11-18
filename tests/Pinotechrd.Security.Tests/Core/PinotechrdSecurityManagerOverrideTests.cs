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

    [Fact]
    public async Task ReplaceUserOverridesAsync_ShouldKeepDenyWhenBothAreSent_AndClearOnAnEmptyList()
    {
        await using var db = NewDb();
        var permission = SecurityPermission.Create(Guid.NewGuid(), "Read", "mod_on.read");
        db.PermissionRows.Add(permission);
        await db.SaveChangesAsync();

        var manager = new PinotechrdSecurityManager<TestUser, TestRole>(null!, null!, db);
        var userId = Guid.NewGuid().ToString();

        var replaced = await manager.ReplaceUserOverridesAsync(userId, [
            new UserPermissionOverride("mod_on.read", PermissionAccessType.Allow),
            new UserPermissionOverride("MOD_ON.READ", PermissionAccessType.Deny)
        ]);

        replaced.Should().BeTrue();
        var stored = await db.OverrideRows.SingleAsync();
        stored.AccessType.Should().Be(PermissionAccessType.Deny);
        stored.PermissionId.Should().Be(permission.Id);

        var unknown = await manager.ReplaceUserOverridesAsync(userId, [
            new UserPermissionOverride("MISSING.CODE", PermissionAccessType.Allow)
        ]);
        unknown.Should().BeFalse();
        (await db.OverrideRows.CountAsync()).Should().Be(1);

        var cleared = await manager.ReplaceUserOverridesAsync(userId, []);
        cleared.Should().BeTrue();
        (await db.OverrideRows.CountAsync()).Should().Be(0);
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
