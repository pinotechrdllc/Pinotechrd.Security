using FluentAssertions;
using MockQueryable;
using MockQueryable.NSubstitute;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Microsoft.AspNetCore.Identity;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class SecurityEngineTests
{
    private readonly ISecurityDataProvider _provider = Substitute.For<ISecurityDataProvider>();
    private readonly ISecurityStore _store = Substitute.For<ISecurityStore>();
    private readonly SecurityEngine _engine;

    public SecurityEngineTests()
    {
        _engine = new SecurityEngine(_store, _provider);
    }

    [Fact]
    public async Task CanAccessAsync_ShouldReturnTrue_WhenEverythingIsValid()
    {
        // Arrange
        var userId = "user-1";
        var tenantId = "tenant-A";
        var moduleCode = "MOD_A";
        var permName = "PERM_1";

        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(true);
        _store.IsModuleActiveAsync(tenantId, moduleCode).Returns(true);
        _provider.GetUserPermissionsAsync(userId).Returns(new List<string> { $"{moduleCode}.{permName}" });

        // Act
        var result = await _engine.CanAccessAsync(moduleCode, permName);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldReturnFalse_WhenTheUserHoldsOnlyTheBarePermissionName()
    {
        _provider.GetCurrentUserId().Returns("user-1");
        _provider.GetCurrentTenantId().Returns("tenant-A");
        _store.IsSubscriptionActiveAsync("tenant-A").Returns(true);
        _store.IsModuleActiveAsync("tenant-A", "MOD_A").Returns(true);
        _provider.GetUserPermissionsAsync("user-1").Returns(new List<string> { "PERM_1" });

        var result = await _engine.CanAccessAsync("MOD_A", "PERM_1");

        result.Should().BeFalse("a bare name would grant that permission in every module");
    }

    [Fact]
    public async Task CanAccessAsync_ShouldReturnFalse_WhenSubscriptionIsExpired()
    {
        // Arrange
        var userId = "user-1";
        var tenantId = "tenant-A";
        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(false);

        // Act
        var result = await _engine.CanAccessAsync("MOD_A", "PERM_1");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldReturnFalse_WhenModuleIsInactive()
    {
        // Arrange
        var userId = "user-1";
        var tenantId = "tenant-A";
        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(true);
        _store.IsModuleActiveAsync(tenantId, "MOD_A").Returns(false);

        // Act
        var result = await _engine.CanAccessAsync("MOD_A", "PERM_1");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldReturnFalse_WhenUserHasNoPermission()
    {
        // Arrange
        var userId = "user-1";
        var tenantId = "tenant-A";
        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(true);
        _store.IsModuleActiveAsync(tenantId, "MOD_A").Returns(true);
        _provider.GetUserPermissionsAsync(userId).Returns(new List<string>());
        
        // Act
        var result = await _engine.CanAccessAsync("MOD_A", "PERM_1");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldReturnFalse_WhenTenantIdIsMissing()
    {
        // Arrange
        _provider.GetCurrentUserId().Returns("user-1");
        _provider.GetCurrentTenantId().Returns((string?)null);

        // Act
        var result = await _engine.CanAccessAsync("MOD_A", "PERM_1");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task GetAuthorizedMenuAsync_ShouldReturnEmpty_WhenSubscriptionInactive()
    {
        // Arrange
        var tenantId = "tenant-A";
        _provider.GetCurrentUserId().Returns("user-1");
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(false);

        var menu = new List<SecurityMenuItem>
        {
            new() { TitleKey = "Test", Order = 1 }
        };

        // Act
        var result = await _engine.GetAuthorizedMenuAsync(menu);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task GetAuthorizedMenuAsync_ShouldRecursiveFilterAuthorizedItems()
    {
        // Arrange
        var userId = "user-1";
        var tenantId = "tenant-A";
        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(true);
        _store.GetActiveModuleCodesAsync(tenantId).Returns(new List<string> { "Orders" });
        _provider.GetUserPermissionsAsync(userId).Returns(new List<string> { "Orders.Read" });

        var menu = new List<SecurityMenuItem>
        {
            new() 
            { 
                TitleKey = "Orders", 
                ModuleCode = "Orders",
                RequiredPermissions = new List<string> { "Orders.Read" },
                Order = 1,
                Children = new List<SecurityMenuItem>
                {
                    new() { TitleKey = "List", RequiredPermissions = new List<string> { "Orders.Read" }, Order = 1 },
                    new() { TitleKey = "Create", RequiredPermissions = new List<string> { "Orders.Write" }, Order = 2 }
                }
            },
            new()
            {
                TitleKey = "Admin",
                ModuleCode = "Admin", // Not in active modules
                Order = 2
            }
        };

        // Act
        var result = await _engine.GetAuthorizedMenuAsync(menu);

        // Assert
        result.Should().HaveCount(1);
        result[0].TitleKey.Should().Be("Orders");
        result[0].Children.Should().HaveCount(1);
        result[0].Children[0].TitleKey.Should().Be("List");
    }

    [Fact]
    public async Task GetAuthorizedMenuAsync_ShouldOrderItemsByOrderProperty()
    {
        // Arrange
        var userId = "user-1";
        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns("tenant-A");
        _store.IsSubscriptionActiveAsync(Arg.Any<string>()).Returns(true);
        _store.GetActiveModuleCodesAsync(Arg.Any<string>()).Returns(new List<string>());
        _provider.GetUserPermissionsAsync(userId).Returns(new List<string>());

        var menu = new List<SecurityMenuItem>
        {
            new() { TitleKey = "Last", Order = 100 },
            new() { TitleKey = "First", Order = 1 },
            new() { TitleKey = "Middle", Order = 50 }
        };

        // Act
        var result = await _engine.GetAuthorizedMenuAsync(menu);

        // Assert
        result.Should().HaveCount(3);
        result[0].TitleKey.Should().Be("First");
        result[1].TitleKey.Should().Be("Middle");
        result[2].TitleKey.Should().Be("Last");
    }

    [Fact]
    public async Task GetPermissionsAsync_ShouldReturnPermissionsFromProvider()
    {
        // Arrange
        var userId = "user-123";
        var expectedPermissions = new List<string> { "Perm1", "Perm2" };
        _provider.GetUserPermissionsAsync(userId).Returns(expectedPermissions);

        // Act
        var result = await _engine.GetPermissionsAsync(userId);

        // Assert
        result.Should().BeEquivalentTo(expectedPermissions);
        await _provider.Received(1).GetUserPermissionsAsync(userId);
    }

    [Fact]
    public async Task CanAccessAsync_ShouldGrantTheFullCode_AndRejectAnotherModulesSuffix()
    {
        var userId = "user-1";
        var tenantId = "tenant-A";
        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(true);
        _store.IsModuleActiveAsync(tenantId, Arg.Any<string>()).Returns(true);
        _provider.GetUserPermissionsAsync(userId).Returns(new List<string> { "mod_a.perm_1" });
        _store.GetUserOverridesAsync(userId).Returns(new List<UserPermissionOverride>());

        (await _engine.CanAccessAsync("MOD_A", "PERM_1")).Should().BeTrue();
        (await _engine.CanAccessAsync("OTHER", "PERM_1")).Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldLetDenyRemoveARolePermission()
    {
        var userId = "user-1";
        var tenantId = "tenant-A";
        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(true);
        _store.IsModuleActiveAsync(tenantId, "MOD_A").Returns(true);
        _provider.GetUserPermissionsAsync(userId).Returns(new List<string> { "MOD_A.PERM_1" });
        _store.GetUserOverridesAsync(userId).Returns(new List<UserPermissionOverride>
        {
            new("MOD_A.PERM_1", PermissionAccessType.Allow),
            new("MOD_A.PERM_1", PermissionAccessType.Deny)
        });

        (await _engine.CanAccessAsync("MOD_A", "PERM_1")).Should().BeFalse();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldGrantAnAllowTheRoleDoesNotHave()
    {
        var userId = "user-1";
        var tenantId = "tenant-A";
        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(true);
        _store.IsModuleActiveAsync(tenantId, "MOD_A").Returns(true);
        _provider.GetUserPermissionsAsync(userId).Returns(new List<string> { "MOD_A.OTHER" });
        _store.GetUserOverridesAsync(userId).Returns(new List<UserPermissionOverride>
        {
            new("MOD_A.PERM_1", PermissionAccessType.Allow)
        });

        (await _engine.CanAccessAsync("MOD_A", "PERM_1")).Should().BeTrue();
    }

    [Fact]
    public async Task CanAccessAsync_ShouldNotLetAnAllowBypassAnInactiveModule()
    {
        var userId = "user-1";
        var tenantId = "tenant-A";
        _provider.GetCurrentUserId().Returns(userId);
        _provider.GetCurrentTenantId().Returns(tenantId);
        _store.IsSubscriptionActiveAsync(tenantId).Returns(true);
        _store.IsModuleActiveAsync(tenantId, "MOD_A").Returns(false);
        _provider.GetUserPermissionsAsync(userId).Returns(new List<string>());
        _store.GetUserOverridesAsync(userId).Returns(new List<UserPermissionOverride>
        {
            new("MOD_A.PERM_1", PermissionAccessType.Allow)
        });

        (await _engine.CanAccessAsync("MOD_A", "PERM_1")).Should().BeFalse();
    }

    [Fact]
    public async Task GetPermissionsAsync_ShouldDropCodesWhoseModuleIsNotActive()
    {
        var userId = "user-123";
        _provider.GetCurrentTenantId().Returns("tenant-A");
        _provider.GetUserPermissionsAsync(userId).Returns(new List<string>
        {
            "ORDERS.READ",
            "ACCOUNTING.VIEW",
            "CORE.HOME",
            "BARE"
        });
        _store.GetUserOverridesAsync(userId).Returns(new List<UserPermissionOverride>());
        _store.GetActiveModuleCodesAsync("tenant-A").Returns(new List<string> { "ORDERS" });

        var result = await _engine.GetPermissionsAsync(userId);

        result.Should().BeEquivalentTo(new[] { "ORDERS.READ", "CORE.HOME", "BARE" });
    }

    private class TestSubscription : SystemSubscription { }
    private class TestModule : SecurityModule { }
}
