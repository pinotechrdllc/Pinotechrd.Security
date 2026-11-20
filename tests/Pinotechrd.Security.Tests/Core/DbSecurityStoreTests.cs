using FluentAssertions;
using MockQueryable;
using MockQueryable.NSubstitute;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Enums;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class DbSecurityStoreTests
{
    private readonly ISecurityDbContext _db = Substitute.For<ISecurityDbContext>();
    private readonly DbSecurityStore _store;

    public DbSecurityStoreTests()
    {
        _store = new DbSecurityStore(_db);
    }

    [Fact]
    public async Task IsSubscriptionActiveAsync_ShouldReturnTrue_WhenActive()
    {
        // Arrange
        var tenantId = "tenant-1";
        _db.SystemSubscriptions.Returns(new List<TestSubscription> 
        { 
            new() { TenantName = tenantId, IsActive = true, StartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1)) } 
        }.BuildMock());

        // Act
        var result = await _store.IsSubscriptionActiveAsync(tenantId);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task IsModuleActiveAsync_ShouldReturnTrue_WhenActive()
    {
        // Arrange
        var tenantId = "tenant-1";
        var moduleCode = "MOD_X";
        var planId = Guid.NewGuid();
        var moduleId = SecurityModuleId.FromCode(moduleCode);

        _db.SystemSubscriptions.Returns(new List<TestSubscription> 
        { 
            new() { TenantName = tenantId, PlanId = planId, IsActive = true, StartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1)) } 
        }.BuildMock());

        _db.SubscriptionPlanModules.Returns(new List<TestSubscriptionPlanModule>
        {
            new() { PlanId = planId, ModuleId = moduleId }
        }.BuildMock());

        _db.Modules.Returns(new List<TestModule> 
        { 
            new() { Id = moduleId, Code = moduleCode, IsActive = true } 
        }.BuildMock());

        // Act
        var result = await _store.IsModuleActiveAsync(tenantId, moduleCode);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task ModuleRowWhoseCodeDoesNotBelongToItsId_ShouldNotCountForThePlan()
    {
        // The plan maps SALES by id. The tenant's row has that id but another code (changed after creation), and a
        // second row has a random id from before deterministic ids. Neither is the module the plan names.
        var tenantId = "tenant-1";
        var planId = Guid.NewGuid();
        var salesId = SecurityModuleId.FromCode("SALES");
        var legacyId = Guid.NewGuid();

        _db.SystemSubscriptions.Returns(new List<TestSubscription>
        {
            new() { TenantName = tenantId, PlanId = planId, IsActive = true, StartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1)) }
        }.BuildMock());
        _db.SubscriptionPlanModules.Returns(new List<TestSubscriptionPlanModule>
        {
            new() { PlanId = planId, ModuleId = salesId },
            new() { PlanId = planId, ModuleId = legacyId }
        }.BuildMock());
        _db.Modules.Returns(new List<TestModule>
        {
            new() { Id = salesId, Code = "PREMIUM", IsActive = true },
            new() { Id = legacyId, Code = "LEGACY", IsActive = true }
        }.BuildMock());

        (await _store.IsModuleActiveAsync(tenantId, "PREMIUM")).Should().BeFalse();
        (await _store.IsModuleActiveAsync(tenantId, "LEGACY")).Should().BeFalse();
        (await _store.GetActiveModuleCodesAsync(tenantId)).Should().BeEmpty();
        (await _store.GetActiveCatalogAsync(tenantId)).Should().BeEmpty();
    }

    [Fact]
    public async Task GetActiveModuleCodesAsync_ShouldReturnCodes_WhenSubscriptionIsActive()
    {
        // Arrange
        var tenantId = "tenant-2";
        var planId = Guid.NewGuid();
        var moduleId = SecurityModuleId.FromCode("MOD_ABC");

        _db.SystemSubscriptions.Returns(new List<TestSubscription> 
        { 
            new() { TenantName = tenantId, PlanId = planId, IsActive = true, StartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1)) } 
        }.BuildMock());

        _db.SubscriptionPlanModules.Returns(new List<TestSubscriptionPlanModule>
        {
            new() { PlanId = planId, ModuleId = moduleId }
        }.BuildMock());

        _db.Modules.Returns(new List<TestModule> 
        { 
            new() { Id = moduleId, Code = "MOD_ABC", IsActive = true } 
        }.BuildMock());

        // Act
        var result = await _store.GetActiveModuleCodesAsync(tenantId);

        // Assert
        result.Should().Contain("MOD_ABC");
    }

    [Fact]
    public async Task GetActiveCatalogAsync_ShouldOmitModulesOutsideThePlanAndInactivePermissions()
    {
        var tenantId = "tenant-1";
        var planId = Guid.NewGuid();
        var activeModuleId = SecurityModuleId.FromCode("MOD_ON");
        var offPlanModuleId = SecurityModuleId.FromCode("MOD_OFF");
        var dormantModuleId = SecurityModuleId.FromCode("MOD_DORMANT");

        _db.SystemSubscriptions.Returns(new List<TestSubscription>
        {
            new() { TenantName = tenantId, PlanId = planId, IsActive = true, StartDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-1)) }
        }.BuildMock());

        _db.SubscriptionPlanModules.Returns(new List<TestSubscriptionPlanModule>
        {
            new() { PlanId = planId, ModuleId = activeModuleId },
            new() { PlanId = planId, ModuleId = dormantModuleId }
        }.BuildMock());

        _db.Modules.Returns(new List<TestModule>
        {
            new() { Id = activeModuleId, Code = "MOD_ON", IsActive = true, DisplayOrder = 1 },
            new() { Id = offPlanModuleId, Code = "MOD_OFF", IsActive = true, DisplayOrder = 2 },
            new() { Id = dormantModuleId, Code = "MOD_DORMANT", IsActive = false, DisplayOrder = 0 }
        }.BuildMock());

        _db.Permissions.Returns(new List<TestPermission>
        {
            new() { ModuleId = activeModuleId, Code = "MOD_ON.READ", IsActive = true },
            new() { ModuleId = activeModuleId, Code = "MOD_ON.HIDDEN", IsActive = false },
            new() { ModuleId = offPlanModuleId, Code = "MOD_OFF.READ", IsActive = true }
        }.BuildMock());

        var result = await _store.GetActiveCatalogAsync(tenantId);

        result.Should().ContainSingle();
        result[0].Code.Should().Be("MOD_ON");
        result[0].Permissions.Select(permission => permission.Code).Should().Equal("MOD_ON.READ");
    }

    [Fact]
    public async Task GetUserOverridesAsync_ShouldReturnOnlyThatUsersAllowAndDeny()
    {
        var userId = Guid.NewGuid();
        var otherUserId = Guid.NewGuid();
        _db.UserModulePermissions.Returns(new List<UserModulePermission>
        {
            new()
            {
                UserId = userId,
                AccessType = PermissionAccessType.Allow,
                Permission = new TestPermission { Code = "MOD_ON.READ" }
            },
            new()
            {
                UserId = userId,
                AccessType = PermissionAccessType.Deny,
                Permission = new TestPermission { Code = "MOD_ON.WRITE" }
            },
            new()
            {
                UserId = otherUserId,
                AccessType = PermissionAccessType.Allow,
                Permission = new TestPermission { Code = "OTHER.READ" }
            }
        }.BuildMock());

        var result = await _store.GetUserOverridesAsync(userId.ToString());

        result.Should().BeEquivalentTo(new[]
        {
            new UserPermissionOverride("MOD_ON.READ", PermissionAccessType.Allow),
            new UserPermissionOverride("MOD_ON.WRITE", PermissionAccessType.Deny)
        });
    }

    [Fact]
    public async Task GetUserOverridesAsync_ShouldReturnEmpty_WhenUserIdIsNotAGuid()
    {
        var result = await _store.GetUserOverridesAsync("not-a-guid");

        result.Should().BeEmpty();
    }

    private class TestSubscription : SystemSubscription { }
    private class TestModule : SecurityModule { }
    private class TestPermission : SecurityPermission { }
    private class TestSubscriptionPlanModule : SubscriptionPlanModule { }
}
