using FluentAssertions;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

/// <summary>Self-service permission listing: the user is the authenticated user of the request.</summary>
public class SecurityEngineCurrentUserTests
{
    private readonly ISecurityDataProvider _provider = Substitute.For<ISecurityDataProvider>();
    private readonly ISecurityStore _store = Substitute.For<ISecurityStore>();
    private readonly SecurityEngine _engine;

    public SecurityEngineCurrentUserTests()
    {
        _engine = new SecurityEngine(_store, _provider);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task GetCurrentUserPermissionsAsync_ShouldBeEmptyWithoutReadingAnyPermission_WhenThereIsNoAuthenticatedUser(string? currentId)
    {
        _provider.GetCurrentUserId().Returns(currentId);

        var permissions = await _engine.GetCurrentUserPermissionsAsync();

        permissions.Should().BeEmpty();
        await _provider.DidNotReceiveWithAnyArgs().GetUserPermissionsAsync(default!);
    }

    [Fact]
    public async Task GetCurrentUserPermissionsAsync_ShouldEqualGetPermissionsAsyncOfTheCurrentUser()
    {
        _provider.GetCurrentUserId().Returns("user-1");
        _provider.GetCurrentTenantId().Returns("tenant-A");
        _provider.GetUserPermissionsAsync("user-1").Returns(new List<string> { "MOD_A.READ", "MOD_B.READ", "CORE.HOME" });
        _provider.GetUserPermissionsAsync("user-2").Returns(new List<string> { "MOD_A.ADMIN" });
        _store.GetActiveModuleCodesAsync("tenant-A").Returns(new List<string> { "MOD_A" });

        var current = await _engine.GetCurrentUserPermissionsAsync();

        current.Should().BeEquivalentTo(await _engine.GetPermissionsAsync("user-1"));
        current.Should().BeEquivalentTo(["MOD_A.READ"], "permissions of modules outside the plan (CORE included) are filtered like GetPermissionsAsync");
        current.Should().NotContain("MOD_A.ADMIN", "another user's permissions are never reported");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task GetCurrentUserPermissionsAsync_ShouldBeEmpty_WhenTheTenantIdIsEmpty_EvenIfTheUserHasPermissions(string? tenantId)
    {
        _provider.GetCurrentUserId().Returns("user-1");
        _provider.GetCurrentTenantId().Returns(tenantId);
        _provider.GetUserPermissionsAsync("user-1").Returns(new List<string> { "MOD_A.READ", "CORE.HOME" });

        var permissions = await _engine.GetCurrentUserPermissionsAsync();

        permissions.Should().BeEmpty();
    }
}
