using FluentAssertions;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Models;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class SecurityEngineCancellationTests
{
    private readonly ISecurityDataProvider _provider = Substitute.For<ISecurityDataProvider>();
    private readonly ISecurityStore _store = Substitute.For<ISecurityStore>();

    [Fact]
    public async Task CanAccessAsync_ShouldPassTheSameTokenToTheStoreAndTheDataProvider()
    {
        using var cts = new CancellationTokenSource();
        var token = cts.Token;
        _provider.GetCurrentUserId().Returns("user-1");
        _provider.GetCurrentTenantId().Returns("tenant-A");
        _store.IsSubscriptionActiveAsync("tenant-A", Arg.Any<CancellationToken>()).Returns(true);
        _store.IsModuleActiveAsync("tenant-A", "MOD_A", Arg.Any<CancellationToken>()).Returns(true);
        _provider.GetUserPermissionsAsync("user-1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IEnumerable<string>>(["MOD_A.PERM_1"]));
        _provider.GetUserRolesAsync("user-1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IEnumerable<string>>([]));
        _store.GetUserOverridesAsync("user-1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<UserPermissionOverride>>([]));

        var allowed = await new SecurityEngine(_store, _provider).CanAccessAsync("MOD_A", "PERM_1", token);

        allowed.Should().BeTrue();
        await _store.Received().IsSubscriptionActiveAsync("tenant-A", token);
        await _store.Received().IsModuleActiveAsync("tenant-A", "MOD_A", token);
        await _provider.Received().GetUserPermissionsAsync("user-1", token);
        await _store.Received().GetUserOverridesAsync("user-1", token);
        await _store.DidNotReceive().IsSubscriptionActiveAsync(Arg.Any<string>(), Arg.Is<CancellationToken>(t => t != token));
        await _store.DidNotReceive().IsModuleActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Is<CancellationToken>(t => t != token));
        await _provider.DidNotReceive().GetUserPermissionsAsync(Arg.Any<string>(), Arg.Is<CancellationToken>(t => t != token));
        await _store.DidNotReceive().GetUserOverridesAsync(Arg.Any<string>(), Arg.Is<CancellationToken>(t => t != token));
    }
}
