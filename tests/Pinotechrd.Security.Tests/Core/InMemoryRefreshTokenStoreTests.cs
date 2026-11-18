using FluentAssertions;
using Pinotechrd.Security.Core;
using Xunit;

namespace Pinotechrd.Security.Tests.Core;

public class InMemoryRefreshTokenStoreTests
{
    [Fact]
    public async Task ValidateAsync_ShouldReturnContext_WhenTokenIsValid()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = "refresh-token-valid";

        await store.SaveAsync("user-1", "tenant-a", token, DateTime.UtcNow.AddMinutes(10));

        var result = await store.ValidateAsync(token);

        result.IsValid.Should().BeTrue();
        result.UserId.Should().Be("user-1");
        result.TenantId.Should().Be("tenant-a");
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenTokenWasRevoked()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = "refresh-token-revoked";

        await store.SaveAsync("user-1", "tenant-a", token, DateTime.UtcNow.AddMinutes(10));
        await store.RevokeAsync(token);

        var result = await store.ValidateAsync(token);

        result.IsValid.Should().BeFalse();
        result.Reason.Should().Be("Refresh token revoked");
    }

    [Fact]
    public async Task ValidateAsync_ShouldFail_WhenTokenIsExpired()
    {
        var store = new InMemoryRefreshTokenStore();
        var token = "refresh-token-expired";

        await store.SaveAsync("user-1", "tenant-a", token, DateTime.UtcNow.AddMinutes(-1));

        var result = await store.ValidateAsync(token);

        result.IsValid.Should().BeFalse();
        result.Reason.Should().Be("Refresh token expired");
    }
}
