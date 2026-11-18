using FluentAssertions;
using Pinotechrd.Security.Entities;
using Xunit;

namespace Pinotechrd.Security.Tests.Entities;

public class BaseSecurityEntityTests
{
    private class TestEntity : BaseSecurityEntity { }

    [Fact]
    public void BaseSecurityEntity_ShouldHaveRequiredProperties()
    {
        // Act
        var entity = new TestEntity();

        // Assert
        entity.Id.Should().NotBeEmpty();
        entity.TenantId.Should().BeEmpty(); // Initial state should be empty
    }
}
