using NSubstitute;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Interfaces;
using Xunit;

namespace Pinotechrd.Security.Tests.Interfaces;

public class SecurityInterfacesTests
{
    [Fact]
    public void ISecurityDbContext_ShouldDefineRequiredSets()
    {
        // Arrange
        var mockContext = Substitute.For<ISecurityDbContext>();

        // Act & Assert (Verification of contract existence via mock usage)
        _ = mockContext.Permissions;
        _ = mockContext.Modules;
        _ = mockContext.SystemSubscriptions;
        _ = mockContext.RolePermissions;
    }

    [Fact]
    public void ISecurityDataProvider_ShouldDefineRequiredMethods()
    {
        // Arrange
        var mockProvider = Substitute.For<ISecurityDataProvider>();

        // Act & Assert
        _ = mockProvider.GetCurrentUserId();
        _ = mockProvider.GetUserRolesAsync(Arg.Any<string>());
        _ = mockProvider.GetUserPermissionsAsync(Arg.Any<string>());
    }
}
