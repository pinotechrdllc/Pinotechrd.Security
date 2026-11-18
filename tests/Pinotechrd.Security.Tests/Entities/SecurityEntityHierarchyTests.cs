using FluentAssertions;
using Pinotechrd.Security.Entities;
using Xunit;

namespace Pinotechrd.Security.Tests.Entities;

public class SecurityEntityHierarchyTests
{
    private class TestPermission : SecurityPermission { }
    private class TestModule : SecurityModule { }
    private class TestRole : BaseSecurityRole { }
    private class TestSubscription : SystemSubscription { }

    [Fact]
    public void SecurityPermission_ShouldInheritFromBase()
    {
        var permission = new TestPermission();
        permission.Should().BeAssignableTo<BaseSecurityEntity>();
        permission.Name.Should().BeEmpty();
    }

    [Fact]
    public void SecurityModule_ShouldInheritFromBase()
    {
        var module = new TestModule();
        module.Should().BeAssignableTo<BaseSecurityEntity>();
        module.Code.Should().BeEmpty();
    }

    [Fact]
    public void BaseSecurityRole_ShouldInheritFromIdentityRole()
    {
        var role = new BaseSecurityRole();
        role.Should().BeAssignableTo<Microsoft.AspNetCore.Identity.IdentityRole<Guid>>();
    }

    [Fact]
    public void SystemSubscription_ShouldInheritFromBase()
    {
        var subscription = new TestSubscription();
        subscription.Should().BeAssignableTo<SecurityBaseEntity>();
    }
}
