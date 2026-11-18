using System;
using System.Linq;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Xunit;

namespace Pinotechrd.Security.Tests.Extensions;

public class SecurityExtensionsTests
{
    [Fact]
    public void AddPinotechrdSecurity_ShouldThrow_WhenJwtSecretTooShort()
    {
        var services = new ServiceCollection();
        services.AddDbContext<TestSecurityDbContext>(options => options.UseInMemoryDatabase(Guid.NewGuid().ToString()));

        var act = () => services.AddPinotechrdSecurity<TestSecurityDbContext, TestUser, TestRole>(options =>
        {
            options.Jwt = new JwtSettings
            {
                Secret = "short-secret",
                MinimumSecretLength = 32,
                Issuer = "pinotechrd-tests",
                Audience = "pinotechrd-tests"
            };
        });

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*at least 32 characters*");
    }

    private sealed class TestUser : BaseSecurityUser
    {
    }

    private sealed class TestRole : BaseSecurityRole
    {
    }

    private sealed class TestSecurityDbContext : IdentityDbContext<TestUser, TestRole, Guid>, ISecurityDbContext
    {
        public TestSecurityDbContext(DbContextOptions<TestSecurityDbContext> options) : base(options)
        {
        }

        public IQueryable<SecurityPermission> Permissions => Array.Empty<SecurityPermission>().AsQueryable();
        public IQueryable<SecurityModule> Modules => Array.Empty<SecurityModule>().AsQueryable();
        public IQueryable<SystemSubscription> SystemSubscriptions => Array.Empty<SystemSubscription>().AsQueryable();
        public IQueryable<RolePermission> RolePermissions => Array.Empty<RolePermission>().AsQueryable();
        public IQueryable<UserModulePermission> UserModulePermissions => Array.Empty<UserModulePermission>().AsQueryable();
        public IQueryable<SubscriptionPlanModule> SubscriptionPlanModules => Array.Empty<SubscriptionPlanModule>().AsQueryable();
    }
}
