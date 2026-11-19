using System;
using System.Linq;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Xunit;

namespace Pinotechrd.Security.Tests.Extensions;

public class SecurityExtensionsTests
{
    [Fact]
    public void AddPinotechrdSecurity_ShouldNotThrow_WhenJwtSecretTooShort_BecauseValidationRunsAtHostStart()
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

        act.Should().NotThrow();
    }

    [Fact]
    public void ResolvingTheOptions_ShouldThrowOptionsValidationException_WhenJwtSecretTooShort()
    {
        var services = new ServiceCollection();
        services.AddDbContext<TestSecurityDbContext>(options => options.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        services.AddPinotechrdSecurity<TestSecurityDbContext, TestUser, TestRole>(options =>
        {
            options.Jwt = new JwtSettings
            {
                Secret = "short-secret",
                MinimumSecretLength = 32,
                Issuer = "pinotechrd-tests",
                Audience = "pinotechrd-tests"
            };
        });
        using var provider = services.BuildServiceProvider();

        var act = () => provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<PinotechrdSecurityOptions>>().Value;

        act.Should().Throw<Microsoft.Extensions.Options.OptionsValidationException>()
            .WithMessage("*Jwt.Secret*");
    }

    private static ServiceCollection NewServices()
    {
        var services = new ServiceCollection();
        services.AddDbContext<TestSecurityDbContext>(options => options.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        return services;
    }

    private static void AddSecurity(IServiceCollection services) =>
        services.AddPinotechrdSecurity<TestSecurityDbContext, TestUser, TestRole>(options =>
        {
            options.Jwt = new JwtSettings
            {
                Secret = new string('k', 48),
                Issuer = "pinotechrd-tests",
                Audience = "pinotechrd-tests"
            };
        });

    [Fact]
    public void AddPinotechrdEfRefreshTokenStore_ShouldStillWin_WhenCalledBeforeAddPinotechrdSecurity()
    {
        var services = NewServices();
        services.AddPinotechrdEfRefreshTokenStore<TestSecurityDbContext>();
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        scope.ServiceProvider.GetRequiredService<IRefreshTokenStore>().Should().BeOfType<EfRefreshTokenStore<TestSecurityDbContext>>();
        services.Count(d => d.ServiceType == typeof(IRefreshTokenStore)).Should().Be(1);
    }

    [Fact]
    public void AddPinotechrdSecurity_ShouldKeepACustomRefreshTokenStore_RegisteredBeforeIt()
    {
        var custom = Substitute.For<IRefreshTokenStore>();
        var services = NewServices();
        services.AddSingleton(custom);
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IRefreshTokenStore>().Should().BeSameAs(custom);
    }

    [Fact]
    public void AddPinotechrdSecurity_ShouldKeepACustomTwoFactorAttemptStore_RegisteredBeforeIt()
    {
        var custom = Substitute.For<ITwoFactorAttemptStore>();
        var services = NewServices();
        services.AddSingleton(custom);
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<ITwoFactorAttemptStore>().Should().BeSameAs(custom);
    }

    [Fact]
    public void AddPinotechrdSecurity_ShouldRegisterTheInMemoryStores_WhenNoneWasRegistered()
    {
        var services = NewServices();
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IRefreshTokenStore>().Should().BeOfType<InMemoryRefreshTokenStore>();
        provider.GetRequiredService<ITwoFactorAttemptStore>().Should().BeOfType<InMemoryTwoFactorAttemptStore>();
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
