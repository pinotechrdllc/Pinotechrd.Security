using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Extensions;

public class EfTwoFactorAttemptStoreRegistrationTests
{
    private static void AddSecurity(IServiceCollection services) =>
        services.AddPinotechrdSecurity<SecDb, HostUser, HostRole>(o =>
        {
            o.Jwt.Secret = TenantDatabaseApi.Secret;
            o.Jwt.Issuer = TenantDatabaseApi.Issuer;
            o.Jwt.Audience = TenantDatabaseApi.Audience;
        });

    private static ServiceCollection NewServices()
    {
        var services = new ServiceCollection();
        services.AddDbContext<SecDb>(o => o.UseSqlite("DataSource=:memory:"));
        return services;
    }

    private static ServiceDescriptor[] AttemptStoreRegistrations(IServiceCollection services) =>
        services.Where(d => d.ServiceType == typeof(ITwoFactorAttemptStore)).ToArray();

    [Fact]
    public void AddPinotechrdEfTwoFactorAttemptStore_ShouldKeepTheEfStore_WhenCalledBeforeAddPinotechrdSecurity()
    {
        var services = NewServices();

        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();
        AddSecurity(services);

        var registrations = AttemptStoreRegistrations(services);
        registrations.Should().ContainSingle();
        registrations[0].ImplementationType.Should().Be(typeof(EfTwoFactorAttemptStore<SecDb>));
        registrations[0].Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public void AddPinotechrdEfTwoFactorAttemptStore_ShouldReplaceTheInMemoryStore_WhenCalledAfterAddPinotechrdSecurity()
    {
        var services = NewServices();
        AddSecurity(services);
        AttemptStoreRegistrations(services).Should().ContainSingle().Which.ImplementationType.Should().Be(typeof(InMemoryTwoFactorAttemptStore));

        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();

        var registrations = AttemptStoreRegistrations(services);
        registrations.Should().ContainSingle();
        registrations[0].ImplementationType.Should().Be(typeof(EfTwoFactorAttemptStore<SecDb>));
        registrations[0].Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public void AddPinotechrdSecurity_ShouldRegisterTheInMemoryStore_WhenTheEfStoreIsNotAdded()
    {
        var services = NewServices();

        AddSecurity(services);

        AttemptStoreRegistrations(services).Should().ContainSingle().Which.ImplementationType.Should().Be(typeof(InMemoryTwoFactorAttemptStore));
    }

    [Fact]
    public void AddPinotechrdEfTwoFactorAttemptStore_ShouldThrow_WhenServicesIsNull()
    {
        var act = () => PersistentStoreExtensions.AddPinotechrdEfTwoFactorAttemptStore<SecDb>(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddPinotechrdEfTwoFactorAttemptStore_ShouldNotTouchTheRefreshTokenStore()
    {
        var services = NewServices();
        AddSecurity(services);

        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();

        services.Where(d => d.ServiceType == typeof(IRefreshTokenStore)).Should().ContainSingle()
            .Which.ImplementationType.Should().Be(typeof(InMemoryRefreshTokenStore));
    }
}
