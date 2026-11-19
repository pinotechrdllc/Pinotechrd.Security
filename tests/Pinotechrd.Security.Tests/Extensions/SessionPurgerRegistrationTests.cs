using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Tests.Data;
using Xunit;

namespace Pinotechrd.Security.Tests.Extensions;

public class SessionPurgerRegistrationTests
{
    private static ServiceCollection NewServices()
    {
        var services = new ServiceCollection();
        services.AddDbContext<SecDb>(o => o.UseSqlite("DataSource=:memory:"));
        return services;
    }

    private static ServiceDescriptor[] Purgers(IServiceCollection services) =>
        services.Where(d => d.ServiceType == typeof(IPinotechrdSessionPurger)).ToArray();

    [Fact]
    public void BothEfStoreRegistrations_ShouldYieldASingleScopedPurger()
    {
        var services = NewServices();

        services.AddPinotechrdEfRefreshTokenStore<SecDb>();
        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();

        var purgers = Purgers(services);
        purgers.Should().ContainSingle();
        purgers[0].ImplementationType.Should().Be(typeof(EfSessionPurger<SecDb>));
        purgers[0].Lifetime.Should().Be(ServiceLifetime.Scoped);
    }

    [Fact]
    public void BothEfStoreRegistrations_ShouldYieldASingleScopedPurger_InTheOtherOrder()
    {
        var services = NewServices();

        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();
        services.AddPinotechrdEfRefreshTokenStore<SecDb>();

        Purgers(services).Should().ContainSingle();
    }

    [Fact]
    public void AddPinotechrdEfRefreshTokenStore_ShouldRegisterThePurger()
    {
        var services = NewServices();

        services.AddPinotechrdEfRefreshTokenStore<SecDb>();

        Purgers(services).Should().ContainSingle();
    }

    [Fact]
    public void AddPinotechrdEfTwoFactorAttemptStore_ShouldRegisterThePurger()
    {
        var services = NewServices();

        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();

        Purgers(services).Should().ContainSingle();
    }

    [Fact]
    public void EfStoreRegistrations_ShouldKeepAPurgerTheApplicationRegisteredFirst()
    {
        var services = NewServices();
        services.AddScoped<IPinotechrdSessionPurger, CustomPurger>();

        services.AddPinotechrdEfRefreshTokenStore<SecDb>();
        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();

        Purgers(services).Should().ContainSingle().Which.ImplementationType.Should().Be(typeof(CustomPurger));
    }

    [Fact]
    public void RefreshStoreThenTwoFactorStore_ShouldThrow_WhenTheirContextsDiffer()
    {
        var services = NewServices();
        services.AddPinotechrdEfRefreshTokenStore<SecDb>();

        var act = () => services.AddPinotechrdEfTwoFactorAttemptStore<OtherDb>();

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void TwoFactorStoreThenRefreshStore_ShouldThrow_WhenTheirContextsDiffer()
    {
        var services = NewServices();
        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();

        var act = () => services.AddPinotechrdEfRefreshTokenStore<OtherDb>();

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void BothEfStoreRegistrations_ShouldUseTheSharedContext_WhenItIsNotTheFirstOneUsed()
    {
        var services = NewServices();

        services.AddPinotechrdEfRefreshTokenStore<OtherDb>();
        services.AddPinotechrdEfTwoFactorAttemptStore<OtherDb>();

        Purgers(services).Should().ContainSingle().Which.ImplementationType.Should().Be(typeof(EfSessionPurger<OtherDb>));
    }

    [Fact]
    public void ReRegisteringTheRefreshStoreWithAnotherContext_ShouldMovePurgerToTheNewContext()
    {
        var services = NewServices();
        services.AddPinotechrdEfRefreshTokenStore<SecDb>();

        services.AddPinotechrdEfRefreshTokenStore<OtherDb>();

        Purgers(services).Should().ContainSingle().Which.ImplementationType.Should().Be(typeof(EfSessionPurger<OtherDb>));
    }

    [Fact]
    public void EfStoreRegistration_ShouldKeepAnApplicationPurger_EvenWithAnotherContext()
    {
        var services = NewServices();
        services.AddPinotechrdEfRefreshTokenStore<SecDb>();
        services.AddScoped<IPinotechrdSessionPurger, CustomPurger>();

        services.AddPinotechrdEfTwoFactorAttemptStore<SecDb>();

        Purgers(services).Should().Contain(d => d.ImplementationType == typeof(CustomPurger));
        Purgers(services).Last().ImplementationType.Should().Be(typeof(CustomPurger));
    }

    private sealed class OtherDb(DbContextOptions<OtherDb> options) : DbContext(options);

    private sealed class CustomPurger : IPinotechrdSessionPurger
    {
        public Task<SessionPurgeResult> PurgeExpiredAsync(TimeSpan? margin = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new SessionPurgeResult(0, 0, 0));
    }
}
