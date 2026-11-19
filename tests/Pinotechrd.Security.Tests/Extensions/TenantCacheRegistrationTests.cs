using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Pinotechrd.Security.Core;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Extensions;

/// <summary>AddPinotechrdSecurity wires the tenant cache to an IDistributedCache and exposes the invalidator.</summary>
public class TenantCacheRegistrationTests
{
    private const string Secret = "tenant-cache-registration-secret-with-32-plus-bytes";

    private static void Configure(PinotechrdSecurityOptions o)
    {
        o.Jwt.Secret = Secret;
        o.Jwt.Issuer = "tenant-cache-tests";
        o.Jwt.Audience = "tenant-cache-tests-clients";
        o.AllowUnverifiedTenantMembership = true;
    }

    private static ServiceCollection NewServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        return services;
    }

    private static void AddSecurity(IServiceCollection services, Action<PinotechrdSecurityOptions>? extra = null) =>
        services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
        {
            Configure(o);
            extra?.Invoke(o);
        });

    [Fact]
    public void ISecurityStoreAndISecurityCacheInvalidator_ShouldResolveToTheSameTenantCacheStore_WithinAScope()
    {
        var services = NewServices();
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();

        using var scope = provider.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<ISecurityStore>();
        var invalidator = scope.ServiceProvider.GetRequiredService<ISecurityCacheInvalidator>();

        store.Should().BeOfType<TenantCacheStore>();
        invalidator.Should().BeSameAs(store);
    }

    [Fact]
    public void ISecurityStore_ShouldBeADifferentInstanceInAnotherScope()
    {
        var services = NewServices();
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();

        using var first = provider.CreateScope();
        using var second = provider.CreateScope();

        second.ServiceProvider.GetRequiredService<ISecurityStore>()
            .Should().NotBeSameAs(first.ServiceProvider.GetRequiredService<ISecurityStore>());
    }

    [Fact]
    public void AddPinotechrdSecurity_ShouldRegisterTheInMemoryDistributedCache_WhenNoneIsRegistered()
    {
        var services = NewServices();
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IDistributedCache>().Should().BeOfType<MemoryDistributedCache>();
    }

    [Fact]
    public void AnApplicationDistributedCache_ShouldWin_WhenRegisteredBeforeAddPinotechrdSecurity()
    {
        var appCache = Substitute.For<IDistributedCache>();
        var services = NewServices();
        services.AddSingleton(appCache);
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IDistributedCache>().Should().BeSameAs(appCache);
    }

    [Fact]
    public void AnApplicationDistributedCache_ShouldWin_WhenRegisteredAfterAddPinotechrdSecurity()
    {
        var appCache = Substitute.For<IDistributedCache>();
        var services = NewServices();
        AddSecurity(services);
        services.AddSingleton(appCache);
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IDistributedCache>().Should().BeSameAs(appCache);
    }

    [Fact]
    public async Task TheTenantCacheStore_ShouldUseTheApplicationDistributedCache()
    {
        var appCache = Substitute.For<IDistributedCache>();
        appCache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(Task.FromResult<byte[]?>(null));
        var services = NewServices();
        services.AddSingleton(appCache);
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        await scope.ServiceProvider.GetRequiredService<ISecurityCacheInvalidator>().InvalidateTenantAsync("tenant-a");

        await appCache.ReceivedWithAnyArgs().SetAsync(default!, default!, default!, default);
    }

    [Fact]
    public void TenantCacheExpiration_ShouldReachIOptions_FromTheConfigureDelegate()
    {
        var services = NewServices();
        AddSecurity(services, o => o.TenantCacheExpiration = TimeSpan.FromSeconds(90));
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IOptions<PinotechrdSecurityOptions>>().Value.TenantCacheExpiration
            .Should().Be(TimeSpan.FromSeconds(90));
    }

    [Fact]
    public void TenantCacheExpiration_ShouldDefaultToFiveMinutes_WhenNotConfigured()
    {
        var services = NewServices();
        AddSecurity(services);
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<IOptions<PinotechrdSecurityOptions>>().Value.TenantCacheExpiration
            .Should().Be(TimeSpan.FromMinutes(5));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-30)]
    public async Task HostStart_ShouldFailWithOptionsValidationException_WhenTheCacheExpirationIsNotPositive(int seconds)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        AddSecurity(builder.Services, o => o.TenantCacheExpiration = TimeSpan.FromSeconds(seconds));
        using var host = builder.Build();

        var act = () => host.StartAsync();

        (await act.Should().ThrowAsync<OptionsValidationException>())
            .Which.Message.Should().Contain("TenantCacheExpiration");
    }

    [Fact]
    public async Task HostStart_ShouldSucceed_WhenTheCacheExpirationIsPositive()
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        AddSecurity(builder.Services, o => o.TenantCacheExpiration = TimeSpan.FromSeconds(1));
        using var host = builder.Build();

        await host.StartAsync();
        await host.StopAsync();
    }
}
