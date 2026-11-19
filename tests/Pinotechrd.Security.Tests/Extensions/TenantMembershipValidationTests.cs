using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Pinotechrd.Security.Data;
using Pinotechrd.Security.Entities;
using Pinotechrd.Security.Extensions;
using Pinotechrd.Security.Interfaces;
using Pinotechrd.Security.Options;
using Pinotechrd.Security.Tenancy;
using Pinotechrd.Security.Tests.Data;
using Pinotechrd.Security.Tests.Hosting;
using Xunit;

namespace Pinotechrd.Security.Tests.Extensions;

/// <summary>
/// Tenant membership fails closed: a context that does not derive from the library's base context proves nothing about
/// which tenant a user belongs to, so the host refuses to start unless an <see cref="IIdentityValidator{TUser}"/> is
/// registered or the application opts out with <see cref="PinotechrdSecurityOptions.AllowUnverifiedTenantMembership"/>.
/// </summary>
public class TenantMembershipValidationTests
{
    private static void ConfigureJwt(PinotechrdSecurityOptions o)
    {
        o.Jwt.Secret = "tenant-membership-validation-secret-32-bytes!!";
        o.Jwt.Issuer = "membership-tests";
        o.Jwt.Audience = "membership-clients";
    }

    /// <summary>Adds the library over <see cref="HostSecurityDbContext"/>, which does not derive from the base context.</summary>
    private static IServiceCollection AddOverPlainContext(
        IServiceCollection services, Action<PinotechrdSecurityOptions>? extra = null)
    {
        services.AddDbContext<HostSecurityDbContext>(o => o.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        services.AddPinotechrdSecurity<HostSecurityDbContext, HostUser, HostRole>(o =>
        {
            ConfigureJwt(o);
            extra?.Invoke(o);
        });
        return services;
    }

    private static async Task StartAsync(Action<IServiceCollection> configure)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        configure(builder.Services);
        using var host = builder.Build();
        await host.StartAsync();
        await host.StopAsync();
    }

    private static IIdentityValidator<HostUser> Validator() => Substitute.For<IIdentityValidator<HostUser>>();

    [Fact]
    public async Task Start_ShouldThrowOptionsValidationNamingTheContextTheValidatorAndTheOptOut_WhenTheContextIsNotTheBaseAndNoValidatorIsRegistered()
    {
        var act = () => StartAsync(services => AddOverPlainContext(services));

        var failure = await act.Should().ThrowAsync<OptionsValidationException>();
        failure.Which.Message.Should().Contain(nameof(HostSecurityDbContext));
        failure.Which.Message.Should().Contain("IIdentityValidator");
        failure.Which.Message.Should().Contain("AllowUnverifiedTenantMembership");
    }

    [Fact]
    public async Task Start_ShouldSucceed_WhenAValidatorIsRegisteredBeforeAddPinotechrdSecurity()
    {
        var act = () => StartAsync(services =>
        {
            services.AddSingleton(Validator());
            AddOverPlainContext(services);
        });

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Start_ShouldSucceed_WhenAValidatorIsRegisteredAfterAddPinotechrdSecurity()
    {
        var act = () => StartAsync(services =>
        {
            AddOverPlainContext(services);
            services.AddSingleton(Validator());
        });

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Start_ShouldSucceed_WhenUnverifiedMembershipIsAllowed()
    {
        var act = () => StartAsync(services => AddOverPlainContext(services, o => o.AllowUnverifiedTenantMembership = true));

        await act.Should().NotThrowAsync();
    }

    /// <summary>Adds the library over <see cref="SecDb"/>, which derives from the base context.</summary>
    private static void AddOverBaseContext(
        IServiceCollection services, Action<DbContextOptionsBuilder>? configureDb = null, Action<PinotechrdSecurityOptions>? extra = null)
    {
        services.AddScoped<ISchemaProvider>(_ => Substitute.For<ISchemaProvider>());
        services.AddDbContext<SecDb>(o =>
        {
            o.UseInMemoryDatabase(Guid.NewGuid().ToString());
            configureDb?.Invoke(o);
        });
        services.AddPinotechrdSecurity<SecDb, HostUser, HostRole>(o =>
        {
            ConfigureJwt(o);
            extra?.Invoke(o);
        });
    }

    private static Action<DbContextOptionsBuilder> UseLibrary(
        TenantSchemaMode mode = TenantSchemaMode.SchemaPerTenantInModel, bool applicationTakesSearchPath = false) =>
        o => o.UsePinotechrdSecurity(m =>
        {
            m.TenantSchemaMode = mode;
            m.ApplicationTakesResponsibilityForSearchPath = applicationTakesSearchPath;
        });

    [Theory]
    [InlineData(TenantSchemaMode.SchemaPerTenantInModel)]
    [InlineData(TenantSchemaMode.SearchPath)]
    public async Task Start_ShouldSucceed_WhenTheContextDerivesFromTheBaseContextIsConfiguredWithTheLibraryAndNeitherEscapeIsUsed(TenantSchemaMode mode)
    {
        var act = () => StartAsync(services => AddOverBaseContext(services, UseLibrary(mode)));

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Start_ShouldThrowNamingUsePinotechrdSecurity_WhenTheBaseDerivedContextIsNotConfiguredWithIt_AndNoValidatorIsRegistered()
    {
        var act = () => StartAsync(services => AddOverBaseContext(services));

        var failure = await act.Should().ThrowAsync<OptionsValidationException>();
        failure.Which.Message.Should().Contain("UsePinotechrdSecurity");
    }

    [Fact]
    public async Task Start_ShouldThrow_WhenSearchPathIsLeftToTheApplication_AndNoValidatorIsRegistered()
    {
        var act = () => StartAsync(services => AddOverBaseContext(
            services, UseLibrary(TenantSchemaMode.SearchPath, applicationTakesSearchPath: true)));

        var failure = await act.Should().ThrowAsync<OptionsValidationException>();
        failure.Which.Message.Should().Contain("ApplicationTakesResponsibilityForSearchPath");
    }

    [Fact]
    public async Task Start_ShouldSucceed_WhenSearchPathIsLeftToTheApplication_AndAValidatorIsRegistered()
    {
        var act = () => StartAsync(services =>
        {
            services.AddSingleton(Validator());
            AddOverBaseContext(services, UseLibrary(TenantSchemaMode.SearchPath, applicationTakesSearchPath: true));
        });

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Start_ShouldSucceed_WhenTheApplicationTakesTheSearchPathButTheModeIsSchemaPerTenantInModel()
    {
        var act = () => StartAsync(services => AddOverBaseContext(
            services, UseLibrary(TenantSchemaMode.SchemaPerTenantInModel, applicationTakesSearchPath: true)));

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Start_ShouldThrow_WhenTheOnlyValidatorRegisteredIsForAnotherUserType()
    {
        var act = () => StartAsync(services =>
        {
            services.AddSingleton(Substitute.For<IIdentityValidator<OtherUser>>());
            AddOverPlainContext(services);
        });

        await act.Should().ThrowAsync<OptionsValidationException>();
    }

    [Fact]
    public async Task Start_ShouldSucceed_WhenAnOpenGenericValidatorIsRegistered()
    {
        var act = () => StartAsync(services =>
        {
            services.AddScoped(typeof(IIdentityValidator<>), typeof(AllowAllValidator<>));
            AddOverPlainContext(services);
        });

        await act.Should().NotThrowAsync();
    }

    public sealed class OtherUser : BaseSecurityUser;

    private sealed class AllowAllValidator<TUser> : IIdentityValidator<TUser> where TUser : class
    {
        public Task<IdentityValidationResult> ValidateAsync(TUser user, string tenantId) =>
            Task.FromResult(new IdentityValidationResult(true));
    }

    [Fact]
    public void AllowUnverifiedTenantMembership_ShouldDefaultToFalse()
    {
        new PinotechrdSecurityOptions().AllowUnverifiedTenantMembership.Should().BeFalse();
    }

    [Fact]
    public void ResolvingTheAuthManager_ShouldThrowOptionsValidation_WhenTheHostWasNotStarted_AndMembershipCannotBeVerified()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        AddOverPlainContext(services);
        services.AddHostStubs();
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var act = () => scope.ServiceProvider.GetRequiredService<IPinotechrdAuthManager<HostUser>>();

        act.Should().Throw<OptionsValidationException>()
            .WithMessage("*AllowUnverifiedTenantMembership*");
    }

    [Fact]
    public void ResolvingTheAuthManager_ShouldSucceed_WhenTheHostWasNotStarted_AndUnverifiedMembershipIsAllowed()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        AddOverPlainContext(services, o => o.AllowUnverifiedTenantMembership = true);
        services.AddHostStubs();
        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var manager = scope.ServiceProvider.GetRequiredService<IPinotechrdAuthManager<HostUser>>();

        manager.Should().NotBeNull();
    }
}
